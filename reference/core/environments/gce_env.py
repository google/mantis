import asyncio
import base64
import json
import logging
import os
from pathlib import Path
import shlex
import shutil
import subprocess
from typing import Optional, Union, List
import uuid

from google.adk.environment import ExecutionResult
from .base import BaseEnvironment

logger = logging.getLogger(__name__)

ISOLATION_PROBE_SCRIPT = """import sys
import urllib.request
import socket

errors = []

# 1. Probe Metadata Service Account Token
try:
    req = urllib.request.Request(
        'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token',
        headers={'Metadata-Flavor': 'Google'}
    )
    with urllib.request.urlopen(req, timeout=1.5) as r:
        if r.status == 200:
            errors.append('IAM: Service account OAuth tokens accessible via metadata server (set --no-service-account --no-scopes)')
except Exception:
    pass

# 2. Probe Direct Internet IP Egress
try:
    s = socket.create_connection(('1.1.1.1', 80), timeout=1.5)
    s.close()
    errors.append('NETWORK: Direct internet IP egress accessible (remove NAT / default route)')
except Exception:
    pass

# 3. Probe Public DNS Recursion / Exfil
try:
    ip = socket.gethostbyname('example.com')
    if ip and not ip.startswith('0.') and not ip.startswith('127.'):
        errors.append(f'DNS: Public DNS recursion resolved example.com to {ip} (attach Cloud DNS Response Policy *. -> 0.0.0.0)')
except Exception:
    pass

# 4. Probe Google APIs
try:
    s = socket.create_connection(('storage.googleapis.com', 443), timeout=1.5)
    s.close()
    errors.append('GCP: Private Google Access enabled (set --no-enable-private-ip-google-access)')
except Exception:
    pass

if errors:
    print('ISOLATION_FAILURE: ' + ' | '.join(errors))
    sys.exit(42)

print('ISOLATION_VERIFIED')
"""


MAX_OUTPUT = 16000


class GceEnvironment(BaseEnvironment):
    """Hardened Google Compute Engine (GCE) VM sandbox environment.

    Security & Hardening Invariants:
    - GOLDEN MACHINE IMAGE: Clones pre-configured build/dev VM with local tools and caches.
    - NO EXTERNAL IPV4 ADDRESS / PRIVATE VPC: --no-address ensures no external IPv4
      address is assigned. Full egress containment additionally requires the VPC, DNS policy,
      and firewall configuration in docs/gce_sandbox_setup.md (including Private Google Access
      disabled and no NAT gateway), verified at provision time by the isolation probe.
    - DNS EXFILTRATION DEFENSE: VPC should be attached to a Cloud DNS Response Policy with a
      wildcard rule (*. -> 0.0.0.0 / NODATA) or an Outbound DNS Server Policy directing queries
      to a private blackhole IP (e.g. 10.0.0.254), closing the link-local 169.254.169.254:53
      out-of-band recursive DNS exfiltration path.
    - IAP-ONLY INGRESS: Communication is strictly proxied over Google Cloud IAP SSH tunnel
      (--tunnel-through-iap) on port 22 from CIDR 35.235.240.0/20.
    - HOST ISOLATION: Host runs gcloud via explicit argv array with shell=False, preventing
      host-side command injection or metacharacter expansion.
    - SHIELDED VM: Secure Boot, vTPM, and Integrity Monitoring are enabled.
    - METADATA DEFENSE: disable-legacy-endpoints=TRUE and block-project-ssh-keys=TRUE.
    - CONFINED WORKSPACE: Target code is staged into guest /workspace; execution is jailed.
    - STATEFUL LIFECYCLE: VM and filesystem state persist across execute() and apply_patch()
      for the duration of a file/run, then cleanly deleted on close().
    - ADK COMPLIANT: Implements execute(), read_file(), write_file(), list_files(), apply_patch(),
      preflight(), initialize(), and close().
    """

    def __init__(
        self,
        target_path: str = "",
        project: Optional[str] = None,
        zone: Optional[str] = None,
        source_machine_image: Optional[str] = None,
        network: str = "mantis-isolated-vpc",
        subnet: Optional[str] = "mantis-isolated-subnet",
        machine_type: str = "e2-medium",
        image_family: Optional[str] = None,
        image_project: Optional[str] = None,
        image: Optional[str] = None,
        timeout_seconds: int = 60,
        workdir: str = "/workspace",
        tunnel_through_iap: bool = True,
        no_service_account: bool = True,
        no_external_ip: bool = True,
        verify_isolation: bool = True,
        max_run_duration: str = "30m",
        gcloud_bin: Optional[str] = None,
    ):
        super().__init__()
        self.target_path = os.path.realpath(target_path) if target_path else ""
        self.project = project or os.environ.get("GOOGLE_CLOUD_PROJECT") or os.environ.get("VERTEXAI_PROJECT") or ""
        self.zone = zone or os.environ.get("GOOGLE_CLOUD_ZONE") or "us-central1-a"
        self.source_machine_image = source_machine_image
        self.network = network
        self.subnet = subnet
        self.machine_type = machine_type
        self.image_family = image_family
        self.image_project = image_project
        self.image = image
        self.timeout = timeout_seconds
        self._workdir = Path(workdir)
        self.tunnel_through_iap = tunnel_through_iap
        self.no_service_account = no_service_account
        self.no_external_ip = no_external_ip
        self.verify_isolation_flag = verify_isolation
        self.max_run_duration = max_run_duration

        bin_path = gcloud_bin or shutil.which("gcloud")
        if not bin_path:
            bin_path = "gcloud"
        self.gcloud_bin = bin_path

        self.instance_name = f"mantis-gce-{uuid.uuid4().hex[:12]}"
        self._started = False
        self._stage_error: Optional[Exception] = None
        self._lock = asyncio.Lock()

    @property
    def working_dir(self) -> Path:
        return self._workdir

    def _run_gcloud(
        self, argv: list[str], stdin: Optional[str] = None, timeout: Optional[int] = None
    ) -> tuple[int, str]:
        t = timeout or self.timeout
        cmd = [self.gcloud_bin] + argv
        try:
            p = subprocess.run(
                cmd,
                input=stdin or "",
                capture_output=True,
                text=True,
                timeout=t,
                shell=False,
            )
            out = (p.stdout or "") + (p.stderr or "")
            return p.returncode, out
        except subprocess.TimeoutExpired:
            return -1, f"SANDBOX-TIMEOUT: command exceeded {t}s."
        except Exception as e:
            return -1, f"SANDBOX-ERROR: {e}"

    async def preflight(self) -> None:
        """Validates prerequisites: gcloud CLI availability and active GCP credentials/project."""
        if self.source_machine_image and self.no_service_account:
            raise ValueError(
                "GCP Machine Images ('source_machine_image') lock the source VM's IAM service account "
                "identity and reject '--no-service-account'. To enforce zero-IAM sandbox isolation, "
                "capture a custom disk image instead (`gcloud compute images create ... --source-disk=... --force`) "
                "and configure 'image' in workflow.json."
            )
        if shutil.which(self.gcloud_bin) is None and not os.path.exists(self.gcloud_bin):
            raise ValueError(
                f"sandbox type 'gce' requires '{self.gcloud_bin}' on PATH. "
                "Install Google Cloud SDK or set sandbox.type to 'static-only'."
            )
        if self.project and self.project.strip().upper() in {"YOUR_PROJECT_ID", "YOUR_PROJECT", "<YOUR_PROJECT_ID>"}:
            raise ValueError(
                f"GCE sandbox project is set to default placeholder '{self.project}'. "
                "Update 'options.project' in workflow.json with your actual GCP Project ID, or configure sandbox.type to 'static-only' or 'microsandbox'."
            )
        if not self.project:
            rc, out = self._run_gcloud(["config", "get-value", "project"])
            if rc != 0 or not out.strip() or "unset" in out:
                raise ValueError(
                    "GCP project not specified for GCE VM sandbox. Set options.project or GOOGLE_CLOUD_PROJECT env."
                )
            resolved_proj = out.strip()
            if resolved_proj.upper() in {"YOUR_PROJECT_ID", "YOUR_PROJECT", "<YOUR_PROJECT_ID>"}:
                raise ValueError(
                    f"GCE sandbox project is set to default placeholder '{resolved_proj}'. "
                    "Update 'options.project' in workflow.json with your actual GCP Project ID, or configure sandbox.type to 'static-only' or 'microsandbox'."
                )
            self.project = resolved_proj

        rc, out = self._run_gcloud(["auth", "list", "--filter=status:ACTIVE", "--format=value(account)"])
        if rc != 0 or not out.strip():
            raise RuntimeError(
                f"No active Google Cloud authentication found. Run 'gcloud auth login' or 'gcloud auth application-default login': {out}"
            )

    async def _ensure(self) -> None:
        """Creates the hardened ephemeral GCE VM instance and stages workspace files."""
        async with self._lock:
            if self._started:
                return
            if self._stage_error is not None:
                raise self._stage_error

            def _init():
                # 1. Build instance create command with security hardening flags
                create_args = [
                    "compute", "instances", "create", self.instance_name,
                    f"--project={self.project}",
                    f"--zone={self.zone}",
                    f"--machine-type={self.machine_type}",
                    "--shielded-secure-boot",
                    "--shielded-vtpm",
                    "--shielded-integrity-monitoring",
                    "--metadata=disable-legacy-endpoints=TRUE,block-project-ssh-keys=TRUE",
                ]

                # Maintenance policy: E2 instances require MIGRATE (default) unless preemptible/SPOT
                if not self.machine_type.startswith("e2-"):
                    create_args.append("--maintenance-policy=TERMINATE")

                # Hardening: Cloud-enforced TTL auto-deletion
                if self.max_run_duration:
                    create_args.extend([
                        f"--max-run-duration={self.max_run_duration}",
                        "--instance-termination-action=DELETE",
                    ])

                # Identifiable resource labeling
                create_args.append("--labels=mantis-sandbox=true,created-by=mantis")

                # Hardening: No attached service account
                if self.no_service_account:
                    create_args.extend(["--no-service-account", "--no-scopes"])

                # Hardening: Zero internet access / No external public IP
                if self.no_external_ip:
                    create_args.append("--no-address")

                # Subnet / Network configuration
                if self.subnet:
                    create_args.append(f"--subnet={self.subnet}")
                elif self.network:
                    create_args.append(f"--network={self.network}")

                # Image source: Golden Machine Image preferred, fallback to image/family
                if self.source_machine_image:
                    create_args.append(f"--source-machine-image={self.source_machine_image}")
                elif self.image:
                    create_args.append(f"--image={self.image}")
                elif self.image_family:
                    create_args.append(f"--image-family={self.image_family}")
                    if self.image_project:
                        create_args.append(f"--image-project={self.image_project}")
                else:
                    create_args.extend([
                        "--image-family=ubuntu-2204-lts",
                        "--image-project=ubuntu-os-cloud",
                    ])

                rc, out = self._run_gcloud(create_args, timeout=120)
                if rc != 0:
                    raise RuntimeError(f"Failed to create GCE VM instance '{self.instance_name}': {out}")

                # 2. Wait for SSH readiness / create workspace directory
                mkdir_cmd = f"sudo mkdir -p {self._workdir} && sudo chown -R $(whoami) {self._workdir}"
                ssh_args = [
                    "compute", "ssh", self.instance_name,
                    f"--project={self.project}",
                    f"--zone={self.zone}",
                ]
                if self.tunnel_through_iap:
                    ssh_args.append("--tunnel-through-iap")
                ssh_args.extend(["--command", mkdir_cmd])

                # Retry loop waiting for VM boot & guest agent SSH readiness
                ready = False
                for _ in range(12):
                    rc, out = self._run_gcloud(ssh_args, timeout=20)
                    if rc == 0:
                        ready = True
                        break
                    import time
                    time.sleep(3)

                if not ready:
                    raise RuntimeError(
                        f"GCE VM '{self.instance_name}' failed to initialize guest SSH / workspace: {out}"
                    )

                # 3. Stage target file or directory into guest VM /workspace
                if self.target_path and os.path.exists(self.target_path):
                    scp_args = [
                        "compute", "scp",
                    ]
                    if self.tunnel_through_iap:
                        scp_args.append("--tunnel-through-iap")
                    scp_args.extend([
                        f"--project={self.project}",
                        f"--zone={self.zone}",
                    ])

                    if os.path.isdir(self.target_path):
                        scp_args.append("--recurse")
                        scp_args.append(f"{self.target_path}/.")
                    else:
                        scp_args.append(self.target_path)

                    scp_args.append(f"{self.instance_name}:{self._workdir}/")
                    rc, out = self._run_gcloud(scp_args, timeout=60)
                    if rc != 0:
                        raise RuntimeError(
                            f"Failed to stage files into GCE VM '{self.instance_name}': {out}"
                        )

                # 4. Active in-guest isolation verification (if enabled)
                if self.verify_isolation_flag:
                    self._verify_guest_isolation()

            try:
                await asyncio.to_thread(_init)
                self._started = True
                self.is_initialized = True
            except Exception as e:
                self._stage_error = e
                try:
                    await asyncio.to_thread(self._delete_instance)
                except Exception:
                    pass
                raise e

    def _verify_guest_isolation(self) -> None:
        """Executes active in-guest probes to verify zero internet access, no IAM token leak, and no public DNS recursion."""
        b64_probe = base64.b64encode(ISOLATION_PROBE_SCRIPT.encode("utf-8")).decode("ascii")
        guest_cmd = f"echo '{b64_probe}' | base64 -d | python3 -"
        ssh_args = [
            "compute", "ssh", self.instance_name,
            f"--project={self.project}",
            f"--zone={self.zone}",
        ]
        if self.tunnel_through_iap:
            ssh_args.append("--tunnel-through-iap")
        ssh_args.extend(["--command", guest_cmd])

        rc, out = self._run_gcloud(ssh_args, timeout=20)
        if rc == 42 or "ISOLATION_FAILURE" in out:
            raise RuntimeError(
                f"GCE VM '{self.instance_name}' failed security isolation audit:\n{out.strip()}"
            )
        elif rc != 0:
            raise RuntimeError(
                f"GCE VM '{self.instance_name}' failed to execute isolation probe (ensure python3 is installed in golden machine image):\n{out.strip()}"
            )

    async def initialize(self) -> None:
        await self._ensure()

    async def execute(self, command: str, *, timeout: Optional[float] = None) -> ExecutionResult:
        """Executes a command inside the hardened GCE VM workspace via IAP SSH tunnel."""
        await self._ensure()
        t = timeout or self.timeout

        guest_cmd = f"cd {self._workdir} && {command}"
        ssh_args = [
            "compute", "ssh", self.instance_name,
            f"--project={self.project}",
            f"--zone={self.zone}",
        ]
        if self.tunnel_through_iap:
            ssh_args.append("--tunnel-through-iap")
        ssh_args.extend(["--command", guest_cmd])

        def _exec():
            try:
                p = subprocess.run(
                    [self.gcloud_bin] + ssh_args,
                    capture_output=True,
                    text=True,
                    timeout=t,
                    shell=False,
                )
                return ExecutionResult(
                    stdout=(p.stdout or "")[:MAX_OUTPUT],
                    stderr=(p.stderr or "")[:MAX_OUTPUT],
                    exit_code=p.returncode,
                    timed_out=False,
                )
            except subprocess.TimeoutExpired as e:
                return ExecutionResult(
                    stdout=(e.stdout or "")[:MAX_OUTPUT] if hasattr(e, "stdout") and e.stdout else "",
                    stderr=f"SANDBOX-TIMEOUT: Command exceeded {t}s limit.",
                    exit_code=124,
                    timed_out=True,
                )
            except Exception as e:
                return ExecutionResult(
                    stdout="",
                    stderr=f"SANDBOX-ERROR: {e}",
                    exit_code=-1,
                    timed_out=False,
                )

        return await asyncio.to_thread(_exec)

    def _resolve_guest_path(self, path: Union[Path, str]) -> Path:
        p = Path(path)
        if not p.is_absolute():
            return self._workdir / p
        try:
            if p == self._workdir or self._workdir in p.parents:
                return p
        except Exception:
            pass
        if self.target_path:
            target_p = Path(self.target_path)
            if target_p.is_file():
                if p == target_p:
                    return self._workdir / target_p.name
                if target_p.parent in p.parents or p == target_p.parent:
                    try:
                        rel = p.relative_to(target_p.parent)
                        return self._workdir / rel
                    except ValueError:
                        pass
            elif target_p.is_dir():
                if target_p in p.parents or p == target_p:
                    try:
                        rel = p.relative_to(target_p)
                        return self._workdir / rel
                    except ValueError:
                        pass
        fallback_target = self._workdir / p.name
        logger.info(f"[GCE] Remapping out-of-workdir path '{path}' -> '{fallback_target}'")
        return fallback_target

    async def read_file(self, path: Union[Path, str]) -> bytes:
        """Reads a file from the guest VM workspace without output truncation."""
        await self._ensure()
        resolved_path = self._resolve_guest_path(path)
        guest_cmd = f"base64 -w 0 {shlex.quote(str(resolved_path))}"
        ssh_args = [
            "compute", "ssh", self.instance_name,
            f"--project={self.project}",
            f"--zone={self.zone}",
        ]
        if self.tunnel_through_iap:
            ssh_args.append("--tunnel-through-iap")
        ssh_args.extend(["--command", guest_cmd])

        def _read():
            p = subprocess.run(
                [self.gcloud_bin] + ssh_args,
                capture_output=True,
                text=False,
                timeout=self.timeout,
                shell=False,
            )
            if p.returncode != 0:
                stderr = p.stderr.decode("utf-8", errors="replace") if isinstance(p.stderr, bytes) else str(p.stderr)
                if "No such file" in stderr:
                    raise FileNotFoundError(f"File not found in GCE VM: {path}")
                if "Permission denied" in stderr:
                    raise PermissionError(f"Permission denied reading file in GCE VM: {path}")
                raise RuntimeError(f"Error reading file {path} from GCE VM: {stderr}")
            try:
                raw_b64 = p.stdout.strip()
                return base64.b64decode(raw_b64)
            except Exception as e:
                raise RuntimeError(f"Failed to decode file {path} content: {e}")

        return await asyncio.to_thread(_read)

    async def write_file(self, path: Union[Path, str], content: Union[str, bytes]) -> None:
        """Writes content to a file inside the guest VM workspace via stdin streaming without argv limits."""
        await self._ensure()
        resolved_path = self._resolve_guest_path(path)
        data_bytes = content.encode("utf-8") if isinstance(content, str) else content
        parent_dir = str(resolved_path.parent)

        guest_cmd = f"mkdir -p {shlex.quote(parent_dir)} && cat > {shlex.quote(str(resolved_path))}"
        ssh_args = [
            "compute", "ssh", self.instance_name,
            f"--project={self.project}",
            f"--zone={self.zone}",
        ]
        if self.tunnel_through_iap:
            ssh_args.append("--tunnel-through-iap")
        ssh_args.extend(["--command", guest_cmd])

        def _write():
            p = subprocess.run(
                [self.gcloud_bin] + ssh_args,
                input=data_bytes,
                capture_output=True,
                timeout=self.timeout,
                shell=False,
            )
            if p.returncode != 0:
                stderr = p.stderr.decode("utf-8", errors="replace") if isinstance(p.stderr, bytes) else str(p.stderr)
                raise RuntimeError(f"Failed to write file {path} in GCE VM: {stderr}")

        await asyncio.to_thread(_write)

    async def list_files(self, directory: str = "") -> List[str]:
        """Lists files inside the guest VM workspace under directory without output truncation."""
        await self._ensure()
        target_dir = str(self._resolve_guest_path(directory)) if directory else str(self._workdir)
        guest_cmd = (
            f"if [ ! -d {shlex.quote(target_dir)} ]; then exit 44; fi; "
            f"find {shlex.quote(target_dir)} -maxdepth 5 -type f ! -path '*/.*' | sort"
        )
        ssh_args = [
            "compute", "ssh", self.instance_name,
            f"--project={self.project}",
            f"--zone={self.zone}",
        ]
        if self.tunnel_through_iap:
            ssh_args.append("--tunnel-through-iap")
        ssh_args.extend(["--command", guest_cmd])

        def _list():
            p = subprocess.run(
                [self.gcloud_bin] + ssh_args,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                shell=False,
            )
            if p.returncode == 44:
                raise FileNotFoundError(f"Directory not found in GCE VM: {directory}")
            if p.returncode != 0:
                raise RuntimeError(f"Error listing files in GCE VM: {p.stderr}")
            prefix = str(self._workdir).rstrip("/") + "/"
            results = []
            for line in (p.stdout or "").splitlines():
                line = line.strip()
                if not line:
                    continue
                if line.startswith(prefix):
                    line = line[len(prefix):]
                results.append(line)
            return results

        return await asyncio.to_thread(_list)

    async def apply_patch(self, diff: str) -> str:
        """Applies a unified diff patch inside the guest VM workspace via stdin streaming without argv limits."""
        await self._ensure()
        guest_cmd = f"patch -p1 -d {shlex.quote(str(self._workdir))}"
        ssh_args = [
            "compute", "ssh", self.instance_name,
            f"--project={self.project}",
            f"--zone={self.zone}",
        ]
        if self.tunnel_through_iap:
            ssh_args.append("--tunnel-through-iap")
        ssh_args.extend(["--command", guest_cmd])

        def _patch():
            p = subprocess.run(
                [self.gcloud_bin] + ssh_args,
                input=diff.encode("utf-8"),
                capture_output=True,
                text=True,
                timeout=self.timeout,
                shell=False,
            )
            if p.returncode == 0:
                return f"exit=0\n{p.stdout}"
            return f"exit={p.returncode}\n{p.stderr}\n{p.stdout}"

        return await asyncio.to_thread(_patch)

    def _delete_instance(self) -> None:
        delete_args = [
            "compute", "instances", "delete", self.instance_name,
            f"--project={self.project}",
            f"--zone={self.zone}",
            "--quiet",
        ]
        self._run_gcloud(delete_args, timeout=60)

    async def close(self) -> None:
        """Terminates and deletes the ephemeral GCE VM instance."""
        async with self._lock:
            if not self._started and self._stage_error is None:
                return
            try:
                await asyncio.to_thread(self._delete_instance)
            finally:
                self._started = False
                self.is_initialized = False
