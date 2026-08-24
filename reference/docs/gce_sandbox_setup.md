# Hardened GCE VM Sandbox Setup & Isolation Guide

This guide describes how to provision, harden, and verify a Google Compute
Engine (GCE) VM sandbox for dynamic exploit reproduction and patch verification
in Mantis.

An automated idempotent setup script is provided at
[`reference/scripts/setup_gce_sandbox.sh`](../scripts/setup_gce_sandbox.sh):

```bash
PROJECT_ID="your-project-id" SOURCE_INSTANCE="your-dev-vm" ./reference/scripts/setup_gce_sandbox.sh
```

______________________________________________________________________

## Configuration Variables

Set these environment variables in your shell before running the manual setup
commands:

```bash
export PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project)}"
export REGION="us-central1"
export ZONE="us-central1-a"
export VPC_NAME="mantis-isolated-vpc"
export SUBNET_NAME="mantis-isolated-subnet"
export SUBNET_RANGE="10.0.0.0/24"
export DNS_POLICY_NAME="mantis-block-public-dns"
export IMAGE_NAME="mantis-assessment-disk-v1"
export DEV_BUILD_VM="my-dev-build-vm"
```

______________________________________________________________________

## 1. Assessment Disk Image Creation

1. Provision a development VM with all necessary build runtimes, compilers,
   package managers, and test suites.
2. Build your target repository on the VM to warm all local build caches,
   dependencies, and artifacts.
3. Capture a custom disk image from the source build VM:

```bash
gcloud compute images create "${IMAGE_NAME}" \
    --project="${PROJECT_ID}" \
    --source-disk="${DEV_BUILD_VM}" \
    --source-disk-zone="${ZONE}" \
    --force \
    --description="Assessment disk image with pre-warmed build dependencies for Mantis"
```

> [!IMPORTANT] **Disk Images vs Machine Images**: Custom disk images
> (`gcloud compute images create --source-disk=...`) allow full instance
> identity override (`--no-service-account --no-scopes`), ensuring the sandbox
> VM runs with zero IAM credentials (`serviceAccounts: null`). GCE Machine
> Images (`--source-machine-image`) lock in the service account identity from
> the source VM and disallow `--no-service-account`.

______________________________________________________________________

## 2. Private Isolated VPC & Network Containment

Create a dedicated VPC with zero external access and Private Google Access
disabled:

```bash
# 1. Custom VPC
gcloud compute networks create "${VPC_NAME}" \
    --project="${PROJECT_ID}" \
    --subnet-mode=custom

# 2. Private subnet (no internet route, no Cloud NAT, no Google API access)
gcloud compute networks subnets create "${SUBNET_NAME}" \
    --project="${PROJECT_ID}" \
    --network="${VPC_NAME}" \
    --region="${REGION}" \
    --range="${SUBNET_RANGE}" \
    --no-enable-private-ip-google-access

# 3. Allow SSH strictly from Google Cloud Identity-Aware Proxy (IAP) IP range
gcloud compute firewall-rules create "allow-iap-ssh-${VPC_NAME}" \
    --project="${PROJECT_ID}" \
    --network="${VPC_NAME}" \
    --allow=tcp:22 \
    --source-ranges=35.235.240.0/20
```

______________________________________________________________________

## 3. Link-Local DNS Exfiltration Defense (`169.254.169.254:53`)

By default in GCE, queries to the link-local metadata resolver
(`169.254.169.254:53`) perform recursive public DNS lookups out-of-band via the
hypervisor, creating an exfiltration path even without external IP routing.

Seal this path at the VPC infrastructure level using Cloud DNS:

### Option A: Cloud DNS Response Policy (RPZ Wildcard Blackhole)

```bash
# Create response policy bound to isolated VPC
gcloud dns response-policies create "${DNS_POLICY_NAME}" \
    --project="${PROJECT_ID}" \
    --networks="${VPC_NAME}" \
    --description="Block all public DNS lookups"

# Wildcard rule returning 0.0.0.0 for all domains (*.)
gcloud dns response-policies rules create block-all-domains \
    --project="${PROJECT_ID}" \
    --response-policy="${DNS_POLICY_NAME}" \
    --dns-name="*." \
    --local-data=name="*.",type="A",ttl=300,rrdatas="0.0.0.0"
```

### Option B: Outbound DNS Server Policy (Private Sinkhole & Logging)

```bash
# Redirect all VM DNS queries away from public recursion to an unassigned private IP
gcloud dns policies create mantis-dns-blackhole \
    --project="${PROJECT_ID}" \
    --networks="${VPC_NAME}" \
    --description="Redirect VM DNS queries to private blackhole" \
    --private-alternative-name-servers=10.0.0.254 \
    --enable-logging
```

______________________________________________________________________

## 4. Mantis Workflow Configuration

Add the GCE sandbox configuration to `workflow.json`:

```json
{
  "sandbox": {
    "type": "gce",
    "options": {
      "project": "YOUR_PROJECT_ID",
      "zone": "us-central1-a",
      "image": "mantis-assessment-disk-v1",
      "subnet": "mantis-isolated-subnet",
      "workdir": "/workspace",
      "tunnel_through_iap": true,
      "no_service_account": true,
      "no_external_ip": true,
      "verify_isolation": true,
      "timeout_seconds": 60
    }
  }
}
```

______________________________________________________________________

## 5. Automated Active Isolation Audit Probes

When `verify_isolation: true` is set (the default), `GceEnvironment` executes an
active in-guest probe before executing any PoCs or analysis tasks:

1. **IAM Token Leak Probe**: Queries
   `http://169.254.169.254/.../service-accounts/default/token`. Fails if access
   tokens are accessible.
2. **Direct Internet Egress Probe**: Attempts TCP connection to external IP
   (`1.1.1.1:80`). Fails if reachable.
3. **Public DNS Recursion Probe**: Attempts resolving `example.com`. Fails if
   public IP is returned.
4. **Private Google Access Probe**: Attempts TCP connection to
   `storage.googleapis.com:443`. Fails if reachable.

If any check fails, the VM is immediately deleted and Mantis halts with a
fail-closed `RuntimeError` detailing the misconfiguration.

______________________________________________________________________

## 6. Single-VM Scope & Multi-VM Architecture Considerations

> [!NOTE] The GCE sandbox setup is currently designed and configured for
> **single-VM execution only**.

If an operator wants to adapt this setup for multi-VM campaigns (e.g.
distributed targets or multi-node exploit chains), they must resolve at least
the following architectural constraints:

1. **DNS Name Resolution (`*.internal`)**: The wildcard Cloud DNS response
   policy (`*.` → `0.0.0.0`) catches everything, including internal metadata
   domains (`*.internal`), making peer VMs unresolvable by hostname. Multi-VM
   setups require explicit private DNS zone rules bypassing the wildcard
   sinkhole for internal peer records.
2. **Internal VM-to-VM Ingress**: The firewall section creates IAP ingress on
   `tcp:22` and nothing else. Because GCP denies ingress by default, all
   VM-to-VM network traffic between sandbox instances is blocked (there is no
   `allow-internal` rule).
3. **Instance Tagging & Firewall Scoping**: Instances created by
   `GceEnvironment` do not currently attach network `--tags`. An operator adding
   an internal communication rule cannot scope it to sandbox VMs by tag, but
   only by CIDR (which means scoping it to the entire subnet).
