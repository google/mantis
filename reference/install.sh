#!/bin/sh
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e

cd "$(dirname "$0")"

# --- Platform Gate ---
OS="$(uname -s)"
case "$OS" in
    Linux)
        # Standard Linux environment (including WSL2)
        ;;
    Darwin)
        if [ "$(uname -m)" = "arm64" ]; then
            echo "macOS (Apple Silicon) detected: microsandbox microVMs run via Hypervisor.framework."
        else
            echo "WARNING: macOS on Intel is unsupported for microVM isolation."
            echo "         Set sandbox.type to 'static-only' in workflow.json for static-only analysis."
        fi
        ;;
    CYGWIN*|MINGW*|MSYS*)
        echo "ERROR: Native Windows is not supported due to shell and virtualenv layout differences (.venv/Scripts vs .venv/bin)." >&2
        echo "       Please use WSL2 (Windows Subsystem for Linux), where Mantis runs unmodified." >&2
        exit 1
        ;;
    *)
        echo "WARNING: Unrecognized platform '$OS'. Proceeding with standard installation..."
        ;;
esac

# --- Python Version Gate ---
PYTHON="${PYTHON:-python3}"
if ! "$PYTHON" -c 'import sys; sys.exit(0 if (3, 12) <= sys.version_info < (3, 15) else 1)' 2>/dev/null; then
    echo "ERROR: Mantis requires Python >= 3.12 and < 3.15." >&2
    echo "       Current interpreter ($PYTHON): $("$PYTHON" --version 2>&1 || echo 'none')" >&2
    exit 1
fi

echo "Setting up virtual environment..."
"$PYTHON" -m venv .venv
. .venv/bin/activate

echo "Installing dependencies..."
pip install --require-hashes -r requirements.txt

# --- Sandbox image (optional: enables dynamic reproduction) ---
TAG="mantis-sandbox:latest"

build_image() {
    _msb_tool="$1"
    _msb_tar="$(mktemp -t mantis-sandbox-XXXXXX.tar)"
    _msb_status=0
    {
        "$_msb_tool" build -t "$TAG" ./sandbox &&
        case "$_msb_tool" in
            buildah) buildah push "$TAG" "oci-archive:$_msb_tar" ;;
            podman)  podman save --format oci-archive -o "$_msb_tar" "$TAG" ;;
            docker)  docker save -o "$_msb_tar" "$TAG" ;;
        esac &&
        .venv/bin/msb image load -i "$_msb_tar" -t "$TAG"
    } || _msb_status=$?
    rm -f "$_msb_tar"
    return "$_msb_status"
}

if .venv/bin/msb image list 2>/dev/null | grep -q "mantis-sandbox"; then
    echo "Sandbox image '$TAG' already cached; skipping build."
else
    BUILD_SUCCESS=0
    for t in buildah podman docker; do
        if command -v "$t" >/dev/null 2>&1; then
            echo "Attempting to build sandbox image with $t..."
            if build_image "$t"; then
                BUILD_SUCCESS=1
                echo "Successfully built and loaded '$TAG' with $t."
                break
            else
                echo "Building with $t failed; trying next builder if available..."
            fi
        fi
    done

    if [ "$BUILD_SUCCESS" -eq 0 ]; then
        # Fallback: no container builder on this host (typical macOS dev
        # machine). Pull a pinned base image straight into the microsandbox
        # cache instead. This is the only time a pull happens -- the runtime
        # always boots with PullPolicy.NEVER. Keep this list in sync with
        # MICROSANDBOX_FALLBACK_IMAGES in scripts/configure.py.
        # mirror.gcr.io first: some networks block Docker Hub.
        PULL_SUCCESS=0
        for img in "mirror.gcr.io/library/python:3-slim" "docker.io/library/python:3-slim"; do
            echo "No container builder found; pulling base image '$img' into the sandbox cache..."
            if .venv/bin/msb image pull "$img"; then
                PULL_SUCCESS=1
                echo "Successfully cached '$img'. Auto-configure will select it as the guest image."
                break
            else
                echo "Pulling '$img' failed; trying next mirror if available..."
            fi
        done

        if [ "$PULL_SUCCESS" -eq 0 ]; then
            echo "WARNING: could not build (buildah, podman, docker) or pull a sandbox guest image."
            echo "         Dynamic reproduction needs a cached guest image; fix network/registry access"
            echo "         and re-run ./install.sh, or set sandbox.type to 'static-only' in workflow.json."
        fi
    fi
fi


# --- Authoritative MANTIS_HOME ---
# Skills instruct agents to anchor every script invocation via "$MANTIS_HOME/reference/...".
# That anchoring is what keeps an agent from executing a same-named script out of an
# untrusted checkout, so MANTIS_HOME must be set by something authoritative rather than
# left to the operator. Emit it as a sourceable file next to the install root.
MANTIS_HOME_DIR="$(cd .. && pwd)"
cat > mantis-env.sh <<EOF
# Generated by reference/install.sh. Source this before invoking Mantis skills.
export MANTIS_HOME="$MANTIS_HOME_DIR"
EOF
echo "Wrote reference/mantis-env.sh (export MANTIS_HOME=\"$MANTIS_HOME_DIR\")."
echo "Add 'source \"$MANTIS_HOME_DIR/reference/mantis-env.sh\"' to your shell profile so"
echo "skill invocations anchor to this installation instead of the current directory."

echo "Setup complete! You can now run ./run.sh"
