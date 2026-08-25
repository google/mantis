#!/bin/bash
set -e

cd "$(dirname "$0")"

# --- Platform Gate ---
OS="$(uname -s)"
case "$OS" in
    Linux)
        # Standard Linux environment (including WSL2)
        ;;
    Darwin)
        echo "WARNING: macOS (Darwin) detected. MicroVM / KVM hardware virtualization is unsupported on macOS."
        echo "         Dynamic reproduction requires a container runtime or setting sandbox.type to 'static-only'"
        echo "         in workflow.json for static-only analysis."
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

echo "Setting up virtual environment..."
python3 -m venv .venv
source .venv/bin/activate

echo "Installing dependencies..."
pip install --require-hashes -r requirements.txt

# --- Sandbox image (optional: enables dynamic reproduction) ---
TAG="mantis-sandbox:latest"

build_image() {
    local tool="$1" tar
    tar="$(mktemp -t mantis-sandbox-XXXXXX.tar)"
    local status=0
    {
        "$tool" build -t "$TAG" ./sandbox &&
        case "$tool" in
            buildah) buildah push "$TAG" "oci-archive:$tar" ;;
            podman)  podman save --format oci-archive -o "$tar" "$TAG" ;;
            docker)  docker save -o "$tar" "$TAG" ;;
        esac &&
        .venv/bin/msb image load -i "$tar" -t "$TAG"
    } || status=$?
    rm -f "$tar"
    return "$status"
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
        echo "WARNING: failed to build sandbox image with any available builder (buildah, podman, docker)."
        echo "         Dynamic reproduction needs the sandbox image; install one and re-run ./install.sh,"
        echo "         or set sandbox.type to 'gvisor' or 'static-only' in workflow.json."
    fi
fi

echo "Setup complete! You can now run ./run.sh"
