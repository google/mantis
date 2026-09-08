#!/bin/bash
set -e

if [ -z "$1" ]; then
    echo "Usage: ./run.sh <directory_or_file_to_scan> [extra_args...]"
    exit 1
fi

TARGET="$1"
# Anchor relative path to absolute without dereferencing symlinks.
# POSIX `case` is used instead of bash's [[ ]] so anchoring still applies when the
# script is invoked as `sh run.sh`, which would otherwise skip this branch entirely.
if [ -e "$TARGET" ] || [ -L "$TARGET" ]; then
    case "$TARGET" in
        /*) ;;
        *) TARGET="$(pwd)/$TARGET" ;;
    esac
fi
shift || true

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -d ".venv" ]; then
    echo "Virtual environment not found. Please run ./install.sh first."
    exit 1
fi

source .venv/bin/activate
export PYTHONUNBUFFERED=1
python3 scripts/launch.py "$TARGET" "$@"
