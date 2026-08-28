#!/bin/bash
set -e

if [ -z "$1" ]; then
    echo "Usage: ./run.sh <directory_or_file_to_scan> [extra_args...]"
    exit 1
fi

TARGET="$1"
if [ -e "$TARGET" ]; then
    TARGET="$(realpath "$TARGET")"
fi
shift || true

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -d ".venv" ]; then
    echo "Virtual environment not found. Please run ./install.sh first."
    exit 1
fi

source .venv/bin/activate
python3 scripts/launch.py "$TARGET" "$@"
