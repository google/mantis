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

if [ "$#" -eq 0 ] || [ -z "$1" ]; then
    echo "Usage: ./run.sh <directory_or_file_to_scan> [extra_args...]"
    exit 1
fi

MANTIS_INVOCATION_DIR="$(pwd)"
export MANTIS_INVOCATION_DIR

FIRST_ARG="$1"
TARGET="$1"
# Anchor relative path to absolute without dereferencing symlinks.
# POSIX `case` is used instead of bash's [[ ]] so anchoring still applies when the
# script is invoked as `sh run.sh`, which would otherwise skip this branch entirely.
case "$TARGET" in
    -*|/*) ;;
    *) TARGET="$MANTIS_INVOCATION_DIR/$TARGET" ;;
esac
shift || true

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -d ".venv" ]; then
    echo "Virtual environment not found. Please run ./install.sh first."
    exit 1
fi

. .venv/bin/activate
export PYTHONUNBUFFERED=1
case "$FIRST_ARG" in
    -*) exec .venv/bin/python3 scripts/launch.py "$FIRST_ARG" "$@" ;;
    *)  exec .venv/bin/python3 scripts/launch.py "$TARGET" "$@" ;;
esac
