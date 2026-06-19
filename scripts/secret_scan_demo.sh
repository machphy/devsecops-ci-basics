#!/bin/bash
set -euo pipefail

# Demo script for running a simple Go-based secret scanning tool.
# Run from repository root: bash scripts/secret_scan_demo.sh

if [ -z "${SCAN_FILE:-}" ]; then
  echo "ERROR: SCAN_FILE is not set. Set it with 'export SCAN_FILE=path/to/file' and try again."
  exit 1
fi

if ! command -v go >/dev/null 2>&1; then
  echo "ERROR: Go is not installed or not on PATH. Install Go to use this demo."
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

cd "$REPO_ROOT/go_tools/secret_scanner"

go run . "$SCAN_FILE"
