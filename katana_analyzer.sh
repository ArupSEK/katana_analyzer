#!/usr/bin/env bash
# Thin compatibility wrapper for the Python 3 analyzer.
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if ! command -v python3 >/dev/null 2>&1; then
  echo '[ERROR] Python 3 is required.' >&2
  exit 1
fi
exec python3 "$SCRIPT_DIR/katana_analyzer.py" "${@}"
