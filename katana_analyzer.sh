#!/bin/sh
# POSIX-compatible launcher: works with sh, bash, or direct execution.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if ! command -v python3 >/dev/null 2>&1; then
  echo '[ERROR] Python 3 is required.' >&2
  exit 1
fi

exec python3 "$SCRIPT_DIR/katana_analyzer.py" "$@"
