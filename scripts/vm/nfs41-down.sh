#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VM_DIR="$ROOT_DIR/.vm/nfs41"
PID_FILE="$VM_DIR/qemu.pid"

if [[ ! -f "$PID_FILE" ]]; then
  echo "No pidfile found: $PID_FILE" >&2
  exit 0
fi

PID="$(cat "$PID_FILE" || true)"
if [[ -n "$PID" ]] && kill -0 "$PID" >/dev/null 2>&1; then
  echo "Stopping VM (pid $PID)..." >&2
  kill "$PID" || true
fi

rm -f "$PID_FILE"
echo "VM stopped." >&2
