#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VM_DIR="$ROOT_DIR/.vm/nfs41"

BASE_URL="https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img"
BASE_IMG="$VM_DIR/jammy-base.img"
OVERLAY_IMG="$VM_DIR/jammy-overlay.qcow2"
SEED_ISO="$VM_DIR/seed.iso"
PID_FILE="$VM_DIR/qemu.pid"
SERIAL_LOG="$VM_DIR/serial.log"

HOST_NFS_PORT="${HOST_NFS_PORT:-2049}"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing tool: $1" >&2
    exit 1
  }
}

need qemu-system-x86_64
need qemu-img
need curl

mkdir -p "$VM_DIR"

if [[ -f "$PID_FILE" ]]; then
  echo "VM appears to be running (pidfile exists): $PID_FILE" >&2
  echo "Stop it first: ./scripts/vm/nfs41-down.sh" >&2
  exit 1
fi

if [[ ! -f "$BASE_IMG" ]]; then
  echo "Downloading Ubuntu cloud image..." >&2
  curl -L --fail -o "$BASE_IMG" "$BASE_URL"
fi

if [[ ! -f "$OVERLAY_IMG" ]]; then
  echo "Creating overlay..." >&2
  qemu-img create -f qcow2 -b "$BASE_IMG" "$OVERLAY_IMG" >/dev/null
fi

USER_DATA="$VM_DIR/user-data"
META_DATA="$VM_DIR/meta-data"

cat >"$USER_DATA" <<'EOF'
#cloud-config
package_update: true
packages:
  - nfs-kernel-server
write_files:
  - path: /etc/exports
    permissions: '0644'
    content: |
      /srv/nfs *(rw,fsid=0,no_subtree_check,no_root_squash,insecure)
  - path: /etc/default/nfs-kernel-server
    permissions: '0644'
    content: |
      RPCNFSDOPTS="--nfs-version 4 --nfs-version 4.1"
runcmd:
  - mkdir -p /srv/nfs/subdir
  - bash -lc 'printf "hello world\\n" > /srv/nfs/hello.txt'
  - bash -lc 'printf "nested\\n" > /srv/nfs/subdir/nested.txt'
  - systemctl enable --now nfs-server || systemctl enable --now nfs-kernel-server
  - exportfs -ra
  - systemctl restart nfs-server || systemctl restart nfs-kernel-server
EOF

cat >"$META_DATA" <<'EOF'
instance-id: nfs-rs-nfs41
local-hostname: nfs-rs-nfs41
EOF

if command -v cloud-localds >/dev/null 2>&1; then
  cloud-localds "$SEED_ISO" "$USER_DATA" "$META_DATA" >/dev/null
elif command -v genisoimage >/dev/null 2>&1; then
  genisoimage -output "$SEED_ISO" -volid cidata -joliet -rock "$USER_DATA" "$META_DATA" \
    >/dev/null
elif command -v mkisofs >/dev/null 2>&1; then
  mkisofs -output "$SEED_ISO" -volid cidata -joliet -rock "$USER_DATA" "$META_DATA" \
    >/dev/null
else
  echo "missing tool: cloud-localds OR genisoimage OR mkisofs" >&2
  exit 1
fi

echo "Starting VM..." >&2
qemu-system-x86_64 \
  -machine accel=kvm:tcg \
  -cpu host \
  -smp 2 \
  -m 2048 \
  -display none \
  -serial "file:$SERIAL_LOG" \
  -drive "file=$OVERLAY_IMG,if=virtio" \
  -drive "file=$SEED_ISO,if=virtio,format=raw,readonly=on" \
  -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:${HOST_NFS_PORT}-:2049" \
  -device "virtio-net-pci,netdev=net0" \
  -daemonize \
  -pidfile "$PID_FILE"

echo "Waiting for NFS port ${HOST_NFS_PORT}..." >&2
for _ in $(seq 1 120); do
  if (echo >/dev/tcp/127.0.0.1/${HOST_NFS_PORT}) >/dev/null 2>&1; then
    echo "NFSv4.1 server is up on 127.0.0.1:${HOST_NFS_PORT}" >&2
    echo "Run: cargo test --test nfs41_vm -- --ignored" >&2
    exit 0
  fi
  sleep 1
done

echo "Timed out waiting for NFS port. See: $SERIAL_LOG" >&2
exit 1
