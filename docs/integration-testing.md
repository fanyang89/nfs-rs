# Integration testing

This repo has two tiers of tests:

- Fast, hermetic tests (`cargo test`) that do not need external services.
- Optional integration tests that require a real Linux NFS server.

## NFSv3

NFSv3 integration tests use the in-process Rust server `nfsserve`.

Run:

```bash
cargo test
```

## NFSv4.1 (local-only via QEMU VM)

NFSv4.1 (and later pNFS) is best validated against a real Linux server.
This repo provides a QEMU + cloud-init harness that boots an Ubuntu cloud image,
starts `nfs-kernel-server`, and exposes port 2049 to the host.

Prereqs (host):

- `qemu-system-x86_64`
- `qemu-img`
- `curl`
- One of:
  - `cloud-localds` (preferred), or
  - `genisoimage` / `mkisofs`

Start the VM:

```bash
./scripts/vm/nfs41-up.sh
```

Run the ignored integration tests:

```bash
cargo test --test nfs41_vm -- --ignored
```

Stop the VM:

```bash
./scripts/vm/nfs41-down.sh
```

## NFSv4.1 (user-space via nfs-ganesha)

This repo includes an `nfs-ganesha` submodule that can be used for local
user-space NFSv4.1 testing without a VM. The tests are gated behind an env var.

Build nfs-ganesha (once):

```bash
mkdir -p nfs-ganesha/build
cd nfs-ganesha/build
cmake ../src
make -j
```

Run the ganesha-backed tests:

```bash
NFS_GANESHA_TESTS=1 NFS_GANESHA_BUILD_DIR=$(pwd) cargo test --test nfs41_ganesha
```

If you already have `ganesha.nfsd` built elsewhere, set `NFS_GANESHA_BIN`
to its full path instead of `NFS_GANESHA_BUILD_DIR`.
