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
