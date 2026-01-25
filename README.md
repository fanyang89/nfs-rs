# nfs-rs

Pure Rust NFS client (work-in-progress).

Currently implemented (MVP):
- ONC RPC over TCP (record marking)
- PORTMAP v2: `GETPORT`
- MOUNT v3: `MNT`
- NFS v3: `GETATTR`, `LOOKUP`, `READ`
- NFS v4.1: session handshake + `LOOKUP`/`GETFH`/`READ` (read-only)

## Quick start (NFSv3)

```rust
use nfs_rs::client::Nfs3Client;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut c = Nfs3Client::connect_and_mount("127.0.0.1", "/export")?;
    c.set_auth_sys("nfs-rs", 1000, 1000, &[1000]);

    let fh = c.lookup_path("path/to/file.txt")??;
    let chunk = nfs_rs::nfs3::read(&mut c.nfs, &fh, 0, 4096)??;
    println!("read {} bytes", chunk.data.len());
    Ok(())
}
```

You can also try the examples:

```bash
cargo run --example nfs_ls  -- <server> <export> <path>
cargo run --example nfs_cat -- <server> <export> <path>
cargo run --example nfs4_cat -- <server> <path>
```

## References

Protocol definitions used as reference live under `.refs/` (for local development).
