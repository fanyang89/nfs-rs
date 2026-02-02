# nfs-rs

Pure Rust NFS client (work-in-progress).

Currently implemented (MVP):
- ONC RPC over TCP (record marking)
- PORTMAP v2: `GETPORT`
- MOUNT v3: `MNT`
- NFS v3: `GETATTR`, `SETATTR`, `LOOKUP`, `ACCESS`, `READLINK`, `READ`, `WRITE`,
  `CREATE`, `MKDIR`, `SYMLINK`, `MKNOD`, `REMOVE`, `RMDIR`, `RENAME`, `LINK`,
  `READDIR`, `READDIRPLUS`, `FSSTAT`, `FSINFO`, `PATHCONF`, `COMMIT`
- NFS v4.1: session handshake + `LOOKUP`/`GETFH`/`OPEN`/`READ`/`WRITE`/`CLOSE`
- pNFS flexfiles: `LAYOUTGET`/`GETDEVICEINFO`/`LAYOUTCOMMIT`/`LAYOUTRETURN`
  (MDS over NFSv4.1, DS over NFSv3)

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
