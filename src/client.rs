//! Higher-level convenience wrapper (NFSv3 + MOUNTv3).

use crate::mount3;
use crate::nfs3::{self, FileHandle};
use crate::portmap2::{self, Proto};
use crate::rpc::{OpaqueAuth, Result, RpcError, TcpRpcClient};

#[derive(Debug)]
pub struct Nfs3Client {
    pub mount: TcpRpcClient,
    pub nfs: TcpRpcClient,
    pub root: FileHandle,
}

impl Nfs3Client {
    /// Connects using TCP to portmapper (:111), looks up MOUNT and NFS ports,
    /// mounts the export path, and returns a client rooted at that export.
    pub fn connect_and_mount(server: &str, export: &str) -> Result<Self> {
        let mut pmap = TcpRpcClient::connect(&format!("{server}:111"))?;
        let mount_port = portmap2::getport(
            &mut pmap,
            mount3::MOUNT_PROG,
            mount3::MOUNT_VERS,
            Proto::Tcp,
        )?;
        let nfs_port = portmap2::getport(&mut pmap, nfs3::NFS_PROG, nfs3::NFS_VERS, Proto::Tcp)?;

        if mount_port == 0 {
            return Err(RpcError::RpcAcceptedError(
                "portmapper returned mount port 0".into(),
            ));
        }
        if nfs_port == 0 {
            return Err(RpcError::RpcAcceptedError(
                "portmapper returned nfs port 0".into(),
            ));
        }

        let mut mount = TcpRpcClient::connect(&format!("{server}:{mount_port}"))?;
        let mut nfs = TcpRpcClient::connect(&format!("{server}:{nfs_port}"))?;

        // Default to AUTH_SYS with common Linux-ish uid/gid for a local user.
        // Callers can override via `set_auth_sys`.
        let cred = OpaqueAuth::auth_sys("nfs-rs", 1000, 1000, &[1000]);
        mount.set_auth(cred.clone());
        nfs.set_auth(cred);

        let res = mount3::mnt(&mut mount, export)?;
        let ok =
            res.map_err(|e| RpcError::RpcAcceptedError(format!("mount status {}", e.status)))?;
        let root = FileHandle(ok.fh);
        Ok(Self { mount, nfs, root })
    }

    pub fn set_auth_sys(&mut self, machine: &str, uid: u32, gid: u32, groups: &[u32]) {
        let cred = OpaqueAuth::auth_sys(machine, uid, gid, groups);
        self.mount.set_auth(cred.clone());
        self.nfs.set_auth(cred);
    }

    pub fn lookup_path(
        &mut self,
        path: &str,
    ) -> Result<core::result::Result<FileHandle, nfs3::NfsError>> {
        let mut cur = self.root.clone();
        for comp in path.split('/').filter(|s| !s.is_empty()) {
            let res = nfs3::lookup(&mut self.nfs, &cur, comp)?;
            let ok = match res {
                Ok(v) => v,
                Err(e) => return Ok(Err(e)),
            };
            cur = ok.fh;
        }
        Ok(Ok(cur))
    }

    pub fn readdirplus_all(
        &mut self,
        path: &str,
    ) -> Result<core::result::Result<Vec<nfs3::DirEntryPlus>, nfs3::NfsError>> {
        let dir = match self.lookup_path(path)? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };

        let mut cookie = 0u64;
        let mut verifier = [0u8; 8];
        let mut out = Vec::new();
        loop {
            let res =
                nfs3::readdirplus(&mut self.nfs, &dir, cookie, verifier, 8 * 1024, 64 * 1024)?;
            let ok = match res {
                Ok(v) => v,
                Err(e) => return Ok(Err(e)),
            };

            verifier = ok.verifier;
            if let Some(last) = ok.entries.last() {
                cookie = last.cookie;
            }
            out.extend(ok.entries);
            if ok.eof {
                break;
            }
        }
        Ok(Ok(out))
    }

    pub fn read_to_end(
        &mut self,
        path: &str,
        chunk_size: u32,
    ) -> Result<core::result::Result<Vec<u8>, nfs3::NfsError>> {
        let fh = match self.lookup_path(path)? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };

        let mut out = Vec::new();
        let mut offset = 0u64;
        loop {
            let res = nfs3::read(&mut self.nfs, &fh, offset, chunk_size)?;
            let ok = match res {
                Ok(v) => v,
                Err(e) => return Ok(Err(e)),
            };
            if ok.data.is_empty() {
                break;
            }
            offset = offset.saturating_add(ok.data.len() as u64);
            out.extend_from_slice(&ok.data);
            if ok.eof {
                break;
            }
        }
        Ok(Ok(out))
    }
}
