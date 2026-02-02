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

    pub fn getattr(
        &mut self,
        path: &str,
    ) -> Result<core::result::Result<nfs3::Fattr3, nfs3::NfsError>> {
        let fh = match self.lookup_path(path)? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        nfs3::getattr(&mut self.nfs, &fh)
    }

    pub fn setattr(
        &mut self,
        path: &str,
        attrs: &nfs3::SetAttr3,
        guard: Option<nfs3::Time3>,
    ) -> Result<core::result::Result<nfs3::WccData, nfs3::NfsError>> {
        let fh = match self.lookup_path(path)? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        nfs3::setattr(&mut self.nfs, &fh, attrs, guard)
    }

    pub fn access(
        &mut self,
        path: &str,
        access: u32,
    ) -> Result<core::result::Result<nfs3::AccessOk, nfs3::NfsError>> {
        let fh = match self.lookup_path(path)? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        nfs3::access(&mut self.nfs, &fh, access)
    }

    pub fn readlink(
        &mut self,
        path: &str,
    ) -> Result<core::result::Result<nfs3::ReadLinkOk, nfs3::NfsError>> {
        let fh = match self.lookup_path(path)? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        nfs3::readlink(&mut self.nfs, &fh)
    }

    pub fn create(
        &mut self,
        path: &str,
        how: &nfs3::CreateHow3,
    ) -> Result<core::result::Result<nfs3::CreateOk, nfs3::NfsError>> {
        let (dir_path, name) = split_parent(path)?;
        let dir = match self.lookup_path(dir_path)? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        nfs3::create(&mut self.nfs, &dir, name, how)
    }

    pub fn mkdir(
        &mut self,
        path: &str,
        attrs: &nfs3::SetAttr3,
    ) -> Result<core::result::Result<nfs3::MkdirOk, nfs3::NfsError>> {
        let (dir_path, name) = split_parent(path)?;
        let dir = match self.lookup_path(dir_path)? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        nfs3::mkdir(&mut self.nfs, &dir, name, attrs)
    }

    pub fn symlink(
        &mut self,
        path: &str,
        link_path: &str,
        attrs: &nfs3::SetAttr3,
    ) -> Result<core::result::Result<nfs3::SymlinkOk, nfs3::NfsError>> {
        let (dir_path, name) = split_parent(path)?;
        let dir = match self.lookup_path(dir_path)? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        nfs3::symlink(&mut self.nfs, &dir, name, link_path, attrs)
    }

    pub fn mknod(
        &mut self,
        path: &str,
        data: &nfs3::MknodData,
        attrs: &nfs3::SetAttr3,
    ) -> Result<core::result::Result<nfs3::MknodOk, nfs3::NfsError>> {
        let (dir_path, name) = split_parent(path)?;
        let dir = match self.lookup_path(dir_path)? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        nfs3::mknod(&mut self.nfs, &dir, name, data, attrs)
    }

    pub fn remove(
        &mut self,
        path: &str,
    ) -> Result<core::result::Result<nfs3::WccData, nfs3::NfsError>> {
        let (dir_path, name) = split_parent(path)?;
        let dir = match self.lookup_path(dir_path)? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        nfs3::remove(&mut self.nfs, &dir, name)
    }

    pub fn rmdir(
        &mut self,
        path: &str,
    ) -> Result<core::result::Result<nfs3::WccData, nfs3::NfsError>> {
        let (dir_path, name) = split_parent(path)?;
        let dir = match self.lookup_path(dir_path)? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        nfs3::rmdir(&mut self.nfs, &dir, name)
    }

    pub fn rename(
        &mut self,
        from: &str,
        to: &str,
    ) -> Result<core::result::Result<nfs3::RenameOk, nfs3::NfsError>> {
        let (from_dir_path, from_name) = split_parent(from)?;
        let (to_dir_path, to_name) = split_parent(to)?;
        let from_dir = match self.lookup_path(from_dir_path)? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        let to_dir = match self.lookup_path(to_dir_path)? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        nfs3::rename(&mut self.nfs, &from_dir, from_name, &to_dir, to_name)
    }

    pub fn link(
        &mut self,
        existing_path: &str,
        new_path: &str,
    ) -> Result<core::result::Result<nfs3::LinkOk, nfs3::NfsError>> {
        let fh = match self.lookup_path(existing_path)? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        let (dir_path, name) = split_parent(new_path)?;
        let dir = match self.lookup_path(dir_path)? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        nfs3::link(&mut self.nfs, &fh, &dir, name)
    }

    pub fn fsstat(
        &mut self,
        path: &str,
    ) -> Result<core::result::Result<nfs3::FsStatOk, nfs3::NfsError>> {
        let fh = match self.lookup_path(path)? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        nfs3::fsstat(&mut self.nfs, &fh)
    }

    pub fn fsinfo(
        &mut self,
        path: &str,
    ) -> Result<core::result::Result<nfs3::FsInfoOk, nfs3::NfsError>> {
        let fh = match self.lookup_path(path)? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        nfs3::fsinfo(&mut self.nfs, &fh)
    }

    pub fn pathconf(
        &mut self,
        path: &str,
    ) -> Result<core::result::Result<nfs3::PathConfOk, nfs3::NfsError>> {
        let fh = match self.lookup_path(path)? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        nfs3::pathconf(&mut self.nfs, &fh)
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

    pub fn readdir_all(
        &mut self,
        path: &str,
    ) -> Result<core::result::Result<Vec<nfs3::DirEntry>, nfs3::NfsError>> {
        let dir = match self.lookup_path(path)? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };

        let mut cookie = 0u64;
        let mut verifier = [0u8; 8];
        let mut out = Vec::new();
        loop {
            let res = nfs3::readdir(&mut self.nfs, &dir, cookie, verifier, 64 * 1024)?;
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

fn split_parent(path: &str) -> Result<(&str, &str)> {
    let p = path.trim_matches('/');
    if p.is_empty() {
        return Err(RpcError::RpcDenied("path is empty".into()));
    }
    match p.rsplit_once('/') {
        Some((dir, name)) if !name.is_empty() => Ok((dir, name)),
        None => Ok(("", p)),
        _ => Err(RpcError::RpcDenied("invalid path".into())),
    }
}
