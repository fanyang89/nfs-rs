//! High-level NFSv4.1 client (read-only MVP).

use crate::nfs4::{self, Nfs4Error};
use crate::rpc::{OpaqueAuth, Result, RpcError, TcpRpcClient};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub struct Nfs41Client {
    pub rpc: TcpRpcClient,
    clientid: u64,
    open_owner: Vec<u8>,
    open_seqid: u32,
    close_seqid: u32,
    sessionid: [u8; 16],
    slotid: u32,
    seq: u32,
}

impl Nfs41Client {
    pub fn connect(server: &str) -> Result<Self> {
        let mut rpc = TcpRpcClient::connect(&format!("{server}:2049"))?;
        let cred = OpaqueAuth::auth_sys("nfs-rs", 1000, 1000, &[1000]);
        rpc.set_auth(cred);

        let owner = nfs4::ClientOwner4 {
            verifier: make_verifier8(),
            ownerid: make_ownerid(),
        };

        let ex = nfs4::exchange_id(
            &mut rpc,
            &owner,
            nfs4::EXCHGID4_FLAG_USE_PNFS_MDS | nfs4::EXCHGID4_FLAG_USE_NON_PNFS,
        )?;
        let exok = ex.map_err(|e| RpcError::RpcAcceptedError(e.to_string()))?;

        let cs = nfs4::create_session(&mut rpc, exok.clientid, exok.sequenceid)?;
        let csok = cs.map_err(|e| RpcError::RpcAcceptedError(e.to_string()))?;

        Ok(Self {
            rpc,
            clientid: exok.clientid,
            open_owner: owner.ownerid,
            open_seqid: 1,
            close_seqid: 1,
            sessionid: csok.sessionid,
            slotid: 0,
            seq: csok.sequenceid,
        })
    }

    pub fn set_auth_sys(&mut self, machine: &str, uid: u32, gid: u32, groups: &[u32]) {
        self.rpc
            .set_auth(OpaqueAuth::auth_sys(machine, uid, gid, groups));
    }

    pub fn lookup_fh(&mut self, path: &str) -> Result<core::result::Result<Vec<u8>, Nfs4Error>> {
        let (seqok, fh) = match nfs4::compound_with_session_lookup_getfh(
            &mut self.rpc,
            self.sessionid,
            self.seq,
            self.slotid,
            path,
        )? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        self.seq = seqok.sequenceid.wrapping_add(1);
        Ok(Ok(fh))
    }

    pub fn open_getfh_access(
        &mut self,
        path: &str,
        access: u32,
    ) -> Result<core::result::Result<nfs4::OpenGetFhOk, Nfs4Error>> {
        let (dir_path, name) = split_parent(path)?;
        let sess = self.session_args();
        let (seqok, open_ok, fh) = match nfs4::compound_with_session_open_getfh_access(
            &mut self.rpc,
            sess,
            nfs4::OpenOwner {
                clientid: self.clientid,
                owner: &self.open_owner,
                seqid: self.open_seqid,
            },
            nfs4::OpenPath { dir_path, name },
            access,
        )? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        self.seq = seqok.sequenceid.wrapping_add(1);
        self.open_seqid = self.open_seqid.wrapping_add(1);
        Ok(Ok((seqok, open_ok, fh)))
    }

    pub fn read_at(
        &mut self,
        fh: &[u8],
        stateid: &nfs4::StateId4,
        offset: u64,
        count: u32,
    ) -> Result<core::result::Result<nfs4::ReadOk, Nfs4Error>> {
        let sess = self.session_args();
        let (seqok, r) = match nfs4::compound_with_session_putfh_read_stateid(
            &mut self.rpc,
            sess,
            nfs4::ReadArgs {
                fh,
                stateid,
                offset,
                count,
            },
        )? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        self.seq = seqok.sequenceid.wrapping_add(1);
        Ok(Ok(r))
    }

    pub fn write_at(
        &mut self,
        fh: &[u8],
        stateid: &nfs4::StateId4,
        offset: u64,
        data: &[u8],
        stable_how: u32,
    ) -> Result<core::result::Result<nfs4::WriteOk, Nfs4Error>> {
        let sess = self.session_args();
        let (seqok, w) = match nfs4::compound_with_session_putfh_write_stateid(
            &mut self.rpc,
            sess,
            nfs4::WriteArgs {
                fh,
                stateid,
                offset,
                data,
                stable_how,
            },
        )? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        self.seq = seqok.sequenceid.wrapping_add(1);
        Ok(Ok(w))
    }

    pub fn close_fh(
        &mut self,
        fh: &[u8],
        stateid: &nfs4::StateId4,
    ) -> Result<core::result::Result<(), Nfs4Error>> {
        let seqok = match nfs4::compound_with_session_putfh_close(
            &mut self.rpc,
            self.sessionid,
            self.seq,
            self.slotid,
            fh,
            self.close_seqid,
            stateid,
        )? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        self.seq = seqok.sequenceid.wrapping_add(1);
        self.close_seqid = self.close_seqid.wrapping_add(1);
        Ok(Ok(()))
    }

    pub fn layoutget(
        &mut self,
        fh: &[u8],
        stateid: &nfs4::StateId4,
        iomode: u32,
        offset: u64,
        length: u64,
        minlength: u64,
        maxcount: u32,
    ) -> Result<core::result::Result<nfs4::LayoutGetOk, Nfs4Error>> {
        let sess = self.session_args();
        let (seqok, lg) = match nfs4::compound_with_session_putfh_layoutget(
            &mut self.rpc,
            sess,
            nfs4::LayoutGetArgs {
                fh,
                stateid,
                avail: false,
                layout_type: nfs4::LAYOUT4_FLEX_FILES,
                iomode,
                offset,
                length,
                minlength,
                maxcount,
            },
        )? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        self.seq = seqok.sequenceid.wrapping_add(1);
        Ok(Ok(lg))
    }

    pub fn getdeviceinfo(
        &mut self,
        deviceid: &nfs4::DeviceId4,
        maxcount: u32,
    ) -> Result<core::result::Result<nfs4::GetDeviceInfoOk, Nfs4Error>> {
        let sess = self.session_args();
        let (seqok, gd) = match nfs4::compound_with_session_getdeviceinfo(
            &mut self.rpc,
            sess,
            deviceid,
            nfs4::LAYOUT4_FLEX_FILES,
            maxcount,
            &[],
        )? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        self.seq = seqok.sequenceid.wrapping_add(1);
        Ok(Ok(gd))
    }

    pub fn layoutcommit(
        &mut self,
        fh: &[u8],
        offset: u64,
        length: u64,
        stateid: &nfs4::StateId4,
        last_write_offset: Option<u64>,
    ) -> Result<core::result::Result<nfs4::LayoutCommitOk, Nfs4Error>> {
        let sess = self.session_args();
        let (seqok, lc) = match nfs4::compound_with_session_putfh_layoutcommit(
            &mut self.rpc,
            sess,
            nfs4::LayoutCommitArgs {
                fh,
                offset,
                length,
                reclaim: false,
                stateid,
                last_write_offset,
            },
        )? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        self.seq = seqok.sequenceid.wrapping_add(1);
        Ok(Ok(lc))
    }

    pub fn layoutreturn(
        &mut self,
        fh: &[u8],
        iomode: u32,
        offset: u64,
        length: u64,
        stateid: &nfs4::StateId4,
    ) -> Result<core::result::Result<Option<nfs4::StateId4>, Nfs4Error>> {
        let sess = self.session_args();
        let (seqok, lr) = match nfs4::compound_with_session_putfh_layoutreturn(
            &mut self.rpc,
            sess,
            nfs4::LayoutReturnArgs {
                fh,
                reclaim: false,
                iomode,
                offset,
                length,
                stateid,
            },
        )? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        self.seq = seqok.sequenceid.wrapping_add(1);
        Ok(Ok(lr))
    }

    pub fn read_to_end(
        &mut self,
        path: &str,
        chunk_size: u32,
    ) -> Result<core::result::Result<Vec<u8>, Nfs4Error>> {
        let (dir_path, name) = split_parent(path)?;

        let (seqok, open_ok, fh) = match nfs4::compound_with_session_open_getfh(
            &mut self.rpc,
            nfs4::SessionArgs {
                sessionid: self.sessionid,
                seq: self.seq,
                slot: self.slotid,
            },
            nfs4::OpenOwner {
                clientid: self.clientid,
                owner: &self.open_owner,
                seqid: self.open_seqid,
            },
            nfs4::OpenPath { dir_path, name },
        )? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        self.seq = seqok.sequenceid.wrapping_add(1);
        self.open_seqid = self.open_seqid.wrapping_add(1);

        let mut out = Vec::new();
        let mut offset = 0u64;
        loop {
            let (seqok, r) = match nfs4::compound_with_session_putfh_read_stateid(
                &mut self.rpc,
                nfs4::SessionArgs {
                    sessionid: self.sessionid,
                    seq: self.seq,
                    slot: self.slotid,
                },
                nfs4::ReadArgs {
                    fh: &fh,
                    stateid: &open_ok.stateid,
                    offset,
                    count: chunk_size,
                },
            )? {
                Ok(v) => v,
                Err(e) => return Ok(Err(e)),
            };
            self.seq = seqok.sequenceid.wrapping_add(1);
            if r.data.is_empty() {
                break;
            }
            offset = offset.saturating_add(r.data.len() as u64);
            out.extend_from_slice(&r.data);
            if r.eof {
                break;
            }
        }

        let seqok = match nfs4::compound_with_session_putfh_close(
            &mut self.rpc,
            self.sessionid,
            self.seq,
            self.slotid,
            &fh,
            self.close_seqid,
            &open_ok.stateid,
        )? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        self.seq = seqok.sequenceid.wrapping_add(1);
        self.close_seqid = self.close_seqid.wrapping_add(1);

        Ok(Ok(out))
    }

    fn session_args(&self) -> nfs4::SessionArgs {
        nfs4::SessionArgs {
            sessionid: self.sessionid,
            seq: self.seq,
            slot: self.slotid,
        }
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

fn make_verifier8() -> [u8; 8] {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let nanos = now.subsec_nanos() as u64;
    (secs ^ nanos).to_be_bytes()
}

fn make_ownerid() -> Vec<u8> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("nfs-rs:{}:{}", std::process::id(), now.as_nanos()).into_bytes()
}
