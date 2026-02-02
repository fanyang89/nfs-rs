//! High-level NFSv4.1 client (basic read/write + metadata + create/rename/remove).

use crate::nfs4::{self, Nfs4Error};
use crate::rpc::{
    OpaqueAuth, Result, RpcCall, RpcCallbackHandler, RpcError, RpcReply, TcpRpcClient,
};
use crate::xdr::{XdrReader, XdrWriter};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
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
    cb_state: Arc<Mutex<CallbackState>>,
    auth_machine: String,
    default_uid: u32,
    default_gid: u32,
    default_groups: Vec<u32>,
}

impl Nfs41Client {
    pub fn connect(server: &str) -> Result<Self> {
        Self::connect_with_port(server, 2049)
    }

    pub fn connect_with_port(server: &str, port: u16) -> Result<Self> {
        Self::connect_with_port_flags(
            server,
            port,
            nfs4::EXCHGID4_FLAG_USE_PNFS_MDS | nfs4::EXCHGID4_FLAG_USE_NON_PNFS,
            nfs4::NFS4_CALLBACK_PROG,
            true,
        )
    }

    pub fn connect_ds(server: &str, port: u16) -> Result<Self> {
        Self::connect_with_port_flags(
            server,
            port,
            nfs4::EXCHGID4_FLAG_USE_PNFS_DS,
            0,
            false,
        )
    }

    pub fn connect_with_port_flags(
        server: &str,
        port: u16,
        exchg_flags: u32,
        cb_program: u32,
        enable_callbacks: bool,
    ) -> Result<Self> {
        let mut rpc = TcpRpcClient::connect(&format!("{server}:{port}"))?;
        let auth_machine = "nfs-rs".to_string();
        let default_uid = 1000;
        let default_gid = 1000;
        let default_groups = vec![1000];
        let cred = OpaqueAuth::auth_sys(&auth_machine, default_uid, default_gid, &default_groups);
        rpc.set_auth(cred);

        let owner = nfs4::ClientOwner4 {
            verifier: make_verifier8(),
            ownerid: make_ownerid(),
        };

        let ex = nfs4::exchange_id(
            &mut rpc,
            &owner,
            exchg_flags,
        )?;
        let exok = ex.map_err(|e| RpcError::RpcAcceptedError(e.to_string()))?;

        let cb_auth = if enable_callbacks {
            Some(nfs4::AuthSysParams {
                machine: &auth_machine,
                uid: default_uid,
                gid: default_gid,
                groups: &default_groups,
            })
        } else {
            None
        };
        let cs = nfs4::create_session(
            &mut rpc,
            exok.clientid,
            exok.sequenceid,
            cb_program,
            cb_auth,
        )?;
        let csok = cs.map_err(|e| RpcError::RpcAcceptedError(e.to_string()))?;
        let cb_state = Arc::new(Mutex::new(CallbackState::new(csok.sessionid)));
        if enable_callbacks && cb_program != 0 {
            rpc.set_callback_handler(Box::new(Nfs4CallbackHandler {
                cb_program,
                state: cb_state.clone(),
            }));
        }

        Ok(Self {
            rpc,
            clientid: exok.clientid,
            open_owner: owner.ownerid,
            open_seqid: 1,
            close_seqid: 1,
            sessionid: csok.sessionid,
            slotid: 0,
            seq: csok.sequenceid,
            cb_state,
            auth_machine,
            default_uid,
            default_gid,
            default_groups,
        })
    }

    pub fn set_auth_sys(&mut self, machine: &str, uid: u32, gid: u32, groups: &[u32]) {
        self.rpc
            .set_auth(OpaqueAuth::auth_sys(machine, uid, gid, groups));
        self.auth_machine = machine.to_string();
        self.default_uid = uid;
        self.default_gid = gid;
        self.default_groups = groups.to_vec();
    }

    pub fn take_layout_recalls(&mut self) -> Vec<nfs4::LayoutRecall4> {
        let mut state = self.cb_state.lock().unwrap();
        std::mem::take(&mut state.pending_layout_recalls)
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

    pub fn getattr_basic(
        &mut self,
        fh: &[u8],
    ) -> Result<core::result::Result<nfs4::GetAttrOk, Nfs4Error>> {
        self.getattr(fh, &nfs4::ATTR_BASIC)
    }

    pub fn getattr(
        &mut self,
        fh: &[u8],
        attr_request: &[u32],
    ) -> Result<core::result::Result<nfs4::GetAttrOk, Nfs4Error>> {
        let sess = self.session_args();
        let (seqok, gok) =
            match nfs4::compound_with_session_putfh_getattr(&mut self.rpc, sess, fh, attr_request)?
            {
                Ok(v) => v,
                Err(e) => return Ok(Err(e)),
            };
        self.seq = seqok.sequenceid.wrapping_add(1);
        Ok(Ok(gok))
    }

    pub fn access(
        &mut self,
        fh: &[u8],
        access: u32,
    ) -> Result<core::result::Result<nfs4::AccessOk, Nfs4Error>> {
        let sess = self.session_args();
        let (seqok, aok) =
            match nfs4::compound_with_session_putfh_access(&mut self.rpc, sess, fh, access)? {
                Ok(v) => v,
                Err(e) => return Ok(Err(e)),
            };
        self.seq = seqok.sequenceid.wrapping_add(1);
        Ok(Ok(aok))
    }

    pub fn readlink(
        &mut self,
        fh: &[u8],
    ) -> Result<core::result::Result<nfs4::ReadLinkOk, Nfs4Error>> {
        let sess = self.session_args();
        let (seqok, rok) =
            match nfs4::compound_with_session_putfh_readlink(&mut self.rpc, sess, fh)? {
                Ok(v) => v,
                Err(e) => return Ok(Err(e)),
            };
        self.seq = seqok.sequenceid.wrapping_add(1);
        Ok(Ok(rok))
    }

    pub fn readdir_basic(
        &mut self,
        fh: &[u8],
        cookie: u64,
        cookieverf: [u8; 8],
        dircount: u32,
        maxcount: u32,
    ) -> Result<core::result::Result<nfs4::ReadDirOk, Nfs4Error>> {
        self.readdir(
            fh,
            cookie,
            cookieverf,
            dircount,
            maxcount,
            &nfs4::ATTR_READDIR,
        )
    }

    pub fn readdir(
        &mut self,
        fh: &[u8],
        cookie: u64,
        cookieverf: [u8; 8],
        dircount: u32,
        maxcount: u32,
        attr_request: &[u32],
    ) -> Result<core::result::Result<nfs4::ReadDirOk, Nfs4Error>> {
        let sess = self.session_args();
        let (seqok, rok) = match nfs4::compound_with_session_putfh_readdir(
            &mut self.rpc,
            sess,
            nfs4::ReadDirArgs {
                fh,
                cookie,
                cookieverf,
                dircount,
                maxcount,
                attr_request,
            },
        )? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        self.seq = seqok.sequenceid.wrapping_add(1);
        Ok(Ok(rok))
    }

    pub fn mkdir(
        &mut self,
        path: &str,
        attrs: &nfs4::SetAttr4,
    ) -> Result<core::result::Result<Vec<u8>, Nfs4Error>> {
        let (dir_path, name) = split_parent(path)?;
        let dir_fh = match self.lookup_fh(dir_path)? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        let sess = self.session_args();
        let (seqok, _cok, fh) = match nfs4::compound_with_session_putfh_create_dir_getfh(
            &mut self.rpc,
            sess,
            &dir_fh,
            name,
            attrs,
        )? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        self.seq = seqok.sequenceid.wrapping_add(1);
        Ok(Ok(fh))
    }

    pub fn symlink(
        &mut self,
        path: &str,
        target: &str,
        attrs: &nfs4::SetAttr4,
    ) -> Result<core::result::Result<Vec<u8>, Nfs4Error>> {
        let (dir_path, name) = split_parent(path)?;
        let dir_fh = match self.lookup_fh(dir_path)? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        let sess = self.session_args();
        let (seqok, _cok, fh) = match nfs4::compound_with_session_putfh_create_symlink_getfh(
            &mut self.rpc,
            sess,
            &dir_fh,
            name,
            target,
            attrs,
        )? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        self.seq = seqok.sequenceid.wrapping_add(1);
        Ok(Ok(fh))
    }

    pub fn remove(&mut self, path: &str) -> Result<core::result::Result<nfs4::RemoveOk, Nfs4Error>> {
        let (dir_path, name) = split_parent(path)?;
        let dir_fh = match self.lookup_fh(dir_path)? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        let sess = self.session_args();
        let (seqok, rok) = match nfs4::compound_with_session_putfh_remove(
            &mut self.rpc,
            sess,
            &dir_fh,
            name,
        )? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        self.seq = seqok.sequenceid.wrapping_add(1);
        Ok(Ok(rok))
    }

    pub fn rmdir(&mut self, path: &str) -> Result<core::result::Result<nfs4::RemoveOk, Nfs4Error>> {
        self.remove(path)
    }

    pub fn rename(
        &mut self,
        from: &str,
        to: &str,
    ) -> Result<core::result::Result<nfs4::RenameOk, Nfs4Error>> {
        let (from_dir_path, from_name) = split_parent(from)?;
        let (to_dir_path, to_name) = split_parent(to)?;
        let from_dir_fh = match self.lookup_fh(from_dir_path)? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        let to_dir_fh = match self.lookup_fh(to_dir_path)? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        let sess = self.session_args();
        let (seqok, rok) = match nfs4::compound_with_session_putfh_rename(
            &mut self.rpc,
            sess,
            &from_dir_fh,
            from_name,
            &to_dir_fh,
            to_name,
        )? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        self.seq = seqok.sequenceid.wrapping_add(1);
        Ok(Ok(rok))
    }

    pub fn link(
        &mut self,
        source: &str,
        dest: &str,
    ) -> Result<core::result::Result<nfs4::LinkOk, Nfs4Error>> {
        let source_fh = match self.lookup_fh(source)? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        let (dir_path, name) = split_parent(dest)?;
        let dir_fh = match self.lookup_fh(dir_path)? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        let sess = self.session_args();
        let (seqok, lok) = match nfs4::compound_with_session_putfh_link(
            &mut self.rpc,
            sess,
            &source_fh,
            &dir_fh,
            name,
        )? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        self.seq = seqok.sequenceid.wrapping_add(1);
        Ok(Ok(lok))
    }

    pub fn secinfo(
        &mut self,
        path: &str,
    ) -> Result<core::result::Result<nfs4::SecInfoOk, Nfs4Error>> {
        let (dir_path, name) = split_parent(path)?;
        let dir_fh = match self.lookup_fh(dir_path)? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        let sess = self.session_args();
        let (seqok, sok) = match nfs4::compound_with_session_putfh_secinfo(
            &mut self.rpc,
            sess,
            &dir_fh,
            name,
        )? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        self.seq = seqok.sequenceid.wrapping_add(1);
        Ok(Ok(sok))
    }

    pub fn setattr(
        &mut self,
        fh: &[u8],
        attrs: &nfs4::SetAttr4,
    ) -> Result<core::result::Result<nfs4::SetAttrOk, Nfs4Error>> {
        self.setattr_stateid(fh, &nfs4::StateId4::special(), attrs)
    }

    pub fn setattr_stateid(
        &mut self,
        fh: &[u8],
        stateid: &nfs4::StateId4,
        attrs: &nfs4::SetAttr4,
    ) -> Result<core::result::Result<nfs4::SetAttrOk, Nfs4Error>> {
        let sess = self.session_args();
        let (seqok, sok) = match nfs4::compound_with_session_putfh_setattr(
            &mut self.rpc,
            sess,
            fh,
            stateid,
            attrs,
        )? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        self.seq = seqok.sequenceid.wrapping_add(1);
        Ok(Ok(sok))
    }

    pub fn open_create_getfh_access(
        &mut self,
        path: &str,
        access: u32,
        guarded: bool,
        attrs: &nfs4::SetAttr4,
    ) -> Result<core::result::Result<nfs4::OpenGetFhOk, Nfs4Error>> {
        let (dir_path, name) = split_parent(path)?;
        let sess = self.session_args();
        let (seqok, open_ok, fh) = match nfs4::compound_with_session_open_create_getfh_access(
            &mut self.rpc,
            sess,
            nfs4::OpenOwner {
                clientid: self.clientid,
                owner: &self.open_owner,
                seqid: self.open_seqid,
            },
            nfs4::OpenPath { dir_path, name },
            access,
            guarded,
            attrs,
        )? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        self.seq = seqok.sequenceid.wrapping_add(1);
        self.open_seqid = self.open_seqid.wrapping_add(1);
        Ok(Ok((seqok, open_ok, fh)))
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

    #[allow(clippy::too_many_arguments)]
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

#[derive(Debug)]
struct CallbackState {
    sessionid: [u8; 16],
    slot_seq: HashMap<u32, u32>,
    pending_layout_recalls: Vec<nfs4::LayoutRecall4>,
}

impl CallbackState {
    fn new(sessionid: [u8; 16]) -> Self {
        Self {
            sessionid,
            slot_seq: HashMap::new(),
            pending_layout_recalls: Vec::new(),
        }
    }
}

struct Nfs4CallbackHandler {
    cb_program: u32,
    state: Arc<Mutex<CallbackState>>,
}

impl RpcCallbackHandler for Nfs4CallbackHandler {
    fn handle_call(&mut self, call: RpcCall) -> Result<RpcReply> {
        if call.prog != self.cb_program || call.vers != nfs4::NFS4_CALLBACK_VERS {
            return Ok(RpcReply {
                accept_stat: RPC_ACCEPT_PROG_UNAVAIL,
                body: Vec::new(),
            });
        }

        match call.proc_ {
            nfs4::NFSCBPROC_CB_NULL => Ok(RpcReply {
                accept_stat: RPC_ACCEPT_SUCCESS,
                body: Vec::new(),
            }),
            nfs4::NFSCBPROC_CB_COMPOUND => {
                let mut r = XdrReader::new(&call.args);
                let args = nfs4::decode_cb_compound_args(&mut r).map_err(RpcError::from)?;

                let mut res_ops = Vec::new();
                let mut status = nfs4::NFS4_OK;
                let mut saw_sequence = false;

                for op in args.ops {
                    match op {
                        nfs4::CbArgOp::Sequence(seq) => {
                            saw_sequence = true;
                            let mut state = self.state.lock().unwrap();
                            if state.sessionid != seq.sessionid {
                                state.sessionid = seq.sessionid;
                                state.slot_seq.clear();
                            }
                            state.slot_seq.insert(seq.slotid, seq.sequenceid);
                            let resok = nfs4::CbSequenceResOk {
                                sessionid: seq.sessionid,
                                sequenceid: seq.sequenceid,
                                slotid: seq.slotid,
                                highest_slotid: seq.highest_slotid,
                                target_highest_slotid: seq.highest_slotid,
                            };
                            res_ops.push(nfs4::CbResOp::Sequence(Ok(resok)));
                        }
                        nfs4::CbArgOp::LayoutRecall(recall) => {
                            let mut state = self.state.lock().unwrap();
                            state.pending_layout_recalls.push(recall);
                            res_ops.push(nfs4::CbResOp::LayoutRecall(Ok(())));
                        }
                        nfs4::CbArgOp::Unknown(opnum) => {
                            status = nfs4::NFS4ERR_OP_ILLEGAL;
                            res_ops.push(nfs4::CbResOp::Unknown { op: opnum, status });
                            break;
                        }
                    }
                }

                if !saw_sequence {
                    status = nfs4::NFS4ERR_OP_ILLEGAL;
                    res_ops.clear();
                }

                let res = nfs4::CbCompoundRes {
                    tag: args.tag,
                    status,
                    ops: res_ops,
                };
                let mut w = XdrWriter::new();
                nfs4::encode_cb_compound_res(&mut w, &res);
                Ok(RpcReply {
                    accept_stat: RPC_ACCEPT_SUCCESS,
                    body: w.into_bytes(),
                })
            }
            _ => Ok(RpcReply {
                accept_stat: RPC_ACCEPT_PROC_UNAVAIL,
                body: Vec::new(),
            }),
        }
    }
}

const RPC_ACCEPT_SUCCESS: u32 = 0;
const RPC_ACCEPT_PROG_UNAVAIL: u32 = 1;
const RPC_ACCEPT_PROC_UNAVAIL: u32 = 3;

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
