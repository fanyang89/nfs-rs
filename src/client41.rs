//! High-level NFSv4.1 client (read-only MVP).

use crate::nfs4::{self, Nfs4Error};
use crate::rpc::{OpaqueAuth, Result, RpcError, TcpRpcClient};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub struct Nfs41Client {
    pub rpc: TcpRpcClient,
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

        let ex = nfs4::exchange_id(&mut rpc, &owner)?;
        let exok = ex.map_err(|e| RpcError::RpcAcceptedError(e.to_string()))?;

        let cs = nfs4::create_session(&mut rpc, exok.clientid, exok.sequenceid)?;
        let csok = cs.map_err(|e| RpcError::RpcAcceptedError(e.to_string()))?;

        Ok(Self {
            rpc,
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

    pub fn read_to_end(
        &mut self,
        path: &str,
        chunk_size: u32,
    ) -> Result<core::result::Result<Vec<u8>, Nfs4Error>> {
        let fh = match self.lookup_fh(path)? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };

        let mut out = Vec::new();
        let mut offset = 0u64;
        loop {
            let (seqok, r) = match nfs4::compound_with_session_putfh_read(
                &mut self.rpc,
                self.sessionid,
                self.seq,
                self.slotid,
                &fh,
                offset,
                chunk_size,
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
        Ok(Ok(out))
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
