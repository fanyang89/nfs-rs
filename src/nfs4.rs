//! NFSv4.x building blocks; currently focused on NFSv4.1.

use crate::rpc::Result;
use crate::rpc::TcpRpcClient;
use crate::xdr::XdrReader;
use crate::xdr::XdrWriter;
use core::fmt;

pub const NFS_PROG: u32 = 100_003;
pub const NFS_VERS: u32 = 4;
pub const NFSPROC4_COMPOUND: u32 = 1;

pub const NFS4_MIN_VERSION_1: u32 = 1;

// NFS operation numbers (subset)
pub const OP_GETFH: u32 = 10;
pub const OP_LOOKUP: u32 = 15;
pub const OP_PUTFH: u32 = 22;
pub const OP_PUTROOTFH: u32 = 24;
pub const OP_READ: u32 = 25;

pub const OP_EXCHANGE_ID: u32 = 42;
pub const OP_CREATE_SESSION: u32 = 43;
pub const OP_SEQUENCE: u32 = 53;

// EXCHANGE_ID flags (subset)
pub const EXCHGID4_FLAG_USE_NON_PNFS: u32 = 0x0001_0000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nfs4Error {
    pub status: u32,
    pub op: Option<u32>,
}

impl fmt::Display for Nfs4Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.op {
            Some(op) => write!(f, "NFSv4 error status={} op={}", self.status, op),
            None => write!(f, "NFSv4 error status={}", self.status),
        }
    }
}

impl std::error::Error for Nfs4Error {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientOwner4 {
    pub verifier: [u8; 8],
    pub ownerid: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeIdOk {
    pub clientid: u64,
    pub sequenceid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateSessionOk {
    pub sessionid: [u8; 16],
    pub sequenceid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequenceOk {
    pub sequenceid: u32,
    pub status_flags: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadOk {
    pub eof: bool,
    pub data: Vec<u8>,
}

pub fn exchange_id(
    rpc: &mut TcpRpcClient,
    owner: &ClientOwner4,
) -> Result<core::result::Result<ExchangeIdOk, Nfs4Error>> {
    compound(
        rpc,
        NFS4_MIN_VERSION_1,
        "exchid",
        |ops| {
            ops.exchange_id(owner);
        },
        |r| {
            let res = decode_compound_res(r)?;
            res.expect_exchange_id()
        },
    )
}

pub fn create_session(
    rpc: &mut TcpRpcClient,
    clientid: u64,
    sequenceid: u32,
) -> Result<core::result::Result<CreateSessionOk, Nfs4Error>> {
    compound(
        rpc,
        NFS4_MIN_VERSION_1,
        "createsess",
        |ops| {
            ops.create_session(clientid, sequenceid);
        },
        |r| {
            let res = decode_compound_res(r)?;
            res.expect_create_session()
        },
    )
}

pub fn compound_with_session_lookup_getfh(
    rpc: &mut TcpRpcClient,
    sessionid: [u8; 16],
    seq: u32,
    slot: u32,
    path: &str,
) -> Result<core::result::Result<(SequenceOk, Vec<u8>), Nfs4Error>> {
    compound(
        rpc,
        NFS4_MIN_VERSION_1,
        "lookup",
        |ops| {
            ops.sequence(sessionid, seq, slot);
            ops.putrootfh();
            for comp in path.split('/').filter(|s| !s.is_empty()) {
                ops.lookup(comp);
            }
            ops.getfh();
        },
        |r| {
            let res = decode_compound_res(r)?;
            if let Some(e) = res.first_error() {
                return Ok(Err(e));
            }
            let seqok = res.expect_sequence()?;
            let fh = res.expect_getfh()?;
            Ok(match (seqok, fh) {
                (Ok(s), Ok(fh)) => Ok((s, fh)),
                (Err(e), _) => Err(e),
                (_, Err(e)) => Err(e),
            })
        },
    )
}

pub fn compound_with_session_putfh_read(
    rpc: &mut TcpRpcClient,
    sessionid: [u8; 16],
    seq: u32,
    slot: u32,
    fh: &[u8],
    offset: u64,
    count: u32,
) -> Result<core::result::Result<(SequenceOk, ReadOk), Nfs4Error>> {
    compound(
        rpc,
        NFS4_MIN_VERSION_1,
        "read",
        |ops| {
            ops.sequence(sessionid, seq, slot);
            ops.putfh(fh);
            ops.read(offset, count);
        },
        |r| {
            let res = decode_compound_res(r)?;
            if let Some(e) = res.first_error() {
                return Ok(Err(e));
            }
            let seqok = res.expect_sequence()?;
            let rok = res.expect_read()?;
            Ok(match (seqok, rok) {
                (Ok(s), Ok(rk)) => Ok((s, rk)),
                (Err(e), _) => Err(e),
                (_, Err(e)) => Err(e),
            })
        },
    )
}

fn compound<T>(
    rpc: &mut TcpRpcClient,
    minor: u32,
    tag: &str,
    encode_ops: impl FnOnce(&mut OpsWriter),
    decode: impl FnOnce(&mut XdrReader<'_>) -> Result<T>,
) -> Result<T> {
    rpc.call(
        NFS_PROG,
        NFS_VERS,
        NFSPROC4_COMPOUND,
        |w| {
            // COMPOUND4args { utf8str_cs tag; uint32 minorversion; nfs_argop4 array<>; }
            w.put_string(tag);
            w.put_u32(minor);

            let mut ops = OpsWriter::new();
            encode_ops(&mut ops);
            w.put_u32(ops.count);
            w.put_opaque_fixed(&ops.w.into_bytes());
        },
        decode,
    )
}

// --- encoding ---

struct OpsWriter {
    w: XdrWriter,
    count: u32,
}

impl OpsWriter {
    fn new() -> Self {
        Self {
            w: XdrWriter::new(),
            count: 0,
        }
    }

    fn push(&mut self, opnum: u32) -> &mut XdrWriter {
        self.count = self.count.wrapping_add(1);
        self.w.put_u32(opnum);
        &mut self.w
    }

    fn exchange_id(&mut self, owner: &ClientOwner4) {
        let w = self.push(OP_EXCHANGE_ID);
        // client_owner4
        w.put_opaque_fixed(&owner.verifier);
        w.put_opaque(&owner.ownerid);

        w.put_u32(EXCHGID4_FLAG_USE_NON_PNFS);

        // state_protect4_a: SP4_NONE
        w.put_u32(0);

        // client_impl_id<1> : empty
        w.put_u32(0);
    }

    fn create_session(&mut self, clientid: u64, sequenceid: u32) {
        let w = self.push(OP_CREATE_SESSION);
        w.put_u64(clientid);
        w.put_u32(sequenceid);
        w.put_u32(0); // flags

        encode_channel_attrs4(w, 0, 1024 * 1024, 1024 * 1024, 1024 * 1024, 64, 16);
        encode_channel_attrs4(w, 0, 1024 * 1024, 1024 * 1024, 1024 * 1024, 64, 16);

        w.put_u32(0); // cb_program
                      // sec_parms<>: one entry AUTH_NONE
        w.put_u32(1);
        w.put_u32(0); // AUTH_NONE
    }

    fn sequence(&mut self, sessionid: [u8; 16], sequenceid: u32, slotid: u32) {
        let w = self.push(OP_SEQUENCE);
        w.put_opaque_fixed(&sessionid);
        w.put_u32(sequenceid);
        w.put_u32(slotid);
        w.put_u32(slotid); // highest_slotid
        w.put_bool(true);
    }

    fn putrootfh(&mut self) {
        let _ = self.push(OP_PUTROOTFH);
    }

    fn lookup(&mut self, name: &str) {
        let w = self.push(OP_LOOKUP);
        w.put_string(name);
    }

    fn getfh(&mut self) {
        let _ = self.push(OP_GETFH);
    }

    fn putfh(&mut self, fh: &[u8]) {
        let w = self.push(OP_PUTFH);
        w.put_opaque(fh);
    }

    fn read(&mut self, offset: u64, count: u32) {
        let w = self.push(OP_READ);
        encode_stateid4(w, 0, [0u8; 12]);
        w.put_u64(offset);
        w.put_u32(count);
    }
}

fn encode_channel_attrs4(
    w: &mut XdrWriter,
    headerpadsize: u32,
    maxrequestsize: u32,
    maxresponsesize: u32,
    maxresponsesize_cached: u32,
    maxoperations: u32,
    maxrequests: u32,
) {
    w.put_u32(headerpadsize);
    w.put_u32(maxrequestsize);
    w.put_u32(maxresponsesize);
    w.put_u32(maxresponsesize_cached);
    w.put_u32(maxoperations);
    w.put_u32(maxrequests);
    w.put_u32(0); // rdma_ird<1> empty
}

fn encode_stateid4(w: &mut XdrWriter, seqid: u32, other: [u8; 12]) {
    w.put_u32(seqid);
    w.put_opaque_fixed(&other);
}

// --- decoding ---

struct CompoundRes {
    status: u32,
    ops: Vec<ResOp>,
}

#[derive(Debug)]
enum ResOp {
    ExchangeId(core::result::Result<ExchangeIdOk, u32>),
    CreateSession(core::result::Result<CreateSessionOk, u32>),
    Sequence(core::result::Result<SequenceOk, u32>),
    PutRootFh(core::result::Result<(), u32>),
    Lookup(core::result::Result<(), u32>),
    GetFh(core::result::Result<Vec<u8>, u32>),
    PutFh(core::result::Result<(), u32>),
    Read(core::result::Result<ReadOk, u32>),
    Unknown { op: u32, status: u32 },
}

impl CompoundRes {
    fn first_error(&self) -> Option<Nfs4Error> {
        for op in &self.ops {
            let (opnum, st) = match op {
                ResOp::ExchangeId(Err(st)) => (OP_EXCHANGE_ID, *st),
                ResOp::CreateSession(Err(st)) => (OP_CREATE_SESSION, *st),
                ResOp::Sequence(Err(st)) => (OP_SEQUENCE, *st),
                ResOp::PutRootFh(Err(st)) => (OP_PUTROOTFH, *st),
                ResOp::Lookup(Err(st)) => (OP_LOOKUP, *st),
                ResOp::GetFh(Err(st)) => (OP_GETFH, *st),
                ResOp::PutFh(Err(st)) => (OP_PUTFH, *st),
                ResOp::Read(Err(st)) => (OP_READ, *st),
                ResOp::Unknown { op, status } if *status != 0 => (*op, *status),
                _ => continue,
            };
            return Some(Nfs4Error {
                status: st,
                op: Some(opnum),
            });
        }
        None
    }

    fn expect_exchange_id(&self) -> Result<core::result::Result<ExchangeIdOk, Nfs4Error>> {
        for op in &self.ops {
            if let ResOp::ExchangeId(r) = op {
                return Ok(match r {
                    Ok(v) => Ok(v.clone()),
                    Err(st) => Err(Nfs4Error {
                        status: *st,
                        op: Some(OP_EXCHANGE_ID),
                    }),
                });
            }
        }
        Ok(Err(Nfs4Error {
            status: self.status,
            op: Some(OP_EXCHANGE_ID),
        }))
    }

    fn expect_create_session(&self) -> Result<core::result::Result<CreateSessionOk, Nfs4Error>> {
        for op in &self.ops {
            if let ResOp::CreateSession(r) = op {
                return Ok(match r {
                    Ok(v) => Ok(v.clone()),
                    Err(st) => Err(Nfs4Error {
                        status: *st,
                        op: Some(OP_CREATE_SESSION),
                    }),
                });
            }
        }
        Ok(Err(Nfs4Error {
            status: self.status,
            op: Some(OP_CREATE_SESSION),
        }))
    }

    fn expect_sequence(&self) -> Result<core::result::Result<SequenceOk, Nfs4Error>> {
        for op in &self.ops {
            if let ResOp::Sequence(r) = op {
                return Ok(match r {
                    Ok(v) => Ok(v.clone()),
                    Err(st) => Err(Nfs4Error {
                        status: *st,
                        op: Some(OP_SEQUENCE),
                    }),
                });
            }
        }
        Ok(Err(Nfs4Error {
            status: self.status,
            op: Some(OP_SEQUENCE),
        }))
    }

    fn expect_getfh(&self) -> Result<core::result::Result<Vec<u8>, Nfs4Error>> {
        for op in &self.ops {
            if let ResOp::GetFh(r) = op {
                return Ok(match r {
                    Ok(v) => Ok(v.clone()),
                    Err(st) => Err(Nfs4Error {
                        status: *st,
                        op: Some(OP_GETFH),
                    }),
                });
            }
        }
        Ok(Err(Nfs4Error {
            status: self.status,
            op: Some(OP_GETFH),
        }))
    }

    fn expect_read(&self) -> Result<core::result::Result<ReadOk, Nfs4Error>> {
        for op in &self.ops {
            if let ResOp::Read(r) = op {
                return Ok(match r {
                    Ok(v) => Ok(v.clone()),
                    Err(st) => Err(Nfs4Error {
                        status: *st,
                        op: Some(OP_READ),
                    }),
                });
            }
        }
        Ok(Err(Nfs4Error {
            status: self.status,
            op: Some(OP_READ),
        }))
    }
}

fn decode_compound_res(r: &mut XdrReader<'_>) -> Result<CompoundRes> {
    let status = r.get_u32()?;
    let _tag = r.get_string()?;
    let nops = r.get_u32()? as usize;
    let mut ops = Vec::with_capacity(nops.min(64));
    for _ in 0..nops {
        let op = r.get_u32()?;
        ops.push(decode_resop(r, op)?);
    }
    Ok(CompoundRes { status, ops })
}

fn decode_resop(r: &mut XdrReader<'_>, op: u32) -> Result<ResOp> {
    match op {
        OP_EXCHANGE_ID => {
            let st = r.get_u32()?;
            if st != 0 {
                return Ok(ResOp::ExchangeId(Err(st)));
            }
            let clientid = r.get_u64()?;
            let sequenceid = r.get_u32()?;
            let _flags = r.get_u32()?;

            // state_protect4_r
            let how = r.get_u32()?;
            match how {
                0 => {}
                1 => {
                    // state_protect_ops4: enforce_mask bitmap4<>, allow_mask bitmap4<>
                    let _enforce = r.get_vec(|r| Ok(r.get_u32()?))?;
                    let _allow = r.get_vec(|r| Ok(r.get_u32()?))?;
                }
                2 => {
                    // ssv_prot_info4 (skip)
                    let _ops_enforce = r.get_vec(|r| Ok(r.get_u32()?))?;
                    let _ops_allow = r.get_vec(|r| Ok(r.get_u32()?))?;
                    let _hash_alg = r.get_u32()?;
                    let _encr_alg = r.get_u32()?;
                    let _ssv_len = r.get_u32()?;
                    let _window = r.get_u32()?;
                    let _handles = r.get_vec(|r| Ok(r.get_opaque()?))?;
                }
                other => return Ok(ResOp::Unknown { op, status: other }),
            }

            // server_owner4
            let _minor_id = r.get_u64()?;
            let _major_id = r.get_opaque()?;
            let _server_scope = r.get_opaque()?;
            // server_impl_id<1>
            let impls = r.get_u32()? as usize;
            for _ in 0..impls {
                let _domain = r.get_string()?;
                let _name = r.get_string()?;
                let _seconds = r.get_i64()?;
                let _nseconds = r.get_u32()?;
            }

            Ok(ResOp::ExchangeId(Ok(ExchangeIdOk {
                clientid,
                sequenceid,
            })))
        }
        OP_CREATE_SESSION => {
            let st = r.get_u32()?;
            if st != 0 {
                return Ok(ResOp::CreateSession(Err(st)));
            }
            let sid = r.get_opaque_fixed(16)?;
            let sessionid: [u8; 16] = sid.as_slice().try_into().unwrap();
            let sequenceid = r.get_u32()?;
            let _flags = r.get_u32()?;
            skip_channel_attrs4(r)?;
            skip_channel_attrs4(r)?;
            Ok(ResOp::CreateSession(Ok(CreateSessionOk {
                sessionid,
                sequenceid,
            })))
        }
        OP_SEQUENCE => {
            let st = r.get_u32()?;
            if st != 0 {
                return Ok(ResOp::Sequence(Err(st)));
            }
            let _sid = r.get_opaque_fixed(16)?;
            let sequenceid = r.get_u32()?;
            let _slotid = r.get_u32()?;
            let _highest_slotid = r.get_u32()?;
            let _target_highest_slotid = r.get_u32()?;
            let status_flags = r.get_u32()?;
            Ok(ResOp::Sequence(Ok(SequenceOk {
                sequenceid,
                status_flags,
            })))
        }
        OP_PUTROOTFH => {
            let st = r.get_u32()?;
            if st != 0 {
                Ok(ResOp::PutRootFh(Err(st)))
            } else {
                Ok(ResOp::PutRootFh(Ok(())))
            }
        }
        OP_LOOKUP => {
            let st = r.get_u32()?;
            if st != 0 {
                Ok(ResOp::Lookup(Err(st)))
            } else {
                Ok(ResOp::Lookup(Ok(())))
            }
        }
        OP_GETFH => {
            let st = r.get_u32()?;
            if st != 0 {
                return Ok(ResOp::GetFh(Err(st)));
            }
            let fh = r.get_opaque()?;
            Ok(ResOp::GetFh(Ok(fh)))
        }
        OP_PUTFH => {
            let st = r.get_u32()?;
            if st != 0 {
                Ok(ResOp::PutFh(Err(st)))
            } else {
                Ok(ResOp::PutFh(Ok(())))
            }
        }
        OP_READ => {
            let st = r.get_u32()?;
            if st != 0 {
                return Ok(ResOp::Read(Err(st)));
            }
            let eof = r.get_bool()?;
            let data = r.get_opaque()?;
            Ok(ResOp::Read(Ok(ReadOk { eof, data })))
        }
        other => {
            // Best-effort: most NFSv4 res types start with nfsstat4.
            let st = r.get_u32()?;
            Ok(ResOp::Unknown {
                op: other,
                status: st,
            })
        }
    }
}

fn skip_channel_attrs4(r: &mut XdrReader<'_>) -> Result<()> {
    let _headerpadsize = r.get_u32()?;
    let _maxrequestsize = r.get_u32()?;
    let _maxresponsesize = r.get_u32()?;
    let _maxresponsesize_cached = r.get_u32()?;
    let _maxoperations = r.get_u32()?;
    let _maxrequests = r.get_u32()?;
    let rdma_len = r.get_u32()? as usize;
    for _ in 0..rdma_len {
        let _ = r.get_u32()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_stateid4_special_is_16_zeros() {
        let mut w = XdrWriter::new();
        encode_stateid4(&mut w, 0, [0u8; 12]);
        let b = w.into_bytes();
        assert_eq!(b.len(), 16);
        assert!(b.iter().all(|&x| x == 0));
    }
}
