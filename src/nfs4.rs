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
pub const OP_CLOSE: u32 = 4;
pub const OP_GETFH: u32 = 10;
pub const OP_LOOKUP: u32 = 15;
pub const OP_OPEN: u32 = 18;
pub const OP_PUTFH: u32 = 22;
pub const OP_PUTROOTFH: u32 = 24;
pub const OP_READ: u32 = 25;

pub const OP_EXCHANGE_ID: u32 = 42;
pub const OP_CREATE_SESSION: u32 = 43;
pub const OP_SEQUENCE: u32 = 53;

// OPEN share access/deny flags (subset)
pub const OPEN4_SHARE_ACCESS_READ: u32 = 0x0000_0001;
pub const OPEN4_SHARE_DENY_NONE: u32 = 0x0000_0000;
pub const OPEN4_SHARE_ACCESS_WANT_NO_DELEG: u32 = 0x0000_0400;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateId4 {
    pub seqid: u32,
    pub other: [u8; 12],
}

impl StateId4 {
    pub fn special() -> Self {
        Self {
            seqid: 0,
            other: [0u8; 12],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenOk {
    pub stateid: StateId4,
    pub rflags: u32,
}

pub type Nfs4Res<T> = core::result::Result<T, Nfs4Error>;
pub type Nfs4Call<T> = Result<Nfs4Res<T>>;

pub type OpenGetFhOk = (SequenceOk, OpenOk, Vec<u8>);
pub type ReadCallOk = (SequenceOk, ReadOk);

#[derive(Debug, Clone, Copy)]
pub struct SessionArgs {
    pub sessionid: [u8; 16],
    pub seq: u32,
    pub slot: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct OpenOwner<'a> {
    pub clientid: u64,
    pub owner: &'a [u8],
    pub seqid: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct OpenPath<'a> {
    pub dir_path: &'a str,
    pub name: &'a str,
}

#[derive(Debug, Clone, Copy)]
pub struct ReadArgs<'a> {
    pub fh: &'a [u8],
    pub stateid: &'a StateId4,
    pub offset: u64,
    pub count: u32,
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

pub fn compound_with_session_open_getfh(
    rpc: &mut TcpRpcClient,
    sess: SessionArgs,
    open: OpenOwner<'_>,
    path: OpenPath<'_>,
) -> Nfs4Call<OpenGetFhOk> {
    compound(
        rpc,
        NFS4_MIN_VERSION_1,
        "open",
        |ops| {
            ops.sequence(sess.sessionid, sess.seq, sess.slot);
            ops.putrootfh();
            for comp in path.dir_path.split('/').filter(|s| !s.is_empty()) {
                ops.lookup(comp);
            }
            ops.open_readonly_claim_null(open.clientid, open.owner, open.seqid, path.name);
            ops.getfh();
        },
        |r| {
            let res = decode_compound_res(r)?;
            if let Some(e) = res.first_error() {
                return Ok(Err(e));
            }
            let seqok = res.expect_sequence()?;
            let opok = res.expect_open()?;
            let fh = res.expect_getfh()?;
            Ok(match (seqok, opok, fh) {
                (Ok(s), Ok(o), Ok(fh)) => Ok((s, o, fh)),
                (Err(e), _, _) => Err(e),
                (_, Err(e), _) => Err(e),
                (_, _, Err(e)) => Err(e),
            })
        },
    )
}

pub fn compound_with_session_putfh_close(
    rpc: &mut TcpRpcClient,
    sessionid: [u8; 16],
    seq: u32,
    slot: u32,
    fh: &[u8],
    close_seqid: u32,
    stateid: &StateId4,
) -> Result<core::result::Result<SequenceOk, Nfs4Error>> {
    compound(
        rpc,
        NFS4_MIN_VERSION_1,
        "close",
        |ops| {
            ops.sequence(sessionid, seq, slot);
            ops.putfh(fh);
            ops.close(close_seqid, stateid);
        },
        |r| {
            let res = decode_compound_res(r)?;
            if let Some(e) = res.first_error() {
                return Ok(Err(e));
            }
            let seqok = res.expect_sequence()?;
            let _closed = match res.expect_close()? {
                Ok(v) => v,
                Err(e) => return Ok(Err(e)),
            };
            Ok(seqok)
        },
    )
}

pub fn compound_with_session_putfh_read(
    rpc: &mut TcpRpcClient,
    sess: SessionArgs,
    fh: &[u8],
    offset: u64,
    count: u32,
) -> Nfs4Call<ReadCallOk> {
    compound_with_session_putfh_read_stateid(
        rpc,
        sess,
        ReadArgs {
            fh,
            stateid: &StateId4::special(),
            offset,
            count,
        },
    )
}

pub fn compound_with_session_putfh_read_stateid(
    rpc: &mut TcpRpcClient,
    sess: SessionArgs,
    args: ReadArgs<'_>,
) -> Nfs4Call<ReadCallOk> {
    compound(
        rpc,
        NFS4_MIN_VERSION_1,
        "read",
        |ops| {
            ops.sequence(sess.sessionid, sess.seq, sess.slot);
            ops.putfh(args.fh);
            ops.read_stateid(args.stateid, args.offset, args.count);
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

    fn open_readonly_claim_null(&mut self, clientid: u64, owner: &[u8], seqid: u32, name: &str) {
        let w = self.push(OP_OPEN);
        w.put_u32(seqid);
        w.put_u32(OPEN4_SHARE_ACCESS_READ | OPEN4_SHARE_ACCESS_WANT_NO_DELEG);
        w.put_u32(OPEN4_SHARE_DENY_NONE);

        // open_owner4 == state_owner4 { clientid4, opaque owner<> }
        w.put_u64(clientid);
        w.put_opaque(owner);

        // openflag4: OPEN4_NOCREATE
        w.put_u32(0);

        // open_claim4: CLAIM_NULL + component4 name
        w.put_u32(0);
        w.put_string(name);
    }

    fn close(&mut self, seqid: u32, stateid: &StateId4) {
        let w = self.push(OP_CLOSE);
        w.put_u32(seqid);
        encode_stateid4(w, stateid.seqid, stateid.other);
    }

    fn read_stateid(&mut self, stateid: &StateId4, offset: u64, count: u32) {
        let w = self.push(OP_READ);
        encode_stateid4(w, stateid.seqid, stateid.other);
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
    Open(core::result::Result<OpenOk, u32>),
    Close(core::result::Result<StateId4, u32>),
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
                ResOp::Open(Err(st)) => (OP_OPEN, *st),
                ResOp::Close(Err(st)) => (OP_CLOSE, *st),
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

    fn expect_open(&self) -> Result<core::result::Result<OpenOk, Nfs4Error>> {
        for op in &self.ops {
            if let ResOp::Open(r) = op {
                return Ok(match r {
                    Ok(v) => Ok(v.clone()),
                    Err(st) => Err(Nfs4Error {
                        status: *st,
                        op: Some(OP_OPEN),
                    }),
                });
            }
        }
        Ok(Err(Nfs4Error {
            status: self.status,
            op: Some(OP_OPEN),
        }))
    }

    fn expect_close(&self) -> Result<core::result::Result<StateId4, Nfs4Error>> {
        for op in &self.ops {
            if let ResOp::Close(r) = op {
                return Ok(match r {
                    Ok(v) => Ok(v.clone()),
                    Err(st) => Err(Nfs4Error {
                        status: *st,
                        op: Some(OP_CLOSE),
                    }),
                });
            }
        }
        Ok(Err(Nfs4Error {
            status: self.status,
            op: Some(OP_CLOSE),
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
                    let _enforce = r.get_vec(|r| r.get_u32())?;
                    let _allow = r.get_vec(|r| r.get_u32())?;
                }
                2 => {
                    // ssv_prot_info4 (skip)
                    let _ops_enforce = r.get_vec(|r| r.get_u32())?;
                    let _ops_allow = r.get_vec(|r| r.get_u32())?;
                    let _hash_alg = r.get_u32()?;
                    let _encr_alg = r.get_u32()?;
                    let _ssv_len = r.get_u32()?;
                    let _window = r.get_u32()?;
                    let _handles = r.get_vec(|r| r.get_opaque())?;
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
        OP_OPEN => {
            let st = r.get_u32()?;
            if st != 0 {
                return Ok(ResOp::Open(Err(st)));
            }

            let stateid = decode_stateid4(r)?;
            skip_change_info4(r)?;
            let rflags = r.get_u32()?;
            let _attrset = r.get_vec(|r| r.get_u32())?;
            skip_open_delegation4(r)?;

            Ok(ResOp::Open(Ok(OpenOk { stateid, rflags })))
        }
        OP_CLOSE => {
            let st = r.get_u32()?;
            if st != 0 {
                return Ok(ResOp::Close(Err(st)));
            }
            let stateid = decode_stateid4(r)?;
            Ok(ResOp::Close(Ok(stateid)))
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

fn decode_stateid4(r: &mut XdrReader<'_>) -> Result<StateId4> {
    let seqid = r.get_u32()?;
    let other_v = r.get_opaque_fixed(12)?;
    let other: [u8; 12] = other_v.as_slice().try_into().unwrap();
    Ok(StateId4 { seqid, other })
}

fn skip_change_info4(r: &mut XdrReader<'_>) -> Result<()> {
    let _atomic = r.get_bool()?;
    let _before = r.get_u64()?;
    let _after = r.get_u64()?;
    Ok(())
}

fn skip_nfsace4(r: &mut XdrReader<'_>) -> Result<()> {
    let _type_ = r.get_u32()?;
    let _flag = r.get_u32()?;
    let _mask = r.get_u32()?;
    let _who = r.get_string()?;
    Ok(())
}

fn skip_nfs_space_limit4(r: &mut XdrReader<'_>) -> Result<()> {
    let limitby = r.get_u32()?;
    match limitby {
        1 => {
            // NFS_LIMIT_SIZE
            let _filesize = r.get_u64()?;
        }
        2 => {
            // NFS_LIMIT_BLOCKS
            let _num_blocks = r.get_u32()?;
            let _bytes_per_block = r.get_u32()?;
        }
        other => {
            return Err(crate::rpc::RpcError::RpcDenied(format!(
                "unknown nfs_space_limit4 discriminant {other}"
            )));
        }
    }
    Ok(())
}

fn skip_open_delegation4(r: &mut XdrReader<'_>) -> Result<()> {
    let deleg_type = r.get_u32()?;
    match deleg_type {
        0 => Ok(()),
        1 => {
            // OPEN_DELEGATE_READ
            let _stateid = decode_stateid4(r)?;
            let _recall = r.get_bool()?;
            skip_nfsace4(r)
        }
        2 => {
            // OPEN_DELEGATE_WRITE
            let _stateid = decode_stateid4(r)?;
            let _recall = r.get_bool()?;
            skip_nfs_space_limit4(r)?;
            skip_nfsace4(r)
        }
        3 => {
            // OPEN_DELEGATE_NONE_EXT
            let why = r.get_u32()?;
            match why {
                1 => {
                    // WND4_CONTENTION
                    let _push = r.get_bool()?;
                }
                2 => {
                    // WND4_RESOURCE
                    let _signal = r.get_bool()?;
                }
                _ => {}
            }
            Ok(())
        }
        other => Err(crate::rpc::RpcError::RpcDenied(format!(
            "unknown open_delegation_type4 {other}"
        ))),
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
