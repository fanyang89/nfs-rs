//! NFSv4.x building blocks; currently focused on NFSv4.1.

use crate::rpc::Result;
use crate::rpc::TcpRpcClient;
use crate::xdr::XdrReader;
use crate::xdr::XdrWriter;
use core::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

pub const NFS_PROG: u32 = 100_003;
pub const NFS_VERS: u32 = 4;
pub const NFSPROC4_COMPOUND: u32 = 1;

pub const NFS4_MIN_VERSION_1: u32 = 1;
pub const NFS4_OK: u32 = 0;

// Callback program/procedures (RFC 5662).
pub const NFS4_CALLBACK_PROG: u32 = 0x4000_0000;
pub const NFS4_CALLBACK_VERS: u32 = 1;
pub const NFSCBPROC_CB_NULL: u32 = 0;
pub const NFSCBPROC_CB_COMPOUND: u32 = 1;

// NFS operation numbers (subset)
pub const OP_ACCESS: u32 = 3;
pub const OP_CLOSE: u32 = 4;
pub const OP_GETATTR: u32 = 9;
pub const OP_GETFH: u32 = 10;
pub const OP_LOOKUP: u32 = 15;
pub const OP_OPEN: u32 = 18;
pub const OP_PUTFH: u32 = 22;
pub const OP_PUTROOTFH: u32 = 24;
pub const OP_READ: u32 = 25;
pub const OP_READDIR: u32 = 26;
pub const OP_READLINK: u32 = 27;
pub const OP_SETATTR: u32 = 34;
pub const OP_WRITE: u32 = 38;

pub const OP_EXCHANGE_ID: u32 = 42;
pub const OP_CREATE_SESSION: u32 = 43;
pub const OP_GETDEVICEINFO: u32 = 47;
pub const OP_LAYOUTCOMMIT: u32 = 49;
pub const OP_LAYOUTGET: u32 = 50;
pub const OP_LAYOUTRETURN: u32 = 51;
pub const OP_SEQUENCE: u32 = 53;

// Callback op numbers (RFC 5662).
pub const OP_CB_LAYOUTRECALL: u32 = 5;
pub const OP_CB_SEQUENCE: u32 = 11;

// OPEN share access/deny flags (subset)
pub const OPEN4_SHARE_ACCESS_READ: u32 = 0x0000_0001;
pub const OPEN4_SHARE_ACCESS_WRITE: u32 = 0x0000_0002;
pub const OPEN4_SHARE_DENY_NONE: u32 = 0x0000_0000;
pub const OPEN4_SHARE_ACCESS_WANT_NO_DELEG: u32 = 0x0000_0400;

// ACCESS bits (subset)
pub const ACCESS4_READ: u32 = 0x0000_0001;
pub const ACCESS4_LOOKUP: u32 = 0x0000_0002;
pub const ACCESS4_MODIFY: u32 = 0x0000_0004;
pub const ACCESS4_EXTEND: u32 = 0x0000_0008;
pub const ACCESS4_DELETE: u32 = 0x0000_0010;
pub const ACCESS4_EXECUTE: u32 = 0x0000_0020;

// EXCHANGE_ID flags (subset)
pub const EXCHGID4_FLAG_USE_NON_PNFS: u32 = 0x0001_0000;
pub const EXCHGID4_FLAG_USE_PNFS_MDS: u32 = 0x0002_0000;
pub const EXCHGID4_FLAG_USE_PNFS_DS: u32 = 0x0004_0000;

pub const LAYOUT4_FLEX_FILES: u32 = 0x0000_0004;

pub const FF_FLAGS_NO_LAYOUTCOMMIT: u32 = 0x0000_0001;
pub const FF_FLAGS_NO_IO_THRU_MDS: u32 = 0x0000_0002;
pub const FF_FLAGS_NO_READ_IO: u32 = 0x0000_0004;
pub const FF_FLAGS_WRITE_ONE_MIRROR: u32 = 0x0000_0008;

pub const LAYOUTIOMODE4_READ: u32 = 1;
pub const LAYOUTIOMODE4_RW: u32 = 2;
pub const LAYOUTIOMODE4_ANY: u32 = 3;

pub const LAYOUTRETURN4_FILE: u32 = 1;
pub const LAYOUT4_RET_REC_FILE: u32 = 1;
pub const LAYOUT4_RET_REC_FSID: u32 = 2;
pub const LAYOUT4_RET_REC_ALL: u32 = 3;

pub const STABLE_HOW_UNSTABLE4: u32 = 0;
pub const STABLE_HOW_DATA_SYNC4: u32 = 1;
pub const STABLE_HOW_FILE_SYNC4: u32 = 2;

// FATTR4 (subset)
pub const FATTR4_TYPE: u32 = 1;
pub const FATTR4_SIZE: u32 = 4;
pub const FATTR4_FILEID: u32 = 13;
pub const FATTR4_MODE: u32 = 20;
pub const FATTR4_OWNER: u32 = 23;
pub const FATTR4_OWNER_GROUP: u32 = 24;
pub const FATTR4_TIME_ACCESS: u32 = 34;
pub const FATTR4_TIME_MODIFY: u32 = 40;

pub const ATTR_BASIC: [u32; 6] = [
    FATTR4_TYPE,
    FATTR4_SIZE,
    FATTR4_MODE,
    FATTR4_FILEID,
    FATTR4_TIME_MODIFY,
    FATTR4_TIME_ACCESS,
];

pub const ATTR_READDIR: [u32; 2] = [FATTR4_TYPE, FATTR4_FILEID];

pub const NFS4ERR_TOOSMALL: u32 = 10005;
pub const NFS4ERR_LAYOUTTRYLATER: u32 = 10058;
pub const NFS4ERR_OP_ILLEGAL: u32 = 10044;

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
pub struct NfsTime4 {
    pub seconds: i64,
    pub nseconds: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fsid4 {
    pub major: u64,
    pub minor: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadOk {
    pub eof: bool,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DeviceId4(pub [u8; 16]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetAddr4 {
    pub netid: String,
    pub addr: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FfDeviceVersion4 {
    pub version: u32,
    pub minorversion: u32,
    pub rsize: u32,
    pub wsize: u32,
    pub tightly_coupled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FfDeviceAddr4 {
    pub netaddrs: Vec<NetAddr4>,
    pub versions: Vec<FfDeviceVersion4>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FfDataServer4 {
    pub deviceid: DeviceId4,
    pub efficiency: u32,
    pub stateid: StateId4,
    pub fh_list: Vec<Vec<u8>>,
    pub user: String,
    pub group: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FfMirror4 {
    pub data_servers: Vec<FfDataServer4>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FfLayout4 {
    pub stripe_unit: u64,
    pub mirrors: Vec<FfMirror4>,
    pub flags: u32,
    pub stats_hint: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LayoutContent4 {
    FlexFiles(FfLayout4),
    Opaque { layout_type: u32, body: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout4 {
    pub offset: u64,
    pub length: u64,
    pub iomode: u32,
    pub content: LayoutContent4,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceAddr4 {
    FlexFiles(FfDeviceAddr4),
    Opaque { layout_type: u32, body: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutGetOk {
    pub return_on_close: bool,
    pub stateid: StateId4,
    pub layout: Vec<Layout4>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutRecallFile4 {
    pub fh: Vec<u8>,
    pub offset: u64,
    pub length: u64,
    pub stateid: StateId4,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LayoutRecallTarget {
    File(LayoutRecallFile4),
    Fsid(Fsid4),
    All,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutRecall4 {
    pub layout_type: u32,
    pub iomode: u32,
    pub target: LayoutRecallTarget,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CbSequenceArgs {
    pub sessionid: [u8; 16],
    pub sequenceid: u32,
    pub slotid: u32,
    pub highest_slotid: u32,
    pub cachethis: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CbSequenceResOk {
    pub sessionid: [u8; 16],
    pub sequenceid: u32,
    pub slotid: u32,
    pub highest_slotid: u32,
    pub target_highest_slotid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CbArgOp {
    Sequence(CbSequenceArgs),
    LayoutRecall(LayoutRecall4),
    Unknown(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CbCompoundArgs {
    pub tag: String,
    pub minorversion: u32,
    pub callback_ident: u32,
    pub ops: Vec<CbArgOp>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CbResOp {
    Sequence(core::result::Result<CbSequenceResOk, u32>),
    LayoutRecall(core::result::Result<(), u32>),
    Unknown { op: u32, status: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CbCompoundRes {
    pub tag: String,
    pub status: u32,
    pub ops: Vec<CbResOp>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetDeviceInfoOk {
    pub device_addr: DeviceAddr4,
    pub notify_mask: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutCommitOk {
    pub new_size: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteOk {
    pub count: u32,
    pub committed: u32,
    pub verifier: [u8; 8],
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FileAttr4 {
    pub type_: Option<u32>,
    pub size: Option<u64>,
    pub mode: Option<u32>,
    pub fileid: Option<u64>,
    pub owner: Option<String>,
    pub owner_group: Option<String>,
    pub time_access: Option<NfsTime4>,
    pub time_modify: Option<NfsTime4>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessOk {
    pub supported: u32,
    pub access: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetAttrOk {
    pub attrset: Vec<u32>,
    pub attrs: FileAttr4,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadLinkOk {
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadDirEntry4 {
    pub cookie: u64,
    pub name: String,
    pub attrs: FileAttr4,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadDirOk {
    pub cookieverf: [u8; 8],
    pub entries: Vec<ReadDirEntry4>,
    pub eof: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetAttrOk {
    pub attrset: Vec<u32>,
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
pub struct AuthSysParams<'a> {
    pub machine: &'a str,
    pub uid: u32,
    pub gid: u32,
    pub groups: &'a [u32],
}

#[derive(Debug, Clone, Copy)]
pub struct ReadArgs<'a> {
    pub fh: &'a [u8],
    pub stateid: &'a StateId4,
    pub offset: u64,
    pub count: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct WriteArgs<'a> {
    pub fh: &'a [u8],
    pub stateid: &'a StateId4,
    pub offset: u64,
    pub data: &'a [u8],
    pub stable_how: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct ReadDirArgs<'a> {
    pub fh: &'a [u8],
    pub cookie: u64,
    pub cookieverf: [u8; 8],
    pub dircount: u32,
    pub maxcount: u32,
    pub attr_request: &'a [u32],
}

#[derive(Debug, Clone, Default)]
pub struct SetAttr4 {
    pub size: Option<u64>,
    pub mode: Option<u32>,
}

impl SetAttr4 {
    fn is_empty(&self) -> bool {
        self.size.is_none() && self.mode.is_none()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct LayoutGetArgs<'a> {
    pub fh: &'a [u8],
    pub stateid: &'a StateId4,
    pub avail: bool,
    pub layout_type: u32,
    pub iomode: u32,
    pub offset: u64,
    pub length: u64,
    pub minlength: u64,
    pub maxcount: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct LayoutCommitArgs<'a> {
    pub fh: &'a [u8],
    pub offset: u64,
    pub length: u64,
    pub reclaim: bool,
    pub stateid: &'a StateId4,
    pub last_write_offset: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
pub struct LayoutReturnArgs<'a> {
    pub fh: &'a [u8],
    pub reclaim: bool,
    pub iomode: u32,
    pub offset: u64,
    pub length: u64,
    pub stateid: &'a StateId4,
}

pub fn exchange_id(
    rpc: &mut TcpRpcClient,
    owner: &ClientOwner4,
    flags: u32,
) -> Result<core::result::Result<ExchangeIdOk, Nfs4Error>> {
    compound(
        rpc,
        NFS4_MIN_VERSION_1,
        "exchid",
        |ops| {
            ops.exchange_id(owner, flags);
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
    cb_program: u32,
    cb_auth: Option<AuthSysParams<'_>>,
) -> Result<core::result::Result<CreateSessionOk, Nfs4Error>> {
    compound(
        rpc,
        NFS4_MIN_VERSION_1,
        "createsess",
        |ops| {
            ops.create_session(clientid, sequenceid, cb_program, cb_auth);
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
    compound_with_session_open_getfh_access(
        rpc,
        sess,
        open,
        path,
        OPEN4_SHARE_ACCESS_READ | OPEN4_SHARE_ACCESS_WANT_NO_DELEG,
    )
}

pub fn compound_with_session_open_getfh_access(
    rpc: &mut TcpRpcClient,
    sess: SessionArgs,
    open: OpenOwner<'_>,
    path: OpenPath<'_>,
    access: u32,
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
            ops.open_claim_null(open.clientid, open.owner, open.seqid, path.name, access);
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

pub fn compound_with_session_putfh_access(
    rpc: &mut TcpRpcClient,
    sess: SessionArgs,
    fh: &[u8],
    access: u32,
) -> Result<core::result::Result<(SequenceOk, AccessOk), Nfs4Error>> {
    compound(
        rpc,
        NFS4_MIN_VERSION_1,
        "access",
        |ops| {
            ops.sequence(sess.sessionid, sess.seq, sess.slot);
            ops.putfh(fh);
            ops.access(access);
        },
        |r| {
            let res = decode_compound_res(r)?;
            if let Some(e) = res.first_error() {
                return Ok(Err(e));
            }
            let seqok = res.expect_sequence()?;
            let aok = res.expect_access()?;
            Ok(match (seqok, aok) {
                (Ok(s), Ok(a)) => Ok((s, a)),
                (Err(e), _) => Err(e),
                (_, Err(e)) => Err(e),
            })
        },
    )
}

pub fn compound_with_session_putfh_getattr(
    rpc: &mut TcpRpcClient,
    sess: SessionArgs,
    fh: &[u8],
    attr_request: &[u32],
) -> Result<core::result::Result<(SequenceOk, GetAttrOk), Nfs4Error>> {
    compound(
        rpc,
        NFS4_MIN_VERSION_1,
        "getattr",
        |ops| {
            ops.sequence(sess.sessionid, sess.seq, sess.slot);
            ops.putfh(fh);
            ops.getattr(attr_request);
        },
        |r| {
            let res = decode_compound_res(r)?;
            if let Some(e) = res.first_error() {
                return Ok(Err(e));
            }
            let seqok = res.expect_sequence()?;
            let gok = res.expect_getattr()?;
            Ok(match (seqok, gok) {
                (Ok(s), Ok(g)) => Ok((s, g)),
                (Err(e), _) => Err(e),
                (_, Err(e)) => Err(e),
            })
        },
    )
}

pub fn compound_with_session_putfh_readlink(
    rpc: &mut TcpRpcClient,
    sess: SessionArgs,
    fh: &[u8],
) -> Result<core::result::Result<(SequenceOk, ReadLinkOk), Nfs4Error>> {
    compound(
        rpc,
        NFS4_MIN_VERSION_1,
        "readlink",
        |ops| {
            ops.sequence(sess.sessionid, sess.seq, sess.slot);
            ops.putfh(fh);
            ops.readlink();
        },
        |r| {
            let res = decode_compound_res(r)?;
            if let Some(e) = res.first_error() {
                return Ok(Err(e));
            }
            let seqok = res.expect_sequence()?;
            let rok = res.expect_readlink()?;
            Ok(match (seqok, rok) {
                (Ok(s), Ok(v)) => Ok((s, v)),
                (Err(e), _) => Err(e),
                (_, Err(e)) => Err(e),
            })
        },
    )
}

pub fn compound_with_session_putfh_readdir(
    rpc: &mut TcpRpcClient,
    sess: SessionArgs,
    args: ReadDirArgs<'_>,
) -> Result<core::result::Result<(SequenceOk, ReadDirOk), Nfs4Error>> {
    compound(
        rpc,
        NFS4_MIN_VERSION_1,
        "readdir",
        |ops| {
            ops.sequence(sess.sessionid, sess.seq, sess.slot);
            ops.putfh(args.fh);
            ops.readdir(&args);
        },
        |r| {
            let res = decode_compound_res(r)?;
            if let Some(e) = res.first_error() {
                return Ok(Err(e));
            }
            let seqok = res.expect_sequence()?;
            let rok = res.expect_readdir()?;
            Ok(match (seqok, rok) {
                (Ok(s), Ok(v)) => Ok((s, v)),
                (Err(e), _) => Err(e),
                (_, Err(e)) => Err(e),
            })
        },
    )
}

pub fn compound_with_session_putfh_setattr(
    rpc: &mut TcpRpcClient,
    sess: SessionArgs,
    fh: &[u8],
    stateid: &StateId4,
    attrs: &SetAttr4,
) -> Result<core::result::Result<(SequenceOk, SetAttrOk), Nfs4Error>> {
    if attrs.is_empty() {
        return Err(crate::rpc::RpcError::RpcDenied(
            "setattr requires at least one attribute".into(),
        ));
    }
    compound(
        rpc,
        NFS4_MIN_VERSION_1,
        "setattr",
        |ops| {
            ops.sequence(sess.sessionid, sess.seq, sess.slot);
            ops.putfh(fh);
            ops.setattr(stateid, attrs);
        },
        |r| {
            let res = decode_compound_res(r)?;
            if let Some(e) = res.first_error() {
                return Ok(Err(e));
            }
            let seqok = res.expect_sequence()?;
            let sok = res.expect_setattr()?;
            Ok(match (seqok, sok) {
                (Ok(s), Ok(v)) => Ok((s, v)),
                (Err(e), _) => Err(e),
                (_, Err(e)) => Err(e),
            })
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

pub fn compound_with_session_putfh_write_stateid(
    rpc: &mut TcpRpcClient,
    sess: SessionArgs,
    args: WriteArgs<'_>,
) -> Result<core::result::Result<(SequenceOk, WriteOk), Nfs4Error>> {
    compound(
        rpc,
        NFS4_MIN_VERSION_1,
        "write",
        |ops| {
            ops.sequence(sess.sessionid, sess.seq, sess.slot);
            ops.putfh(args.fh);
            ops.write_stateid(args.stateid, args.offset, args.stable_how, args.data);
        },
        |r| {
            let res = decode_compound_res(r)?;
            if let Some(e) = res.first_error() {
                return Ok(Err(e));
            }
            let seqok = res.expect_sequence()?;
            let wr = res.expect_write()?;
            Ok(match (seqok, wr) {
                (Ok(s), Ok(w)) => Ok((s, w)),
                (Err(e), _) => Err(e),
                (_, Err(e)) => Err(e),
            })
        },
    )
}

pub fn compound_with_session_putfh_layoutget(
    rpc: &mut TcpRpcClient,
    sess: SessionArgs,
    args: LayoutGetArgs<'_>,
) -> Result<core::result::Result<(SequenceOk, LayoutGetOk), Nfs4Error>> {
    compound(
        rpc,
        NFS4_MIN_VERSION_1,
        "layoutget",
        |ops| {
            ops.sequence(sess.sessionid, sess.seq, sess.slot);
            ops.putfh(args.fh);
            ops.layoutget(&args);
        },
        |r| {
            let res = decode_compound_res(r)?;
            if let Some(e) = res.first_error() {
                return Ok(Err(e));
            }
            let seqok = res.expect_sequence()?;
            let lg = res.expect_layoutget()?;
            Ok(match (seqok, lg) {
                (Ok(s), Ok(v)) => Ok((s, v)),
                (Err(e), _) => Err(e),
                (_, Err(e)) => Err(e),
            })
        },
    )
}

pub fn compound_with_session_getdeviceinfo(
    rpc: &mut TcpRpcClient,
    sess: SessionArgs,
    deviceid: &DeviceId4,
    layout_type: u32,
    maxcount: u32,
    notify_mask: &[u32],
) -> Result<core::result::Result<(SequenceOk, GetDeviceInfoOk), Nfs4Error>> {
    compound(
        rpc,
        NFS4_MIN_VERSION_1,
        "getdevinfo",
        |ops| {
            ops.sequence(sess.sessionid, sess.seq, sess.slot);
            ops.getdeviceinfo(deviceid, layout_type, maxcount, notify_mask);
        },
        |r| {
            let res = decode_compound_res(r)?;
            if let Some(e) = res.first_error() {
                return Ok(Err(e));
            }
            let seqok = res.expect_sequence()?;
            let gd = res.expect_getdeviceinfo()?;
            Ok(match (seqok, gd) {
                (Ok(s), Ok(v)) => Ok((s, v)),
                (Err(e), _) => Err(e),
                (_, Err(e)) => Err(e),
            })
        },
    )
}

pub fn compound_with_session_putfh_layoutcommit(
    rpc: &mut TcpRpcClient,
    sess: SessionArgs,
    args: LayoutCommitArgs<'_>,
) -> Result<core::result::Result<(SequenceOk, LayoutCommitOk), Nfs4Error>> {
    compound(
        rpc,
        NFS4_MIN_VERSION_1,
        "layoutcommit",
        |ops| {
            ops.sequence(sess.sessionid, sess.seq, sess.slot);
            ops.putfh(args.fh);
            ops.layoutcommit(&args);
        },
        |r| {
            let res = decode_compound_res(r)?;
            if let Some(e) = res.first_error() {
                return Ok(Err(e));
            }
            let seqok = res.expect_sequence()?;
            let lc = res.expect_layoutcommit()?;
            Ok(match (seqok, lc) {
                (Ok(s), Ok(v)) => Ok((s, v)),
                (Err(e), _) => Err(e),
                (_, Err(e)) => Err(e),
            })
        },
    )
}

pub fn compound_with_session_putfh_layoutreturn(
    rpc: &mut TcpRpcClient,
    sess: SessionArgs,
    args: LayoutReturnArgs<'_>,
) -> Result<core::result::Result<(SequenceOk, Option<StateId4>), Nfs4Error>> {
    compound(
        rpc,
        NFS4_MIN_VERSION_1,
        "layoutreturn",
        |ops| {
            ops.sequence(sess.sessionid, sess.seq, sess.slot);
            ops.putfh(args.fh);
            ops.layoutreturn_flexfiles(&args);
        },
        |r| {
            let res = decode_compound_res(r)?;
            if let Some(e) = res.first_error() {
                return Ok(Err(e));
            }
            let seqok = res.expect_sequence()?;
            let lr = res.expect_layoutreturn()?;
            Ok(match (seqok, lr) {
                (Ok(s), Ok(v)) => Ok((s, v)),
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

    fn exchange_id(&mut self, owner: &ClientOwner4, flags: u32) {
        let w = self.push(OP_EXCHANGE_ID);
        // client_owner4
        w.put_opaque_fixed(&owner.verifier);
        w.put_opaque(&owner.ownerid);

        w.put_u32(flags);

        // state_protect4_a: SP4_NONE
        w.put_u32(0);

        // client_impl_id<1> : empty
        w.put_u32(0);
    }

    fn create_session(
        &mut self,
        clientid: u64,
        sequenceid: u32,
        cb_program: u32,
        cb_auth: Option<AuthSysParams<'_>>,
    ) {
        let w = self.push(OP_CREATE_SESSION);
        w.put_u64(clientid);
        w.put_u32(sequenceid);
        w.put_u32(0); // flags

        encode_channel_attrs4(w, 0, 1024 * 1024, 1024 * 1024, 1024 * 1024, 64, 16);
        encode_channel_attrs4(w, 0, 1024 * 1024, 1024 * 1024, 1024 * 1024, 64, 16);

        w.put_u32(cb_program);
        match cb_auth {
            Some(auth) => {
                w.put_u32(1);
                w.put_u32(1); // AUTH_SYS
                encode_authsys_parms(w, auth);
            }
            None => {
                // sec_parms<>: one entry AUTH_NONE
                w.put_u32(1);
                w.put_u32(0); // AUTH_NONE
            }
        }
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

    fn access(&mut self, access: u32) {
        let w = self.push(OP_ACCESS);
        w.put_u32(access);
    }

    fn getattr(&mut self, attr_request: &[u32]) {
        let w = self.push(OP_GETATTR);
        encode_attrmask(w, attr_request);
    }

    fn open_claim_null(
        &mut self,
        clientid: u64,
        owner: &[u8],
        seqid: u32,
        name: &str,
        access: u32,
    ) {
        let w = self.push(OP_OPEN);
        w.put_u32(seqid);
        w.put_u32(access);
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

    fn write_stateid(&mut self, stateid: &StateId4, offset: u64, stable_how: u32, data: &[u8]) {
        let w = self.push(OP_WRITE);
        encode_stateid4(w, stateid.seqid, stateid.other);
        w.put_u64(offset);
        w.put_u32(stable_how);
        w.put_opaque(data);
    }

    fn readlink(&mut self) {
        let _ = self.push(OP_READLINK);
    }

    fn readdir(&mut self, args: &ReadDirArgs<'_>) {
        let w = self.push(OP_READDIR);
        w.put_u64(args.cookie);
        w.put_opaque_fixed(&args.cookieverf);
        w.put_u32(args.dircount);
        w.put_u32(args.maxcount);
        encode_attrmask(w, args.attr_request);
    }

    fn setattr(&mut self, stateid: &StateId4, attrs: &SetAttr4) {
        let w = self.push(OP_SETATTR);
        encode_stateid4(w, stateid.seqid, stateid.other);
        encode_setattr4(w, attrs);
    }

    fn getdeviceinfo(
        &mut self,
        deviceid: &DeviceId4,
        layout_type: u32,
        maxcount: u32,
        notify_mask: &[u32],
    ) {
        let w = self.push(OP_GETDEVICEINFO);
        w.put_opaque_fixed(&deviceid.0);
        w.put_u32(layout_type);
        w.put_u32(maxcount);
        w.put_vec(notify_mask, |w, v| w.put_u32(*v));
    }

    fn layoutget(&mut self, args: &LayoutGetArgs<'_>) {
        let w = self.push(OP_LAYOUTGET);
        w.put_bool(args.avail);
        w.put_u32(args.layout_type);
        w.put_u32(args.iomode);
        w.put_u64(args.offset);
        w.put_u64(args.length);
        w.put_u64(args.minlength);
        encode_stateid4(w, args.stateid.seqid, args.stateid.other);
        w.put_u32(args.maxcount);
    }

    fn layoutcommit(&mut self, args: &LayoutCommitArgs<'_>) {
        let w = self.push(OP_LAYOUTCOMMIT);
        w.put_u64(args.offset);
        w.put_u64(args.length);
        w.put_bool(args.reclaim);
        encode_stateid4(w, args.stateid.seqid, args.stateid.other);

        match args.last_write_offset {
            Some(v) => {
                w.put_bool(true);
                w.put_u64(v);
            }
            None => w.put_bool(false),
        }

        // newtime4: not updating mtime
        w.put_bool(false);

        // layoutupdate4: type + empty body
        w.put_u32(LAYOUT4_FLEX_FILES);
        w.put_opaque(&[]);
    }

    fn layoutreturn_flexfiles(&mut self, args: &LayoutReturnArgs<'_>) {
        let w = self.push(OP_LAYOUTRETURN);
        w.put_bool(args.reclaim);
        w.put_u32(LAYOUT4_FLEX_FILES);
        w.put_u32(args.iomode);

        // layoutreturn4: return FILE range
        w.put_u32(LAYOUTRETURN4_FILE);
        w.put_u64(args.offset);
        w.put_u64(args.length);
        encode_stateid4(w, args.stateid.seqid, args.stateid.other);

        // layoutreturn_file_body4 for flexfiles (empty report)
        w.put_u32(LAYOUT4_FLEX_FILES);
        w.put_u32(0); // size
        w.put_u32(0); // ioerr_report len
        w.put_u32(0); // iostats_report len
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

fn encode_authsys_parms(w: &mut XdrWriter, auth: AuthSysParams<'_>) {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    w.put_u32(stamp);
    w.put_string(auth.machine);
    w.put_u32(auth.uid);
    w.put_u32(auth.gid);
    w.put_vec(auth.groups, |w, g| w.put_u32(*g));
}

fn encode_attrmask(w: &mut XdrWriter, attr_request: &[u32]) {
    let bitmap = bitmap4_from_attrs(attr_request);
    w.put_vec(&bitmap, |w, v| w.put_u32(*v));
}

fn encode_setattr4(w: &mut XdrWriter, attrs: &SetAttr4) {
    let mut attrnums = Vec::new();
    let mut attrlist = XdrWriter::new();

    if let Some(size) = attrs.size {
        attrnums.push(FATTR4_SIZE);
        attrlist.put_u64(size);
    }
    if let Some(mode) = attrs.mode {
        attrnums.push(FATTR4_MODE);
        attrlist.put_u32(mode);
    }

    w.put_vec(&bitmap4_from_attrs(&attrnums), |w, v| w.put_u32(*v));
    w.put_opaque(&attrlist.into_bytes());
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
    Access(core::result::Result<AccessOk, u32>),
    GetAttr(core::result::Result<GetAttrOk, u32>),
    GetFh(core::result::Result<Vec<u8>, u32>),
    PutFh(core::result::Result<(), u32>),
    Open(core::result::Result<OpenOk, u32>),
    Close(core::result::Result<StateId4, u32>),
    Read(core::result::Result<ReadOk, u32>),
    ReadDir(core::result::Result<ReadDirOk, u32>),
    ReadLink(core::result::Result<ReadLinkOk, u32>),
    SetAttr(core::result::Result<SetAttrOk, u32>),
    Write(core::result::Result<WriteOk, u32>),
    LayoutGet(core::result::Result<LayoutGetOk, u32>),
    GetDeviceInfo(core::result::Result<GetDeviceInfoOk, u32>),
    LayoutCommit(core::result::Result<LayoutCommitOk, u32>),
    LayoutReturn(core::result::Result<Option<StateId4>, u32>),
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
                ResOp::Access(Err(st)) => (OP_ACCESS, *st),
                ResOp::GetAttr(Err(st)) => (OP_GETATTR, *st),
                ResOp::GetFh(Err(st)) => (OP_GETFH, *st),
                ResOp::PutFh(Err(st)) => (OP_PUTFH, *st),
                ResOp::Open(Err(st)) => (OP_OPEN, *st),
                ResOp::Close(Err(st)) => (OP_CLOSE, *st),
                ResOp::Read(Err(st)) => (OP_READ, *st),
                ResOp::ReadDir(Err(st)) => (OP_READDIR, *st),
                ResOp::ReadLink(Err(st)) => (OP_READLINK, *st),
                ResOp::SetAttr(Err(st)) => (OP_SETATTR, *st),
                ResOp::Write(Err(st)) => (OP_WRITE, *st),
                ResOp::LayoutGet(Err(st)) => (OP_LAYOUTGET, *st),
                ResOp::GetDeviceInfo(Err(st)) => (OP_GETDEVICEINFO, *st),
                ResOp::LayoutCommit(Err(st)) => (OP_LAYOUTCOMMIT, *st),
                ResOp::LayoutReturn(Err(st)) => (OP_LAYOUTRETURN, *st),
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

    fn expect_access(&self) -> Result<core::result::Result<AccessOk, Nfs4Error>> {
        for op in &self.ops {
            if let ResOp::Access(r) = op {
                return Ok(match r {
                    Ok(v) => Ok(v.clone()),
                    Err(st) => Err(Nfs4Error {
                        status: *st,
                        op: Some(OP_ACCESS),
                    }),
                });
            }
        }
        Ok(Err(Nfs4Error {
            status: self.status,
            op: Some(OP_ACCESS),
        }))
    }

    fn expect_getattr(&self) -> Result<core::result::Result<GetAttrOk, Nfs4Error>> {
        for op in &self.ops {
            if let ResOp::GetAttr(r) = op {
                return Ok(match r {
                    Ok(v) => Ok(v.clone()),
                    Err(st) => Err(Nfs4Error {
                        status: *st,
                        op: Some(OP_GETATTR),
                    }),
                });
            }
        }
        Ok(Err(Nfs4Error {
            status: self.status,
            op: Some(OP_GETATTR),
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

    fn expect_readdir(&self) -> Result<core::result::Result<ReadDirOk, Nfs4Error>> {
        for op in &self.ops {
            if let ResOp::ReadDir(r) = op {
                return Ok(match r {
                    Ok(v) => Ok(v.clone()),
                    Err(st) => Err(Nfs4Error {
                        status: *st,
                        op: Some(OP_READDIR),
                    }),
                });
            }
        }
        Ok(Err(Nfs4Error {
            status: self.status,
            op: Some(OP_READDIR),
        }))
    }

    fn expect_readlink(&self) -> Result<core::result::Result<ReadLinkOk, Nfs4Error>> {
        for op in &self.ops {
            if let ResOp::ReadLink(r) = op {
                return Ok(match r {
                    Ok(v) => Ok(v.clone()),
                    Err(st) => Err(Nfs4Error {
                        status: *st,
                        op: Some(OP_READLINK),
                    }),
                });
            }
        }
        Ok(Err(Nfs4Error {
            status: self.status,
            op: Some(OP_READLINK),
        }))
    }

    fn expect_setattr(&self) -> Result<core::result::Result<SetAttrOk, Nfs4Error>> {
        for op in &self.ops {
            if let ResOp::SetAttr(r) = op {
                return Ok(match r {
                    Ok(v) => Ok(v.clone()),
                    Err(st) => Err(Nfs4Error {
                        status: *st,
                        op: Some(OP_SETATTR),
                    }),
                });
            }
        }
        Ok(Err(Nfs4Error {
            status: self.status,
            op: Some(OP_SETATTR),
        }))
    }

    fn expect_write(&self) -> Result<core::result::Result<WriteOk, Nfs4Error>> {
        for op in &self.ops {
            if let ResOp::Write(r) = op {
                return Ok(match r {
                    Ok(v) => Ok(v.clone()),
                    Err(st) => Err(Nfs4Error {
                        status: *st,
                        op: Some(OP_WRITE),
                    }),
                });
            }
        }
        Ok(Err(Nfs4Error {
            status: self.status,
            op: Some(OP_WRITE),
        }))
    }

    fn expect_layoutget(&self) -> Result<core::result::Result<LayoutGetOk, Nfs4Error>> {
        for op in &self.ops {
            if let ResOp::LayoutGet(r) = op {
                return Ok(match r {
                    Ok(v) => Ok(v.clone()),
                    Err(st) => Err(Nfs4Error {
                        status: *st,
                        op: Some(OP_LAYOUTGET),
                    }),
                });
            }
        }
        Ok(Err(Nfs4Error {
            status: self.status,
            op: Some(OP_LAYOUTGET),
        }))
    }

    fn expect_getdeviceinfo(&self) -> Result<core::result::Result<GetDeviceInfoOk, Nfs4Error>> {
        for op in &self.ops {
            if let ResOp::GetDeviceInfo(r) = op {
                return Ok(match r {
                    Ok(v) => Ok(v.clone()),
                    Err(st) => Err(Nfs4Error {
                        status: *st,
                        op: Some(OP_GETDEVICEINFO),
                    }),
                });
            }
        }
        Ok(Err(Nfs4Error {
            status: self.status,
            op: Some(OP_GETDEVICEINFO),
        }))
    }

    fn expect_layoutcommit(&self) -> Result<core::result::Result<LayoutCommitOk, Nfs4Error>> {
        for op in &self.ops {
            if let ResOp::LayoutCommit(r) = op {
                return Ok(match r {
                    Ok(v) => Ok(v.clone()),
                    Err(st) => Err(Nfs4Error {
                        status: *st,
                        op: Some(OP_LAYOUTCOMMIT),
                    }),
                });
            }
        }
        Ok(Err(Nfs4Error {
            status: self.status,
            op: Some(OP_LAYOUTCOMMIT),
        }))
    }

    fn expect_layoutreturn(&self) -> Result<core::result::Result<Option<StateId4>, Nfs4Error>> {
        for op in &self.ops {
            if let ResOp::LayoutReturn(r) = op {
                return Ok(match r {
                    Ok(v) => Ok(v.clone()),
                    Err(st) => Err(Nfs4Error {
                        status: *st,
                        op: Some(OP_LAYOUTRETURN),
                    }),
                });
            }
        }
        Ok(Err(Nfs4Error {
            status: self.status,
            op: Some(OP_LAYOUTRETURN),
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
        OP_ACCESS => {
            let st = r.get_u32()?;
            if st != 0 {
                return Ok(ResOp::Access(Err(st)));
            }
            let supported = r.get_u32()?;
            let access = r.get_u32()?;
            Ok(ResOp::Access(Ok(AccessOk { supported, access })))
        }
        OP_GETATTR => {
            let st = r.get_u32()?;
            if st != 0 {
                return Ok(ResOp::GetAttr(Err(st)));
            }
            let attrset = r.get_vec(|r| r.get_u32())?;
            let attrlist = r.get_opaque()?;
            let attrs = decode_fattr4(&attrset, &attrlist)?;
            Ok(ResOp::GetAttr(Ok(GetAttrOk { attrset, attrs })))
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
        OP_READDIR => {
            let st = r.get_u32()?;
            if st != 0 {
                return Ok(ResOp::ReadDir(Err(st)));
            }
            let cookieverf_v = r.get_opaque_fixed(8)?;
            let cookieverf: [u8; 8] = cookieverf_v.as_slice().try_into().unwrap();
            let mut entries = Vec::new();
            loop {
                let present = r.get_bool()?;
                if !present {
                    break;
                }
                let cookie = r.get_u64()?;
                let name = r.get_string()?;
                let attrs = decode_fattr4_from_reader(r)?;
                entries.push(ReadDirEntry4 {
                    cookie,
                    name,
                    attrs,
                });
            }
            let eof = r.get_bool()?;
            Ok(ResOp::ReadDir(Ok(ReadDirOk {
                cookieverf,
                entries,
                eof,
            })))
        }
        OP_READLINK => {
            let st = r.get_u32()?;
            if st != 0 {
                return Ok(ResOp::ReadLink(Err(st)));
            }
            let path = r.get_string()?;
            Ok(ResOp::ReadLink(Ok(ReadLinkOk { path })))
        }
        OP_SETATTR => {
            let st = r.get_u32()?;
            if st != 0 {
                return Ok(ResOp::SetAttr(Err(st)));
            }
            let attrset = r.get_vec(|r| r.get_u32())?;
            Ok(ResOp::SetAttr(Ok(SetAttrOk { attrset })))
        }
        OP_WRITE => {
            let st = r.get_u32()?;
            if st != 0 {
                return Ok(ResOp::Write(Err(st)));
            }
            let count = r.get_u32()?;
            let committed = r.get_u32()?;
            let verf = r.get_opaque_fixed(8)?;
            let verifier: [u8; 8] = verf.as_slice().try_into().unwrap();
            Ok(ResOp::Write(Ok(WriteOk {
                count,
                committed,
                verifier,
            })))
        }
        OP_GETDEVICEINFO => {
            let st = r.get_u32()?;
            if st != 0 {
                if st == NFS4ERR_TOOSMALL {
                    let _mincount = r.get_u32()?;
                }
                return Ok(ResOp::GetDeviceInfo(Err(st)));
            }
            let device_addr = decode_device_addr4(r)?;
            let notify_mask = r.get_vec(|r| r.get_u32())?;
            Ok(ResOp::GetDeviceInfo(Ok(GetDeviceInfoOk {
                device_addr,
                notify_mask,
            })))
        }
        OP_LAYOUTGET => {
            let st = r.get_u32()?;
            if st != 0 {
                if st == NFS4ERR_LAYOUTTRYLATER {
                    let _signal = r.get_bool()?;
                }
                return Ok(ResOp::LayoutGet(Err(st)));
            }
            let return_on_close = r.get_bool()?;
            let stateid = decode_stateid4(r)?;
            let layout = r.get_vec(decode_layout4)?;
            Ok(ResOp::LayoutGet(Ok(LayoutGetOk {
                return_on_close,
                stateid,
                layout,
            })))
        }
        OP_LAYOUTCOMMIT => {
            let st = r.get_u32()?;
            if st != 0 {
                return Ok(ResOp::LayoutCommit(Err(st)));
            }
            let sizechanged = r.get_bool()?;
            let new_size = if sizechanged {
                Some(r.get_u64()?)
            } else {
                None
            };
            Ok(ResOp::LayoutCommit(Ok(LayoutCommitOk { new_size })))
        }
        OP_LAYOUTRETURN => {
            let st = r.get_u32()?;
            if st != 0 {
                return Ok(ResOp::LayoutReturn(Err(st)));
            }
            let present = r.get_bool()?;
            let stateid = if present {
                Some(decode_stateid4(r)?)
            } else {
                None
            };
            Ok(ResOp::LayoutReturn(Ok(stateid)))
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

fn decode_stateid4(r: &mut XdrReader<'_>) -> crate::xdr::Result<StateId4> {
    let seqid = r.get_u32()?;
    let other_v = r.get_opaque_fixed(12)?;
    let other: [u8; 12] = other_v.as_slice().try_into().unwrap();
    Ok(StateId4 { seqid, other })
}

pub fn decode_cb_compound_args(r: &mut XdrReader<'_>) -> crate::xdr::Result<CbCompoundArgs> {
    let tag = r.get_string()?;
    let minorversion = r.get_u32()?;
    let callback_ident = r.get_u32()?;
    let opcount = r.get_u32()?;
    let mut ops = Vec::new();
    for _ in 0..opcount {
        let op = r.get_u32()?;
        let arg = match op {
            OP_CB_SEQUENCE => CbArgOp::Sequence(decode_cb_sequence_args(r)?),
            OP_CB_LAYOUTRECALL => CbArgOp::LayoutRecall(decode_layoutrecall4(r)?),
            other => {
                ops.push(CbArgOp::Unknown(other));
                break;
            }
        };
        ops.push(arg);
    }
    Ok(CbCompoundArgs {
        tag,
        minorversion,
        callback_ident,
        ops,
    })
}

pub fn encode_cb_compound_res(w: &mut XdrWriter, res: &CbCompoundRes) {
    w.put_u32(res.status);
    w.put_string(&res.tag);
    w.put_u32(res.ops.len() as u32);
    for op in &res.ops {
        match op {
            CbResOp::Sequence(res) => {
                w.put_u32(OP_CB_SEQUENCE);
                match res {
                    Ok(ok) => {
                        w.put_u32(NFS4_OK);
                        encode_cb_sequence_resok(w, ok);
                    }
                    Err(st) => {
                        w.put_u32(*st);
                    }
                }
            }
            CbResOp::LayoutRecall(res) => {
                w.put_u32(OP_CB_LAYOUTRECALL);
                match res {
                    Ok(()) => w.put_u32(NFS4_OK),
                    Err(st) => w.put_u32(*st),
                }
            }
            CbResOp::Unknown { op, status } => {
                w.put_u32(*op);
                w.put_u32(*status);
            }
        }
    }
}

fn decode_cb_sequence_args(r: &mut XdrReader<'_>) -> crate::xdr::Result<CbSequenceArgs> {
    let sessionid_v = r.get_opaque_fixed(16)?;
    let sessionid: [u8; 16] = sessionid_v.as_slice().try_into().unwrap();
    let sequenceid = r.get_u32()?;
    let slotid = r.get_u32()?;
    let highest_slotid = r.get_u32()?;
    let cachethis = r.get_bool()?;
    Ok(CbSequenceArgs {
        sessionid,
        sequenceid,
        slotid,
        highest_slotid,
        cachethis,
    })
}

fn encode_cb_sequence_resok(w: &mut XdrWriter, ok: &CbSequenceResOk) {
    w.put_opaque_fixed(&ok.sessionid);
    w.put_u32(ok.sequenceid);
    w.put_u32(ok.slotid);
    w.put_u32(ok.highest_slotid);
    w.put_u32(ok.target_highest_slotid);
}

fn decode_layoutrecall4(r: &mut XdrReader<'_>) -> crate::xdr::Result<LayoutRecall4> {
    let recall_type = r.get_u32()?;
    let layout_type = r.get_u32()?;
    let iomode = r.get_u32()?;
    let target = match recall_type {
        LAYOUT4_RET_REC_FILE => {
            let fh = r.get_opaque()?;
            let offset = r.get_u64()?;
            let length = r.get_u64()?;
            let stateid = decode_stateid4(r)?;
            LayoutRecallTarget::File(LayoutRecallFile4 {
                fh,
                offset,
                length,
                stateid,
            })
        }
        LAYOUT4_RET_REC_FSID => {
            let major = r.get_u64()?;
            let minor = r.get_u64()?;
            LayoutRecallTarget::Fsid(Fsid4 { major, minor })
        }
        LAYOUT4_RET_REC_ALL => LayoutRecallTarget::All,
        _ => return Err(crate::xdr::XdrError::InvalidEnum(recall_type)),
    };
    Ok(LayoutRecall4 {
        layout_type,
        iomode,
        target,
    })
}

fn bitmap4_from_attrs(attrs: &[u32]) -> Vec<u32> {
    if attrs.is_empty() {
        return Vec::new();
    }
    let mut max = 0u32;
    for &attr in attrs {
        if attr > max {
            max = attr;
        }
    }
    let words = (max / 32) as usize + 1;
    let mut bitmap = vec![0u32; words];
    for &attr in attrs {
        let word = (attr / 32) as usize;
        let bit = attr % 32;
        bitmap[word] |= 1u32 << bit;
    }
    bitmap
}

fn bitmap4_iter(bitmap: &[u32]) -> impl Iterator<Item = u32> + '_ {
    bitmap.iter().enumerate().flat_map(|(word_idx, word)| {
        let mut w = *word;
        let mut out = Vec::new();
        while w != 0 {
            let bit = w.trailing_zeros();
            out.push(word_idx as u32 * 32 + bit);
            w &= w - 1;
        }
        out.into_iter()
    })
}

fn decode_nfstime4(r: &mut XdrReader<'_>) -> Result<NfsTime4> {
    let seconds = r.get_i64()?;
    let nseconds = r.get_u32()?;
    Ok(NfsTime4 { seconds, nseconds })
}

fn decode_fattr4(attrset: &[u32], attrlist: &[u8]) -> Result<FileAttr4> {
    let mut attrs = FileAttr4::default();
    let mut r = XdrReader::new(attrlist);
    for attr in bitmap4_iter(attrset) {
        match attr {
            FATTR4_TYPE => attrs.type_ = Some(r.get_u32()?),
            FATTR4_SIZE => attrs.size = Some(r.get_u64()?),
            FATTR4_MODE => attrs.mode = Some(r.get_u32()?),
            FATTR4_FILEID => attrs.fileid = Some(r.get_u64()?),
            FATTR4_OWNER => attrs.owner = Some(r.get_string()?),
            FATTR4_OWNER_GROUP => attrs.owner_group = Some(r.get_string()?),
            FATTR4_TIME_ACCESS => attrs.time_access = Some(decode_nfstime4(&mut r)?),
            FATTR4_TIME_MODIFY => attrs.time_modify = Some(decode_nfstime4(&mut r)?),
            other => {
                return Err(crate::rpc::RpcError::RpcDenied(format!(
                    "unsupported fattr4 {other}"
                )));
            }
        }
    }
    Ok(attrs)
}

fn decode_fattr4_from_reader(r: &mut XdrReader<'_>) -> Result<FileAttr4> {
    let attrset = r.get_vec(|r| r.get_u32())?;
    let attrlist = r.get_opaque()?;
    decode_fattr4(&attrset, &attrlist)
}

fn decode_deviceid4(r: &mut XdrReader<'_>) -> crate::xdr::Result<DeviceId4> {
    let v = r.get_opaque_fixed(16)?;
    let id: [u8; 16] = v.as_slice().try_into().unwrap();
    Ok(DeviceId4(id))
}

fn decode_netaddr4(r: &mut XdrReader<'_>) -> crate::xdr::Result<NetAddr4> {
    Ok(NetAddr4 {
        netid: r.get_string()?,
        addr: r.get_string()?,
    })
}

fn decode_ff_device_version4(r: &mut XdrReader<'_>) -> crate::xdr::Result<FfDeviceVersion4> {
    let version = r.get_u32()?;
    let minorversion = r.get_u32()?;
    let rsize = r.get_u32()?;
    let wsize = r.get_u32()?;
    let tightly_coupled = r.get_bool()?;
    Ok(FfDeviceVersion4 {
        version,
        minorversion,
        rsize,
        wsize,
        tightly_coupled,
    })
}

fn decode_ff_device_addr4(r: &mut XdrReader<'_>) -> crate::xdr::Result<FfDeviceAddr4> {
    let _size = r.get_u32()?;
    let netaddrs = r.get_vec(decode_netaddr4)?;
    let versions = r.get_vec(decode_ff_device_version4)?;
    Ok(FfDeviceAddr4 { netaddrs, versions })
}

fn decode_ff_data_server4(r: &mut XdrReader<'_>) -> crate::xdr::Result<FfDataServer4> {
    let deviceid = decode_deviceid4(r)?;
    let efficiency = r.get_u32()?;
    let stateid = decode_stateid4(r)?;
    let fh_list = r.get_vec(|r| r.get_opaque())?;
    let user = r.get_string()?;
    let group = r.get_string()?;
    Ok(FfDataServer4 {
        deviceid,
        efficiency,
        stateid,
        fh_list,
        user,
        group,
    })
}

fn decode_ff_mirror4(r: &mut XdrReader<'_>) -> crate::xdr::Result<FfMirror4> {
    let data_servers = r.get_vec(decode_ff_data_server4)?;
    Ok(FfMirror4 { data_servers })
}

fn decode_ff_layout4(r: &mut XdrReader<'_>) -> crate::xdr::Result<FfLayout4> {
    let _size = r.get_u32()?;
    let stripe_unit = r.get_u64()?;
    let mirrors = r.get_vec(decode_ff_mirror4)?;
    let flags = r.get_u32()?;
    let stats_hint = r.get_u32()?;
    Ok(FfLayout4 {
        stripe_unit,
        mirrors,
        flags,
        stats_hint,
    })
}

fn decode_layout_content4(r: &mut XdrReader<'_>) -> crate::xdr::Result<LayoutContent4> {
    let layout_type = r.get_u32()?;
    match layout_type {
        LAYOUT4_FLEX_FILES => Ok(LayoutContent4::FlexFiles(decode_ff_layout4(r)?)),
        _ => Ok(LayoutContent4::Opaque {
            layout_type,
            body: r.get_opaque()?,
        }),
    }
}

fn decode_layout4(r: &mut XdrReader<'_>) -> crate::xdr::Result<Layout4> {
    let offset = r.get_u64()?;
    let length = r.get_u64()?;
    let iomode = r.get_u32()?;
    let content = decode_layout_content4(r)?;
    Ok(Layout4 {
        offset,
        length,
        iomode,
        content,
    })
}

fn decode_device_addr4(r: &mut XdrReader<'_>) -> crate::xdr::Result<DeviceAddr4> {
    let layout_type = r.get_u32()?;
    match layout_type {
        LAYOUT4_FLEX_FILES => Ok(DeviceAddr4::FlexFiles(decode_ff_device_addr4(r)?)),
        _ => Ok(DeviceAddr4::Opaque {
            layout_type,
            body: r.get_opaque()?,
        }),
    }
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

    #[test]
    fn flexfiles_layout_roundtrip() {
        let layout = FfLayout4 {
            stripe_unit: 4096,
            mirrors: vec![FfMirror4 {
                data_servers: vec![FfDataServer4 {
                    deviceid: DeviceId4([0x11; 16]),
                    efficiency: 7,
                    stateid: StateId4 {
                        seqid: 3,
                        other: [0x22; 12],
                    },
                    fh_list: vec![vec![1, 2, 3, 4]],
                    user: "1000".into(),
                    group: "1000".into(),
                }],
            }],
            flags: 0,
            stats_hint: 0,
        };

        let mut w = XdrWriter::new();
        encode_ff_layout4(&mut w, &layout);
        let bytes = w.into_bytes();
        let mut r = XdrReader::new(&bytes);
        let decoded = decode_ff_layout4(&mut r).unwrap();

        assert_eq!(decoded.stripe_unit, layout.stripe_unit);
        assert_eq!(decoded.flags, layout.flags);
        assert_eq!(decoded.stats_hint, layout.stats_hint);
        assert_eq!(decoded.mirrors.len(), 1);
        let ds = &decoded.mirrors[0].data_servers[0];
        assert_eq!(ds.deviceid, layout.mirrors[0].data_servers[0].deviceid);
        assert_eq!(ds.efficiency, 7);
        assert_eq!(ds.fh_list[0], vec![1, 2, 3, 4]);
        assert_eq!(ds.user, "1000");
        assert_eq!(ds.group, "1000");
    }

    fn encode_ff_layout4(w: &mut XdrWriter, layout: &FfLayout4) {
        w.put_u32(0); // size (ignored by decoder)
        w.put_u64(layout.stripe_unit);
        w.put_vec(&layout.mirrors, |w, mirror| {
            w.put_vec(&mirror.data_servers, |w, ds| {
                w.put_opaque_fixed(&ds.deviceid.0);
                w.put_u32(ds.efficiency);
                encode_stateid4(w, ds.stateid.seqid, ds.stateid.other);
                w.put_vec(&ds.fh_list, |w, fh| w.put_opaque(fh));
                w.put_string(&ds.user);
                w.put_string(&ds.group);
            });
        });
        w.put_u32(layout.flags);
        w.put_u32(layout.stats_hint);
    }
}
