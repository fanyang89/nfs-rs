//! NFS v3 (RFC 1813) minimal client-side types.

use crate::rpc::Result;
use crate::rpc::TcpRpcClient;
use crate::xdr::XdrReader;
use core::fmt;

pub const NFS_PROG: u32 = 100_003;
pub const NFS_VERS: u32 = 3;

pub const NFSPROC_GETATTR: u32 = 1;
pub const NFSPROC_LOOKUP: u32 = 3;
pub const NFSPROC_READ: u32 = 6;
pub const NFSPROC_READDIRPLUS: u32 = 17;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHandle(pub Vec<u8>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fattr3 {
    pub ftype: u32,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub used: u64,
    pub fsid: u64,
    pub fileid: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadOk {
    pub count: u32,
    pub eof: bool,
    pub data: Vec<u8>,
    pub attributes: Option<Fattr3>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupOk {
    pub fh: FileHandle,
    pub attributes: Option<Fattr3>,
    pub dir_attributes: Option<Fattr3>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntryPlus {
    pub fileid: u64,
    pub name: String,
    pub cookie: u64,
    pub attributes: Option<Fattr3>,
    pub fh: Option<FileHandle>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadDirPlusOk {
    pub attributes: Option<Fattr3>,
    pub verifier: [u8; 8],
    pub entries: Vec<DirEntryPlus>,
    pub eof: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NfsError {
    pub status: u32,
}

impl fmt::Display for NfsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NFSv3 error status={}", self.status)
    }
}

impl std::error::Error for NfsError {}

pub fn getattr(
    rpc: &mut TcpRpcClient,
    fh: &FileHandle,
) -> Result<core::result::Result<Fattr3, NfsError>> {
    rpc.call(
        NFS_PROG,
        NFS_VERS,
        NFSPROC_GETATTR,
        |w| w.put_opaque(&fh.0),
        decode_getattr_res,
    )
}

pub fn lookup(
    rpc: &mut TcpRpcClient,
    dir: &FileHandle,
    name: &str,
) -> Result<core::result::Result<LookupOk, NfsError>> {
    rpc.call(
        NFS_PROG,
        NFS_VERS,
        NFSPROC_LOOKUP,
        |w| {
            w.put_opaque(&dir.0);
            w.put_string(name);
        },
        decode_lookup_res,
    )
}

pub fn read(
    rpc: &mut TcpRpcClient,
    fh: &FileHandle,
    offset: u64,
    count: u32,
) -> Result<core::result::Result<ReadOk, NfsError>> {
    rpc.call(
        NFS_PROG,
        NFS_VERS,
        NFSPROC_READ,
        |w| {
            w.put_opaque(&fh.0);
            w.put_u64(offset);
            w.put_u32(count);
        },
        decode_read_res,
    )
}

pub fn readdirplus(
    rpc: &mut TcpRpcClient,
    fh: &FileHandle,
    cookie: u64,
    verifier: [u8; 8],
    dircount: u32,
    maxcount: u32,
) -> Result<core::result::Result<ReadDirPlusOk, NfsError>> {
    rpc.call(
        NFS_PROG,
        NFS_VERS,
        NFSPROC_READDIRPLUS,
        |w| {
            w.put_opaque(&fh.0);
            w.put_u64(cookie);
            w.put_opaque_fixed(&verifier);
            w.put_u32(dircount);
            w.put_u32(maxcount);
        },
        decode_readdirplus_res,
    )
}

fn decode_getattr_res(r: &mut XdrReader<'_>) -> Result<core::result::Result<Fattr3, NfsError>> {
    let status = r.get_u32()?;
    if status != 0 {
        return Ok(Err(NfsError { status }));
    }
    Ok(Ok(decode_fattr3(r)?))
}

fn decode_lookup_res(r: &mut XdrReader<'_>) -> Result<core::result::Result<LookupOk, NfsError>> {
    let status = r.get_u32()?;
    if status != 0 {
        // LOOKUP3resfail includes dir_attributes, but we can ignore for now.
        let _dir_attr = decode_post_op_attr(r)?;
        return Ok(Err(NfsError { status }));
    }
    let fh = FileHandle(r.get_opaque()?);
    let attributes = decode_post_op_attr(r)?;
    let dir_attributes = decode_post_op_attr(r)?;
    Ok(Ok(LookupOk {
        fh,
        attributes,
        dir_attributes,
    }))
}

fn decode_read_res(r: &mut XdrReader<'_>) -> Result<core::result::Result<ReadOk, NfsError>> {
    let status = r.get_u32()?;
    if status != 0 {
        let _file_attr = decode_post_op_attr(r)?;
        return Ok(Err(NfsError { status }));
    }
    let attributes = decode_post_op_attr(r)?;
    let count = r.get_u32()?;
    let eof = r.get_bool()?;
    let data = r.get_opaque()?;
    Ok(Ok(ReadOk {
        count,
        eof,
        data,
        attributes,
    }))
}

fn decode_readdirplus_res(
    r: &mut XdrReader<'_>,
) -> Result<core::result::Result<ReadDirPlusOk, NfsError>> {
    let status = r.get_u32()?;
    if status != 0 {
        let _attrs = decode_post_op_attr(r)?;
        return Ok(Err(NfsError { status }));
    }
    let attributes = decode_post_op_attr(r)?;
    let v = r.get_opaque_fixed(8)?;
    let verifier: [u8; 8] = v.as_slice().try_into().unwrap();
    let (entries, eof) = decode_dirlistplus3(r)?;
    Ok(Ok(ReadDirPlusOk {
        attributes,
        verifier,
        entries,
        eof,
    }))
}

fn decode_dirlistplus3(r: &mut XdrReader<'_>) -> Result<(Vec<DirEntryPlus>, bool)> {
    let mut out = Vec::new();
    let mut has_entry = r.get_bool()?;
    while has_entry {
        let fileid = r.get_u64()?;
        let name = r.get_string()?;
        let cookie = r.get_u64()?;
        let attributes = decode_post_op_attr(r)?;
        let fh = decode_post_op_fh3(r)?;
        out.push(DirEntryPlus {
            fileid,
            name,
            cookie,
            attributes,
            fh,
        });
        has_entry = r.get_bool()?;
    }
    let eof = r.get_bool()?;
    Ok((out, eof))
}

fn decode_post_op_fh3(r: &mut XdrReader<'_>) -> Result<Option<FileHandle>> {
    let follows = r.get_bool()?;
    if !follows {
        return Ok(None);
    }
    Ok(Some(FileHandle(r.get_opaque()?)))
}

fn decode_post_op_attr(r: &mut XdrReader<'_>) -> Result<Option<Fattr3>> {
    let follows = r.get_bool()?;
    if !follows {
        return Ok(None);
    }
    Ok(Some(decode_fattr3(r)?))
}

fn decode_fattr3(r: &mut XdrReader<'_>) -> Result<Fattr3> {
    let ftype = r.get_u32()?;
    let mode = r.get_u32()?;
    let nlink = r.get_u32()?;
    let uid = r.get_u32()?;
    let gid = r.get_u32()?;
    let size = r.get_u64()?;
    let used = r.get_u64()?;
    // specdata3
    let _rdev1 = r.get_u32()?;
    let _rdev2 = r.get_u32()?;
    let fsid = r.get_u64()?;
    let fileid = r.get_u64()?;
    // nfstime3 atime/mtime/ctime (seconds, nseconds)
    let _atime_s = r.get_u32()?;
    let _atime_ns = r.get_u32()?;
    let _mtime_s = r.get_u32()?;
    let _mtime_ns = r.get_u32()?;
    let _ctime_s = r.get_u32()?;
    let _ctime_ns = r.get_u32()?;
    Ok(Fattr3 {
        ftype,
        mode,
        nlink,
        uid,
        gid,
        size,
        used,
        fsid,
        fileid,
    })
}
