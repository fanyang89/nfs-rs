//! NFS v3 (RFC 1813) minimal client-side types.

use crate::rpc::Result;
use crate::rpc::TcpRpcClient;
use crate::xdr::XdrReader;
use core::fmt;

pub const NFS_PROG: u32 = 100_003;
pub const NFS_VERS: u32 = 3;

pub const NFSPROC_SETATTR: u32 = 2;
pub const NFSPROC_GETATTR: u32 = 1;
pub const NFSPROC_LOOKUP: u32 = 3;
pub const NFSPROC_ACCESS: u32 = 4;
pub const NFSPROC_READLINK: u32 = 5;
pub const NFSPROC_READ: u32 = 6;
pub const NFSPROC_WRITE: u32 = 7;
pub const NFSPROC_CREATE: u32 = 8;
pub const NFSPROC_MKDIR: u32 = 9;
pub const NFSPROC_SYMLINK: u32 = 10;
pub const NFSPROC_MKNOD: u32 = 11;
pub const NFSPROC_REMOVE: u32 = 12;
pub const NFSPROC_RMDIR: u32 = 13;
pub const NFSPROC_RENAME: u32 = 14;
pub const NFSPROC_LINK: u32 = 15;
pub const NFSPROC_READDIR: u32 = 16;
pub const NFSPROC_READDIRPLUS: u32 = 17;
pub const NFSPROC_FSSTAT: u32 = 18;
pub const NFSPROC_FSINFO: u32 = 19;
pub const NFSPROC_PATHCONF: u32 = 20;
pub const NFSPROC_COMMIT: u32 = 21;

pub const NF3REG: u32 = 1;
pub const NF3DIR: u32 = 2;
pub const NF3BLK: u32 = 3;
pub const NF3CHR: u32 = 4;
pub const NF3LNK: u32 = 5;
pub const NF3SOCK: u32 = 6;
pub const NF3FIFO: u32 = 7;

pub const STABLE_HOW_UNSTABLE: u32 = 0;
pub const STABLE_HOW_DATA_SYNC: u32 = 1;
pub const STABLE_HOW_FILE_SYNC: u32 = 2;

pub const ACCESS3_READ: u32 = 0x0000_0001;
pub const ACCESS3_LOOKUP: u32 = 0x0000_0002;
pub const ACCESS3_MODIFY: u32 = 0x0000_0004;
pub const ACCESS3_EXTEND: u32 = 0x0000_0008;
pub const ACCESS3_DELETE: u32 = 0x0000_0010;
pub const ACCESS3_EXECUTE: u32 = 0x0000_0020;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHandle(pub Vec<u8>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Time3 {
    pub seconds: u32,
    pub nseconds: u32,
}

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
pub struct WriteOk {
    pub count: u32,
    pub committed: u32,
    pub verifier: [u8; 8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitOk {
    pub verifier: [u8; 8],
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
pub struct DirEntry {
    pub fileid: u64,
    pub name: String,
    pub cookie: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadDirOk {
    pub attributes: Option<Fattr3>,
    pub verifier: [u8; 8],
    pub entries: Vec<DirEntry>,
    pub eof: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessOk {
    pub access: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadLinkOk {
    pub attributes: Option<Fattr3>,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsInfoOk {
    pub attributes: Option<Fattr3>,
    pub rtmax: u32,
    pub rtpref: u32,
    pub rtmult: u32,
    pub wtmax: u32,
    pub wtpref: u32,
    pub wtmult: u32,
    pub dtpref: u32,
    pub maxfilesize: u64,
    pub time_delta: Time3,
    pub properties: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsStatOk {
    pub attributes: Option<Fattr3>,
    pub tbytes: u64,
    pub fbytes: u64,
    pub abytes: u64,
    pub tfiles: u64,
    pub ffiles: u64,
    pub afiles: u64,
    pub invarsec: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathConfOk {
    pub attributes: Option<Fattr3>,
    pub linkmax: u32,
    pub namemax: u32,
    pub no_trunc: bool,
    pub chown_restricted: bool,
    pub case_insensitive: bool,
    pub case_preserving: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreOpAttr {
    pub size: u64,
    pub mtime: Time3,
    pub ctime: Time3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WccData {
    pub before: Option<PreOpAttr>,
    pub after: Option<Fattr3>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetTime {
    DontChange,
    ServerTime,
    ClientTime(Time3),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetAttr3 {
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub size: Option<u64>,
    pub atime: SetTime,
    pub mtime: SetTime,
}

impl Default for SetAttr3 {
    fn default() -> Self {
        Self {
            mode: None,
            uid: None,
            gid: None,
            size: None,
            atime: SetTime::DontChange,
            mtime: SetTime::DontChange,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateHow3 {
    Unchecked(SetAttr3),
    Guarded(SetAttr3),
    Exclusive([u8; 8]),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateOk {
    pub fh: Option<FileHandle>,
    pub attributes: Option<Fattr3>,
    pub dir_wcc: WccData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MkdirOk {
    pub fh: Option<FileHandle>,
    pub attributes: Option<Fattr3>,
    pub dir_wcc: WccData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymlinkOk {
    pub fh: Option<FileHandle>,
    pub attributes: Option<Fattr3>,
    pub dir_wcc: WccData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MknodData {
    CharDevice { major: u32, minor: u32 },
    BlockDevice { major: u32, minor: u32 },
    Socket,
    Fifo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MknodOk {
    pub fh: Option<FileHandle>,
    pub attributes: Option<Fattr3>,
    pub dir_wcc: WccData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenameOk {
    pub from_wcc: WccData,
    pub to_wcc: WccData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkOk {
    pub file_attributes: Option<Fattr3>,
    pub linkdir_wcc: WccData,
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

pub fn setattr(
    rpc: &mut TcpRpcClient,
    fh: &FileHandle,
    attrs: &SetAttr3,
    guard: Option<Time3>,
) -> Result<core::result::Result<WccData, NfsError>> {
    rpc.call(
        NFS_PROG,
        NFS_VERS,
        NFSPROC_SETATTR,
        |w| {
            w.put_opaque(&fh.0);
            encode_sattr3(w, attrs);
            encode_sattrguard3(w, guard);
        },
        decode_setattr_res,
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

pub fn access(
    rpc: &mut TcpRpcClient,
    fh: &FileHandle,
    access: u32,
) -> Result<core::result::Result<AccessOk, NfsError>> {
    rpc.call(
        NFS_PROG,
        NFS_VERS,
        NFSPROC_ACCESS,
        |w| {
            w.put_opaque(&fh.0);
            w.put_u32(access);
        },
        decode_access_res,
    )
}

pub fn readlink(
    rpc: &mut TcpRpcClient,
    fh: &FileHandle,
) -> Result<core::result::Result<ReadLinkOk, NfsError>> {
    rpc.call(
        NFS_PROG,
        NFS_VERS,
        NFSPROC_READLINK,
        |w| w.put_opaque(&fh.0),
        decode_readlink_res,
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

pub fn write(
    rpc: &mut TcpRpcClient,
    fh: &FileHandle,
    offset: u64,
    data: &[u8],
    stable: u32,
) -> Result<core::result::Result<WriteOk, NfsError>> {
    rpc.call(
        NFS_PROG,
        NFS_VERS,
        NFSPROC_WRITE,
        |w| {
            w.put_opaque(&fh.0);
            w.put_u64(offset);
            w.put_u32(data.len() as u32);
            w.put_u32(stable);
            w.put_opaque(data);
        },
        decode_write_res,
    )
}

pub fn create(
    rpc: &mut TcpRpcClient,
    dir: &FileHandle,
    name: &str,
    how: &CreateHow3,
) -> Result<core::result::Result<CreateOk, NfsError>> {
    rpc.call(
        NFS_PROG,
        NFS_VERS,
        NFSPROC_CREATE,
        |w| {
            encode_diropargs(w, dir, name);
            encode_createhow3(w, how);
        },
        decode_create_res,
    )
}

pub fn mkdir(
    rpc: &mut TcpRpcClient,
    dir: &FileHandle,
    name: &str,
    attrs: &SetAttr3,
) -> Result<core::result::Result<MkdirOk, NfsError>> {
    rpc.call(
        NFS_PROG,
        NFS_VERS,
        NFSPROC_MKDIR,
        |w| {
            encode_diropargs(w, dir, name);
            encode_sattr3(w, attrs);
        },
        decode_mkdir_res,
    )
}

pub fn symlink(
    rpc: &mut TcpRpcClient,
    dir: &FileHandle,
    name: &str,
    link_path: &str,
    attrs: &SetAttr3,
) -> Result<core::result::Result<SymlinkOk, NfsError>> {
    rpc.call(
        NFS_PROG,
        NFS_VERS,
        NFSPROC_SYMLINK,
        |w| {
            encode_diropargs(w, dir, name);
            encode_sattr3(w, attrs);
            w.put_string(link_path);
        },
        decode_symlink_res,
    )
}

pub fn mknod(
    rpc: &mut TcpRpcClient,
    dir: &FileHandle,
    name: &str,
    data: &MknodData,
    attrs: &SetAttr3,
) -> Result<core::result::Result<MknodOk, NfsError>> {
    rpc.call(
        NFS_PROG,
        NFS_VERS,
        NFSPROC_MKNOD,
        |w| {
            encode_diropargs(w, dir, name);
            encode_mknoddata3(w, data, attrs);
        },
        decode_mknod_res,
    )
}

pub fn remove(
    rpc: &mut TcpRpcClient,
    dir: &FileHandle,
    name: &str,
) -> Result<core::result::Result<WccData, NfsError>> {
    rpc.call(
        NFS_PROG,
        NFS_VERS,
        NFSPROC_REMOVE,
        |w| encode_diropargs(w, dir, name),
        decode_remove_res,
    )
}

pub fn rmdir(
    rpc: &mut TcpRpcClient,
    dir: &FileHandle,
    name: &str,
) -> Result<core::result::Result<WccData, NfsError>> {
    rpc.call(
        NFS_PROG,
        NFS_VERS,
        NFSPROC_RMDIR,
        |w| encode_diropargs(w, dir, name),
        decode_rmdir_res,
    )
}

pub fn rename(
    rpc: &mut TcpRpcClient,
    from_dir: &FileHandle,
    from_name: &str,
    to_dir: &FileHandle,
    to_name: &str,
) -> Result<core::result::Result<RenameOk, NfsError>> {
    rpc.call(
        NFS_PROG,
        NFS_VERS,
        NFSPROC_RENAME,
        |w| {
            encode_diropargs(w, from_dir, from_name);
            encode_diropargs(w, to_dir, to_name);
        },
        decode_rename_res,
    )
}

pub fn link(
    rpc: &mut TcpRpcClient,
    file: &FileHandle,
    to_dir: &FileHandle,
    to_name: &str,
) -> Result<core::result::Result<LinkOk, NfsError>> {
    rpc.call(
        NFS_PROG,
        NFS_VERS,
        NFSPROC_LINK,
        |w| {
            w.put_opaque(&file.0);
            encode_diropargs(w, to_dir, to_name);
        },
        decode_link_res,
    )
}

pub fn readdir(
    rpc: &mut TcpRpcClient,
    fh: &FileHandle,
    cookie: u64,
    verifier: [u8; 8],
    count: u32,
) -> Result<core::result::Result<ReadDirOk, NfsError>> {
    rpc.call(
        NFS_PROG,
        NFS_VERS,
        NFSPROC_READDIR,
        |w| {
            w.put_opaque(&fh.0);
            w.put_u64(cookie);
            w.put_opaque_fixed(&verifier);
            w.put_u32(count);
        },
        decode_readdir_res,
    )
}

pub fn commit(
    rpc: &mut TcpRpcClient,
    fh: &FileHandle,
    offset: u64,
    count: u32,
) -> Result<core::result::Result<CommitOk, NfsError>> {
    rpc.call(
        NFS_PROG,
        NFS_VERS,
        NFSPROC_COMMIT,
        |w| {
            w.put_opaque(&fh.0);
            w.put_u64(offset);
            w.put_u32(count);
        },
        decode_commit_res,
    )
}

pub fn fsstat(
    rpc: &mut TcpRpcClient,
    fh: &FileHandle,
) -> Result<core::result::Result<FsStatOk, NfsError>> {
    rpc.call(
        NFS_PROG,
        NFS_VERS,
        NFSPROC_FSSTAT,
        |w| w.put_opaque(&fh.0),
        decode_fsstat_res,
    )
}

pub fn fsinfo(
    rpc: &mut TcpRpcClient,
    fh: &FileHandle,
) -> Result<core::result::Result<FsInfoOk, NfsError>> {
    rpc.call(
        NFS_PROG,
        NFS_VERS,
        NFSPROC_FSINFO,
        |w| w.put_opaque(&fh.0),
        decode_fsinfo_res,
    )
}

pub fn pathconf(
    rpc: &mut TcpRpcClient,
    fh: &FileHandle,
) -> Result<core::result::Result<PathConfOk, NfsError>> {
    rpc.call(
        NFS_PROG,
        NFS_VERS,
        NFSPROC_PATHCONF,
        |w| w.put_opaque(&fh.0),
        decode_pathconf_res,
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

fn decode_setattr_res(r: &mut XdrReader<'_>) -> Result<core::result::Result<WccData, NfsError>> {
    let status = r.get_u32()?;
    let wcc = decode_wcc_data(r)?;
    if status != 0 {
        return Ok(Err(NfsError { status }));
    }
    Ok(Ok(wcc))
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

fn decode_access_res(r: &mut XdrReader<'_>) -> Result<core::result::Result<AccessOk, NfsError>> {
    let status = r.get_u32()?;
    if status != 0 {
        let _attrs = decode_post_op_attr(r)?;
        return Ok(Err(NfsError { status }));
    }
    let _attrs = decode_post_op_attr(r)?;
    let access = r.get_u32()?;
    Ok(Ok(AccessOk { access }))
}

fn decode_readlink_res(
    r: &mut XdrReader<'_>,
) -> Result<core::result::Result<ReadLinkOk, NfsError>> {
    let status = r.get_u32()?;
    if status != 0 {
        let _attrs = decode_post_op_attr(r)?;
        return Ok(Err(NfsError { status }));
    }
    let attributes = decode_post_op_attr(r)?;
    let path = r.get_string()?;
    Ok(Ok(ReadLinkOk { attributes, path }))
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

fn decode_write_res(r: &mut XdrReader<'_>) -> Result<core::result::Result<WriteOk, NfsError>> {
    let status = r.get_u32()?;
    if status != 0 {
        let _wcc = decode_wcc_data(r)?;
        return Ok(Err(NfsError { status }));
    }
    let _wcc = decode_wcc_data(r)?;
    let count = r.get_u32()?;
    let committed = r.get_u32()?;
    let v = r.get_opaque_fixed(8)?;
    let verifier: [u8; 8] = v.as_slice().try_into().unwrap();
    Ok(Ok(WriteOk {
        count,
        committed,
        verifier,
    }))
}

fn decode_commit_res(r: &mut XdrReader<'_>) -> Result<core::result::Result<CommitOk, NfsError>> {
    let status = r.get_u32()?;
    if status != 0 {
        let _wcc = decode_wcc_data(r)?;
        return Ok(Err(NfsError { status }));
    }
    let _wcc = decode_wcc_data(r)?;
    let v = r.get_opaque_fixed(8)?;
    let verifier: [u8; 8] = v.as_slice().try_into().unwrap();
    Ok(Ok(CommitOk { verifier }))
}

fn decode_create_res(r: &mut XdrReader<'_>) -> Result<core::result::Result<CreateOk, NfsError>> {
    let status = r.get_u32()?;
    if status != 0 {
        let _wcc = decode_wcc_data(r)?;
        return Ok(Err(NfsError { status }));
    }
    let fh = decode_post_op_fh3(r)?;
    let attributes = decode_post_op_attr(r)?;
    let dir_wcc = decode_wcc_data(r)?;
    Ok(Ok(CreateOk {
        fh,
        attributes,
        dir_wcc,
    }))
}

fn decode_mkdir_res(r: &mut XdrReader<'_>) -> Result<core::result::Result<MkdirOk, NfsError>> {
    let status = r.get_u32()?;
    if status != 0 {
        let _wcc = decode_wcc_data(r)?;
        return Ok(Err(NfsError { status }));
    }
    let fh = decode_post_op_fh3(r)?;
    let attributes = decode_post_op_attr(r)?;
    let dir_wcc = decode_wcc_data(r)?;
    Ok(Ok(MkdirOk {
        fh,
        attributes,
        dir_wcc,
    }))
}

fn decode_symlink_res(r: &mut XdrReader<'_>) -> Result<core::result::Result<SymlinkOk, NfsError>> {
    let status = r.get_u32()?;
    if status != 0 {
        let _wcc = decode_wcc_data(r)?;
        return Ok(Err(NfsError { status }));
    }
    let fh = decode_post_op_fh3(r)?;
    let attributes = decode_post_op_attr(r)?;
    let dir_wcc = decode_wcc_data(r)?;
    Ok(Ok(SymlinkOk {
        fh,
        attributes,
        dir_wcc,
    }))
}

fn decode_mknod_res(r: &mut XdrReader<'_>) -> Result<core::result::Result<MknodOk, NfsError>> {
    let status = r.get_u32()?;
    if status != 0 {
        let _wcc = decode_wcc_data(r)?;
        return Ok(Err(NfsError { status }));
    }
    let fh = decode_post_op_fh3(r)?;
    let attributes = decode_post_op_attr(r)?;
    let dir_wcc = decode_wcc_data(r)?;
    Ok(Ok(MknodOk {
        fh,
        attributes,
        dir_wcc,
    }))
}

fn decode_remove_res(r: &mut XdrReader<'_>) -> Result<core::result::Result<WccData, NfsError>> {
    let status = r.get_u32()?;
    let wcc = decode_wcc_data(r)?;
    if status != 0 {
        return Ok(Err(NfsError { status }));
    }
    Ok(Ok(wcc))
}

fn decode_rmdir_res(r: &mut XdrReader<'_>) -> Result<core::result::Result<WccData, NfsError>> {
    let status = r.get_u32()?;
    let wcc = decode_wcc_data(r)?;
    if status != 0 {
        return Ok(Err(NfsError { status }));
    }
    Ok(Ok(wcc))
}

fn decode_rename_res(r: &mut XdrReader<'_>) -> Result<core::result::Result<RenameOk, NfsError>> {
    let status = r.get_u32()?;
    let from_wcc = decode_wcc_data(r)?;
    let to_wcc = decode_wcc_data(r)?;
    if status != 0 {
        return Ok(Err(NfsError { status }));
    }
    Ok(Ok(RenameOk { from_wcc, to_wcc }))
}

fn decode_link_res(r: &mut XdrReader<'_>) -> Result<core::result::Result<LinkOk, NfsError>> {
    let status = r.get_u32()?;
    if status != 0 {
        let _file_attr = decode_post_op_attr(r)?;
        let _linkdir_wcc = decode_wcc_data(r)?;
        return Ok(Err(NfsError { status }));
    }
    let file_attributes = decode_post_op_attr(r)?;
    let linkdir_wcc = decode_wcc_data(r)?;
    Ok(Ok(LinkOk {
        file_attributes,
        linkdir_wcc,
    }))
}

fn decode_readdir_res(r: &mut XdrReader<'_>) -> Result<core::result::Result<ReadDirOk, NfsError>> {
    let status = r.get_u32()?;
    if status != 0 {
        let _attrs = decode_post_op_attr(r)?;
        return Ok(Err(NfsError { status }));
    }
    let attributes = decode_post_op_attr(r)?;
    let v = r.get_opaque_fixed(8)?;
    let verifier: [u8; 8] = v.as_slice().try_into().unwrap();
    let (entries, eof) = decode_dirlist3(r)?;
    Ok(Ok(ReadDirOk {
        attributes,
        verifier,
        entries,
        eof,
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

fn decode_fsstat_res(r: &mut XdrReader<'_>) -> Result<core::result::Result<FsStatOk, NfsError>> {
    let status = r.get_u32()?;
    if status != 0 {
        let _attrs = decode_post_op_attr(r)?;
        return Ok(Err(NfsError { status }));
    }
    let attributes = decode_post_op_attr(r)?;
    let tbytes = r.get_u64()?;
    let fbytes = r.get_u64()?;
    let abytes = r.get_u64()?;
    let tfiles = r.get_u64()?;
    let ffiles = r.get_u64()?;
    let afiles = r.get_u64()?;
    let invarsec = r.get_u32()?;
    Ok(Ok(FsStatOk {
        attributes,
        tbytes,
        fbytes,
        abytes,
        tfiles,
        ffiles,
        afiles,
        invarsec,
    }))
}

fn decode_fsinfo_res(r: &mut XdrReader<'_>) -> Result<core::result::Result<FsInfoOk, NfsError>> {
    let status = r.get_u32()?;
    if status != 0 {
        let _attrs = decode_post_op_attr(r)?;
        return Ok(Err(NfsError { status }));
    }
    let attributes = decode_post_op_attr(r)?;
    let rtmax = r.get_u32()?;
    let rtpref = r.get_u32()?;
    let rtmult = r.get_u32()?;
    let wtmax = r.get_u32()?;
    let wtpref = r.get_u32()?;
    let wtmult = r.get_u32()?;
    let dtpref = r.get_u32()?;
    let maxfilesize = r.get_u64()?;
    let time_delta = decode_time3(r)?;
    let properties = r.get_u32()?;
    Ok(Ok(FsInfoOk {
        attributes,
        rtmax,
        rtpref,
        rtmult,
        wtmax,
        wtpref,
        wtmult,
        dtpref,
        maxfilesize,
        time_delta,
        properties,
    }))
}

fn decode_pathconf_res(
    r: &mut XdrReader<'_>,
) -> Result<core::result::Result<PathConfOk, NfsError>> {
    let status = r.get_u32()?;
    if status != 0 {
        let _attrs = decode_post_op_attr(r)?;
        return Ok(Err(NfsError { status }));
    }
    let attributes = decode_post_op_attr(r)?;
    let linkmax = r.get_u32()?;
    let namemax = r.get_u32()?;
    let no_trunc = r.get_bool()?;
    let chown_restricted = r.get_bool()?;
    let case_insensitive = r.get_bool()?;
    let case_preserving = r.get_bool()?;
    Ok(Ok(PathConfOk {
        attributes,
        linkmax,
        namemax,
        no_trunc,
        chown_restricted,
        case_insensitive,
        case_preserving,
    }))
}

fn decode_dirlist3(r: &mut XdrReader<'_>) -> Result<(Vec<DirEntry>, bool)> {
    let mut out = Vec::new();
    let mut has_entry = r.get_bool()?;
    while has_entry {
        let fileid = r.get_u64()?;
        let name = r.get_string()?;
        let cookie = r.get_u64()?;
        out.push(DirEntry {
            fileid,
            name,
            cookie,
        });
        has_entry = r.get_bool()?;
    }
    let eof = r.get_bool()?;
    Ok((out, eof))
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

fn decode_wcc_data(r: &mut XdrReader<'_>) -> Result<WccData> {
    let before = decode_pre_op_attr(r)?;
    let after = decode_post_op_attr(r)?;
    Ok(WccData { before, after })
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

fn decode_time3(r: &mut XdrReader<'_>) -> Result<Time3> {
    Ok(Time3 {
        seconds: r.get_u32()?,
        nseconds: r.get_u32()?,
    })
}

fn decode_pre_op_attr(r: &mut XdrReader<'_>) -> Result<Option<PreOpAttr>> {
    let follows = r.get_bool()?;
    if !follows {
        return Ok(None);
    }
    let size = r.get_u64()?;
    let mtime = decode_time3(r)?;
    let ctime = decode_time3(r)?;
    Ok(Some(PreOpAttr { size, mtime, ctime }))
}

fn encode_diropargs(w: &mut crate::xdr::XdrWriter, dir: &FileHandle, name: &str) {
    w.put_opaque(&dir.0);
    w.put_string(name);
}

fn encode_sattrguard3(w: &mut crate::xdr::XdrWriter, guard: Option<Time3>) {
    match guard {
        Some(t) => {
            w.put_bool(true);
            encode_time3(w, t);
        }
        None => w.put_bool(false),
    }
}

fn encode_sattr3(w: &mut crate::xdr::XdrWriter, attrs: &SetAttr3) {
    encode_set_u32(w, attrs.mode);
    encode_set_u32(w, attrs.uid);
    encode_set_u32(w, attrs.gid);
    encode_set_u64(w, attrs.size);
    encode_set_time(w, &attrs.atime);
    encode_set_time(w, &attrs.mtime);
}

fn encode_set_u32(w: &mut crate::xdr::XdrWriter, v: Option<u32>) {
    match v {
        Some(v) => {
            w.put_bool(true);
            w.put_u32(v);
        }
        None => w.put_bool(false),
    }
}

fn encode_set_u64(w: &mut crate::xdr::XdrWriter, v: Option<u64>) {
    match v {
        Some(v) => {
            w.put_bool(true);
            w.put_u64(v);
        }
        None => w.put_bool(false),
    }
}

fn encode_set_time(w: &mut crate::xdr::XdrWriter, v: &SetTime) {
    match v {
        SetTime::DontChange => w.put_u32(0),
        SetTime::ServerTime => w.put_u32(1),
        SetTime::ClientTime(t) => {
            w.put_u32(2);
            encode_time3(w, *t);
        }
    }
}

fn encode_time3(w: &mut crate::xdr::XdrWriter, t: Time3) {
    w.put_u32(t.seconds);
    w.put_u32(t.nseconds);
}

fn encode_createhow3(w: &mut crate::xdr::XdrWriter, how: &CreateHow3) {
    match how {
        CreateHow3::Unchecked(attrs) => {
            w.put_u32(0);
            encode_sattr3(w, attrs);
        }
        CreateHow3::Guarded(attrs) => {
            w.put_u32(1);
            encode_sattr3(w, attrs);
        }
        CreateHow3::Exclusive(verf) => {
            w.put_u32(2);
            w.put_opaque_fixed(verf);
        }
    }
}

fn encode_mknoddata3(w: &mut crate::xdr::XdrWriter, data: &MknodData, attrs: &SetAttr3) {
    match data {
        MknodData::CharDevice { major, minor } => {
            w.put_u32(NF3CHR);
            encode_sattr3(w, attrs);
            encode_specdata3(w, *major, *minor);
        }
        MknodData::BlockDevice { major, minor } => {
            w.put_u32(NF3BLK);
            encode_sattr3(w, attrs);
            encode_specdata3(w, *major, *minor);
        }
        MknodData::Socket => {
            w.put_u32(NF3SOCK);
            encode_sattr3(w, attrs);
        }
        MknodData::Fifo => {
            w.put_u32(NF3FIFO);
            encode_sattr3(w, attrs);
        }
    }
}

fn encode_specdata3(w: &mut crate::xdr::XdrWriter, major: u32, minor: u32) {
    w.put_u32(major);
    w.put_u32(minor);
}
