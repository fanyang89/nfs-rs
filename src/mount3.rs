//! MOUNT v3 (RFC 1813) helpers.

use crate::rpc::{Result, TcpRpcClient};
use crate::xdr::{XdrReader, XdrWriter};

pub const MOUNT_PROG: u32 = 100_005;
pub const MOUNT_VERS: u32 = 3;
pub const MOUNTPROC_MNT: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountOk {
    pub fh: Vec<u8>,
    pub auth_flavors: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountError {
    pub status: u32,
}

pub fn mnt(
    rpc: &mut TcpRpcClient,
    export: &str,
) -> Result<core::result::Result<MountOk, MountError>> {
    rpc.call(
        MOUNT_PROG,
        MOUNT_VERS,
        MOUNTPROC_MNT,
        |w| w.put_string(export),
        decode_mnt_res,
    )
}

fn decode_mnt_res(r: &mut XdrReader<'_>) -> Result<core::result::Result<MountOk, MountError>> {
    let status = r.get_u32()?;
    if status != 0 {
        return Ok(Err(MountError { status }));
    }
    // fhandle3 is opaque<64>
    let fh = r.get_opaque()?;
    let auth_flavors = r.get_vec(|r| r.get_u32())?;
    Ok(Ok(MountOk { fh, auth_flavors }))
}

pub fn encode_mnt_args(export: &str) -> Vec<u8> {
    let mut w = XdrWriter::new();
    w.put_string(export);
    w.into_bytes()
}
