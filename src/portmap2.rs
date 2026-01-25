//! PORTMAP v2 (RFC 1833) helpers.

use crate::rpc::{Result, TcpRpcClient};
use crate::xdr::XdrReader;

pub const PMAP_PROG: u32 = 100_000;
pub const PMAP_VERS: u32 = 2;

pub const PMAPPROC_GETPORT: u32 = 3;

#[derive(Debug, Clone, Copy)]
pub enum Proto {
    Tcp = 6,
    Udp = 17,
}

pub fn getport(rpc: &mut TcpRpcClient, prog: u32, vers: u32, proto: Proto) -> Result<u32> {
    rpc.call(
        PMAP_PROG,
        PMAP_VERS,
        PMAPPROC_GETPORT,
        |w| {
            w.put_u32(prog);
            w.put_u32(vers);
            w.put_u32(proto as u32);
            w.put_u32(0); // port (ignored for GETPORT)
        },
        |r| Ok(r.get_u32()?),
    )
}

// Small decode helpers for code using raw bytes.
pub fn decode_getport_res(bytes: &[u8]) -> crate::rpc::Result<u32> {
    let mut r = XdrReader::new(bytes);
    Ok(r.get_u32()?)
}
