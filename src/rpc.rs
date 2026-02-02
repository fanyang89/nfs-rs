//! ONC RPC (RFC 5531) over TCP (record marking).

use crate::xdr::{Result as XdrResult, XdrError, XdrReader, XdrWriter};
use core::fmt;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub enum RpcError {
    Io(std::io::Error),
    Xdr(XdrError),
    ReplyXidMismatch { expected: u32, got: u32 },
    RpcDenied(String),
    RpcAcceptedError(String),
}

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RpcError::Io(e) => write!(f, "I/O error: {e}"),
            RpcError::Xdr(e) => write!(f, "XDR error: {e}"),
            RpcError::ReplyXidMismatch { expected, got } => {
                write!(f, "RPC xid mismatch: expected {expected}, got {got}")
            }
            RpcError::RpcDenied(s) => write!(f, "RPC denied: {s}"),
            RpcError::RpcAcceptedError(s) => write!(f, "RPC accepted but failed: {s}"),
        }
    }
}

impl std::error::Error for RpcError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RpcError::Io(e) => Some(e),
            RpcError::Xdr(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for RpcError {
    fn from(e: std::io::Error) -> Self {
        RpcError::Io(e)
    }
}

impl From<XdrError> for RpcError {
    fn from(e: XdrError) -> Self {
        RpcError::Xdr(e)
    }
}

pub type Result<T> = core::result::Result<T, RpcError>;

#[derive(Debug, Clone)]
pub struct OpaqueAuth {
    pub flavor: u32,
    pub body: Vec<u8>,
}

impl OpaqueAuth {
    pub fn auth_null() -> Self {
        Self {
            flavor: 0,
            body: Vec::new(),
        }
    }

    pub fn auth_sys(machine_name: &str, uid: u32, gid: u32, groups: &[u32]) -> Self {
        // RFC 5531 AUTH_SYS body is itself XDR.
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;

        let mut w = XdrWriter::new();
        w.put_u32(stamp);
        w.put_string(machine_name);
        w.put_u32(uid);
        w.put_u32(gid);
        w.put_vec(groups, |w, g| w.put_u32(*g));

        Self {
            flavor: 1,
            body: w.into_bytes(),
        }
    }

    fn encode_into(&self, w: &mut XdrWriter) {
        w.put_u32(self.flavor);
        w.put_opaque(&self.body);
    }

    fn decode_from(r: &mut XdrReader<'_>) -> XdrResult<Self> {
        let flavor = r.get_u32()?;
        let body = r.get_opaque()?;
        Ok(Self { flavor, body })
    }
}

#[derive(Debug)]
pub struct RpcCall {
    pub xid: u32,
    pub prog: u32,
    pub vers: u32,
    pub proc_: u32,
    pub cred: OpaqueAuth,
    pub verf: OpaqueAuth,
    pub args: Vec<u8>,
}

#[derive(Debug)]
pub struct RpcReply {
    pub accept_stat: u32,
    pub body: Vec<u8>,
}

pub trait RpcCallbackHandler {
    fn handle_call(&mut self, call: RpcCall) -> Result<RpcReply>;
}

pub struct TcpRpcClient {
    stream: TcpStream,
    xid: u32,
    cred: OpaqueAuth,
    verf: OpaqueAuth,
    callback: Option<Box<dyn RpcCallbackHandler + Send>>,
}

impl fmt::Debug for TcpRpcClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpRpcClient")
            .field("xid", &self.xid)
            .field("cred", &self.cred)
            .field("verf", &self.verf)
            .finish()
    }
}

impl TcpRpcClient {
    pub fn connect(addr: &str) -> Result<Self> {
        let stream = TcpStream::connect(addr)?;
        stream.set_nodelay(true).ok();
        Ok(Self {
            stream,
            xid: initial_xid(),
            cred: OpaqueAuth::auth_null(),
            verf: OpaqueAuth::auth_null(),
            callback: None,
        })
    }

    pub fn set_auth(&mut self, cred: OpaqueAuth) {
        self.cred = cred;
    }

    pub fn set_callback_handler(&mut self, handler: Box<dyn RpcCallbackHandler + Send>) {
        self.callback = Some(handler);
    }

    pub fn call_raw(&mut self, prog: u32, vers: u32, proc_: u32, args: &[u8]) -> Result<Vec<u8>> {
        let xid = self.next_xid();
        let mut w = XdrWriter::with_capacity(128 + args.len());
        w.put_u32(xid);
        w.put_u32(0); // CALL
        w.put_u32(2); // rpcvers
        w.put_u32(prog);
        w.put_u32(vers);
        w.put_u32(proc_);
        self.cred.encode_into(&mut w);
        self.verf.encode_into(&mut w);
        w.put_opaque_fixed(args);

        let call_bytes = w.into_bytes();
        write_record(&mut self.stream, &call_bytes)?;

        loop {
            let reply_bytes = read_record(&mut self.stream)?;
            let mut r = XdrReader::new(&reply_bytes);
            let rxid = r.get_u32()?;
            let msg_type = r.get_u32()?;
            match msg_type {
                0 => {
                    // CALL (backchannel)
                    let call = decode_rpc_call(rxid, r, &reply_bytes)?;
                    let reply = if let Some(cb) = self.callback.as_mut() {
                        match cb.handle_call(call) {
                            Ok(reply) => reply,
                            Err(_) => RpcReply {
                                accept_stat: RPC_ACCEPT_PROC_UNAVAIL,
                                body: Vec::new(),
                            },
                        }
                    } else {
                        RpcReply {
                            accept_stat: RPC_ACCEPT_PROC_UNAVAIL,
                            body: Vec::new(),
                        }
                    };
                    send_reply(&mut self.stream, rxid, &reply)?;
                }
                1 => {
                    // REPLY
                    if rxid != xid {
                        continue;
                    }
                    let reply_stat = r.get_u32()?;
                    match reply_stat {
                        0 => {
                            // MSG_ACCEPTED
                            let _verf = OpaqueAuth::decode_from(&mut r)?;
                            let accept_stat = r.get_u32()?;
                            if accept_stat != 0 {
                                return Err(RpcError::RpcAcceptedError(format!(
                                    "accept_stat {accept_stat}"
                                )));
                            }
                            let consumed = reply_bytes.len().saturating_sub(r.remaining());
                            return Ok(reply_bytes[consumed..].to_vec());
                        }
                        1 => {
                            // MSG_DENIED
                            let reject_stat = r.get_u32()?;
                            return match reject_stat {
                                0 => {
                                    let low = r.get_u32()?;
                                    let high = r.get_u32()?;
                                    Err(RpcError::RpcDenied(format!(
                                        "RPC_MISMATCH low={low} high={high}"
                                    )))
                                }
                                1 => {
                                    let auth_stat = r.get_u32()?;
                                    Err(RpcError::RpcDenied(format!("AUTH_ERROR {auth_stat}")))
                                }
                                other => Err(RpcError::RpcDenied(format!("reject_stat {other}"))),
                            };
                        }
                        other => {
                            return Err(RpcError::RpcDenied(format!("unknown reply_stat {other}")));
                        }
                    }
                }
                other => return Err(RpcError::RpcDenied(format!("unexpected msg_type {other}"))),
            }
        }
    }

    pub fn call<T>(
        &mut self,
        prog: u32,
        vers: u32,
        proc_: u32,
        encode_args: impl FnOnce(&mut XdrWriter),
        decode_res: impl FnOnce(&mut XdrReader<'_>) -> Result<T>,
    ) -> Result<T> {
        let mut w = XdrWriter::new();
        encode_args(&mut w);
        let res_bytes = self.call_raw(prog, vers, proc_, w.as_bytes())?;
        let mut r = XdrReader::new(&res_bytes);
        decode_res(&mut r)
    }

    fn next_xid(&mut self) -> u32 {
        self.xid = self.xid.wrapping_add(1);
        self.xid
    }
}

fn initial_xid() -> u32 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    0x4e46_5300u32 ^ nanos
}

const RPC_ACCEPT_SUCCESS: u32 = 0;
const RPC_ACCEPT_PROC_UNAVAIL: u32 = 3;

fn decode_rpc_call(xid: u32, mut r: XdrReader<'_>, bytes: &[u8]) -> Result<RpcCall> {
    let rpcvers = r.get_u32()?;
    if rpcvers != 2 {
        return Err(RpcError::RpcDenied(format!("unexpected rpcvers {rpcvers}")));
    }
    let prog = r.get_u32()?;
    let vers = r.get_u32()?;
    let proc_ = r.get_u32()?;
    let cred = OpaqueAuth::decode_from(&mut r)?;
    let verf = OpaqueAuth::decode_from(&mut r)?;
    let consumed = bytes.len().saturating_sub(r.remaining());
    let args = bytes[consumed..].to_vec();
    Ok(RpcCall {
        xid,
        prog,
        vers,
        proc_,
        cred,
        verf,
        args,
    })
}

fn send_reply(stream: &mut TcpStream, xid: u32, reply: &RpcReply) -> Result<()> {
    let mut w = XdrWriter::new();
    w.put_u32(xid);
    w.put_u32(1); // REPLY
    w.put_u32(0); // MSG_ACCEPTED
    OpaqueAuth::auth_null().encode_into(&mut w);
    w.put_u32(reply.accept_stat);
    if reply.accept_stat == RPC_ACCEPT_SUCCESS {
        w.put_opaque_fixed(&reply.body);
    }
    write_record(stream, w.as_bytes())
}

fn write_record(stream: &mut TcpStream, payload: &[u8]) -> Result<()> {
    let len: u32 = payload
        .len()
        .try_into()
        .map_err(|_| RpcError::RpcDenied("request too large".into()))?;
    let header = (1u32 << 31) | len;
    stream.write_all(&header.to_be_bytes())?;
    stream.write_all(payload)?;
    stream.flush()?;
    Ok(())
}

fn read_record(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let mut hdr = [0u8; 4];
        stream.read_exact(&mut hdr)?;
        let v = u32::from_be_bytes(hdr);
        let last = (v & (1u32 << 31)) != 0;
        let len = (v & 0x7fff_ffff) as usize;
        let mut frag = vec![0u8; len];
        stream.read_exact(&mut frag)?;
        out.extend_from_slice(&frag);
        if last {
            break;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_sys_body_is_xdr() {
        let a = OpaqueAuth::auth_sys("host", 1000, 1000, &[1, 2, 3]);
        assert_eq!(a.flavor, 1);
        let mut r = XdrReader::new(&a.body);
        let _stamp = r.get_u32().unwrap();
        let host = r.get_string().unwrap();
        assert_eq!(host, "host");
        assert_eq!(r.get_u32().unwrap(), 1000);
        assert_eq!(r.get_u32().unwrap(), 1000);
        let gs = r.get_vec(|r| r.get_u32()).unwrap();
        assert_eq!(gs, vec![1, 2, 3]);
    }
}
