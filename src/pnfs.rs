//! pNFS flexfiles client (MDS over NFSv4.1, DS over NFSv3).

use crate::client41::Nfs41Client;
use crate::nfs3::{self, FileHandle};
use crate::nfs4::{
    DeviceAddr4, DeviceId4, FF_FLAGS_NO_LAYOUTCOMMIT, FF_FLAGS_NO_READ_IO,
    FF_FLAGS_WRITE_ONE_MIRROR, FfDataServer4, FfDeviceAddr4, FfLayout4, FfMirror4,
    LAYOUT4_FLEX_FILES, LAYOUTIOMODE4_ANY, LAYOUTIOMODE4_READ, LAYOUTIOMODE4_RW, Layout4,
    LayoutContent4, LayoutGetOk, LayoutRecall4, LayoutRecallTarget, Nfs4Error,
    OPEN4_SHARE_ACCESS_READ, OPEN4_SHARE_ACCESS_WANT_NO_DELEG, OPEN4_SHARE_ACCESS_WRITE,
    STABLE_HOW_FILE_SYNC4, StateId4,
};
use crate::rpc::{OpaqueAuth, Result, RpcError, TcpRpcClient};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};

#[derive(Debug)]
pub struct FlexFilesClient {
    mds: Nfs41Client,
    device_cache: HashMap<DeviceId4, FfDeviceAddr4>,
    ds_pool: HashMap<SocketAddr, TcpRpcClient>,
    auth_machine: String,
    default_uid: u32,
    default_gid: u32,
    default_groups: Vec<u32>,
    active_layouts: Vec<ActiveLayout>,
}

impl FlexFilesClient {
    pub fn connect(server: &str) -> Result<Self> {
        Ok(Self {
            mds: Nfs41Client::connect(server)?,
            device_cache: HashMap::new(),
            ds_pool: HashMap::new(),
            auth_machine: "nfs-rs".to_string(),
            default_uid: 1000,
            default_gid: 1000,
            default_groups: vec![1000],
            active_layouts: Vec::new(),
        })
    }

    pub fn set_auth_sys(&mut self, machine: &str, uid: u32, gid: u32, groups: &[u32]) {
        self.auth_machine = machine.to_string();
        self.default_uid = uid;
        self.default_gid = gid;
        self.default_groups = groups.to_vec();
        self.mds.set_auth_sys(machine, uid, gid, groups);
    }

    pub fn read_to_end(&mut self, path: &str, chunk_size: u32) -> Result<Vec<u8>> {
        let (_, open_ok, fh) = match self.mds.open_getfh_access(
            path,
            OPEN4_SHARE_ACCESS_READ | OPEN4_SHARE_ACCESS_WANT_NO_DELEG,
        )? {
            Ok(v) => v,
            Err(e) => return Err(map_nfs4_err(e)),
        };

        let mut layout = match self.mds.layoutget(
            &fh,
            &open_ok.stateid,
            LAYOUTIOMODE4_READ,
            0,
            u64::MAX,
            0,
            1,
        )? {
            Ok(v) => Some(v),
            Err(_) => None,
        };
        if let Some(l) = layout.as_ref() {
            self.register_layout(&fh, LAYOUTIOMODE4_READ, &l.stateid);
        }
        self.apply_layout_recalls(&mut layout)?;

        let mut out = Vec::new();
        let mut offset = 0u64;
        loop {
            self.apply_layout_recalls(&mut layout)?;
            let ds_read = match layout.as_ref() {
                Some(l) => self.read_ds_chunk(l, offset, chunk_size),
                None => Err(RpcError::RpcAcceptedError("no layout".into())),
            };

            let (data, eof) = match ds_read {
                Ok(v) => (v.data, v.eof),
                Err(_) => {
                    let r = self
                        .mds
                        .read_at(&fh, &open_ok.stateid, offset, chunk_size)?;
                    match r {
                        Ok(v) => (v.data, v.eof),
                        Err(e) => return Err(map_nfs4_err(e)),
                    }
                }
            };

            if data.is_empty() {
                break;
            }
            offset = offset.saturating_add(data.len() as u64);
            out.extend_from_slice(&data);
            if eof {
                break;
            }
        }

        if let Some(l) = layout.take() {
            let _ = self
                .mds
                .layoutreturn(&fh, LAYOUTIOMODE4_READ, 0, u64::MAX, &l.stateid);
            self.unregister_layout(&l.stateid);
        }
        let _ = self.mds.close_fh(&fh, &open_ok.stateid);
        Ok(out)
    }

    pub fn write_all(&mut self, path: &str, data: &[u8], chunk_size: u32) -> Result<()> {
        let (_, open_ok, fh) = match self
            .mds
            .open_getfh_access(path, OPEN4_SHARE_ACCESS_READ | OPEN4_SHARE_ACCESS_WRITE)?
        {
            Ok(v) => v,
            Err(e) => return Err(map_nfs4_err(e)),
        };

        let mut layout =
            match self
                .mds
                .layoutget(&fh, &open_ok.stateid, LAYOUTIOMODE4_RW, 0, u64::MAX, 0, 1)?
            {
                Ok(v) => Some(v),
                Err(_) => None,
            };
        if let Some(l) = layout.as_ref() {
            self.register_layout(&fh, LAYOUTIOMODE4_RW, &l.stateid);
        }
        self.apply_layout_recalls(&mut layout)?;

        let mut offset = 0u64;
        let mut last_write_offset = None;
        let mut used_layout = false;
        let mut layout_stateid = None;
        let mut layout_flags = 0u32;

        if let Some(l) = layout.as_ref() {
            used_layout = true;
            layout_stateid = Some(l.stateid.clone());
            layout_flags = flexfiles_flags(l).unwrap_or(0);
        }

        if let Some(l) = layout.as_ref() {
            while (offset as usize) < data.len() {
                self.apply_layout_recalls(&mut layout)?;
                let l = match layout.as_ref() {
                    Some(l) => l,
                    None => {
                        self.write_via_mds(&fh, &open_ok.stateid, 0, data, chunk_size)?;
                        let _ = self.mds.close_fh(&fh, &open_ok.stateid);
                        return Ok(());
                    }
                };
                let end = (offset as usize + chunk_size as usize).min(data.len());
                let chunk = &data[offset as usize..end];
                if let Err(_) = self.write_ds_chunk(l, offset, chunk) {
                    let _ = self
                        .mds
                        .layoutreturn(&fh, LAYOUTIOMODE4_RW, 0, u64::MAX, &l.stateid);
                    self.write_via_mds(&fh, &open_ok.stateid, 0, data, chunk_size)?;
                    let _ = self.mds.close_fh(&fh, &open_ok.stateid);
                    return Ok(());
                }
                offset = offset.saturating_add(chunk.len() as u64);
                last_write_offset = Some(offset.saturating_sub(1));
            }
        } else {
            self.write_via_mds(&fh, &open_ok.stateid, 0, data, chunk_size)?;
            let _ = self.mds.close_fh(&fh, &open_ok.stateid);
            return Ok(());
        }

        if used_layout {
            if layout_flags & FF_FLAGS_NO_LAYOUTCOMMIT == 0 {
                let _ = self.mds.layoutcommit(
                    &fh,
                    0,
                    0,
                    layout_stateid.as_ref().unwrap(),
                    last_write_offset,
                );
            }
            let _ = self.mds.layoutreturn(
                &fh,
                LAYOUTIOMODE4_RW,
                0,
                u64::MAX,
                layout_stateid.as_ref().unwrap(),
            );
            self.unregister_layout(layout_stateid.as_ref().unwrap());
        }

        let _ = self.mds.close_fh(&fh, &open_ok.stateid);
        Ok(())
    }

    fn write_via_mds(
        &mut self,
        fh: &[u8],
        stateid: &crate::nfs4::StateId4,
        mut offset: u64,
        data: &[u8],
        chunk_size: u32,
    ) -> Result<()> {
        let mut pos = 0usize;
        while pos < data.len() {
            let end = (pos + chunk_size as usize).min(data.len());
            let chunk = &data[pos..end];
            let r = self
                .mds
                .write_at(fh, stateid, offset, chunk, STABLE_HOW_FILE_SYNC4)?;
            match r {
                Ok(_) => {}
                Err(e) => return Err(map_nfs4_err(e)),
            }
            offset = offset.saturating_add(chunk.len() as u64);
            pos = end;
        }
        Ok(())
    }

    fn read_ds_chunk(
        &mut self,
        layoutget: &LayoutGetOk,
        offset: u64,
        count: u32,
    ) -> Result<nfs3::ReadOk> {
        let (_mirror, dss) = select_mirror_and_ds(layoutget, offset)?;
        let (addr, version) = self.device_addr_for(&dss.deviceid)?;
        if version.version != 3 {
            return Err(RpcError::RpcAcceptedError(
                "flexfiles DS is not NFSv3".into(),
            ));
        }
        let ds = self.ds_rpc(addr, &dss)?;
        let fh = ds_filehandle(dss)?;
        let res = nfs3::read(ds, &fh, offset, count)?;
        res.map_err(map_nfs3_err)
    }

    fn write_ds_chunk(&mut self, layoutget: &LayoutGetOk, offset: u64, data: &[u8]) -> Result<()> {
        let layout = select_layout(layoutget, offset)?;
        let flex = match &layout.content {
            LayoutContent4::FlexFiles(v) => v,
            _ => return Err(RpcError::RpcAcceptedError("layout is not flexfiles".into())),
        };

        let mirrors = select_write_mirrors(flex, flex.flags);
        for mirror in mirrors {
            let dss_id = calc_dss_id(flex.stripe_unit, mirror.data_servers.len(), offset);
            let dss = mirror
                .data_servers
                .get(dss_id as usize)
                .ok_or_else(|| RpcError::RpcAcceptedError("invalid dss index".into()))?;
            let (addr, version) = self.device_addr_for(&dss.deviceid)?;
            if version.version != 3 {
                return Err(RpcError::RpcAcceptedError(
                    "flexfiles DS is not NFSv3".into(),
                ));
            }
            let ds = self.ds_rpc(addr, dss)?;
            let fh = ds_filehandle(dss)?;
            let res = nfs3::write(ds, &fh, offset, data, nfs3::STABLE_HOW_UNSTABLE)?;
            res.map_err(map_nfs3_err)?;
            let res = nfs3::commit(ds, &fh, 0, 0)?;
            res.map_err(map_nfs3_err)?;
        }
        Ok(())
    }

    fn device_addr_for(
        &mut self,
        deviceid: &DeviceId4,
    ) -> Result<(SocketAddr, crate::nfs4::FfDeviceVersion4)> {
        let dev = if let Some(v) = self.device_cache.get(deviceid) {
            v.clone()
        } else {
            let gd = self.mds.getdeviceinfo(deviceid, 4096)?;
            let ok = match gd {
                Ok(v) => v,
                Err(e) => return Err(map_nfs4_err(e)),
            };
            let addr = match ok.device_addr {
                DeviceAddr4::FlexFiles(v) => v,
                _ => {
                    return Err(RpcError::RpcAcceptedError(
                        "device addr is not flexfiles".into(),
                    ));
                }
            };
            self.device_cache.insert(deviceid.clone(), addr.clone());
            addr
        };

        let addr = dev
            .netaddrs
            .iter()
            .find_map(|a| parse_netaddr(a))
            .ok_or_else(|| RpcError::RpcAcceptedError("no usable netaddr".into()))?;
        let version = dev
            .versions
            .iter()
            .find(|v| v.version == 3)
            .cloned()
            .ok_or_else(|| RpcError::RpcAcceptedError("no NFSv3 version".into()))?;
        Ok((addr, version))
    }

    fn ds_rpc(&mut self, addr: SocketAddr, dss: &FfDataServer4) -> Result<&mut TcpRpcClient> {
        if !self.ds_pool.contains_key(&addr) {
            let rpc = TcpRpcClient::connect(&addr.to_string())?;
            self.ds_pool.insert(addr, rpc);
        }
        let rpc = self.ds_pool.get_mut(&addr).unwrap();
        let cred = auth_from_ffds(
            &self.auth_machine,
            self.default_uid,
            self.default_gid,
            &self.default_groups,
            dss,
        );
        rpc.set_auth(cred);
        Ok(rpc)
    }

    fn register_layout(&mut self, fh: &[u8], iomode: u32, stateid: &StateId4) {
        self.active_layouts.push(ActiveLayout {
            fh: fh.to_vec(),
            iomode,
            stateid: stateid.clone(),
        });
    }

    fn unregister_layout(&mut self, stateid: &StateId4) {
        self.active_layouts.retain(|l| &l.stateid != stateid);
    }

    fn apply_layout_recalls(&mut self, layout: &mut Option<LayoutGetOk>) -> Result<()> {
        let returned = self.handle_layout_recalls()?;
        if let Some(l) = layout.as_ref() {
            if returned.contains(&l.stateid) {
                *layout = None;
            }
        }
        Ok(())
    }

    fn handle_layout_recalls(&mut self) -> Result<HashSet<StateId4>> {
        let recalls = self.mds.take_layout_recalls();
        if recalls.is_empty() {
            return Ok(HashSet::new());
        }

        let mut returned = HashSet::new();
        for recall in recalls {
            if recall.layout_type != LAYOUT4_FLEX_FILES {
                continue;
            }
            let matches: Vec<ActiveLayout> = self
                .active_layouts
                .iter()
                .filter(|l| recall_matches_layout(l, &recall))
                .cloned()
                .collect();
            for layout in matches {
                let _ =
                    self.mds
                        .layoutreturn(&layout.fh, layout.iomode, 0, u64::MAX, &layout.stateid);
                returned.insert(layout.stateid.clone());
            }
        }

        self.active_layouts
            .retain(|l| !returned.contains(&l.stateid));
        Ok(returned)
    }
}

#[derive(Debug, Clone)]
struct ActiveLayout {
    fh: Vec<u8>,
    iomode: u32,
    stateid: StateId4,
}

fn recall_matches_layout(layout: &ActiveLayout, recall: &LayoutRecall4) -> bool {
    if !iomode_matches(recall.iomode, layout.iomode) {
        return false;
    }
    match &recall.target {
        LayoutRecallTarget::All => true,
        LayoutRecallTarget::Fsid(_) => true,
        LayoutRecallTarget::File(file) => {
            if file.fh != layout.fh {
                return false;
            }
            stateid_matches(&file.stateid, &layout.stateid)
        }
    }
}

fn iomode_matches(recall_iomode: u32, layout_iomode: u32) -> bool {
    if recall_iomode == LAYOUTIOMODE4_ANY {
        return true;
    }
    if recall_iomode == layout_iomode {
        return true;
    }
    recall_iomode == LAYOUTIOMODE4_READ && layout_iomode == LAYOUTIOMODE4_RW
}

fn stateid_matches(recall_stateid: &StateId4, layout_stateid: &StateId4) -> bool {
    if is_special_stateid(recall_stateid) {
        return true;
    }
    recall_stateid == layout_stateid
}

fn is_special_stateid(stateid: &StateId4) -> bool {
    stateid.seqid == 0 && stateid.other == [0u8; 12]
}

fn map_nfs4_err(e: Nfs4Error) -> RpcError {
    RpcError::RpcAcceptedError(e.to_string())
}

fn map_nfs3_err(e: nfs3::NfsError) -> RpcError {
    RpcError::RpcAcceptedError(e.to_string())
}

fn parse_netaddr(addr: &crate::nfs4::NetAddr4) -> Option<SocketAddr> {
    if addr.netid != "tcp" && addr.netid != "tcp6" {
        return None;
    }
    parse_universal_address(&addr.addr)
}

fn parse_universal_address(addr: &str) -> Option<SocketAddr> {
    let parts: Vec<&str> = addr.split('.').collect();
    if parts.len() < 6 {
        return None;
    }
    let port_hi: u16 = parts[parts.len() - 2].parse().ok()?;
    let port_lo: u16 = parts[parts.len() - 1].parse().ok()?;
    let port = (port_hi << 8) | port_lo;
    let host = parts[..parts.len() - 2].join(".");
    let ip: IpAddr = host.parse().ok()?;
    Some(SocketAddr::new(ip, port))
}

fn auth_from_ffds(
    machine: &str,
    default_uid: u32,
    default_gid: u32,
    default_groups: &[u32],
    dss: &FfDataServer4,
) -> OpaqueAuth {
    let uid = dss.user.parse().unwrap_or(default_uid);
    let gid = dss.group.parse().unwrap_or(default_gid);
    let groups: Vec<u32> = if default_groups.is_empty() {
        vec![gid]
    } else {
        default_groups.to_vec()
    };
    OpaqueAuth::auth_sys(machine, uid, gid, &groups)
}

fn select_layout(layoutget: &LayoutGetOk, offset: u64) -> Result<&Layout4> {
    let mut best = None;
    for l in &layoutget.layout {
        let end = if l.length == u64::MAX {
            u64::MAX
        } else {
            l.offset.saturating_add(l.length)
        };
        if offset >= l.offset && offset < end {
            return Ok(l);
        }
        if best.is_none() {
            best = Some(l);
        }
    }
    best.ok_or_else(|| RpcError::RpcAcceptedError("empty layout".into()))
}

fn select_mirror_and_ds(
    layoutget: &LayoutGetOk,
    offset: u64,
) -> Result<(&FfMirror4, &FfDataServer4)> {
    let layout = select_layout(layoutget, offset)?;
    let flex = match &layout.content {
        LayoutContent4::FlexFiles(v) => v,
        _ => return Err(RpcError::RpcAcceptedError("layout is not flexfiles".into())),
    };

    if flex.flags & FF_FLAGS_NO_READ_IO != 0 {
        return Err(RpcError::RpcAcceptedError(
            "flexfiles disallows read IO".into(),
        ));
    }

    let mirror = flex
        .mirrors
        .iter()
        .max_by_key(|m| mirror_efficiency(*m))
        .ok_or_else(|| RpcError::RpcAcceptedError("no mirrors".into()))?;
    let dss_id = calc_dss_id(flex.stripe_unit, mirror.data_servers.len(), offset);
    let dss = mirror
        .data_servers
        .get(dss_id as usize)
        .ok_or_else(|| RpcError::RpcAcceptedError("invalid dss index".into()))?;
    Ok((mirror, dss))
}

fn select_write_mirrors<'a>(layout: &'a FfLayout4, flags: u32) -> Vec<&'a FfMirror4> {
    if layout.mirrors.is_empty() {
        return Vec::new();
    }
    if flags & FF_FLAGS_WRITE_ONE_MIRROR != 0 {
        return vec![&layout.mirrors[0]];
    }
    layout.mirrors.iter().collect()
}

fn flexfiles_flags(layoutget: &LayoutGetOk) -> Result<u32> {
    let layout = select_layout(layoutget, 0)?;
    match &layout.content {
        LayoutContent4::FlexFiles(v) => Ok(v.flags),
        _ => Err(RpcError::RpcAcceptedError("layout is not flexfiles".into())),
    }
}

fn mirror_efficiency(mirror: &FfMirror4) -> u32 {
    mirror.data_servers.iter().map(|d| d.efficiency).sum()
}

fn ds_filehandle(dss: &FfDataServer4) -> Result<FileHandle> {
    let fh = dss
        .fh_list
        .get(0)
        .ok_or_else(|| RpcError::RpcAcceptedError("missing DS filehandle".into()))?;
    Ok(FileHandle(fh.clone()))
}

fn calc_dss_id(stripe_unit: u64, dss_count: usize, offset: u64) -> u32 {
    if dss_count <= 1 || stripe_unit == 0 {
        return 0;
    }
    let stripe = offset / stripe_unit;
    (stripe % dss_count as u64) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dss_id_mapping() {
        assert_eq!(calc_dss_id(4096, 1, 0), 0);
        assert_eq!(calc_dss_id(4096, 2, 0), 0);
        assert_eq!(calc_dss_id(4096, 2, 4096), 1);
        assert_eq!(calc_dss_id(4096, 2, 8192), 0);
        assert_eq!(calc_dss_id(0, 4, 4096), 0);
    }
}
