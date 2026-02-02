#![cfg(unix)]

use nfs_rs::client41::Nfs41Client;
use nfs_rs::nfs4;
use nfs_rs::pnfs::FlexFilesClient;
use std::time::{SystemTime, UNIX_EPOCH};

fn pnfs_enabled() -> bool {
    std::env::var("PNFS_TESTS").is_ok()
}

fn pnfs_host_port() -> (String, u16) {
    let host = std::env::var("PNFS_TEST_HOST")
        .or_else(|_| std::env::var("NFS41_TEST_HOST"))
        .unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = std::env::var("PNFS_TEST_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2049);
    (host, port)
}

fn pnfs_test_path() -> String {
    std::env::var("PNFS_TEST_PATH").unwrap_or_else(|_| "/hello.txt".to_string())
}

fn pnfs_expected_data() -> Vec<u8> {
    std::env::var("PNFS_EXPECTED")
        .map(|s| s.into_bytes())
        .unwrap_or_else(|_| b"hello world\n".to_vec())
}

fn pnfs_write_data() -> Vec<u8> {
    std::env::var("PNFS_WRITE_DATA")
        .map(|s| s.into_bytes())
        .unwrap_or_else(|_| b"pnfs write test\n".to_vec())
}

fn pnfs_write_path() -> String {
    if let Ok(path) = std::env::var("PNFS_TEST_WRITE_PATH") {
        return path;
    }
    let base = std::env::var("PNFS_TEST_WRITE_DIR").unwrap_or_else(|_| "/".to_string());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let name = format!("pnfs-write-{}-{}.txt", std::process::id(), now);
    if base.ends_with('/') {
        format!("{base}{name}")
    } else {
        format!("{base}/{name}")
    }
}

fn connect_mds_or_skip(host: &str, port: u16) -> Option<Nfs41Client> {
    match Nfs41Client::connect_with_port(host, port) {
        Ok(mut c) => {
            c.set_auth_sys("nfs-rs", 0, 0, &[]);
            Some(c)
        }
        Err(e) => {
            eprintln!("skipping: connect mds failed with {e}");
            None
        }
    }
}

fn has_flexfiles_layout(layout: &nfs4::LayoutGetOk) -> bool {
    layout
        .layout
        .iter()
        .any(|l| matches!(l.content, nfs4::LayoutContent4::FlexFiles(_)))
}

fn has_v41_ds(mds: &mut Nfs41Client, layout: &nfs4::LayoutGetOk) -> bool {
    for l in &layout.layout {
        let flex = match &l.content {
            nfs4::LayoutContent4::FlexFiles(v) => v,
            _ => continue,
        };
        for mirror in &flex.mirrors {
            for ds in &mirror.data_servers {
                let info = match mds.getdeviceinfo(&ds.deviceid, 4096) {
                    Ok(Ok(v)) => v,
                    _ => continue,
                };
                let addr = match info.device_addr {
                    nfs4::DeviceAddr4::FlexFiles(v) => v,
                    _ => continue,
                };
                if addr
                    .versions
                    .iter()
                    .any(|v| v.version == 4 && v.minorversion == 1)
                {
                    return true;
                }
            }
        }
    }
    false
}

#[test]
#[ignore]
fn pnfs_vm_flexfiles_read() {
    if !pnfs_enabled() {
        eprintln!("skipping: set PNFS_TESTS=1 to run pNFS tests");
        return;
    }

    let (host, port) = pnfs_host_port();
    let path = pnfs_test_path();

    let Some(mut mds) = connect_mds_or_skip(&host, port) else {
        return;
    };

    let (_, open_ok, fh) = match mds.open_getfh_access(
        &path,
        nfs4::OPEN4_SHARE_ACCESS_READ | nfs4::OPEN4_SHARE_ACCESS_WANT_NO_DELEG,
    ) {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            eprintln!("skipping: open failed with {e}");
            return;
        }
        Err(e) => {
            eprintln!("skipping: open rpc error {e}");
            return;
        }
    };

    let layout = match mds.layoutget(
        &fh,
        &open_ok.stateid,
        nfs4::LAYOUTIOMODE4_READ,
        0,
        u64::MAX,
        0,
        1,
    ) {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            eprintln!("skipping: layoutget failed with {e}");
            let _ = mds.close_fh(&fh, &open_ok.stateid);
            return;
        }
        Err(e) => {
            eprintln!("skipping: layoutget rpc error {e}");
            let _ = mds.close_fh(&fh, &open_ok.stateid);
            return;
        }
    };

    if !has_flexfiles_layout(&layout) {
        eprintln!("skipping: server did not return flexfiles layout");
        let _ = mds.layoutreturn(&fh, nfs4::LAYOUTIOMODE4_READ, 0, u64::MAX, &layout.stateid);
        let _ = mds.close_fh(&fh, &open_ok.stateid);
        return;
    }

    let _ = mds.layoutreturn(&fh, nfs4::LAYOUTIOMODE4_READ, 0, u64::MAX, &layout.stateid);
    let _ = mds.close_fh(&fh, &open_ok.stateid);

    let mut pnfs = FlexFilesClient::connect_with_port(&host, port).expect("connect pnfs");
    pnfs.set_auth_sys("nfs-rs", 0, 0, &[]);
    let data = pnfs
        .read_to_end(&path, 128 * 1024)
        .expect("pnfs read_to_end");
    assert_eq!(data, pnfs_expected_data());
}

#[test]
#[ignore]
fn pnfs_vm_flexfiles_write_v41_ds() {
    if !pnfs_enabled() {
        eprintln!("skipping: set PNFS_TESTS=1 to run pNFS tests");
        return;
    }

    let (host, port) = pnfs_host_port();
    let path = pnfs_write_path();
    let write_data = pnfs_write_data();

    let Some(mut mds) = connect_mds_or_skip(&host, port) else {
        return;
    };

    let attrs = nfs4::SetAttr4 {
        mode: Some(0o666),
        size: Some(0),
    };
    let (open_ok, fh) = match mds.open_create_getfh_access(
        &path,
        nfs4::OPEN4_SHARE_ACCESS_READ | nfs4::OPEN4_SHARE_ACCESS_WRITE,
        false,
        &attrs,
    ) {
        Ok(Ok((_, open_ok, fh))) => (open_ok, fh),
        Ok(Err(e)) => {
            eprintln!("skipping: open_create failed with {e}");
            return;
        }
        Err(e) => {
            eprintln!("skipping: open_create rpc error {e}");
            return;
        }
    };

    let layout = match mds.layoutget(
        &fh,
        &open_ok.stateid,
        nfs4::LAYOUTIOMODE4_RW,
        0,
        u64::MAX,
        0,
        1,
    ) {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            eprintln!("skipping: layoutget failed with {e}");
            let _ = mds.close_fh(&fh, &open_ok.stateid);
            return;
        }
        Err(e) => {
            eprintln!("skipping: layoutget rpc error {e}");
            let _ = mds.close_fh(&fh, &open_ok.stateid);
            return;
        }
    };

    if !has_flexfiles_layout(&layout) {
        eprintln!("skipping: server did not return flexfiles layout");
        let _ = mds.layoutreturn(&fh, nfs4::LAYOUTIOMODE4_RW, 0, u64::MAX, &layout.stateid);
        let _ = mds.close_fh(&fh, &open_ok.stateid);
        return;
    }
    if !has_v41_ds(&mut mds, &layout) {
        eprintln!("skipping: flexfiles layout without NFSv4.1 DS");
        let _ = mds.layoutreturn(&fh, nfs4::LAYOUTIOMODE4_RW, 0, u64::MAX, &layout.stateid);
        let _ = mds.close_fh(&fh, &open_ok.stateid);
        return;
    }

    let _ = mds.layoutreturn(&fh, nfs4::LAYOUTIOMODE4_RW, 0, u64::MAX, &layout.stateid);
    let _ = mds.close_fh(&fh, &open_ok.stateid);

    let mut pnfs = FlexFilesClient::connect_with_port(&host, port).expect("connect pnfs");
    pnfs.set_auth_sys("nfs-rs", 0, 0, &[]);
    pnfs.write_all(&path, &write_data, 128 * 1024)
        .expect("pnfs write_all");

    let data = mds
        .read_to_end(&path, 128 * 1024)
        .expect("read_to_end")
        .expect("nfs ok");
    assert_eq!(data, write_data);

    let _ = mds.remove(&path);
}
