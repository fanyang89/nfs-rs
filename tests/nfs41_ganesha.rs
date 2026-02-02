#![cfg(unix)]

use nfs_rs::client41::Nfs41Client;
use nfs_rs::nfs4;
use std::fs;
use std::io;
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct Ganesha {
    child: Child,
    port: u16,
}

impl Drop for Ganesha {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn nfs41_ganesha_basic() {
    if std::env::var("NFS_GANESHA_TESTS").is_err() {
        eprintln!("skipping: set NFS_GANESHA_TESTS=1 to run nfs-ganesha tests");
        return;
    }

    let ganesha = start_ganesha().expect("start ganesha");
    let mut c = Nfs41Client::connect_with_port("127.0.0.1", ganesha.port).expect("connect");
    c.set_auth_sys("nfs-rs", 0, 0, &[]);

    let data = c
        .read_to_end("/export/hello.txt", 128 * 1024)
        .expect("read_to_end")
        .expect("nfs ok");
    assert_eq!(data, b"hello world\n".to_vec());

    let fh = c
        .lookup_fh("/export/hello.txt")
        .expect("lookup")
        .expect("nfs ok");
    let attrs = c.getattr_basic(&fh).expect("getattr").expect("nfs ok");
    assert_eq!(attrs.attrs.size, Some(b"hello world\n".len() as u64));

    let acc = c
        .access(&fh, nfs4::ACCESS4_READ | nfs4::ACCESS4_LOOKUP)
        .expect("access")
        .expect("nfs ok");
    assert_eq!(
        acc.access & (nfs4::ACCESS4_READ | nfs4::ACCESS4_LOOKUP),
        nfs4::ACCESS4_READ | nfs4::ACCESS4_LOOKUP
    );

    let dirfh = c
        .lookup_fh("/export")
        .expect("lookup export")
        .expect("nfs ok");
    let mut names = Vec::new();
    let mut cookie = 0u64;
    let mut cookieverf = [0u8; 8];
    loop {
        let rd = c
            .readdir_basic(&dirfh, cookie, cookieverf, 64 * 1024, 128 * 1024)
            .expect("readdir")
            .expect("nfs ok");
        for entry in &rd.entries {
            names.push(entry.name.clone());
            cookie = entry.cookie;
        }
        cookieverf = rd.cookieverf;
        if rd.eof || rd.entries.is_empty() {
            break;
        }
    }
    assert!(names.contains(&"hello.txt".to_string()));
    assert!(names.contains(&"subdir".to_string()));
    assert!(names.contains(&"link.txt".to_string()));

    let linkfh = c
        .lookup_fh("/export/link.txt")
        .expect("lookup link")
        .expect("nfs ok");
    let link = c.readlink(&linkfh).expect("readlink").expect("nfs ok");
    assert_eq!(link.path, "hello.txt");

    let (_, open_ok, fh) = c
        .open_getfh_access(
            "/export/hello.txt",
            nfs4::OPEN4_SHARE_ACCESS_READ | nfs4::OPEN4_SHARE_ACCESS_WRITE,
        )
        .expect("open")
        .expect("nfs ok");
    let set = nfs4::SetAttr4 {
        mode: Some(0o644),
        size: None,
    };
    let _ = c
        .setattr_stateid(&fh, &open_ok.stateid, &set)
        .expect("setattr")
        .expect("nfs ok");
    let attrs = c.getattr_basic(&fh).expect("getattr").expect("nfs ok");
    if let Some(mode) = attrs.attrs.mode {
        assert_eq!(mode & 0o777, 0o644);
    }
    let _ = c.close_fh(&fh, &open_ok.stateid);

    drop(ganesha);
}

fn start_ganesha() -> io::Result<Ganesha> {
    let ganesha_bin = find_ganesha_bin().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "ganesha.nfsd not found; set NFS_GANESHA_BIN or build nfs-ganesha",
        )
    })?;

    let port = pick_port()?;
    let temp_dir = make_temp_dir()?;
    let export_dir = temp_dir.join("export");
    fs::create_dir_all(&export_dir)?;
    populate_export(&export_dir)?;

    let config_path = temp_dir.join("ganesha.conf");
    let log_path = temp_dir.join("ganesha.log");
    let pid_path = temp_dir.join("ganesha.pid");
    let plugin_dir = find_plugin_dir(&ganesha_bin);
    write_config(&config_path, &export_dir, port, plugin_dir.as_deref())?;

    let mut cmd = Command::new(&ganesha_bin);
    cmd.arg("-F")
        .arg("-f")
        .arg(&config_path)
        .arg("-L")
        .arg(&log_path)
        .arg("-p")
        .arg(&pid_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let child = cmd.spawn()?;
    wait_for_port(port, Duration::from_secs(10))?;

    Ok(Ganesha {
        child,
        port,
    })
}

fn find_ganesha_bin() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("NFS_GANESHA_BIN") {
        let p = PathBuf::from(path);
        if p.exists() {
            return Some(p);
        }
    }
    if let Ok(build_dir) = std::env::var("NFS_GANESHA_BUILD_DIR") {
        let p = PathBuf::from(build_dir).join("ganesha.nfsd");
        if p.exists() {
            return Some(p);
        }
    }
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("nfs-ganesha")
        .join("build")
        .join("ganesha.nfsd");
    if p.exists() {
        return Some(p);
    }
    None
}

fn find_plugin_dir(ganesha_bin: &Path) -> Option<PathBuf> {
    let build_dir = ganesha_bin.parent()?;
    let candidate = build_dir.join("FSAL/FSAL_VFS/vfs");
    if candidate.exists() {
        return Some(candidate);
    }
    None
}

fn pick_port() -> io::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

fn wait_for_port(port: u16, timeout: Duration) -> io::Result<()> {
    let start = SystemTime::now();
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Ok(());
        }
        if start.elapsed().unwrap_or_default() > timeout {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "ganesha did not start listening in time",
            ));
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn make_temp_dir() -> io::Result<PathBuf> {
    let base = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let dir = PathBuf::from(base)
        .join("ganesha-test")
        .join(format!("run-{}-{}", std::process::id(), nanos));
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn populate_export(export_dir: &Path) -> io::Result<()> {
    let subdir = export_dir.join("subdir");
    fs::create_dir_all(&subdir)?;
    fs::write(export_dir.join("hello.txt"), b"hello world\n")?;
    fs::write(subdir.join("nested.txt"), b"nested\n")?;
    let link = export_dir.join("link.txt");
    let _ = fs::remove_file(&link);
    symlink("hello.txt", link)?;

    fs::set_permissions(export_dir, fs::Permissions::from_mode(0o777))?;
    fs::set_permissions(&subdir, fs::Permissions::from_mode(0o777))?;
    fs::set_permissions(
        export_dir.join("hello.txt"),
        fs::Permissions::from_mode(0o666),
    )?;
    fs::set_permissions(
        subdir.join("nested.txt"),
        fs::Permissions::from_mode(0o666),
    )?;
    Ok(())
}

fn write_config(
    path: &Path,
    export_dir: &Path,
    port: u16,
    plugin_dir: Option<&Path>,
) -> io::Result<()> {
    let mut config = String::new();
    config.push_str("NFS_CORE_PARAM {\n");
    config.push_str(&format!("    NFS_Port = {port};\n"));
    config.push_str("    Protocols = 4;\n");
    if let Some(dir) = plugin_dir {
        config.push_str(&format!(
            "    Plugins_Dir = \"{}\";\n",
            dir.display()
        ));
    }
    config.push_str("}\n");

    config.push_str("EXPORT_DEFAULTS {\n");
    config.push_str("    Access_Type = RW;\n");
    config.push_str("}\n");

    config.push_str("EXPORT {\n");
    config.push_str("    Export_Id = 1;\n");
    config.push_str(&format!("    Path = \"{}\";\n", export_dir.display()));
    config.push_str("    Pseudo = /export;\n");
    config.push_str("    Protocols = 4;\n");
    config.push_str("    Access_Type = RW;\n");
    config.push_str("    Squash = No_Root_Squash;\n");
    config.push_str("    Sectype = sys;\n");
    config.push_str("    Transports = TCP;\n");
    config.push_str("    FSAL { Name = VFS; }\n");
    config.push_str("}\n");

    config.push_str("LOG {\n");
    config.push_str("    Default_Log_Level = WARN;\n");
    config.push_str("}\n");

    fs::write(path, config)
}
