use async_trait::async_trait;
use nfs_rs::client::Nfs3Client;
use nfs_rs::mount3;
use nfs_rs::nfs3;
use nfs_rs::portmap2;
use nfs_rs::rpc::{OpaqueAuth, TcpRpcClient};
use nfsserve::tcp::{NFSTcp, NFSTcpListener};
use nfsserve::vfs::{NFSFileSystem, ReadDirResult, VFSCapabilities};

#[derive(Debug, Clone)]
struct TestFs;

// fileid3 is u64; 0 is reserved by nfsserve.
const ID_ROOT: u64 = 1;
const ID_EXPORT: u64 = 2;
const ID_HELLO: u64 = 3;
const ID_SUBDIR: u64 = 4;
const ID_NESTED: u64 = 5;

fn hello_bytes() -> Vec<u8> {
    b"hello world\n".to_vec()
}

fn nested_bytes() -> Vec<u8> {
    b"nested\n".to_vec()
}

fn attr_dir(fileid: u64) -> nfsserve::nfs::fattr3 {
    use nfsserve::nfs::{ftype3, nfstime3, specdata3};
    nfsserve::nfs::fattr3 {
        ftype: ftype3::NF3DIR,
        mode: 0o755,
        nlink: 2,
        uid: 1000,
        gid: 1000,
        size: 0,
        used: 0,
        rdev: specdata3 {
            specdata1: 0,
            specdata2: 0,
        },
        fsid: 1,
        fileid,
        atime: nfstime3 {
            seconds: 1,
            nseconds: 0,
        },
        mtime: nfstime3 {
            seconds: 1,
            nseconds: 0,
        },
        ctime: nfstime3 {
            seconds: 1,
            nseconds: 0,
        },
    }
}

fn attr_file(fileid: u64, len: u64) -> nfsserve::nfs::fattr3 {
    use nfsserve::nfs::{ftype3, nfstime3, specdata3};
    nfsserve::nfs::fattr3 {
        ftype: ftype3::NF3REG,
        mode: 0o644,
        nlink: 1,
        uid: 1000,
        gid: 1000,
        size: len,
        used: len,
        rdev: specdata3 {
            specdata1: 0,
            specdata2: 0,
        },
        fsid: 1,
        fileid,
        atime: nfstime3 {
            seconds: 1,
            nseconds: 0,
        },
        mtime: nfstime3 {
            seconds: 1,
            nseconds: 0,
        },
        ctime: nfstime3 {
            seconds: 1,
            nseconds: 0,
        },
    }
}

#[async_trait]
impl NFSFileSystem for TestFs {
    fn capabilities(&self) -> VFSCapabilities {
        VFSCapabilities::ReadOnly
    }

    fn root_dir(&self) -> nfsserve::nfs::fileid3 {
        ID_ROOT
    }

    async fn lookup(
        &self,
        dirid: nfsserve::nfs::fileid3,
        filename: &nfsserve::nfs::filename3,
    ) -> Result<nfsserve::nfs::fileid3, nfsserve::nfs::nfsstat3> {
        use nfsserve::nfs::nfsstat3;
        let name = filename.as_slice();
        match (dirid, name) {
            (ID_ROOT, b"export") => Ok(ID_EXPORT),
            (ID_EXPORT, b"hello.txt") => Ok(ID_HELLO),
            (ID_EXPORT, b"subdir") => Ok(ID_SUBDIR),
            (ID_SUBDIR, b"nested.txt") => Ok(ID_NESTED),
            _ => Err(nfsstat3::NFS3ERR_NOENT),
        }
    }

    async fn getattr(
        &self,
        id: nfsserve::nfs::fileid3,
    ) -> Result<nfsserve::nfs::fattr3, nfsserve::nfs::nfsstat3> {
        use nfsserve::nfs::nfsstat3;
        match id {
            ID_ROOT => Ok(attr_dir(ID_ROOT)),
            ID_EXPORT => Ok(attr_dir(ID_EXPORT)),
            ID_SUBDIR => Ok(attr_dir(ID_SUBDIR)),
            ID_HELLO => Ok(attr_file(ID_HELLO, hello_bytes().len() as u64)),
            ID_NESTED => Ok(attr_file(ID_NESTED, nested_bytes().len() as u64)),
            _ => Err(nfsstat3::NFS3ERR_NOENT),
        }
    }

    async fn setattr(
        &self,
        _id: nfsserve::nfs::fileid3,
        _setattr: nfsserve::nfs::sattr3,
    ) -> Result<nfsserve::nfs::fattr3, nfsserve::nfs::nfsstat3> {
        Err(nfsserve::nfs::nfsstat3::NFS3ERR_ROFS)
    }

    async fn read(
        &self,
        id: nfsserve::nfs::fileid3,
        offset: u64,
        count: u32,
    ) -> Result<(Vec<u8>, bool), nfsserve::nfs::nfsstat3> {
        use nfsserve::nfs::nfsstat3;
        let data = match id {
            ID_HELLO => hello_bytes(),
            ID_NESTED => nested_bytes(),
            _ => return Err(nfsstat3::NFS3ERR_ISDIR),
        };

        let off = offset as usize;
        if off >= data.len() {
            return Ok((Vec::new(), true));
        }
        let end = (off + count as usize).min(data.len());
        let eof = end >= data.len();
        Ok((data[off..end].to_vec(), eof))
    }

    async fn write(
        &self,
        _id: nfsserve::nfs::fileid3,
        _offset: u64,
        _data: &[u8],
    ) -> Result<nfsserve::nfs::fattr3, nfsserve::nfs::nfsstat3> {
        Err(nfsserve::nfs::nfsstat3::NFS3ERR_ROFS)
    }

    async fn create(
        &self,
        _dirid: nfsserve::nfs::fileid3,
        _filename: &nfsserve::nfs::filename3,
        _attr: nfsserve::nfs::sattr3,
    ) -> Result<(nfsserve::nfs::fileid3, nfsserve::nfs::fattr3), nfsserve::nfs::nfsstat3> {
        Err(nfsserve::nfs::nfsstat3::NFS3ERR_ROFS)
    }

    async fn create_exclusive(
        &self,
        _dirid: nfsserve::nfs::fileid3,
        _filename: &nfsserve::nfs::filename3,
    ) -> Result<nfsserve::nfs::fileid3, nfsserve::nfs::nfsstat3> {
        Err(nfsserve::nfs::nfsstat3::NFS3ERR_ROFS)
    }

    async fn mkdir(
        &self,
        _dirid: nfsserve::nfs::fileid3,
        _dirname: &nfsserve::nfs::filename3,
    ) -> Result<(nfsserve::nfs::fileid3, nfsserve::nfs::fattr3), nfsserve::nfs::nfsstat3> {
        Err(nfsserve::nfs::nfsstat3::NFS3ERR_ROFS)
    }

    async fn remove(
        &self,
        _dirid: nfsserve::nfs::fileid3,
        _filename: &nfsserve::nfs::filename3,
    ) -> Result<(), nfsserve::nfs::nfsstat3> {
        Err(nfsserve::nfs::nfsstat3::NFS3ERR_ROFS)
    }

    async fn rename(
        &self,
        _from_dirid: nfsserve::nfs::fileid3,
        _from_filename: &nfsserve::nfs::filename3,
        _to_dirid: nfsserve::nfs::fileid3,
        _to_filename: &nfsserve::nfs::filename3,
    ) -> Result<(), nfsserve::nfs::nfsstat3> {
        Err(nfsserve::nfs::nfsstat3::NFS3ERR_ROFS)
    }

    async fn readdir(
        &self,
        dirid: nfsserve::nfs::fileid3,
        start_after: nfsserve::nfs::fileid3,
        max_entries: usize,
    ) -> Result<ReadDirResult, nfsserve::nfs::nfsstat3> {
        use nfsserve::nfs::nfsstat3;
        let entries: Vec<(u64, Vec<u8>)> = match dirid {
            ID_EXPORT => vec![
                (ID_HELLO, b"hello.txt".to_vec()),
                (ID_SUBDIR, b"subdir".to_vec()),
            ],
            ID_SUBDIR => vec![(ID_NESTED, b"nested.txt".to_vec())],
            ID_ROOT => vec![(ID_EXPORT, b"export".to_vec())],
            _ => return Err(nfsstat3::NFS3ERR_NOTDIR),
        };

        let mut out = Vec::new();
        for (fileid, name) in entries.into_iter().filter(|(fid, _)| *fid > start_after) {
            if out.len() >= max_entries {
                break;
            }
            let attr = self.getattr(fileid).await?;
            out.push(nfsserve::vfs::DirEntry {
                fileid,
                name: name.into(),
                attr,
            });
        }
        let end = out.len() < max_entries;
        Ok(ReadDirResult { entries: out, end })
    }

    async fn symlink(
        &self,
        _dirid: nfsserve::nfs::fileid3,
        _linkname: &nfsserve::nfs::filename3,
        _symlink: &nfsserve::nfs::nfspath3,
        _attr: &nfsserve::nfs::sattr3,
    ) -> Result<(nfsserve::nfs::fileid3, nfsserve::nfs::fattr3), nfsserve::nfs::nfsstat3> {
        Err(nfsserve::nfs::nfsstat3::NFS3ERR_ROFS)
    }

    async fn readlink(
        &self,
        _id: nfsserve::nfs::fileid3,
    ) -> Result<nfsserve::nfs::nfspath3, nfsserve::nfs::nfsstat3> {
        Err(nfsserve::nfs::nfsstat3::NFS3ERR_INVAL)
    }
}

struct ServerGuard {
    addr: String,
    task: tokio::task::JoinHandle<()>,
}

impl ServerGuard {
    async fn start() -> Self {
        let listener = NFSTcpListener::bind("127.0.0.1:0", TestFs)
            .await
            .expect("bind nfsserve listener");
        let port = listener.get_listen_port();
        let ip = listener.get_listen_ip();
        let addr = format!("{}:{}", ip, port);

        let task = tokio::spawn(async move {
            let _ = listener.handle_forever().await;
        });

        Self { addr, task }
    }
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn connect_with_retry(addr: &str) -> TcpRpcClient {
    for _ in 0..50 {
        if let Ok(c) = TcpRpcClient::connect(addr) {
            return c;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    TcpRpcClient::connect(addr).expect("connect to nfsserve")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nfs3_roundtrip_using_nfsserve() {
    let server = ServerGuard::start().await;
    let addr = server.addr.clone();

    tokio::task::spawn_blocking(move || {
        // portmap GETPORT is faked by nfsserve on the same port.
        let mut pmap = connect_with_retry(&addr);
        let port_mount = portmap2::getport(
            &mut pmap,
            mount3::MOUNT_PROG,
            mount3::MOUNT_VERS,
            portmap2::Proto::Tcp,
        )
        .expect("portmap getport mount");
        let port_nfs = portmap2::getport(
            &mut pmap,
            nfs3::NFS_PROG,
            nfs3::NFS_VERS,
            portmap2::Proto::Tcp,
        )
        .expect("portmap getport nfs");
        assert_eq!(
            port_mount,
            addr.split(':').nth(1).unwrap().parse::<u32>().unwrap()
        );
        assert_eq!(port_nfs, port_mount);

        let mut mount = connect_with_retry(&addr);
        let mut nfs = connect_with_retry(&addr);

        let cred = OpaqueAuth::auth_sys("nfs-rs-test", 1000, 1000, &[1000]);
        mount.set_auth(cred.clone());
        nfs.set_auth(cred);

        let mnt = mount3::mnt(&mut mount, "/export").expect("mount call");
        let ok = mnt.expect("mount status ok");

        let mut c = Nfs3Client {
            mount,
            nfs,
            root: nfs3::FileHandle(ok.fh),
        };

        // lookup + read
        let data = c
            .read_to_end("/hello.txt", 128 * 1024)
            .expect("read_to_end call");
        let data = data.expect("nfs status ok");
        assert_eq!(data, hello_bytes());

        // readdirplus
        let entries = c
            .readdirplus_all("/")
            .expect("readdirplus call")
            .expect("nfs status ok");
        let names: Vec<String> = entries.into_iter().map(|e| e.name).collect();
        assert!(names.contains(&"hello.txt".to_string()));
        assert!(names.contains(&"subdir".to_string()));

        // nested path
        let nested = c
            .read_to_end("/subdir/nested.txt", 128 * 1024)
            .expect("nested read call")
            .expect("nfs status ok");
        assert_eq!(nested, nested_bytes());
    })
    .await
    .expect("spawn_blocking");
}
