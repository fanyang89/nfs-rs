use async_trait::async_trait;
use nfs_rs::client::Nfs3Client;
use nfs_rs::mount3;
use nfs_rs::nfs3;
use nfs_rs::portmap2;
use nfs_rs::rpc::{OpaqueAuth, TcpRpcClient};
use nfsserve::tcp::{NFSTcp, NFSTcpListener};
use nfsserve::vfs::{NFSFileSystem, ReadDirResult, VFSCapabilities};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
struct TestFs {
    state: Arc<Mutex<TestState>>,
}

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

#[derive(Debug, Clone)]
struct TestState {
    next_id: u64,
    nodes: HashMap<u64, Node>,
}

#[derive(Debug, Clone)]
struct Node {
    id: u64,
    parent: Option<u64>,
    name: Vec<u8>,
    kind: NodeKind,
}

#[derive(Debug, Clone)]
enum NodeKind {
    Dir(BTreeMap<Vec<u8>, u64>),
    File(Vec<u8>),
    Symlink(Vec<u8>),
    #[allow(dead_code)]
    Special(nfsserve::nfs::ftype3),
}

impl TestFs {
    fn new() -> Self {
        let mut nodes = HashMap::new();
        nodes.insert(
            ID_ROOT,
            Node {
                id: ID_ROOT,
                parent: None,
                name: Vec::new(),
                kind: NodeKind::Dir(BTreeMap::new()),
            },
        );
        nodes.insert(
            ID_EXPORT,
            Node {
                id: ID_EXPORT,
                parent: Some(ID_ROOT),
                name: b"export".to_vec(),
                kind: NodeKind::Dir(BTreeMap::new()),
            },
        );
        nodes.insert(
            ID_HELLO,
            Node {
                id: ID_HELLO,
                parent: Some(ID_EXPORT),
                name: b"hello.txt".to_vec(),
                kind: NodeKind::File(hello_bytes()),
            },
        );
        nodes.insert(
            ID_SUBDIR,
            Node {
                id: ID_SUBDIR,
                parent: Some(ID_EXPORT),
                name: b"subdir".to_vec(),
                kind: NodeKind::Dir(BTreeMap::new()),
            },
        );
        nodes.insert(
            ID_NESTED,
            Node {
                id: ID_NESTED,
                parent: Some(ID_SUBDIR),
                name: b"nested.txt".to_vec(),
                kind: NodeKind::File(nested_bytes()),
            },
        );

        link_child(&mut nodes, ID_ROOT, b"export", ID_EXPORT);
        link_child(&mut nodes, ID_EXPORT, b"hello.txt", ID_HELLO);
        link_child(&mut nodes, ID_EXPORT, b"subdir", ID_SUBDIR);
        link_child(&mut nodes, ID_SUBDIR, b"nested.txt", ID_NESTED);

        Self {
            state: Arc::new(Mutex::new(TestState { next_id: 6, nodes })),
        }
    }
}

fn link_child(nodes: &mut HashMap<u64, Node>, dir: u64, name: &[u8], child: u64) {
    if let Some(Node {
        kind: NodeKind::Dir(children),
        ..
    }) = nodes.get_mut(&dir)
    {
        children.insert(name.to_vec(), child);
    }
}

fn unlink_child(nodes: &mut HashMap<u64, Node>, dir: u64, name: &[u8]) -> Option<u64> {
    if let Some(Node {
        kind: NodeKind::Dir(children),
        ..
    }) = nodes.get_mut(&dir)
    {
        return children.remove(name);
    }
    None
}

fn attr_with_type(
    fileid: u64,
    ftype: nfsserve::nfs::ftype3,
    size: u64,
    mode: u32,
) -> nfsserve::nfs::fattr3 {
    use nfsserve::nfs::{nfstime3, specdata3};
    nfsserve::nfs::fattr3 {
        ftype,
        mode,
        nlink: 1,
        uid: 1000,
        gid: 1000,
        size,
        used: size,
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

fn attr_for(node: &Node) -> nfsserve::nfs::fattr3 {
    use nfsserve::nfs::ftype3;
    match &node.kind {
        NodeKind::Dir(_) => attr_with_type(node.id, ftype3::NF3DIR, 0, 0o755),
        NodeKind::File(data) => attr_with_type(node.id, ftype3::NF3REG, data.len() as u64, 0o644),
        NodeKind::Symlink(target) => {
            attr_with_type(node.id, ftype3::NF3LNK, target.len() as u64, 0o777)
        }
        NodeKind::Special(ftype) => attr_with_type(node.id, *ftype, 0, 0o644),
    }
}

#[async_trait]
impl NFSFileSystem for TestFs {
    fn capabilities(&self) -> VFSCapabilities {
        VFSCapabilities::ReadWrite
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
        let state = self.state.lock().unwrap();
        let dir = state.nodes.get(&dirid).ok_or(nfsstat3::NFS3ERR_NOENT)?;
        let children = match &dir.kind {
            NodeKind::Dir(children) => children,
            _ => return Err(nfsstat3::NFS3ERR_NOTDIR),
        };
        children.get(name).copied().ok_or(nfsstat3::NFS3ERR_NOENT)
    }

    async fn getattr(
        &self,
        id: nfsserve::nfs::fileid3,
    ) -> Result<nfsserve::nfs::fattr3, nfsserve::nfs::nfsstat3> {
        use nfsserve::nfs::nfsstat3;
        let state = self.state.lock().unwrap();
        let node = state.nodes.get(&id).ok_or(nfsstat3::NFS3ERR_NOENT)?;
        Ok(attr_for(node))
    }

    async fn setattr(
        &self,
        id: nfsserve::nfs::fileid3,
        _setattr: nfsserve::nfs::sattr3,
    ) -> Result<nfsserve::nfs::fattr3, nfsserve::nfs::nfsstat3> {
        let state = self.state.lock().unwrap();
        let node = state
            .nodes
            .get(&id)
            .ok_or(nfsserve::nfs::nfsstat3::NFS3ERR_NOENT)?;
        Ok(attr_for(node))
    }

    async fn read(
        &self,
        id: nfsserve::nfs::fileid3,
        offset: u64,
        count: u32,
    ) -> Result<(Vec<u8>, bool), nfsserve::nfs::nfsstat3> {
        use nfsserve::nfs::nfsstat3;
        let state = self.state.lock().unwrap();
        let node = state.nodes.get(&id).ok_or(nfsstat3::NFS3ERR_NOENT)?;
        let data = match &node.kind {
            NodeKind::File(data) => data.clone(),
            NodeKind::Symlink(target) => target.clone(),
            NodeKind::Dir(_) => return Err(nfsstat3::NFS3ERR_ISDIR),
            NodeKind::Special(_) => return Err(nfsstat3::NFS3ERR_INVAL),
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
        id: nfsserve::nfs::fileid3,
        offset: u64,
        data_in: &[u8],
    ) -> Result<nfsserve::nfs::fattr3, nfsserve::nfs::nfsstat3> {
        use nfsserve::nfs::nfsstat3;
        let mut state = self.state.lock().unwrap();
        let node = state.nodes.get_mut(&id).ok_or(nfsstat3::NFS3ERR_NOENT)?;
        let data = match &mut node.kind {
            NodeKind::File(data) => data,
            NodeKind::Dir(_) => return Err(nfsstat3::NFS3ERR_ISDIR),
            _ => return Err(nfsstat3::NFS3ERR_INVAL),
        };
        let offset = offset as usize;
        if offset > data.len() {
            data.resize(offset, 0);
        }
        if offset + data_in.len() > data.len() {
            data.resize(offset + data_in.len(), 0);
        }
        data[offset..offset + data_in.len()].copy_from_slice(data_in);
        Ok(attr_for(node))
    }

    async fn create(
        &self,
        dirid: nfsserve::nfs::fileid3,
        filename: &nfsserve::nfs::filename3,
        _attr: nfsserve::nfs::sattr3,
    ) -> Result<(nfsserve::nfs::fileid3, nfsserve::nfs::fattr3), nfsserve::nfs::nfsstat3> {
        use nfsserve::nfs::nfsstat3;
        let name = filename.as_slice();
        let mut state = self.state.lock().unwrap();
        let exists = match state.nodes.get(&dirid) {
            Some(Node {
                kind: NodeKind::Dir(children),
                ..
            }) => children.contains_key(name),
            Some(_) => return Err(nfsstat3::NFS3ERR_NOTDIR),
            None => return Err(nfsstat3::NFS3ERR_NOENT),
        };
        if exists {
            return Err(nfsstat3::NFS3ERR_INVAL);
        }
        let id = state.next_id;
        state.next_id += 1;
        state.nodes.insert(
            id,
            Node {
                id,
                parent: Some(dirid),
                name: name.to_vec(),
                kind: NodeKind::File(Vec::new()),
            },
        );
        link_child(&mut state.nodes, dirid, name, id);
        let node = state.nodes.get(&id).unwrap();
        Ok((id, attr_for(node)))
    }

    async fn create_exclusive(
        &self,
        dirid: nfsserve::nfs::fileid3,
        filename: &nfsserve::nfs::filename3,
    ) -> Result<nfsserve::nfs::fileid3, nfsserve::nfs::nfsstat3> {
        use nfsserve::nfs::nfsstat3;
        let name = filename.as_slice();
        let mut state = self.state.lock().unwrap();
        let exists = match state.nodes.get(&dirid) {
            Some(Node {
                kind: NodeKind::Dir(children),
                ..
            }) => children.contains_key(name),
            Some(_) => return Err(nfsstat3::NFS3ERR_NOTDIR),
            None => return Err(nfsstat3::NFS3ERR_NOENT),
        };
        if exists {
            return Err(nfsstat3::NFS3ERR_INVAL);
        }
        let id = state.next_id;
        state.next_id += 1;
        state.nodes.insert(
            id,
            Node {
                id,
                parent: Some(dirid),
                name: name.to_vec(),
                kind: NodeKind::File(Vec::new()),
            },
        );
        link_child(&mut state.nodes, dirid, name, id);
        Ok(id)
    }

    async fn mkdir(
        &self,
        dirid: nfsserve::nfs::fileid3,
        dirname: &nfsserve::nfs::filename3,
    ) -> Result<(nfsserve::nfs::fileid3, nfsserve::nfs::fattr3), nfsserve::nfs::nfsstat3> {
        use nfsserve::nfs::nfsstat3;
        let name = dirname.as_slice();
        let mut state = self.state.lock().unwrap();
        let exists = match state.nodes.get(&dirid) {
            Some(Node {
                kind: NodeKind::Dir(children),
                ..
            }) => children.contains_key(name),
            Some(_) => return Err(nfsstat3::NFS3ERR_NOTDIR),
            None => return Err(nfsstat3::NFS3ERR_NOENT),
        };
        if exists {
            return Err(nfsstat3::NFS3ERR_INVAL);
        }
        let id = state.next_id;
        state.next_id += 1;
        state.nodes.insert(
            id,
            Node {
                id,
                parent: Some(dirid),
                name: name.to_vec(),
                kind: NodeKind::Dir(BTreeMap::new()),
            },
        );
        link_child(&mut state.nodes, dirid, name, id);
        let node = state.nodes.get(&id).unwrap();
        Ok((id, attr_for(node)))
    }

    async fn remove(
        &self,
        dirid: nfsserve::nfs::fileid3,
        filename: &nfsserve::nfs::filename3,
    ) -> Result<(), nfsserve::nfs::nfsstat3> {
        use nfsserve::nfs::nfsstat3;
        let name = filename.as_slice();
        let mut state = self.state.lock().unwrap();
        let id = unlink_child(&mut state.nodes, dirid, name).ok_or(nfsstat3::NFS3ERR_NOENT)?;
        let can_remove_dir = match state.nodes.get(&id) {
            Some(Node {
                kind: NodeKind::Dir(children),
                ..
            }) => {
                if children.is_empty() {
                    true
                } else {
                    link_child(&mut state.nodes, dirid, name, id);
                    return Err(nfsstat3::NFS3ERR_NOTEMPTY);
                }
            }
            Some(Node {
                kind: NodeKind::File(_) | NodeKind::Symlink(_) | NodeKind::Special(_),
                ..
            }) => false,
            None => return Err(nfsstat3::NFS3ERR_NOENT),
        };
        if can_remove_dir {
            state.nodes.remove(&id);
            return Ok(());
        }
        state.nodes.remove(&id);
        Ok(())
    }

    async fn rename(
        &self,
        from_dirid: nfsserve::nfs::fileid3,
        from_filename: &nfsserve::nfs::filename3,
        to_dirid: nfsserve::nfs::fileid3,
        to_filename: &nfsserve::nfs::filename3,
    ) -> Result<(), nfsserve::nfs::nfsstat3> {
        use nfsserve::nfs::nfsstat3;
        let from_name = from_filename.as_slice();
        let to_name = to_filename.as_slice();
        let mut state = self.state.lock().unwrap();
        match state.nodes.get(&from_dirid) {
            Some(Node {
                kind: NodeKind::Dir(_),
                ..
            }) => {}
            Some(_) => return Err(nfsstat3::NFS3ERR_NOTDIR),
            None => return Err(nfsstat3::NFS3ERR_NOENT),
        }
        match state.nodes.get(&to_dirid) {
            Some(Node {
                kind: NodeKind::Dir(_),
                ..
            }) => {}
            Some(_) => return Err(nfsstat3::NFS3ERR_NOTDIR),
            None => return Err(nfsstat3::NFS3ERR_NOENT),
        }
        let id =
            unlink_child(&mut state.nodes, from_dirid, from_name).ok_or(nfsstat3::NFS3ERR_NOENT)?;
        if let Some(existing) = unlink_child(&mut state.nodes, to_dirid, to_name) {
            state.nodes.remove(&existing);
        }
        if let Some(node) = state.nodes.get_mut(&id) {
            node.parent = Some(to_dirid);
            node.name = to_name.to_vec();
        }
        link_child(&mut state.nodes, to_dirid, to_name, id);
        Ok(())
    }

    async fn readdir(
        &self,
        dirid: nfsserve::nfs::fileid3,
        start_after: nfsserve::nfs::fileid3,
        max_entries: usize,
    ) -> Result<ReadDirResult, nfsserve::nfs::nfsstat3> {
        use nfsserve::nfs::nfsstat3;
        let state = self.state.lock().unwrap();
        let dir = state.nodes.get(&dirid).ok_or(nfsstat3::NFS3ERR_NOENT)?;
        let children = match &dir.kind {
            NodeKind::Dir(children) => children,
            _ => return Err(nfsstat3::NFS3ERR_NOTDIR),
        };
        let mut entries: Vec<(u64, Vec<u8>)> = children
            .iter()
            .map(|(name, id)| (*id, name.clone()))
            .collect();
        entries.sort_by_key(|(id, _)| *id);

        let mut out = Vec::new();
        for (fileid, name) in entries.into_iter().filter(|(fid, _)| *fid > start_after) {
            if out.len() >= max_entries {
                break;
            }
            let node = state.nodes.get(&fileid).ok_or(nfsstat3::NFS3ERR_NOENT)?;
            let attr = attr_for(node);
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
        dirid: nfsserve::nfs::fileid3,
        linkname: &nfsserve::nfs::filename3,
        symlink: &nfsserve::nfs::nfspath3,
        _attr: &nfsserve::nfs::sattr3,
    ) -> Result<(nfsserve::nfs::fileid3, nfsserve::nfs::fattr3), nfsserve::nfs::nfsstat3> {
        use nfsserve::nfs::nfsstat3;
        let name = linkname.as_slice();
        let target = symlink.as_slice();
        let mut state = self.state.lock().unwrap();
        let exists = match state.nodes.get(&dirid) {
            Some(Node {
                kind: NodeKind::Dir(children),
                ..
            }) => children.contains_key(name),
            Some(_) => return Err(nfsstat3::NFS3ERR_NOTDIR),
            None => return Err(nfsstat3::NFS3ERR_NOENT),
        };
        if exists {
            return Err(nfsstat3::NFS3ERR_INVAL);
        }
        let id = state.next_id;
        state.next_id += 1;
        state.nodes.insert(
            id,
            Node {
                id,
                parent: Some(dirid),
                name: name.to_vec(),
                kind: NodeKind::Symlink(target.to_vec()),
            },
        );
        link_child(&mut state.nodes, dirid, name, id);
        let node = state.nodes.get(&id).unwrap();
        Ok((id, attr_for(node)))
    }

    async fn readlink(
        &self,
        id: nfsserve::nfs::fileid3,
    ) -> Result<nfsserve::nfs::nfspath3, nfsserve::nfs::nfsstat3> {
        use nfsserve::nfs::nfsstat3;
        let state = self.state.lock().unwrap();
        let node = state.nodes.get(&id).ok_or(nfsstat3::NFS3ERR_NOENT)?;
        match &node.kind {
            NodeKind::Symlink(target) => Ok(target.clone().into()),
            _ => Err(nfsstat3::NFS3ERR_INVAL),
        }
    }
}

struct ServerGuard {
    addr: String,
    task: tokio::task::JoinHandle<()>,
}

impl ServerGuard {
    async fn start() -> Self {
        let listener = NFSTcpListener::bind("127.0.0.1:0", TestFs::new())
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

fn connect_client(addr: &str) -> Nfs3Client {
    let mut pmap = connect_with_retry(addr);
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

    let mut mount = connect_with_retry(addr);
    let mut nfs = connect_with_retry(addr);

    let cred = OpaqueAuth::auth_sys("nfs-rs-test", 1000, 1000, &[1000]);
    mount.set_auth(cred.clone());
    nfs.set_auth(cred);

    let mnt = mount3::mnt(&mut mount, "/export").expect("mount call");
    let ok = mnt.expect("mount status ok");

    Nfs3Client {
        mount,
        nfs,
        root: nfs3::FileHandle(ok.fh),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nfs3_roundtrip_using_nfsserve() {
    let server = ServerGuard::start().await;
    let addr = server.addr.clone();

    tokio::task::spawn_blocking(move || {
        let mut c = connect_client(&addr);

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

        let entries = c
            .readdir_all("/")
            .expect("readdir call")
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nfs3_write_roundtrip_using_nfsserve() {
    let server = ServerGuard::start().await;
    let addr = server.addr.clone();

    tokio::task::spawn_blocking(move || {
        let mut c = connect_client(&addr);

        let dir_attrs = nfs3::SetAttr3 {
            mode: Some(0o755),
            ..Default::default()
        };
        let _ = c
            .mkdir("/tmpdir", &dir_attrs)
            .expect("mkdir call")
            .expect("nfs status ok");

        let attrs = nfs3::SetAttr3 {
            mode: Some(0o644),
            ..Default::default()
        };
        let create = c
            .create("/tmpdir/write.txt", &nfs3::CreateHow3::Unchecked(attrs))
            .expect("create call")
            .expect("nfs status ok");
        let fh = create.fh.expect("create fh");

        let data = b"hello write\n".to_vec();
        let w = nfs3::write(&mut c.nfs, &fh, 0, &data, nfs3::STABLE_HOW_UNSTABLE)
            .expect("write call")
            .expect("nfs status ok");
        assert_eq!(w.count as usize, data.len());

        match nfs3::commit(&mut c.nfs, &fh, 0, 0) {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => panic!("commit nfs error: {e}"),
            Err(nfs_rs::rpc::RpcError::RpcAcceptedError(msg)) if msg.contains("accept_stat 3") => {
                // nfsserve doesn't implement COMMIT; allow PROC_UNAVAIL.
            }
            Err(e) => panic!("commit call: {e}"),
        }

        let read = c
            .read_to_end("/tmpdir/write.txt", 128 * 1024)
            .expect("read_to_end call")
            .expect("nfs status ok");
        assert_eq!(read, data);

        let _ = c
            .rename("/tmpdir/write.txt", "/tmpdir/renamed.txt")
            .expect("rename call")
            .expect("nfs status ok");

        let _ = c
            .remove("/tmpdir/renamed.txt")
            .expect("remove call")
            .expect("nfs status ok");
    })
    .await
    .expect("spawn_blocking");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nfs3_metadata_and_edgecases_using_nfsserve() {
    let server = ServerGuard::start().await;
    let addr = server.addr.clone();

    tokio::task::spawn_blocking(move || {
        let mut c = connect_client(&addr);

        // getattr on file/dir
        let attr = c
            .getattr("/hello.txt")
            .expect("getattr call")
            .expect("nfs status ok");
        assert_eq!(attr.ftype, nfs3::NF3REG);
        assert_eq!(attr.size, hello_bytes().len() as u64);

        let dir_attr = c
            .getattr("/subdir")
            .expect("getattr dir call")
            .expect("nfs status ok");
        assert_eq!(dir_attr.ftype, nfs3::NF3DIR);

        let _ = c
            .setattr(
                "/hello.txt",
                &nfs3::SetAttr3 {
                    mode: Some(0o644),
                    ..Default::default()
                },
                None,
            )
            .expect("setattr call")
            .expect("nfs status ok");

        // access
        let access = c
            .access(
                "/hello.txt",
                nfs3::ACCESS3_READ | nfs3::ACCESS3_LOOKUP | nfs3::ACCESS3_MODIFY,
            )
            .expect("access call")
            .expect("nfs status ok");
        assert_ne!(access.access & nfs3::ACCESS3_READ, 0);
        assert_ne!(access.access & nfs3::ACCESS3_LOOKUP, 0);

        // fsinfo/fsstat/pathconf
        let fsinfo = c.fsinfo("/").expect("fsinfo call").expect("nfs status ok");
        assert!(fsinfo.maxfilesize > 0);
        assert!(fsinfo.rtmax > 0);
        assert!(fsinfo.wtmax > 0);

        let fsstat = c.fsstat("/").expect("fsstat call").expect("nfs status ok");
        assert!(fsstat.tbytes > 0);
        assert!(fsstat.fbytes > 0);

        let pathconf = c
            .pathconf("/")
            .expect("pathconf call")
            .expect("nfs status ok");
        assert!(pathconf.namemax >= 255);
        assert!(pathconf.no_trunc);

        // readdir pagination with small dircount
        let dir = c.lookup_path("/").expect("lookup root").expect("nfs ok");
        let mut cookie = 0u64;
        let mut verifier = [0u8; 8];
        let mut names = Vec::new();
        loop {
            let res = nfs3::readdir(&mut c.nfs, &dir, cookie, verifier, 16)
                .expect("readdir call")
                .expect("nfs status ok");
            verifier = res.verifier;
            if let Some(last) = res.entries.last() {
                cookie = last.cookie;
            }
            names.extend(res.entries.into_iter().map(|e| e.name));
            if res.eof {
                break;
            }
        }
        assert!(names.contains(&"hello.txt".to_string()));
        assert!(names.contains(&"subdir".to_string()));

        // symlink + readlink
        let dir_attrs = nfs3::SetAttr3 {
            mode: Some(0o755),
            ..Default::default()
        };
        let _ = c
            .mkdir("/linkdir", &dir_attrs)
            .expect("mkdir linkdir")
            .expect("nfs status ok");
        let _ = c
            .symlink(
                "/linkdir/hello_link",
                "/hello.txt",
                &nfs3::SetAttr3::default(),
            )
            .expect("symlink call")
            .expect("nfs status ok");
        let link = c
            .readlink("/linkdir/hello_link")
            .expect("readlink call")
            .expect("nfs status ok");
        assert_eq!(link.path, "/hello.txt");
        let not_link = c.readlink("/hello.txt").expect("readlink non-link call");
        assert!(not_link.is_err());

        // offset write + zero-fill
        let created = c
            .create(
                "/offset.txt",
                &nfs3::CreateHow3::Unchecked(nfs3::SetAttr3 {
                    mode: Some(0o644),
                    ..Default::default()
                }),
            )
            .expect("create offset call")
            .expect("nfs status ok");
        let fh = created.fh.expect("create fh");
        let data = b"abc".to_vec();
        let _ = nfs3::write(&mut c.nfs, &fh, 5, &data, nfs3::STABLE_HOW_UNSTABLE)
            .expect("write offset call")
            .expect("nfs status ok");
        let read = c
            .read_to_end("/offset.txt", 128 * 1024)
            .expect("read_to_end offset")
            .expect("nfs status ok");
        let mut expected = vec![0u8; 5];
        expected.extend_from_slice(&data);
        assert_eq!(read, expected);

        // rmdir success + failure
        let _ = c
            .mkdir("/emptydir", &dir_attrs)
            .expect("mkdir emptydir")
            .expect("nfs status ok");
        let _ = c
            .rmdir("/emptydir")
            .expect("rmdir emptydir")
            .expect("nfs status ok");

        let _ = c
            .mkdir("/nonempty", &dir_attrs)
            .expect("mkdir nonempty")
            .expect("nfs status ok");
        let _ = c
            .create(
                "/nonempty/file.txt",
                &nfs3::CreateHow3::Unchecked(nfs3::SetAttr3 {
                    mode: Some(0o644),
                    ..Default::default()
                }),
            )
            .expect("create file")
            .expect("nfs status ok");
        let nonempty = c.rmdir("/nonempty").expect("rmdir nonempty call");
        assert!(nonempty.is_err());

        // remove missing path
        let missing = c.remove("/no_such").expect("remove missing call");
        assert!(missing.is_err());

        // read on directory should error
        let dir_read = c.read_to_end("/subdir", 4096).expect("read dir call");
        assert!(dir_read.is_err());

        // cross-directory rename
        let _ = c
            .mkdir("/dir_a", &dir_attrs)
            .expect("mkdir dir_a")
            .expect("nfs status ok");
        let _ = c
            .mkdir("/dir_b", &dir_attrs)
            .expect("mkdir dir_b")
            .expect("nfs status ok");
        let _ = c
            .create(
                "/dir_a/x.txt",
                &nfs3::CreateHow3::Unchecked(nfs3::SetAttr3 {
                    mode: Some(0o644),
                    ..Default::default()
                }),
            )
            .expect("create x.txt")
            .expect("nfs status ok");
        let _ = c
            .rename("/dir_a/x.txt", "/dir_b/y.txt")
            .expect("rename cross-dir")
            .expect("nfs status ok");
        let moved = c
            .read_to_end("/dir_b/y.txt", 4096)
            .expect("read moved")
            .expect("nfs status ok");
        assert!(moved.is_empty());

        // optional ops: LINK/MKNOD may be unsupported by nfsserve
        match c.link("/hello.txt", "/hardlink.txt") {
            Ok(Ok(_)) => {
                let _ = c.remove("/hardlink.txt");
            }
            Ok(Err(e)) => panic!("link nfs error: {e}"),
            Err(nfs_rs::rpc::RpcError::RpcAcceptedError(msg)) if msg.contains("accept_stat 3") => {}
            Err(e) => panic!("link call: {e}"),
        }

        match c.mknod(
            "/mknod_fifo",
            &nfs3::MknodData::Fifo,
            &nfs3::SetAttr3::default(),
        ) {
            Ok(Ok(_)) => {
                let _ = c.remove("/mknod_fifo");
            }
            Ok(Err(e)) => panic!("mknod nfs error: {e}"),
            Err(nfs_rs::rpc::RpcError::RpcAcceptedError(msg)) if msg.contains("accept_stat 3") => {}
            Err(e) => panic!("mknod call: {e}"),
        }
    })
    .await
    .expect("spawn_blocking");
}
