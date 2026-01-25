use nfs_rs::client41::Nfs41Client;

#[test]
#[ignore]
fn nfs41_vm_read_hello() {
    let server = std::env::var("NFS41_TEST_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let mut c = Nfs41Client::connect(&server).expect("connect");
    let data = c
        .read_to_end("/hello.txt", 128 * 1024)
        .expect("read_to_end")
        .expect("nfs ok");
    assert_eq!(data, b"hello world\n".to_vec());
}

#[test]
#[ignore]
fn nfs41_vm_read_nested() {
    let server = std::env::var("NFS41_TEST_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let mut c = Nfs41Client::connect(&server).expect("connect");
    let data = c
        .read_to_end("/subdir/nested.txt", 128 * 1024)
        .expect("read_to_end")
        .expect("nfs ok");
    assert_eq!(data, b"nested\n".to_vec());
}
