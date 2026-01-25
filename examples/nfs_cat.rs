use nfs_rs::client::Nfs3Client;
use std::io::Write;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: nfs_cat <server> <export> <path>");
        eprintln!("example: nfs_cat 10.0.0.10 /export /dir/file.txt");
        std::process::exit(2);
    }
    let server = &args[1];
    let export = &args[2];
    let path = &args[3];

    let mut c = Nfs3Client::connect_and_mount(server, export)?;
    let data = c.read_to_end(path, 128 * 1024)??;
    std::io::stdout().write_all(&data)?;
    Ok(())
}
