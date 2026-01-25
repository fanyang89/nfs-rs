use nfs_rs::client41::Nfs41Client;
use std::io::Write;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: nfs4_cat <server> <path>");
        eprintln!("example: nfs4_cat 10.0.0.10 /dir/file.txt");
        std::process::exit(2);
    }
    let server = &args[1];
    let path = &args[2];

    let mut c = Nfs41Client::connect(server)?;
    let data = c.read_to_end(path, 128 * 1024)??;
    std::io::stdout().write_all(&data)?;
    Ok(())
}
