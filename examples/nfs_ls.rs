use nfs_rs::client::Nfs3Client;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: nfs_ls <server> <export> <path>");
        eprintln!("example: nfs_ls 10.0.0.10 /export /dir");
        std::process::exit(2);
    }
    let server = &args[1];
    let export = &args[2];
    let path = &args[3];

    let mut c = Nfs3Client::connect_and_mount(server, export)?;

    let entries = c.readdirplus_all(path)??;
    for e in entries {
        let kind = e.attributes.as_ref().map(|a| a.ftype).unwrap_or_default();
        println!("{kind}\t{}", e.name);
    }
    Ok(())
}
