//! Starts the embedded Tor proxy and prints one URL per role, then waits.
//! `cargo run -p zkmsg-tor --example tor_proxy -- <state dir>`
fn main() -> anyhow::Result<()> {
    let dir = std::env::args().nth(1).expect("state dir");
    let tor = zkmsg_tor::Tor::start(std::path::Path::new(&dir))?;
    tor.wait_ready(std::time::Duration::from_secs(120))?;
    for role in zkmsg_tor::ROLES {
        println!("{role} {}", tor.proxy_url(role));
    }
    std::thread::sleep(std::time::Duration::from_secs(600));
    Ok(())
}
