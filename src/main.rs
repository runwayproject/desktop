use std::process;

mod client_tui;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let server_addr = args.get(1).map(String::as_str).unwrap_or("127.0.0.1:8999");
    
    if let Err(err) = client_tui::run_client_tui(server_addr) {
        eprintln!("client tui failed: {err:#}");
        process::exit(1);
    }
}
