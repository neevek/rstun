use anyhow::{bail, Result};
use clap::Parser;
use log::error;
use log::info;
use rstun::*;
use std::net::SocketAddr;

fn main() {
    let args = RstundArgs::parse();
    rs_utilities::LogHelper::init_logger("rstund", args.loglevel.as_str());

    let worker_threads = if args.threads > 0 {
        args.threads
    } else {
        num_cpus::get()
    };

    info!("will use {} worker threads", worker_threads);

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(worker_threads)
        .build()
        .unwrap()
        .block_on(async {
            run(args).await.unwrap();
        })
}

async fn run(mut args: RstundArgs) -> Result<()> {
    let mut downstreams = Vec::<SocketAddr>::new();

    for d in &mut args.downstream {
        if d.starts_with("0.0.0.0:") {
            *d = d.replace("0.0.0.0:", "127.0.0.1:");
        }
        if !d.contains(':') {
            *d = format!("127.0.0.1:{}", d);
        }

        if let Ok(addr) = d.parse() {
            downstreams.push(addr);
        } else {
            bail_with_log!("invalid downstream address: {}", d);
        }
    }

    let mut config = ServerConfig::default();
    config.addr = args.addr;
    config.password = args.password;
    config.cert_path = args.cert;
    config.key_path = args.key;
    config.downstreams = downstreams;
    config.max_idle_timeout_ms = args.max_idle_timeout_ms;

    let server = Server::new(config);
    server.start().await?;
    Ok(())
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct RstundArgs {
    /// Address (ip:port pair) to listen on
    #[clap(short = 'l', long, display_order = 1)]
    addr: String,

    /// Exposed downstream as the receiving end of the tunnel, e.g. -d [ip:]port
    #[clap(short = 'd', long, required = true, min_values = 1, display_order = 2)]
    downstream: Vec<String>,

    /// Password of the tunnel server
    #[clap(short = 'p', long, required = true, display_order = 3)]
    password: String,

    /// Path to the certificate file in DER format
    #[clap(short = 'c', long, required = true, display_order = 4)]
    cert: String,

    /// Path to the key file in DER format
    #[clap(short = 'k', long, required = true, display_order = 5)]
    key: String,

    /// Threads to run async tasks
    #[clap(short = 't', long, default_value = "0", display_order = 6)]
    threads: usize,

    /// Max idle timeout for the connection
    #[clap(short = 'w', long, default_value = "40000", display_order = 7)]
    max_idle_timeout_ms: u64,

    #[clap(short = 'L', long, possible_values = &["T", "D", "I", "W", "E"], default_value = "I", display_order = 8)]
    loglevel: String,
}
