use anyhow::{bail, Result};
use clap::Parser;
use log::error;
use log::info;
use rs_utilities::log_and_bail;
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
            run(args)
                .await
                .map_err(|e| {
                    error!("{}", e);
                })
                .ok();
        })
}

async fn run(mut args: RstundArgs) -> Result<()> {
    if !args.addr.contains(':') {
        args.addr = format!("127.0.0.1:{}", args.addr);
    }

    let mut downstreams = Vec::<SocketAddr>::new();

    for d in &mut args.downstreams {
        if d.starts_with("0.0.0.0:") {
            *d = d.replace("0.0.0.0:", "127.0.0.1:");
        }

        if !d.contains(':') {
            *d = format!("127.0.0.1:{}", d);
        }

        if let Ok(addr) = d.parse() {
            downstreams.push(addr);
        } else {
            log_and_bail!("invalid downstreams address: {}", d);
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
    /// Address ([ip:]port pair) to listen on
    #[clap(short = 'l', long, display_order = 1)]
    addr: String,

    /// Exposed downstreams as the receiving end of the tunnel, e.g. -d [ip:]port,
    /// The entire local network is exposed through the tunnel if empty
    #[clap(short = 'd', long, required = false, display_order = 2)]
    downstreams: Vec<String>,

    /// Password of the tunnel server
    #[clap(short = 'p', long, required = true, display_order = 3)]
    password: String,

    /// Path to the certificate file in DER format, if empty, a self-signed certificate
    /// with the domain "localhost" will be used
    #[clap(short = 'c', long, default_value = "", display_order = 4)]
    cert: String,

    /// Path to the key file in DER format, can be empty if no cert is provided
    #[clap(short = 'k', long, default_value = "", display_order = 5)]
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
