use anyhow::{bail, Result};
use clap::builder::PossibleValuesParser;
use clap::builder::TypedValueParser as _;
use clap::Parser;
use log::error;
use log::info;
use rs_utilities::log_and_bail;
use rstun::*;
use std::net::SocketAddr;

fn main() {
    let args = RstundArgs::parse();
    let log_filter = format!("rstun={},rs_utilities={}", args.loglevel, args.loglevel);
    rs_utilities::LogHelper::init_logger("rstund", log_filter.as_str());

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
                    error!("{e}");
                })
                .ok();
        })
}

async fn run(mut args: RstundArgs) -> Result<()> {
    if args.addr.is_empty() {
        args.addr = "0.0.0.0:0".to_string();
    }

    if !args.addr.contains(':') {
        args.addr = format!("127.0.0.1:{}", args.addr);
    }

    let mut upstreams = Vec::<SocketAddr>::new();

    for mut u in &mut args.upstreams.split(',').map(|u| u.to_string()) {
        if u.starts_with("0.0.0.0:") {
            u = u.replace("0.0.0.0:", "127.0.0.1:");
        }

        if !u.contains(':') {
            u = format!("127.0.0.1:{u}");
        }

        if let Ok(addr) = u.parse() {
            if !upstreams.contains(&addr) {
                info!("upstream: {addr}");
                upstreams.push(addr);
            }
        } else {
            log_and_bail!("invalid upstreams address: {u}");
        }
    }

    let mut config = ServerConfig::default();
    config.addr = args.addr;
    config.password = args.password;
    config.cert_path = args.cert;
    config.key_path = args.key;
    config.upstreams = upstreams;
    config.max_idle_timeout_ms = args.max_idle_timeout_ms;

    let mut server = Server::new(config);
    server.bind()?;
    server.serve().await?;
    Ok(())
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct RstundArgs {
    /// Address ([ip:]port pair) to listen on, if empty, a random port will be chosen
    /// and binding to all network interfaces (0.0.0.0)
    #[arg(short = 'a', long, default_value_t = String::from(""), verbatim_doc_comment)]
    addr: String,

    /// Exposed upstreams (comma separated) as the receiving ends of the tunnel,
    /// e.g. -u "[ip:]port,[ip:]port,[ip:]port",
    /// The entire local network is exposed through the tunnel if empty
    #[arg(short = 'u', long, required = false, verbatim_doc_comment)]
    upstreams: String,

    /// Password of the tunnel server
    #[arg(short = 'p', long, required = true)]
    password: String,

    /// Path to the certificate file, if empty, a self-signed certificate
    /// with the domain "localhost" will be used
    #[arg(short = 'c', long, default_value_t = String::from(""), verbatim_doc_comment)]
    cert: String,

    /// Path to the key file, can be empty if no cert is provided
    #[arg(short = 'k', long, default_value_t = String::from(""))]
    key: String,

    /// Threads to run async tasks
    #[arg(short = 't', long, default_value_t = 0)]
    threads: usize,

    /// Max idle timeout milliseconds for the connection
    #[arg(short = 'w', long, default_value_t = 40000)]
    max_idle_timeout_ms: u64,

    #[arg(short = 'l', long, default_value_t = String::from("I"),
        value_parser = PossibleValuesParser::new(["T", "D", "I", "W", "E"]).map(|v| match v.as_str() {
            "T" => "trace",
            "D" => "debug",
            "I" => "info",
            "W" => "warn",
            "E" => "error",
            _ => "info",
        }.to_string()))]
    loglevel: String,
}
