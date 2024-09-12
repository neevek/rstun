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

    let config = ServerConfig {
        addr: args.addr,
        password: args.password,
        cert_path: args.cert,
        key_path: args.key,
        tcp_upstreams: parse_upstreams("tcp", &args.tcp_upstreams)?,
        udp_upstreams: parse_upstreams("udp", &args.udp_upstreams)?,
        max_idle_timeout_ms: args.max_idle_timeout_ms,
        dashboard_server: "".to_string(),
        dashboard_server_credential: "".to_string(),
    };

    let mut server = Server::new(config);
    server.bind()?;
    server.serve().await?;
    Ok(())
}

fn parse_upstreams(upstream_type: &str, upstreams_str: &str) -> Result<Vec<SocketAddr>> {
    if upstreams_str == "ANY" {
        return Ok(vec![]);
    }

    let mut upstreams = Vec::<SocketAddr>::new();
    for mut u in &mut upstreams_str.split(',').map(|u| u.to_string()) {
        if u.starts_with("0.0.0.0:") {
            u = u.replace("0.0.0.0:", "127.0.0.1:");
        }

        if !u.contains(':') {
            u = format!("127.0.0.1:{u}");
        }

        if let Ok(addr) = u.parse() {
            if !upstreams.contains(&addr) {
                info!("{upstream_type} upstream: {addr}");
                upstreams.push(addr);
            }
        } else {
            log_and_bail!("invalid {upstream_type} upstreams address: {u}");
        }
    }

    Ok(upstreams)
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct RstundArgs {
    /// Address ([ip:]port pair) to listen on, if empty, a random port will be chosen
    /// and binding to all network interfaces (0.0.0.0)
    #[arg(
        short = 'a',
        long,
        required = true,
        default_value = "",
        verbatim_doc_comment
    )]
    addr: String,

    /// Exposed tcp upstreams (comma separated) as the receiving ends of the tunnel,
    /// e.g. -u "[ip:]port,[ip:]port,[ip:]port",
    /// Or the string "ANY" for exposing the entire internet through the tunnel
    #[arg(long, required = false, default_value = "ANY", verbatim_doc_comment)]
    tcp_upstreams: String,

    /// Exposed tcp upstreams (comma separated) as the receiving ends of the tunnel,
    /// e.g. -u "[ip:]port,[ip:]port,[ip:]port",
    /// Or the string "ANY" for exposing the entire internet through the tunnel
    #[arg(long, required = false, default_value = "ANY", verbatim_doc_comment)]
    udp_upstreams: String,

    /// Password of the tunnel server
    #[arg(short = 'p', long, required = true)]
    password: String,

    /// Path to the certificate file, if empty, a self-signed certificate
    /// with the domain "localhost" will be used
    #[arg(short = 'c', long, default_value = "", verbatim_doc_comment)]
    cert: String,

    /// Path to the key file, can be empty if no cert is provided
    #[arg(short = 'k', long, default_value = "")]
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
