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

    let workers = if args.workers > 0 {
        args.workers
    } else {
        num_cpus::get()
    };

    info!("will use {} workers", workers);

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(workers)
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
        default_tcp_upstream: parse_upstreams("tcp", &args.tcp_upstream)?,
        default_udp_upstream: parse_upstreams("udp", &args.udp_upstream)?,
        quic_timeout_ms: args.quic_timeout_ms,
        tcp_timeout_ms: args.tcp_timeout_ms,
        udp_timeout_ms: args.udp_timeout_ms,
        dashboard_server: "".to_string(),
        dashboard_server_credential: "".to_string(),
    };

    let mut server = Server::new(config);
    server.bind()?;
    server.serve().await?;
    Ok(())
}

fn parse_upstreams(upstream_type: &str, upstreams_str: &str) -> Result<Option<SocketAddr>> {
    if upstreams_str.is_empty() {
        return Ok(None);
    }

    let mut upstream = upstreams_str.to_string();
    if upstream.starts_with("0.0.0.0:") {
        upstream = upstream.replace("0.0.0.0:", "127.0.0.1:");
    }

    if !upstream.contains(':') {
        upstream = format!("127.0.0.1:{upstreams_str}");
    }

    if let Ok(addr) = upstream.parse() {
        Ok(Some(addr))
    } else {
        log_and_bail!("invalid {upstream_type} upstream address: {upstreams_str}");
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct RstundArgs {
    /// Address ([ip:]port pair) to listen on
    #[arg(
        short = 'a',
        long,
        required = true,
        default_value = "",
        verbatim_doc_comment
    )]
    addr: String,

    /// The default TCP upstream for TunnelOut connections, format: [ip:]port
    #[arg(
        short = 't',
        long,
        required = false,
        default_value = "",
        verbatim_doc_comment
    )]
    tcp_upstream: String,

    /// The default UDP upstream for TunnelOut connections, format: [ip:]port
    #[arg(
        short = 'u',
        long,
        required = false,
        default_value = "",
        verbatim_doc_comment
    )]
    udp_upstream: String,

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
    #[arg(short = 'w', long, default_value_t = 0)]
    workers: usize,

    /// Quic idle timeout in milliseconds for the connection
    #[arg(long, default_value_t = 40000)]
    quic_timeout_ms: u64,

    /// Tcp idle timeout in milliseconds for the connection
    #[arg(long, default_value_t = 30000)]
    tcp_timeout_ms: u64,

    /// Udp idle timeout in milliseconds for the connection
    #[arg(long, default_value_t = 5000)]
    udp_timeout_ms: u64,

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
