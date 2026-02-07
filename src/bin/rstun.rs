use anyhow::Result;
use clap::Parser;
use clap::Subcommand;
use clap::builder::PossibleValuesParser;
use clap::builder::TypedValueParser as _;
use log::error;
use log::info;
use rs_utilities::log_and_bail;
use rstun::*;
use std::net::SocketAddr;

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Client(args) => run_client(args),
        Commands::Server(args) => run_server(args),
    }
}

fn run_client(args: ClientArgs) {
    let log_filter = format!("rstun={},rs_utilities={}", args.loglevel, args.loglevel);
    rs_utilities::LogHelper::init_logger("rstun", log_filter.as_str());

    let config = ClientConfig::create(
        &args.server_addr,
        &args.password,
        &args.cert,
        &args.cipher,
        &args.tcp_mappings,
        &args.udp_mappings,
        &args.dot,
        &args.dns,
        args.workers,
        args.wait_before_retry_ms,
        args.quic_timeout_ms,
        args.tcp_timeout_ms,
        args.udp_timeout_ms,
        args.heartbeat_interval_ms,
        args.heartbeat_timeout_ms,
        args.hop_interval_ms,
    )
    .map_err(|e| {
        error!("{e}");
    });

    if let Ok(config) = config {
        let mut client = Client::new(config);

        #[cfg(target_os = "android")]
        {
            use log::info;
            let receiver = client.register_for_events();
            std::thread::spawn(move || {
                for event in receiver {
                    if let Ok(json) = event.to_json() {
                        info!("{json}");
                    }
                }
            });
        }

        client.start_tunneling();
    }
}

fn run_server(args: ServerArgs) {
    let log_filter = format!("rstun={},rs_utilities={}", args.loglevel, args.loglevel);
    rs_utilities::LogHelper::init_logger("rstun", log_filter.as_str());

    let workers = if args.workers > 0 {
        args.workers
    } else {
        num_cpus::get()
    };

    info!("will use {workers} workers");

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(workers)
        .build()
        .unwrap()
        .block_on(async {
            run_server_async(args)
                .await
                .map_err(|e| {
                    error!("{e}");
                })
                .ok();
        })
}

async fn run_server_async(mut args: ServerArgs) -> Result<()> {
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
#[command(
    author,
    version,
    about = "TCP/UDP tunneling over QUIC (TLS 1.3)",
    long_about = "TCP/UDP tunneling over QUIC (TLS 1.3).\n\nUse `rstun client` to initiate tunnels and `rstun server` to accept them.",
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run client mode (initiates tunnel mappings)
    #[command(alias = "c")]
    Client(ClientArgs),
    /// Run server mode (accepts tunnels and forwards traffic)
    #[command(alias = "s")]
    Server(ServerArgs),
}

#[derive(Parser, Debug)]
#[command(
    about = "Start rstun client",
    long_about = "Start rstun in client mode.\n\nAt least one of `--tcp-mappings` or `--udp-mappings` must be provided.\nMapping format: `MODE^[ip:]port^[ip:]port` where MODE is `OUT` or `IN`.\nUse `ANY` as destination in OUT mode to use the server's default upstream."
)]
struct ClientArgs {
    /// Server address (<domain|ip>[:port]) of rstun server. Default port is 3515.
    #[arg(short = 'a', long)]
    server_addr: String,

    /// Password for server authentication (must match server's --password)
    #[arg(short = 'p', long, required = true)]
    password: String,

    /// Comma-separated list of TCP tunnel mappings. Each mapping is in the form MODE^[ip:]port^[ip:]port, e.g. OUT^8080^0.0.0.0:9090
    /// MODE is either OUT or IN. Use OUT^8000^ANY to use the server's default upstream for OUT mode.
    #[arg(
        short = 't',
        long,
        verbatim_doc_comment,
        default_value = "",
        hide_default_value = true
    )]
    tcp_mappings: String,

    /// Comma-separated list of UDP tunnel mappings. Each mapping is in the form MODE^[ip:]port^[ip:]port, e.g. OUT^8080^0.0.0.0:9090
    /// MODE is either OUT or IN. Use OUT^8000^ANY to use the server's default upstream for OUT mode.
    #[arg(
        short = 'u',
        long,
        verbatim_doc_comment,
        default_value = "",
        hide_default_value = true
    )]
    udp_mappings: String,

    /// Path to the certificate file (only needed for self-signed certificates)
    #[arg(short = 'c', long, default_value = "", hide_default_value = true)]
    cert: String,

    /// Preferred cipher suite
    #[arg(short = 'e', long, default_value_t = String::from(SUPPORTED_CIPHER_SUITE_STRS[0]),
        value_parser = PossibleValuesParser::new(SUPPORTED_CIPHER_SUITE_STRS).map(|v| v.to_string()))]
    cipher: String,

    /// Number of async worker threads [uses all logical CPUs if 0]
    #[arg(short = 'w', long, default_value_t = 0)]
    workers: usize,

    /// Wait time in milliseconds before retrying connection
    #[arg(short = 'r', long, default_value_t = 5000)]
    wait_before_retry_ms: u64,

    /// QUIC idle timeout in milliseconds
    #[arg(long, default_value_t = 30000)]
    quic_timeout_ms: u64,

    /// TCP idle timeout in milliseconds
    #[arg(long, default_value_t = 30000)]
    tcp_timeout_ms: u64,

    /// UDP idle timeout in milliseconds
    #[arg(long, default_value_t = 5000)]
    udp_timeout_ms: u64,

    /// Heartbeat interval in milliseconds (0 to disable)
    #[arg(long, default_value_t = 5000)]
    heartbeat_interval_ms: u64,

    /// Heartbeat timeout in milliseconds (0 to disable)
    #[arg(long, default_value_t = 10000)]
    heartbeat_timeout_ms: u64,

    /// QUIC endpoint migration interval in milliseconds (0 to disable). Values below 5000 are raised to 5000.
    #[arg(long, default_value_t = 0)]
    hop_interval_ms: u64,

    /// Comma-separated DoT servers (domains) for DNS resolution, e.g. "dns.google,one.one.one.one". Takes precedence over --dns if set.
    #[arg(
        long,
        verbatim_doc_comment,
        default_value = "",
        hide_default_value = true
    )]
    dot: String,

    /// Comma-separated DNS servers (IPs) for DNS resolution, e.g. "1.1.1.1,8.8.8.8"
    #[arg(
        long,
        verbatim_doc_comment,
        default_value = "",
        hide_default_value = true
    )]
    dns: String,

    /// Log level
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

#[derive(Parser, Debug)]
#[command(
    about = "Start rstun server",
    long_about = "Start rstun in server mode.\n\nThe server authenticates clients with `--password`, then forwards TCP/UDP streams according to each client's tunnel mode and mapping."
)]
struct ServerArgs {
    /// Address ([ip:]port) to listen on. If only a port is given, binds to 127.0.0.1:PORT.
    /// Defaults to 0.0.0.0:0 (system-selected port on all interfaces).
    #[arg(short = 'a', long, default_value = "0.0.0.0:0", verbatim_doc_comment)]
    addr: String,

    /// Default TCP upstream for OUT tunnels ([ip:]port). Used if client does not specify an upstream.
    #[arg(
        short = 't',
        long,
        required = false,
        default_value = "",
        verbatim_doc_comment,
        hide_default_value = true
    )]
    tcp_upstream: String,

    /// Default UDP upstream for OUT tunnels ([ip:]port). Used if client does not specify an upstream.
    #[arg(
        short = 'u',
        long,
        required = false,
        default_value = "",
        verbatim_doc_comment,
        hide_default_value = true
    )]
    udp_upstream: String,

    /// Server password (required, must match client --password)
    #[arg(short = 'p', long, required = true)]
    password: String,

    /// Path to certificate file (optional). If empty, a self-signed certificate for "localhost" is generated (testing only).
    #[arg(
        short = 'c',
        long,
        default_value = "",
        verbatim_doc_comment,
        hide_default_value = true
    )]
    cert: String,

    /// Path to key file (optional, only needed if --cert is set)
    #[arg(short = 'k', long, default_value = "", hide_default_value = true)]
    key: String,

    /// Number of async worker threads [uses all logical CPUs if 0]
    #[arg(short = 'w', long, default_value_t = 0)]
    workers: usize,

    /// QUIC idle timeout in milliseconds
    #[arg(long, default_value_t = 40000)]
    quic_timeout_ms: u64,

    /// TCP idle timeout in milliseconds
    #[arg(long, default_value_t = 30000)]
    tcp_timeout_ms: u64,

    /// UDP idle timeout in milliseconds
    #[arg(long, default_value_t = 5000)]
    udp_timeout_ms: u64,

    /// Log level
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
