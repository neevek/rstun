use clap::Parser;
use clap::builder::PossibleValuesParser;
use clap::builder::TypedValueParser as _;
use log::error;
use rstun::*;

fn main() {
    let args = RstuncArgs::parse();
    let log_filter = format!("rstun={},rs_utilities={}", args.loglevel, args.loglevel);
    rs_utilities::LogHelper::init_logger("rstunc", log_filter.as_str());

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
            client.set_enable_on_info_report(true);
            let receiver = client.register_for_events();
            std::thread::spawn(move || {
                for event in receiver {
                    if let Ok(json) = serde_json::to_string(&event) {
                        info!("{json}");
                    }
                }
            });
        }

        client.set_enable_on_info_report(true);
        let c = client.clone();
        std::thread::spawn(move || {
            for event in c.register_for_events() {
                if let Ok(json) = serde_json::to_string(&event) {
                    log::debug!("EVENT = {json}");
                }
            }
        });

        client.start_tunneling();
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct RstuncArgs {
    /// Server address (<domain:ip>[:port]) of rstund. Default port is 3515.
    #[arg(short = 'a', long)]
    server_addr: String,

    /// Password for server authentication (must match server's --password)
    #[arg(short = 'p', long, required = true)]
    password: String,

    /// Comma-separated list of TCP tunnel mappings. Each mapping is in the form MODE^[ip:]port^[ip:]port, e.g. OUT^8080^0.0.0.0:9090
    /// MODE is either OUT or IN. Use OUT^8000^ANY to use the server's default upstream for OUT mode.
    #[arg(short = 't', long, verbatim_doc_comment, default_value = "")]
    tcp_mappings: String,

    /// Comma-separated list of UDP tunnel mappings. Each mapping is in the form MODE^[ip:]port^[ip:]port, e.g. OUT^8080^0.0.0.0:9090
    /// MODE is either OUT or IN. Use OUT^8000^ANY to use the server's default upstream for OUT mode.
    #[arg(short = 'u', long, verbatim_doc_comment, default_value = "")]
    udp_mappings: String,

    /// Path to the certificate file (only needed for self-signed certificates)
    #[arg(short = 'c', long, default_value = "")]
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

    #[arg(long, default_value_t = 0)]
    hop_interval_ms: u64,

    /// Comma-separated DoT servers (domains) for DNS resolution, e.g. "dns.google,one.one.one.one". Takes precedence over --dns if set.
    #[arg(long, verbatim_doc_comment, default_value = "")]
    dot: String,

    /// Comma-separated DNS servers (IPs) for DNS resolution, e.g. "1.1.1.1,8.8.8.8"
    #[arg(long, verbatim_doc_comment, default_value = "")]
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
