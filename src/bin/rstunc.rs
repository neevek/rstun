use clap::builder::PossibleValuesParser;
use clap::builder::TypedValueParser as _;
use clap::Parser;
use log::error;
use rstun::*;

fn main() {
    let args = RstuncArgs::parse();
    let log_filter = format!("rstun={},rs_utilities={}", args.loglevel, args.loglevel);
    rs_utilities::LogHelper::init_logger("rstunc", log_filter.as_str());

    let config = ClientConfig::create(
        &args.mode,
        &args.server_addr,
        &args.password,
        &args.cert,
        &args.cipher,
        &args.tcp_mapping,
        &args.udp_mapping,
        &args.dot,
        &args.dns,
        args.workers,
        args.wait_before_retry_ms,
        args.quic_timeout_ms,
        args.tcp_timeout_ms,
        args.udp_timeout_ms,
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
            client.set_on_info_listener(|s| {
                info!("{}", s);
            });
        }

        client.start_tunneling();
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct RstuncArgs {
    /// Create a tunnel running in IN or OUT mode
    #[arg(short = 'm', long, value_parser = PossibleValuesParser::new([TUNNEL_MODE_IN, TUNNEL_MODE_OUT]))]
    mode: String,

    /// Address (<domain:ip>[:port] pair) of rstund, default port is 3515
    #[arg(short = 'a', long)]
    server_addr: String,

    /// Password to connect with rstund
    #[arg(short = 'p', long, required = true)]
    password: String,

    /// LOCAL and REMOTE mapping in [ip:]port^[ip:]port format, e.g. 8080^0.0.0.0:9090
    /// `8000^ANY` for not explicitly specifying the upstream on the server, the server
    ///            decides that port, so it depends on that the server is started with
    ///            explicitly setting the `--tcp-upstream` option.
    #[arg(short = 't', long, verbatim_doc_comment, default_value = "")]
    tcp_mapping: String,

    /// LOCAL and REMOTE mapping in [ip:]port^[ip:]port format, e.g. 8080^0.0.0.0:9090
    /// `8000^ANY` for not explicitly specifying the upstream on the server, the server
    ///            decides that port, so it depends on that the server is started with
    ///            explicitly setting the `--udp-upstream` option.
    #[arg(short = 'u', long, verbatim_doc_comment, default_value = "")]
    udp_mapping: String,

    /// Path to the certificate file, only needed for self signed certificate
    #[arg(short = 'c', long, default_value = "")]
    cert: String,

    /// Preferred cipher suite
    #[arg(short = 'e', long, default_value_t = String::from(SUPPORTED_CIPHER_SUITE_STRS[0]),
        value_parser = PossibleValuesParser::new(SUPPORTED_CIPHER_SUITE_STRS).map(|v| v.to_string()))]
    cipher: String,

    /// Workers to run async tasks
    #[arg(short = 'w', long, default_value_t = 0)]
    workers: usize,

    /// Wait time in milliseconds before trying
    #[arg(short = 'r', long, default_value_t = 5000)]
    wait_before_retry_ms: u64,

    /// Quic idle timeout in milliseconds for the connection
    #[arg(long, default_value_t = 30000)]
    quic_timeout_ms: u64,

    /// Tcp idle timeout in milliseconds for the connection
    #[arg(long, default_value_t = 30000)]
    tcp_timeout_ms: u64,

    /// Udp idle timeout in milliseconds for the connection
    #[arg(long, default_value_t = 5000)]
    udp_timeout_ms: u64,

    /// Comma separated DoT servers (domains) used to resolve the server address (domain)
    /// e.g. "dns.google,one.one.one.one"
    /// Note that DoT servers will be resolved using any available system DNS
    #[arg(long, verbatim_doc_comment, default_value = "")]
    dot: String,

    /// Comma separated DNS' (IPs) used to resolve the server address (domain)
    /// Note that the --dot option if not empty takes precedence over this option
    /// e.g. "1.1.1.1,8.8.8.8"
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
