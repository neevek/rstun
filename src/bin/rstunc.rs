use clap::builder::PossibleValuesParser;
use clap::builder::TypedValueParser as _;
use clap::Parser;
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
        &args.addr_mapping,
        args.threads,
        args.wait_before_retry_ms,
        args.max_idle_timeout_ms,
    );

    if let Ok(config) = config {
        let client = Client::new(config);

        #[cfg(target_os = "android")]
        {
            use log::info;
            client.set_enable_on_info_report(true);
            client.set_on_info_listener(|s| {
                info!("{}", s);
            });
        }

        client.start_tunnelling();
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct RstuncArgs {
    /// Create a tunnel running in IN or OUT mode
    #[arg(short = 'm', long, value_parser = PossibleValuesParser::new([TUNNEL_MODE_IN, TUNNEL_MODE_OUT]))]
    mode: String,

    /// Address (<domain:ip>[:port] pair) of rstund, default port is 3515
    #[arg(short = 'r', long, display_order = 2)]
    server_addr: String,

    /// Password to connect with rstund
    #[arg(short = 'p', long, required = true, display_order = 3)]
    password: String,

    /// LOCAL and REMOTE mapping in [ip:]port^[ip:]port format, e.g. 8080^0.0.0.0:9090
    /// `ANY^8000` for not explicitly specifying a port for the local access server (the client)
    /// `8000^ANY` for not explicitly specifying a port to bind with the remote server,
    ///            the server decides that port, so it depends on that the server is started
    ///            with explicitly setting the `--upstreams` option.
    /// `ANY^ANY` both the cases of the settings above.
    #[arg(short = 'a', long, display_order = 4)]
    addr_mapping: String,

    /// Path to the certificate file, only needed for self signed certificate
    #[arg(short = 'c', long, default_value = "", display_order = 5)]
    cert: String,

    /// Preferred cipher suite
    #[arg(short = 'e', long, default_value_t = String::from(SUPPORTED_CIPHER_SUITE_STRS[0]),
        value_parser = PossibleValuesParser::new(SUPPORTED_CIPHER_SUITE_STRS).map(|v| v.to_string()))]
    cipher: String,

    /// Threads to run async tasks
    #[arg(short = 't', long, default_value_t = 0)]
    threads: usize,

    /// Wait time before trying
    #[arg(short = 'w', long, default_value_t = 5000)]
    wait_before_retry_ms: u64,

    /// Max idle timeout for the connection
    #[arg(short = 'i', long, default_value_t = 30000)]
    max_idle_timeout_ms: u64,

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
