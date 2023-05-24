use clap::Parser;
use rstun::*;

fn main() {
    let args = RstuncArgs::parse();
    rs_utilities::LogHelper::init_logger("rstunc", args.loglevel.as_ref());
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
#[clap(author, version, about, long_about = None)]
struct RstuncArgs {
    /// Create a tunnel running in IN or OUT mode
    #[clap(short = 'm', long, possible_values = &[TUNNEL_MODE_IN, TUNNEL_MODE_OUT], display_order = 1)]
    mode: String,

    /// Address (<domain:ip>[:port] pair) of rstund, default port is 3515
    #[clap(short = 'r', long, display_order = 2)]
    server_addr: String,

    /// Password to connect with rstund
    #[clap(short = 'p', long, required = true, display_order = 3)]
    password: String,

    /// LOCAL and REMOTE mapping in [ip:]port^[ip:]port format, e.g. 8080^0.0.0.0:9090
    /// `ANY^8000` for not explicitly specifying a port for the local access server (the client)
    /// `8000^ANY` for not explicitly specifying a port to bind with the remote server,
    ///            the server decides that port, so it depends on that the server is started
    ///            with explicitly setting the `--upstreams` option.
    /// `ANY^ANY` both the cases of the settings above.
    #[clap(short = 'a', long, display_order = 4)]
    addr_mapping: String,

    /// Path to the certificate file in DER format, only needed for self signed certificate
    #[clap(short = 'c', long, default_value = "", display_order = 5)]
    cert: String,

    /// Preferred cipher suite
    #[clap(short = 'e', long, default_value = SUPPORTED_CIPHER_SUITES[0], display_order = 6, possible_values = SUPPORTED_CIPHER_SUITES)]
    cipher: String,

    /// Threads to run async tasks
    #[clap(short = 't', long, default_value = "0", display_order = 7)]
    threads: usize,

    /// Wait time before trying
    #[clap(short = 'w', long, default_value = "5000", display_order = 8)]
    wait_before_retry_ms: u64,

    /// Max idle timeout for the connection
    #[clap(short = 'i', long, default_value = "30000", display_order = 9)]
    max_idle_timeout_ms: u64,

    /// Log level
    #[clap(short = 'l', long, possible_values = &["T", "D", "I", "W", "E"], default_value = "I", display_order = 10)]
    loglevel: String,
}
