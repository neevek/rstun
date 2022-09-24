use clap::Parser;
use log::error;
use rstun::*;

fn main() {
    let args = RstuncArgs::parse();
    rs_utilities::LogHelper::init_logger("rstunc", args.loglevel.as_ref());

    let mut config = ClientConfig::default();
    if !parse_command_line_args(args, &mut config) {
        return;
    }

    let mut client = Client::new(config);
    client.set_enable_on_info_report(true);
    client.set_on_info_listener(|s| {
        error!("{}", s);
    });
    client.start_tunnelling();
}

fn parse_command_line_args(args: RstuncArgs, config: &mut ClientConfig) -> bool {
    let addrs: Vec<&str> = args.addr_mapping.split('^').collect();
    if addrs.len() != 2 {
        error!("invalid address mapping: {}", args.addr_mapping);
        return false;
    }
    let mut addrs: Vec<String> = addrs.iter().map(|s| s.to_string()).collect();

    for addr in &mut addrs {
        if !addr.contains(':') {
            *addr = format!("127.0.0.1:{}", addr);
        }
    }

    config.cert_path = args.cert;
    config.server_addr = args.server_addr;
    config.threads = if args.threads > 0 {
        args.threads
    } else {
        num_cpus::get()
    };
    config.connect_max_retry = 0;
    config.wait_before_retry_ms = args.wait_before_retry_ms;
    config.max_idle_timeout_ms = args.max_idle_timeout_ms;
    config.keep_alive_interval_ms = config.max_idle_timeout_ms / 2;
    config.mode = if args.mode == TUNNEL_MODE_IN {
        TUNNEL_MODE_IN
    } else {
        TUNNEL_MODE_OUT
    };

    let local_access_server_addr;
    config.login_msg = if args.mode == TUNNEL_MODE_IN {
        local_access_server_addr = addrs[1].to_string();
        Some(TunnelMessage::ReqInLogin(LoginInfo {
            password: args.password,
            access_server_addr: addrs[0].to_string(),
        }))
    } else {
        local_access_server_addr = addrs[0].to_string();
        Some(TunnelMessage::ReqOutLogin(LoginInfo {
            password: args.password,
            access_server_addr: addrs[1].to_string(),
        }))
    };

    config.local_access_server_addr = Some(local_access_server_addr.parse().unwrap_or_else(|e| {
        panic!(
            "invalid local_access_server_addr: {}, {}",
            local_access_server_addr, e
        )
    }));

    true
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct RstuncArgs {
    /// Create a tunnel running in IN or OUT mode
    #[clap(short = 'm', long, possible_values = &[TUNNEL_MODE_IN, TUNNEL_MODE_OUT], display_order = 1)]
    mode: String,

    /// Address (<domain:ip>[:port] pair) of rstund
    #[clap(short = 'r', long, display_order = 2)]
    server_addr: String,

    /// Password to connect with rstund
    #[clap(short = 'p', long, required = true, display_order = 3)]
    password: String,

    /// Path to the certificate file in DER format
    #[clap(short = 'c', long, required = true, display_order = 4)]
    cert: String,

    /// LOCAL and REMOTE mapping in [ip:]port^[ip:]port format, e.g. 8080^0.0.0.0:9090
    #[clap(short = 'a', long, display_order = 5)]
    addr_mapping: String,

    /// Threads to run async tasks
    #[clap(short = 't', long, default_value = "0", display_order = 6)]
    threads: usize,

    /// Wait time before trying
    #[clap(short = 'w', long, default_value = "5000", display_order = 7)]
    wait_before_retry_ms: u64,

    /// Max idle timeout for the connection
    #[clap(short = 'i', long, default_value = "20000", display_order = 8)]
    max_idle_timeout_ms: u64,

    /// Log level
    #[clap(short = 'l', long, possible_values = &["T", "D", "I", "W", "E"], default_value = "I", display_order = 11)]
    loglevel: String,
}
