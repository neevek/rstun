use anyhow::{bail, Context, Result};
use clap::Parser;
use log::error;
use rs_utilities::log_and_bail;
use rstun::*;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn main() {
    let args = RstuncArgs::parse();
    rs_utilities::LogHelper::init_logger("rstunc", args.loglevel.as_ref());
    if let Ok(config) = parse_command_line_args(args) {
        let mut client = Client::new(config);
        // client.set_enable_on_info_report(true);
        // client.set_on_info_listener(|s| {
        //     error!("{}", s);
        // });
        client.start_tunnelling();
    }
}

fn parse_command_line_args(args: RstuncArgs) -> Result<ClientConfig> {
    let mut config = ClientConfig::default();
    let addr_mapping: Vec<&str> = args.addr_mapping.split('^').collect();
    if addr_mapping.len() != 2 {
        log_and_bail!("invalid address mapping: {}", args.addr_mapping);
    }

    let mut addr_mapping: Vec<String> = addr_mapping.iter().map(|addr| addr.to_string()).collect();
    let mut sock_addr_mapping: Vec<SocketAddr> = Vec::with_capacity(addr_mapping.len());

    for addr in &mut addr_mapping {
        if addr == "ANY" {
            sock_addr_mapping.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
        } else {
            if !addr.contains(':') {
                *addr = format!("127.0.0.1:{}", addr);
            }
            sock_addr_mapping.push(
                addr.parse::<SocketAddr>()
                    .context(format!("invalid address mapping:[{}]", args.addr_mapping))?,
            );
        }
    }

    config.cert_path = args.cert;
    config.cipher = args.cipher;
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

    config.login_msg = if args.mode == TUNNEL_MODE_IN {
        config.local_access_server_addr = Some(sock_addr_mapping[1]);
        Some(TunnelMessage::ReqInLogin(LoginInfo {
            password: args.password,
            access_server_addr: sock_addr_mapping[0],
        }))
    } else {
        config.local_access_server_addr = Some(sock_addr_mapping[0]);
        Some(TunnelMessage::ReqOutLogin(LoginInfo {
            password: args.password,
            access_server_addr: sock_addr_mapping[1],
        }))
    };

    Ok(config)
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
    /// ANY^ANY means
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
    #[clap(short = 'i', long, default_value = "150000", display_order = 9)]
    max_idle_timeout_ms: u64,

    /// Log level
    #[clap(short = 'l', long, possible_values = &["T", "D", "I", "W", "E"], default_value = "I", display_order = 10)]
    loglevel: String,
}
