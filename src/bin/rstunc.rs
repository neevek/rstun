use anyhow::Result;
use clap::Parser;
use log::info;
use log::{debug, error};
use rstun::*;
use tokio::time::Duration;

extern crate colored;
extern crate pretty_env_logger;

const MODE_IN: &str = "IN";
const MODE_OUT: &str = "OUT";

fn main() {
    //raise_fd_limit();

    let mut config = ClientConfig::default();
    if !parse_command_line_args(&mut config) {
        return;
    }

    LogHelper::init_logger(config.loglevel.as_ref());

    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::TRACE)
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .finish(),
    )
    .unwrap();

    let worker_threads = num_cpus::get() + 1;
    info!("will use {} worker threads", worker_threads);

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(worker_threads)
        .build()
        .unwrap()
        .block_on(async {
            run(config).await.unwrap();
        });
}

fn parse_command_line_args(config: &mut ClientConfig) -> bool {
    let args = RstuncArgs::parse();

    let addrs: Vec<&str> = args.addr_mapping.split("^").collect();
    if addrs.len() != 2 {
        print!("invalid address mapping: {}", args.addr_mapping);
        return false;
    }
    let mut addrs: Vec<String> = addrs.iter().map(|s| s.to_string()).collect();

    for addr in &mut addrs {
        if !addr.contains(":") {
            *addr = format!("127.0.0.1:{}", addr);
        }
    }

    config.cert_path = args.cert;
    config.server_addr = args.server_addr;
    config.loglevel = args.loglevel;
    config.connect_max_retry = 0;
    config.wait_before_retry_ms = 5 * 1000;
    config.max_idle_timeout_ms = 5 * 1000;
    config.keep_alive_interval_ms = config.max_idle_timeout_ms / 2;
    config.mode = if args.mode == MODE_IN {
        MODE_IN
    } else {
        MODE_OUT
    };

    let local_access_server_addr;
    config.login_msg = if args.mode == MODE_IN {
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

    config.local_access_server_addr = Some(
        local_access_server_addr.parse().expect(
            format!(
                "invalid local_access_server_addr: {}",
                local_access_server_addr
            )
            .as_str(),
        ),
    );

    true
}

async fn run(config: ClientConfig) -> Result<()> {
    let mut access_server = None;
    if config.mode == MODE_OUT {
        let mut tmp_access_server = AccessServer::new(config.local_access_server_addr.unwrap());
        tmp_access_server.bind().await?;
        tmp_access_server.start().await?;
        access_server = Some(tmp_access_server);
    }

    let mut connect_retry_count = 0;
    let connect_max_retry = config.connect_max_retry;
    let wait_before_retry_ms = config.wait_before_retry_ms;
    let mut client = Client::new(config);

    loop {
        match client.connect().await {
            Ok(_) => {
                connect_retry_count = 0;
                if client.config.mode == MODE_OUT {
                    client
                        .serve_outgoing(access_server.as_mut().unwrap().tcp_receiver_ref())
                        .await
                        .ok();
                } else {
                    client.serve_incoming().await.ok();
                }
            }

            Err(e) => {
                error!("connect failed, err: {}", e);
                if connect_max_retry > 0 {
                    connect_retry_count += 1;
                    if connect_retry_count >= connect_max_retry {
                        info!(
                            "quit after having retried for {} times",
                            connect_retry_count
                        );
                        break;
                    }
                }

                debug!(
                    "will wait for {}ms before retrying...",
                    wait_before_retry_ms
                );
                tokio::time::sleep(Duration::from_millis(wait_before_retry_ms)).await;
            }
        }

        if !client.should_retry() {
            info!("client quit!");
            break;
        }
    }
    Ok(())
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct RstuncArgs {
    /// Create a tunnel running in IN or OUT mode
    #[clap(short = 'm', long, possible_values = &[MODE_IN, MODE_OUT], display_order = 1)]
    mode: String,

    /// Address (ip:port pair) of rstund
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

    /// Log level
    #[clap(short = 'l', long, possible_values = &["T", "D", "I", "W", "E"], default_value = "I", display_order = 6)]
    loglevel: String,
}
