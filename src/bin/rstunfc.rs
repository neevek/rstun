use anyhow::Result;
use colored::Colorize;
use log::info;
use log::{debug, error};
use rstun::ClientConfig;
use rstun::{AccessServer, Client};
use std::io::Write;
use tokio::time::Duration;

extern crate colored;
extern crate pretty_env_logger;

fn main() {
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::TRACE)
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .finish(),
    )
    .unwrap();

    init_logger();

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(16)
        .build()
        .unwrap()
        .block_on(async {
            run().await.unwrap();
        });
}

async fn run() -> Result<()> {
    let mut config = ClientConfig::default();
    config.server_addr = "127.0.0.1:3515".into();
    config.local_access_server_addr = "0.0.0.0:3618".into();
    config.password = "password".to_string();
    config.remote_downstream_name = "http".to_string();
    config.cert_path = "localhost.crt.der".to_string();
    config.connect_max_retry = 0;
    config.wait_before_retry_ms = 5 * 1000;
    config.max_idle_timeout_ms = 5 * 1000;
    config.keep_alive_interval_ms = config.max_idle_timeout_ms / 2;

    let mut access_server = AccessServer::new(config.local_access_server_addr.clone());
    access_server.bind().await?;
    access_server.start().await?;

    let mut connect_retry_count = 0;
    let connect_max_retry = config.connect_max_retry;
    let wait_before_retry_ms = config.wait_before_retry_ms;
    let mut client = Client::new(config);

    loop {
        match client.connect().await {
            Ok(_) => {
                connect_retry_count = 0;
                client.serve(access_server.tcp_receiver()).await.unwrap();
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
    }
    Ok(())
}

fn init_logger() {
    pretty_env_logger::formatted_timed_builder()
        .format(|buf, record| {
            let level = record.level();
            let level = match level {
                log::Level::Trace => "T".white(),
                log::Level::Debug => "D".green(),
                log::Level::Info => "I".blue(),
                log::Level::Warn => "W".yellow(),
                log::Level::Error => "E".red(),
            };
            let filename = record.file().unwrap_or("unknown");
            let filename = &filename[filename.rfind('/').map(|pos| pos + 1).unwrap_or(0)..];
            writeln!(
                buf,
                "{} [{}:{}] [{}] - {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S.%3f"),
                filename,
                record.line().unwrap_or(0),
                level,
                record.args()
            )
        })
        .filter(Some("rstun"), log::LevelFilter::Trace)
        .init();
}
