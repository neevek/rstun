use anyhow::Result;
use colored::Colorize;
use rstun::Client;
use rstun::ClientConfig;
use std::io::Write;

extern crate colored;
extern crate pretty_env_logger;

#[tokio::main]
async fn main() -> Result<()> {
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::TRACE)
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .finish(),
    )
    .unwrap();

    init_logger();
    run().await?;
    Ok(())
}

async fn run() -> Result<()> {
    let mut config = ClientConfig::default();
    config.server_addr = "127.0.0.1:3515".into();
    config.local_access_server_addr = "127.0.0.1:3618".into();
    config.password = "password".to_string();
    config.remote_downstream_name = "http".to_string();
    config.cert_path = "/Users/neevek/dev/bb/rstun/localhost.crt.pem".to_string();
    let client = Client::connect(config).await.unwrap();
    client.run().await?;
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
