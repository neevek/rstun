use anyhow::Result;
use colored::Colorize;
use rstun::Server;
use rstun::ServerConfig;
use std::io::Write;

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
        .build()
        .unwrap()
        .block_on(async {
            run().await.unwrap();
        })
}

async fn run() -> Result<()> {
    let mut config = ServerConfig::default();
    config.addr = "127.0.0.1:3515".into();
    config.cert_path = "/Users/neevek/dev/bb/rstun/localhost.crt.pem".to_string();
    config.key_path = "/Users/neevek/dev/bb/rstun/localhost.key.pem".to_string();

    let mut server = Server::new(config);
    server.start().await?;
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
