use anyhow::{bail, Result};
use clap::Parser;
use rstun::LogHelper;
use rstun::Server;
use rstun::ServerConfig;
use std::collections::HashMap;

extern crate pretty_env_logger;

fn main() {
    // usage: ./target/debug/rstund -a 0.0.0.0:3333 -d http=127.0.0.1:9800 -k localhost.key.der -c localhost.crt.der -p password

    let args = RstundArgs::parse();

    LogHelper::init_logger(args.loglevel.as_str());

    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::TRACE)
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .finish(),
    )
    .unwrap();

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(16)
        .build()
        .unwrap()
        .block_on(async {
            run(args).await.unwrap();
        })
}

async fn run(args: RstundArgs) -> Result<()> {
    let mut downstreams = HashMap::new();

    for d in args.downstream.iter() {
        let split = d.split("=");
        let pair: Vec<&str> = split.collect();
        if pair.len() != 2 {
            bail!("invalid downstream: {}", d);
        }
        downstreams.insert(pair[0].into(), pair[1].into());
    }

    let mut config = ServerConfig::default();
    config.addr = args.addr;
    config.password = args.password;
    config.cert_path = args.cert;
    config.key_path = args.key;
    config.downstreams = downstreams;

    let mut server = Server::new(config);
    server.start().await?;
    Ok(())
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct RstundArgs {
    /// Address (ip:port pair) to listen on
    #[clap(short = 'l', long, display_order = 1)]
    addr: String,

    /// Downstream as the receiving end of the tunnel, e.g. -d name1=ip:port
    #[clap(short = 'd', long, required = true, min_values = 1, display_order = 2)]
    downstream: Vec<String>,

    /// Password of the tunnel server
    #[clap(short = 'p', long, required = true, display_order = 3)]
    password: String,

    /// Path to the certificate file in DER format
    #[clap(short = 'c', long, required = true, display_order = 4)]
    cert: String,

    /// Path to the key file in DER format
    #[clap(short = 'k', long, required = true, display_order = 5)]
    key: String,

    #[clap(short = 'L', long, possible_values = &["T", "D", "I", "W", "E"], default_value = "I", display_order = 6)]
    loglevel: String,
}
