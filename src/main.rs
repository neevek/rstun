use colored::Colorize;
use log::info;
use std::io::Write;

extern crate colored;
extern crate pretty_env_logger;

fn main() {
    println!("hello 1>>>");
    init_logger();
    println!("hello 2>>>");
    log::debug!("hello 1");
    log::info!("hello 1");
    log::warn!("hello 1");
    log::error!("hello 1");
    //run();
}

//#[tokio::main]
//async fn run() {
//info!("hello 2");
//let mut config = ServerConfig::default();
//info!("hello 3");
//config.addr = "0.0.0.0:3515".into();
//let mut server = Server::bind(config).unwrap();
//info!("hello 4");
//server.run().await;
//info!("hello 5");
//}

fn init_logger() {
    pretty_env_logger::formatted_timed_builder()
        //.format(|buf, record| {
        //let level = record.level();
        //let level = match level {
        //log::Level::Trace => "T".white(),
        //log::Level::Debug => "D".green(),
        //log::Level::Info => "I".blue(),
        //log::Level::Warn => "W".yellow(),
        //log::Level::Error => "E".red(),
        //};
        //let filename = record.file().unwrap_or("unknown");
        //let filename = &filename[filename.rfind('/').map(|pos| pos + 1).unwrap_or(0)..];
        //writeln!(
        //buf,
        //"{} [{}:{}] [{}] - {}",
        //chrono::Local::now().format("%Y-%m-%d %H:%M:%S.%3f"),
        //filename,
        //record.line().unwrap_or(0),
        //level,
        //record.args()
        //)
        //})
        .filter(Some("rustun2"), log::LevelFilter::Debug)
        //.filter_level(log::LevelFilter::Debug)
        .init();
}
