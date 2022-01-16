use anyhow::Result;
use clap::Parser;
use log::info;
use log::{debug, error};
use rstun::ClientConfig;
use rstun::LogHelper;
use rstun::{AccessServer, Client};
use tokio::time::Duration;

extern crate colored;
extern crate pretty_env_logger;

fn main() {
    //raise_fd_limit();

    let args = RstuncArgs::parse();

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
        });
}

async fn run(args: RstuncArgs) -> Result<()> {
    let mut config = ClientConfig::default();

    config.server_addr = args.server_addr;
    config.local_access_server_addr = args.addr;
    config.password = args.password;
    config.remote_downstream_name = args.remote_downstream_name;
    config.cert_path = args.cert;
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

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct RstuncArgs {
    /// Address (ip:port pair) to listen on
    #[clap(short, long, display_order = 1)]
    addr: String,

    /// Address (ip:port pair) of rstund
    #[clap(short, long, display_order = 2)]
    server_addr: String,

    /// Name of the remote downstream server the traffic will be relayed to
    #[clap(short, long, required = true, display_order = 3)]
    remote_downstream_name: String,

    /// Password of the tunnel server
    #[clap(short, long, required = true, display_order = 4)]
    password: String,

    /// Path to the certificate file in DER format
    #[clap(short, long, required = true, display_order = 5)]
    cert: String,

    #[clap(short, long, possible_values = &["T", "D", "I", "W", "E"], default_value = "I", display_order = 6)]
    loglevel: String,
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
#[allow(non_camel_case_types)]
pub fn raise_fd_limit() -> Option<u64> {
    use std::io;
    use std::mem::size_of_val;
    use std::ptr::null_mut;

    unsafe {
        static CTL_KERN: libc::c_int = 1;
        static KERN_MAXFILESPERPROC: libc::c_int = 29;

        // The strategy here is to fetch the current resource limits, read the
        // kern.maxfilesperproc sysctl value, and bump the soft resource limit for
        // maxfiles up to the sysctl value.

        // Fetch the kern.maxfilesperproc value
        let mut mib: [libc::c_int; 2] = [CTL_KERN, KERN_MAXFILESPERPROC];
        let mut maxfiles: libc::c_int = 0;
        let mut size: libc::size_t = size_of_val(&maxfiles) as libc::size_t;
        if libc::sysctl(
            &mut mib[0],
            2,
            &mut maxfiles as *mut _ as *mut _,
            &mut size,
            null_mut(),
            0,
        ) != 0
        {
            let err = io::Error::last_os_error();
            panic!("raise_fd_limit: error calling sysctl: {}", err);
        }

        // Fetch the current resource limits
        let mut rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) != 0 {
            let err = io::Error::last_os_error();
            panic!("raise_fd_limit: error calling getrlimit: {}", err);
        }

        // Bump the soft limit to the smaller of kern.maxfilesperproc and the hard
        // limit
        rlim.rlim_cur = 55;

        // Set our newly-increased resource limit
        if libc::setrlimit(libc::RLIMIT_NOFILE, &rlim) != 0 {
            let err = io::Error::last_os_error();
            panic!("raise_fd_limit: error calling setrlimit: {}", err);
        }

        Some(rlim.rlim_cur)
    }
}
