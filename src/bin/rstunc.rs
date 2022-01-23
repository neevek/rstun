use anyhow::Result;
use clap::{AppSettings, Parser, Subcommand};
use log::info;
use log::{debug, error};
use rstun::*;
use tokio::time::Duration;

extern crate colored;
extern crate pretty_env_logger;

fn main() {
    //raise_fd_limit();

    let config = parse_command_line_args();
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

fn parse_command_line_args() -> ClientConfig {
    let mut config: ClientConfig;

    let args = Cli::parse();
    match &args.command {
        Commands::In {
            local_access_server_addr,
            server_addr,
            cert,
            loglevel,
            ..
        }
        | Commands::Out {
            local_access_server_addr,
            server_addr,
            cert,
            loglevel,
            ..
        } => {
            let max_idle_timeout_ms = 5 * 1000;
            config = ClientConfig {
                local_access_server_addr: local_access_server_addr.clone(),
                cert_path: cert.clone(),
                server_addr: server_addr.clone(),
                connect_max_retry: 0,
                wait_before_retry_ms: 5 * 1000,
                max_idle_timeout_ms,
                keep_alive_interval_ms: max_idle_timeout_ms / 2,
                loglevel: loglevel.clone(),
                tun_type: None,
            };
        }
    }

    match &args.command {
        Commands::In {
            password,
            remote_access_port,
            allow_public_access,
            ..
        } => {
            config.tun_type = Some(TunnelType::In(InLoginInfo {
                password: password.clone(),
                remote_access_port: remote_access_port.clone(),
                allow_public_access: allow_public_access.clone(),
            }));
        }
        Commands::Out {
            password,
            remote_downstream_name,
            ..
        } => {
            config.tun_type = Some(TunnelType::Out(OutLoginInfo {
                password: password.clone(),
                remote_downstream_name: remote_downstream_name.clone(),
            }));
        }
    }

    config
}

async fn run(config: ClientConfig) -> Result<()> {
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
#[clap(name = "rstunc", author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Connect to rstund in [IN] mode, which may expose local network to internet
    #[clap(setting(AppSettings::ArgRequiredElseHelp))]
    In {
        /// ip:port pair of the local downstream server the traffic from remote will be relayed to
        #[clap(short = 'l', long, display_order = 1)]
        local_access_server_addr: String,

        /// Address (ip:port pair) of rstund
        #[clap(short = 'r', long, display_order = 2)]
        server_addr: String,

        /// Password to connect with rstund
        #[clap(short = 'p', long, required = true, display_order = 3)]
        password: String,

        /// Path to the certificate file in DER format
        #[clap(short = 'c', long, required = true, display_order = 4)]
        cert: String,

        /// Log level
        #[clap(short = 'L', long, possible_values = &["T", "D", "I", "W", "E"], default_value = "I", display_order = 5)]
        loglevel: String,

        /// ip:port pair of the local downstream server the traffic from remote will be relayed to
        #[clap(short = 'a', long, required = true, display_order = 6)]
        remote_access_port: u16,

        /// ip:port pair of the local downstream server the traffic from remote will be relayed to
        #[clap(short = 'A', long, display_order = 8)]
        allow_public_access: bool,
    },

    /// Connect to rstund in [OUT] mode, which acts as a local proxy
    #[clap(setting(AppSettings::ArgRequiredElseHelp))]
    Out {
        /// The local access point of the tunnel
        #[clap(short = 'a', long, required = true, display_order = 7)]
        local_access_server_addr: String,

        /// Address (ip:port pair) of rstund
        #[clap(short = 'r', long, display_order = 2)]
        server_addr: String,

        /// Password to connect with rstund
        #[clap(short = 'p', long, required = true, display_order = 3)]
        password: String,

        /// Path to the certificate file in DER format
        #[clap(short = 'c', long, required = true, display_order = 4)]
        cert: String,

        /// Log level
        #[clap(short = 'L', long, possible_values = &["T", "D", "I", "W", "E"], default_value = "I", display_order = 5)]
        loglevel: String,

        /// Name of the remote downstream server the traffic will be relayed to
        #[clap(short = 'd', long, required = true, display_order = 6)]
        remote_downstream_name: String,
    },
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
