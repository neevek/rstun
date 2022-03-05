#[macro_use]
pub mod macros;

mod access_server;
mod client;
mod server;
mod tunnel;
mod tunnel_message;
mod util;

pub use access_server::AccessServer;
use anyhow::Result;
use byte_pool::BytePool;
pub use client::Client;
use log::{debug, error, info, warn};
use quinn::{RecvStream, SendStream};
pub use server::Server;
use std::net::SocketAddr;
use std::sync::{Arc, Once};
use std::time::Duration;
pub use tunnel::Tunnel;
pub use tunnel_message::{LoginInfo, TunnelMessage};

#[macro_use]
extern crate serde_derive;
extern crate bincode;
extern crate pretty_env_logger;

pub const TUNNEL_MODE_IN: &str = "IN";
pub const TUNNEL_MODE_OUT: &str = "OUT";
static INIT_LOGGER_ONCE: Once = Once::new();
static mut IS_RUNNING: bool = false;

pub type BufferPool = Arc<BytePool<Vec<u8>>>;

fn new_buffer_pool() -> BufferPool {
    Arc::new(BytePool::<Vec<u8>>::new())
}

#[derive(Debug)]
pub enum TunnelType {
    Out((quinn::NewConnection, SocketAddr)),
    In((quinn::NewConnection, AccessServer, ControlStream)),
}

#[derive(Debug)]
pub struct ControlStream {
    pub quic_send: SendStream,
    pub quic_recv: RecvStream,
}

#[derive(Debug, Default)]
pub struct ClientConfig {
    pub local_access_server_addr: Option<SocketAddr>,
    pub cert_path: String,
    pub server_addr: String,
    pub connect_max_retry: usize,
    pub wait_before_retry_ms: u64,
    pub max_idle_timeout_ms: u64,
    pub keep_alive_interval_ms: u64,
    pub login_msg: Option<TunnelMessage>,
    pub threads: usize,
    pub mode: &'static str,
}

#[derive(Default, Debug)]
pub struct ServerConfig {
    pub addr: String,
    pub password: String,
    pub cert_path: String,
    pub key_path: String,

    /// traffics to the rstun server will be relayed to servers
    /// specified by downstreams, client must specify a target
    /// downstream when it connects to the rstun server in OUT mode.
    pub downstreams: Vec<SocketAddr>,

    /// 0.0.0.0:3515
    pub dashboard_server: String,
    /// user:password
    pub dashboard_server_credential: String,
}

pub(crate) enum ReadResult {
    Succeeded,
    EOF,
}

impl ReadResult {
    #![allow(dead_code)]
    pub fn is_eof(&self) -> bool {
        if let Self::EOF = self {
            true
        } else {
            false
        }
    }
}

pub fn init_logger(log_level: &str) {
    INIT_LOGGER_ONCE.call_once(|| LogHelper::init_logger(log_level.as_ref()));
}

pub fn start_tunnelling(config: ClientConfig) {
    unsafe {
        if IS_RUNNING {
            warn!("rsproxy is alreay running");
            return;
        }
        IS_RUNNING = true;
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(config.threads)
        .build()
        .unwrap()
        .block_on(async {
            run(config).await.ok();
        });

    unsafe {
        IS_RUNNING = false;
    }
}

async fn run(config: ClientConfig) -> Result<()> {
    let mut access_server = None;
    if config.mode == TUNNEL_MODE_OUT {
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
                if client.config.mode == TUNNEL_MODE_OUT {
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

pub fn is_running() -> bool {
    unsafe { IS_RUNNING }
}

#[cfg(not(target_os = "android"))]
macro_rules! colored_log {
    ($buf:ident, $record:ident, $term_color:literal, $level:literal) => {{
        let filename = $record.file().unwrap_or("unknown");
        let filename = &filename[filename.rfind('/').map(|pos| pos + 1).unwrap_or(0)..];
        writeln!(
            $buf,
            concat!($term_color, "{} [{}:{}] [", $level, "] {}\x1B[0m"),
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S.%3f"),
            filename,
            $record.line().unwrap_or(0),
            $record.args()
        )
    }};
}

struct LogHelper {}
impl LogHelper {
    #[cfg(not(target_os = "android"))]
    pub fn init_logger(log_level_str: &str) {
        use std::io::Write;
        let log_level_filter;
        match log_level_str.as_ref() {
            "D" => log_level_filter = log::LevelFilter::Debug,
            "I" => log_level_filter = log::LevelFilter::Info,
            "W" => log_level_filter = log::LevelFilter::Warn,
            "E" => log_level_filter = log::LevelFilter::Error,
            _ => log_level_filter = log::LevelFilter::Trace,
        }

        pretty_env_logger::formatted_timed_builder()
            .format(|buf, record| match record.level() {
                log::Level::Trace => colored_log!(buf, record, "\x1B[0m", "T"),
                log::Level::Debug => colored_log!(buf, record, "\x1B[92m", "D"),
                log::Level::Info => colored_log!(buf, record, "\x1B[34m", "I"),
                log::Level::Warn => colored_log!(buf, record, "\x1B[93m", "W"),
                log::Level::Error => colored_log!(buf, record, "\x1B[31m", "E"),
            })
            .filter(Some("rstun"), log_level_filter)
            .init();
    }

    #[cfg(target_os = "android")]
    pub fn init_logger(log_level_str: &str) {
        let log_level;
        match log_level_str.as_ref() {
            "D" => log_level = log::Level::Debug,
            "I" => log_level = log::Level::Info,
            "W" => log_level = log::Level::Warn,
            "E" => log_level = log::Level::Error,
            _ => log_level = log::Level::Trace,
        }

        android_logger::init_once(
            android_logger::Config::default()
                .with_min_level(log_level)
                .with_tag("rstun"),
        );
    }
}

#[cfg(target_os = "android")]
#[allow(non_snake_case)]
pub mod android {
    extern crate jni;

    use self::jni::objects::{JClass, JString};
    use self::jni::sys::{jboolean, jint, JNI_FALSE, JNI_TRUE, JNI_VERSION_1_6};
    use self::jni::{JNIEnv, JavaVM};
    use super::*;
    use std::os::raw::c_void;
    use std::thread::{self, sleep};

    #[no_mangle]
    pub extern "system" fn JNI_OnLoad(vm: JavaVM, _: *mut c_void) -> jint {
        let _env = vm.get_env().expect("failed to get JNIEnv");
        JNI_VERSION_1_6
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_neevek_rsproxy_RsTunc_initLogger(
        env: JNIEnv,
        _: JClass,
        jlogLevel: JString,
    ) -> jboolean {
        if let Ok(log_level) = env.get_string(jlogLevel) {
            init_logger(log_level.to_str().unwrap());
            return JNI_TRUE;
        }
        JNI_FALSE
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_neevek_rsproxy_RsTunc_isRunning(
        _env: JNIEnv,
        _: JClass,
    ) -> jboolean {
        return if is_running() { JNI_TRUE } else { JNI_FALSE };
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_neevek_rsproxy_RsTunc_startTunnelling(
        env: JNIEnv,
        _: JClass,
        jmode: JString,
        jserverAddr: JString,
        jaddrMapping: JString,
        jpassword: JString,
        jcertFilePath: JString,
        jthreads: jint,
    ) -> jboolean {
        let mode = convert_jstring(&env, jmode);
        let server_addr = convert_jstring(&env, jserverAddr);
        let addr_mapping = convert_jstring(&env, jaddrMapping);
        let password = convert_jstring(&env, jpassword);
        let cert_file_path = convert_jstring(&env, jcertFilePath);

        let addrs: Vec<&str> = addr_mapping.split("^").collect();
        if addrs.len() != 2 {
            error!("invalid address mapping: {}", addr_mapping);
            return JNI_FALSE;
        }
        let mut addrs: Vec<String> = addrs.iter().map(|s| s.to_string()).collect();

        for addr in &mut addrs {
            if !addr.contains(":") {
                *addr = format!("127.0.0.1:{}", addr);
            }
        }

        let mut config = ClientConfig::default();
        config.cert_path = cert_file_path;
        config.server_addr = server_addr;
        config.threads = if jthreads > 0 {
            jthreads as usize
        } else {
            num_cpus::get()
        };
        config.connect_max_retry = 0;
        config.wait_before_retry_ms = 5 * 1000;
        config.max_idle_timeout_ms = 5 * 1000;
        config.keep_alive_interval_ms = config.max_idle_timeout_ms / 2;
        config.mode = if mode == TUNNEL_MODE_IN {
            TUNNEL_MODE_IN
        } else {
            TUNNEL_MODE_OUT
        };

        let local_access_server_addr;
        config.login_msg = if mode == TUNNEL_MODE_IN {
            local_access_server_addr = addrs[1].to_string();
            Some(TunnelMessage::ReqInLogin(LoginInfo {
                password,
                access_server_addr: addrs[0].to_string(),
            }))
        } else {
            local_access_server_addr = addrs[0].to_string();
            Some(TunnelMessage::ReqOutLogin(LoginInfo {
                password,
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

        thread::spawn(|| start_tunnelling(config));

        // wait for a moment for the server to start
        sleep(std::time::Duration::from_millis(500));

        return if IS_RUNNING { JNI_TRUE } else { JNI_FALSE };
    }

    fn convert_jstring(env: &JNIEnv, jstr: JString) -> String {
        if !jstr.is_null() {
            env.get_string(jstr).unwrap().into()
        } else {
            String::from("")
        }
    }
}
