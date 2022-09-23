#[macro_use]
pub mod macros;

mod access_server;
mod client;
mod server;
mod tunnel;
mod tunnel_message;
mod util;

pub use access_server::AccessServer;
use byte_pool::BytePool;
pub use client::Client;
use quinn::{RecvStream, SendStream};
pub use server::Server;
use std::net::SocketAddr;
use std::sync::Arc;
pub use tunnel::Tunnel;
pub use tunnel_message::{LoginInfo, TunnelMessage};

#[macro_use]
extern crate serde_derive;
extern crate bincode;
extern crate pretty_env_logger;

pub const TUNNEL_MODE_IN: &str = "IN";
pub const TUNNEL_MODE_OUT: &str = "OUT";
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
    pub max_idle_timeout_ms: u64,

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

#[cfg(target_os = "android")]
#[allow(non_snake_case)]
pub mod android {
    extern crate jni;

    use jni::sys::jlong;
    use log::error;

    use self::jni::objects::{JClass, JString};
    use self::jni::sys::{jboolean, jint, JNI_FALSE, JNI_TRUE, JNI_VERSION_1_6};
    use self::jni::{JNIEnv, JavaVM};
    use super::*;
    use std::os::raw::c_void;
    use std::thread;

    #[no_mangle]
    pub extern "system" fn JNI_OnLoad(vm: JavaVM, _: *mut c_void) -> jint {
        let _env = vm.get_env().expect("failed to get JNIEnv");
        JNI_VERSION_1_6
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_neevek_rsproxy_RsTuncKt_nativeInitLogger(
        env: JNIEnv,
        _: JClass,
        jlogLevel: JString,
    ) -> jboolean {
        if let Ok(log_level) = env.get_string(jlogLevel) {
            rs_utilities::LogHelper::init_logger("rstc", log_level.to_str().unwrap());
            return JNI_TRUE;
        }
        JNI_FALSE
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_neevek_rsproxy_RsTunc_nativeCreate(
        env: JNIEnv,
        _: JClass,
        jmode: JString,
        jserverAddr: JString,
        jaddrMapping: JString,
        jpassword: JString,
        jcertFilePath: JString,
        jthreads: jint,
        jwaitBeforeRetryMs: jint,
        jmaxIdleTimeoutMs: jint,
    ) -> jlong {
        let mode = convert_jstring(&env, jmode);
        let server_addr = convert_jstring(&env, jserverAddr);
        let addr_mapping = convert_jstring(&env, jaddrMapping);
        let password = convert_jstring(&env, jpassword);
        let cert_file_path = convert_jstring(&env, jcertFilePath);

        let addrs: Vec<&str> = addr_mapping.split("^").collect();
        if addrs.len() != 2 {
            error!("invalid address mapping: {}", addr_mapping);
            return 0;
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
        config.wait_before_retry_ms = jwaitBeforeRetryMs as u64;
        config.max_idle_timeout_ms = jmaxIdleTimeoutMs as u64;
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

        Box::into_raw(Box::new(Client::new(config))) as jlong
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_neevek_rsproxy_RsTunc_nativeStartTunnelling(
        _env: JNIEnv,
        _: JClass,
        client_ptr: jlong,
    ) {
        if client_ptr == 0 {
            return;
        }

        let client = &mut *(client_ptr as *mut Client);
        if client.has_scheduled_start() {
            return;
        }

        client.set_scheduled_start();
        thread::spawn(move || {
            let client = &mut *(client_ptr as *mut Client);
            client.start_tunnelling();
        });
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_neevek_rsproxy_RsTunc_nativeIsRunning(
        _env: JNIEnv,
        _: JClass,
        client_ptr: jlong,
    ) -> jboolean {
        if client_ptr == 0 {
            return false as jboolean;
        }

        let client = &mut *(client_ptr as *mut Client);
        client.is_running() as jboolean
    }

    fn convert_jstring(env: &JNIEnv, jstr: JString) -> String {
        if !jstr.is_null() {
            env.get_string(jstr).unwrap().into()
        } else {
            String::from("")
        }
    }
}
