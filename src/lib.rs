mod client;
mod pem_util;
mod server;
mod tcp;
mod tunnel_info_bridge;
mod tunnel_message;
mod udp;
mod util;

use anyhow::{Context, Result};
use byte_pool::BytePool;
pub use client::Client;
pub use client::ClientState;
use lazy_static::lazy_static;
use rs_utilities::log_and_bail;
use rustls::crypto::ring::cipher_suite;
use serde::Deserialize;
use serde::Serialize;
pub use server::Server;
use std::fmt::Display;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::{net::SocketAddr, ops::Deref};
pub use tcp::tcp_server::TcpServer;
pub use tcp::{AsyncStream, StreamMessage, StreamReceiver, StreamRequest, StreamSender};
use tunnel_message::LoginInfo;
use udp::udp_server::UdpServer;
pub use udp::{UdpMessage, UdpPacket, UdpReceiver, UdpSender};

extern crate bincode;
extern crate pretty_env_logger;

pub const TUNNEL_MODE_IN: &str = "IN";
pub const TUNNEL_MODE_OUT: &str = "OUT";
pub const UDP_PACKET_SIZE: usize = 1500;

lazy_static! {
    static ref BUFFER_POOL: BytePool::<Vec<u8>> = BytePool::<Vec<u8>>::new();
}

pub const SUPPORTED_CIPHER_SUITE_STRS: &[&str] = &[
    "chacha20-poly1305",
    "aes-256-gcm",
    "aes-128-gcm",
    // the following ciphers don't work at the moement, will look into it later
    // "ecdhe-ecdsa-aes256-gcm",
    // "ecdhe-ecdsa-aes128-gcm",
    // "ecdhe-ecdsa-chacha20-poly1305",
    // "ecdhe-rsa-aes256-gcm",
    // "ecdhe-rsa-aes128-gcm",
    // "ecdhe-rsa-chacha20-poly1305",
];

pub static SUPPORTED_CIPHER_SUITES: &[rustls::SupportedCipherSuite] = &[
    cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    cipher_suite::TLS13_AES_256_GCM_SHA384,
    cipher_suite::TLS13_AES_128_GCM_SHA256,
];

pub(crate) struct SelectedCipherSuite(rustls::SupportedCipherSuite);

impl std::str::FromStr for SelectedCipherSuite {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "chacha20-poly1305" => Ok(SelectedCipherSuite(
                cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
            )),
            "aes-256-gcm" => Ok(SelectedCipherSuite(cipher_suite::TLS13_AES_256_GCM_SHA384)),
            "aes-128-gcm" => Ok(SelectedCipherSuite(cipher_suite::TLS13_AES_128_GCM_SHA256)),
            // "ecdhe-ecdsa-aes256-gcm" => Ok(SelectedCipherSuite(
            //     rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            // )),
            // "ecdhe-ecdsa-aes128-gcm" => Ok(SelectedCipherSuite(
            //     rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            // )),
            // "ecdhe-ecdsa-chacha20-poly1305" => Ok(SelectedCipherSuite(
            //     rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            // )),
            // "ecdhe-rsa-aes256-gcm" => Ok(SelectedCipherSuite(
            //     rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            // )),
            // "ecdhe-rsa-aes128-gcm" => Ok(SelectedCipherSuite(
            //     rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            // )),
            // "ecdhe-rsa-chacha20-poly1305" => Ok(SelectedCipherSuite(
            //     rustls::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            // )),
            _ => Ok(SelectedCipherSuite(
                cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
            )),
        }
    }
}

impl Deref for SelectedCipherSuite {
    type Target = rustls::SupportedCipherSuite;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug)]
pub struct TcpTunnelOutInfo {
    conn: quinn::Connection,
    upstream_addr: SocketAddr,
}

#[derive(Debug)]
pub struct TcpTunnelInInfo {
    conn: quinn::Connection,
    tcp_server: TcpServer,
}

#[derive(Debug)]
pub struct UdpTunnelOutInfo {
    conn: quinn::Connection,
    upstream_addr: SocketAddr,
}

#[derive(Debug)]
pub struct UdpTunnelInInfo {
    conn: quinn::Connection,
    udp_server: UdpServer,
}

#[derive(Debug)]
pub enum TunnelType {
    TcpOut(TcpTunnelOutInfo),
    TcpIn(TcpTunnelInInfo),
    UdpOut(UdpTunnelOutInfo),
    UdpIn(UdpTunnelInInfo),
    DynamicUpstreamTcpOut(quinn::Connection),
    DynamicUpstreamUdpOut(quinn::Connection),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum TunnelMode {
    In,
    Out,
}

impl Display for TunnelMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::In => write!(f, "IN"),
            Self::Out => write!(f, "OUT"),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum UpstreamType {
    Tcp,
    Udp,
}

impl Display for UpstreamType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    pub upstream_addr: Option<SocketAddr>,
    pub upstream_type: UpstreamType,
}

impl Display for Upstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.upstream_addr {
            Some(addr) => write!(f, "{}", addr),
            None => write!(f, "PeerDefault"),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TunnelConfig {
    pub mode: TunnelMode,
    pub local_server_addr: Option<SocketAddr>,
    pub upstream: Upstream,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) enum Tunnel {
    NetworkBased(TunnelConfig),
    ChannelBased(UpstreamType),
}

#[derive(Debug, Default, Clone)]
pub struct ClientConfig {
    pub cert_path: String,
    pub cipher: String,
    pub server_addr: String,
    pub password: String,
    pub wait_before_retry_ms: u64,
    pub quic_timeout_ms: u64,
    pub tcp_timeout_ms: u64,
    pub udp_timeout_ms: u64,
    pub tunnels: Vec<TunnelConfig>,
    pub dot_servers: Vec<String>,
    pub dns_servers: Vec<String>,
    pub workers: usize,
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub addr: String,
    pub password: String,
    pub cert_path: String,
    pub key_path: String,
    pub quic_timeout_ms: u64,
    pub tcp_timeout_ms: u64,
    pub udp_timeout_ms: u64,

    /// for TunnelOut only
    pub default_tcp_upstream: Option<SocketAddr>,
    pub default_udp_upstream: Option<SocketAddr>,

    /// 0.0.0.0:3515
    pub dashboard_server: String,
    /// user:password
    pub dashboard_server_credential: String,
}

impl ClientConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        server_addr: &str,
        password: &str,
        cert: &str,
        cipher: &str,
        tcp_addr_mappings: &str,
        udp_addr_mappings: &str,
        dot: &str,
        dns: &str,
        workers: usize,
        wait_before_retry_ms: u64,
        mut quic_timeout_ms: u64,
        mut tcp_timeout_ms: u64,
        mut udp_timeout_ms: u64,
    ) -> Result<ClientConfig> {
        if tcp_addr_mappings.is_empty() && udp_addr_mappings.is_empty() {
            log_and_bail!("must specify either --tcp-mappings or --udp-mappings, or both");
        }

        if quic_timeout_ms == 0 {
            quic_timeout_ms = 30000;
        }
        if tcp_timeout_ms == 0 {
            tcp_timeout_ms = 30000;
        }
        if udp_timeout_ms == 0 {
            udp_timeout_ms = 5000;
        }

        let mut config = ClientConfig {
            cert_path: cert.to_string(),
            cipher: cipher.to_string(),
            server_addr: if !server_addr.contains(':') {
                format!("127.0.0.1:{server_addr}")
            } else {
                server_addr.to_string()
            },
            password: password.to_string(),
            workers: if workers > 0 {
                workers
            } else {
                num_cpus::get()
            },
            wait_before_retry_ms,
            quic_timeout_ms,
            tcp_timeout_ms,
            udp_timeout_ms,
            dot_servers: dot.split(',').map(|s| s.to_string()).collect(),
            dns_servers: dns.split(',').map(|s| s.to_string()).collect(),
            ..ClientConfig::default()
        };

        parse_addr_mappings(tcp_addr_mappings, UpstreamType::Tcp, &mut config.tunnels)?;
        parse_addr_mappings(udp_addr_mappings, UpstreamType::Udp, &mut config.tunnels)?;

        Ok(config)
    }
}

fn parse_addr_mappings(
    mappings: &str,
    upstream_type: UpstreamType,
    v: &mut Vec<TunnelConfig>,
) -> Result<()> {
    if mappings.is_empty() {
        return Ok(());
    }

    for mapping in mappings.split(',') {
        let parts: Vec<&str> = mapping.split('^').collect();
        if parts.len() != 3 {
            log_and_bail!("Invalid mapping format, expected TYPE^SRC^DEST");
        }

        let tunnel_mode = parts[0];
        if tunnel_mode != "OUT" && tunnel_mode != "IN" {
            log_and_bail!("Invalid tunnel type, expected OUT or IN");
        }

        let parse_addr = |addr: &str| -> Result<Option<SocketAddr>> {
            if addr == "ANY" {
                return Ok(None);
            }

            // Handle port-only case
            let port = addr.parse::<u16>();
            if let Ok(port) = port {
                return Ok(Some(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                    port,
                )));
            }

            // Parse full SocketAddr
            Ok(Some(addr.parse().with_context(|| {
                format!("Invalid address format '{addr}', expected IP:PORT or PORT")
            })?))
        };

        let local_server_addr = parse_addr(parts[1])?;
        if local_server_addr.is_none() {
            log_and_bail!("'ANY' is not allowed as local_server_addr");
        }
        let upstream_addr = parse_addr(parts[2])?;

        v.push(TunnelConfig {
            mode: if tunnel_mode == "IN" {
                TunnelMode::In
            } else {
                TunnelMode::Out
            },
            upstream: Upstream {
                upstream_addr,
                upstream_type: upstream_type.clone(),
            },
            local_server_addr,
        });
    }

    Ok(())
}

pub fn socket_addr_with_unspecified_ip_port(ipv6: bool) -> SocketAddr {
    if ipv6 {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    }
}

#[cfg(target_os = "android")]
#[allow(non_snake_case)]
pub mod android {
    extern crate jni;

    use jni::sys::{jlong, jstring};
    use log::{error, info};

    use self::jni::objects::{JClass, JObject, JString};
    use self::jni::sys::{jboolean, jint, JNI_TRUE, JNI_VERSION_1_6};
    use self::jni::{JNIEnv, JavaVM};
    use super::*;
    use std::os::raw::c_void;
    use std::sync::{Arc, Mutex};
    use std::thread;

    #[no_mangle]
    pub extern "system" fn JNI_OnLoad(_vm: JavaVM, _: *mut c_void) -> jint {
        JNI_VERSION_1_6
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_neevek_omnip_RsTunc_initCertificateVerifier(
        mut env: JNIEnv,
        _: JClass,
        context: JObject,
    ) {
        if let Err(e) = rustls_platform_verifier::android::init_hosted(
            &mut env,
            JObject::try_from(context).unwrap(),
        ) {
            error!("failed to init rustls_platform_verifier: {}", e);
        } else {
            info!("initializing rustls_platform_verifier succeeded!");
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_neevek_omnip_RsTunc_nativeInitLogger(
        mut env: JNIEnv,
        _: JClass,
        jlogLevel: JString,
    ) -> jboolean {
        let log_level = match convert_jstring(&mut env, jlogLevel).as_str() {
            "T" => "trace",
            "D" => "debug",
            "I" => "info",
            "W" => "warn",
            "E" => "error",
            _ => "info",
        };
        let log_filter = format!("rstun={},rs_utilities={}", log_level, log_level);
        rs_utilities::LogHelper::init_logger("rstunc", log_filter.as_str());
        return JNI_TRUE;
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_neevek_omnip_RsTunc_nativeCreate(
        mut env: JNIEnv,
        _: JClass,
        jserverAddr: JString,
        jtcpMappings: JString,
        judpMappings: JString,
        jdotServer: JString,
        jdnsServer: JString,
        jpassword: JString,
        jcertFilePath: JString,
        jcipher: JString,
        jworkers: jint,
        jwaitBeforeRetryMs: jint,
        jquicTimeoutMs: jint,
    ) -> jlong {
        let server_addr = convert_jstring(&mut env, jserverAddr);
        let tcp_mappings = convert_jstring(&mut env, jtcpMappings);
        let udp_mappings = convert_jstring(&mut env, judpMappings);
        let dot_server = convert_jstring(&mut env, jdotServer);
        let dns_server = convert_jstring(&mut env, jdnsServer);
        let password = convert_jstring(&mut env, jpassword);
        let cert_file_path = convert_jstring(&mut env, jcertFilePath);
        let cipher = convert_jstring(&mut env, jcipher);

        match ClientConfig::create(
            &server_addr,
            &password,
            &cert_file_path,
            &cipher,
            &tcp_mappings,
            &udp_mappings,
            &dot_server,
            &dns_server,
            jworkers as usize,
            jwaitBeforeRetryMs as u64,
            jquicTimeoutMs as u64,
            0, // tcp_timeout_ms - use default
            0, // udp_timeout_ms - use default
        ) {
            Ok(client_config) => {
                let client = Client::new(client_config);
                let client = Box::into_raw(Box::new(client));
                client as jlong
            }
            Err(e) => {
                error!("failed to create client: {}", e);
                0
            }
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_neevek_omnip_RsTunc_nativeStop(
        _env: JNIEnv,
        _: JClass,
        client_ptr: jlong,
    ) {
        if client_ptr != 0 {
            let _boxed_client = Box::from_raw(client_ptr as *mut Client);
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_neevek_omnip_RsTunc_nativeStartTunnelling(
        _env: JNIEnv,
        _: JClass,
        client_ptr: jlong,
    ) {
        if client_ptr == 0 {
            return;
        }

        thread::spawn(move || {
            let mut client = (&mut *(client_ptr as *mut Arc<Mutex<Client>>))
                .lock()
                .unwrap();
            client.start_tunneling();
        });
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_neevek_omnip_RsTunc_nativeGetState(
        env: JNIEnv,
        _: JClass,
        client_ptr: jlong,
    ) -> jstring {
        if client_ptr == 0 {
            return env.new_string("").unwrap().into_raw();
        }

        let client = (&mut *(client_ptr as *mut Arc<Mutex<Client>>))
            .lock()
            .unwrap();
        env.new_string(client.get_state().to_string())
            .unwrap()
            .into_raw()
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_neevek_omnip_RsTunc_nativeSetEnableOnInfoReport(
        env: JNIEnv,
        jobj: JClass,
        client_ptr: jlong,
        enable: jboolean,
    ) {
        if client_ptr == 0 {
            return;
        }

        let client = (&mut *(client_ptr as *mut Arc<Mutex<Client>>))
            .lock()
            .unwrap();
        let bool_enable = enable == 1;
        if bool_enable && !client.has_on_info_listener() {
            let jvm = env.get_java_vm().unwrap();
            let jobj_global_ref = env.new_global_ref(jobj).unwrap();
            client.set_on_info_listener(move |data: &str| {
                let mut env = jvm.attach_current_thread().unwrap();
                if let Ok(s) = env.new_string(data) {
                    env.call_method(
                        &jobj_global_ref,
                        "onInfo",
                        "(Ljava/lang/String;)V",
                        &[(&s).into()],
                    )
                    .unwrap();
                }
            });
        }

        client.set_enable_on_info_report(bool_enable);
    }

    fn convert_jstring(env: &mut JNIEnv, jstr: JString) -> String {
        if !jstr.is_null() {
            env.get_string(&jstr).unwrap().to_string_lossy().to_string()
        } else {
            String::from("")
        }
    }
}
