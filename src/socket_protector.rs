use anyhow::Result;
use std::sync::Arc;

pub type SocketProtector = Arc<dyn Fn(i32) -> bool + Send + Sync + 'static>;

#[cfg(target_os = "android")]
mod platform {
    use super::*;
    use log::warn;
    use std::os::fd::AsRawFd;
    use std::sync::{Mutex, OnceLock};

    static SOCKET_PROTECTOR: OnceLock<Mutex<Option<SocketProtector>>> = OnceLock::new();

    pub fn set_socket_protector(protector: Option<SocketProtector>) {
        let holder = SOCKET_PROTECTOR.get_or_init(|| Mutex::new(None));
        match holder.lock() {
            Ok(mut current) => {
                *current = protector;
            }
            Err(poisoned) => {
                warn!("socket protector lock poisoned, replacing");
                *poisoned.into_inner() = protector;
            }
        }
    }

    pub fn protect_socket_fd(fd: i32) -> bool {
        let holder = SOCKET_PROTECTOR.get_or_init(|| Mutex::new(None));
        let protector = match holder.lock() {
            Ok(current) => current.clone(),
            Err(poisoned) => {
                warn!("socket protector lock poisoned during read, continuing");
                poisoned.into_inner().clone()
            }
        };
        protector.is_none_or(|callback| callback(fd))
    }

    pub fn protect_udp_socket(socket: &std::net::UdpSocket) -> Result<()> {
        let fd = socket.as_raw_fd();
        if protect_socket_fd(fd) {
            Ok(())
        } else {
            anyhow::bail!("socket protection callback rejected socket fd: {fd}");
        }
    }
}

#[cfg(not(target_os = "android"))]
mod platform {
    use super::*;

    pub fn set_socket_protector(_protector: Option<SocketProtector>) {}

    pub fn protect_socket_fd(_fd: i32) -> bool {
        true
    }

    pub fn protect_udp_socket(_socket: &std::net::UdpSocket) -> Result<()> {
        Ok(())
    }
}

pub use platform::{protect_socket_fd, protect_udp_socket, set_socket_protector};
