use serde::Serialize;
use std::sync::{Arc, Mutex};

#[derive(Serialize, Default, Clone)]
pub(crate) struct TunnelTraffic {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub tx_dgrams: u64,
    pub rx_dgrams: u64,
}

#[derive(Serialize)]
pub(crate) enum TunnelInfoType {
    TunnelState,
    TunnelLog,
    TunnelTraffic,
}

#[derive(Serialize)]
pub(crate) struct TunnelInfo<T>
where
    T: ?Sized + Serialize,
{
    pub info_type: TunnelInfoType,
    pub data: Box<T>,
}

impl<T> TunnelInfo<T>
where
    T: ?Sized + Serialize,
{
    pub(crate) fn new(info_type: TunnelInfoType, data: Box<T>) -> Self {
        Self { info_type, data }
    }
}

#[derive(Clone)]
pub(crate) struct TunnelInfoBridge {
    listener: Option<Arc<Mutex<dyn FnMut(&str) + 'static + Send + Sync>>>,
}

impl TunnelInfoBridge {
    pub(crate) fn new() -> Self {
        TunnelInfoBridge { listener: None }
    }

    pub(crate) fn set_listener(&mut self, listener: impl FnMut(&str) + 'static + Send + Sync) {
        self.listener = Some(Arc::new(Mutex::new(listener)));
    }

    pub(crate) fn has_listener(&self) -> bool {
        self.listener.is_some()
    }

    pub(crate) fn post_tunnel_info<T>(&self, data: TunnelInfo<T>)
    where
        T: ?Sized + Serialize,
    {
        if let Some(ref listener) = self.listener {
            if let Ok(json) = serde_json::to_string(&data) {
                listener.lock().unwrap()(json.as_str());
            }
        }
    }
}
