use crate::{ClientState, TunnelMode, UpstreamType};
use serde::Serialize;
use std::fmt::Display;
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex};

const EVENT_QUEUE_CAPACITY: usize = 256;

#[derive(Serialize, Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct TunnelTraffic {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub tx_dgrams: u64,
    pub rx_dgrams: u64,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq, Hash)]
pub enum TunnelId {
    Network(usize),
    Channel(UpstreamType),
}

impl Display for TunnelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TunnelId::Network(index) => write!(f, "{index}"),
            TunnelId::Channel(protocol) => write!(f, "channel-{protocol}"),
        }
    }
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct TunnelDescriptor {
    #[serde(rename = "tunnel_id")]
    pub id: TunnelId,
    #[serde(rename = "tunnel_protocol")]
    pub protocol: UpstreamType,
    #[serde(rename = "tunnel_mode")]
    pub mode: TunnelMode,
}

impl Display for TunnelDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}:{}", self.id, self.protocol, self.mode)
    }
}

#[derive(Serialize, Clone, Debug)]
#[serde(tag = "type", content = "data")]
pub enum TunnelEventKind {
    State(ClientState),
    Log(String),
    Traffic(TunnelTraffic),
}

#[derive(Serialize, Clone, Debug)]
pub struct TunnelEvent {
    pub timestamp: String,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tunnel: Option<TunnelInfo>,
    pub kind: String,
    pub data: serde_json::Value,
}

#[derive(Serialize, Clone, Debug)]
pub struct TunnelInfo {
    pub origin: String,
    pub id: Option<usize>,
    pub proto: UpstreamType,
    pub mode: TunnelMode,
}

impl TunnelEvent {
    pub fn new_client(timestamp: String, kind: TunnelEventKind) -> Self {
        Self::new(timestamp, "client", None, kind)
    }

    pub fn new_tunnel(timestamp: String, tunnel: TunnelDescriptor, kind: TunnelEventKind) -> Self {
        Self::new(timestamp, "tunnel", Some(tunnel), kind)
    }

    fn new(
        timestamp: String,
        scope: &str,
        tunnel: Option<TunnelDescriptor>,
        kind: TunnelEventKind,
    ) -> Self {
        let (kind_str, data) = match kind {
            TunnelEventKind::State(state) => (
                "state",
                serde_json::to_value(state).unwrap_or(serde_json::Value::Null),
            ),
            TunnelEventKind::Log(msg) => (
                "log",
                serde_json::to_value(msg).unwrap_or(serde_json::Value::Null),
            ),
            TunnelEventKind::Traffic(traffic) => (
                "traffic",
                serde_json::to_value(traffic).unwrap_or(serde_json::Value::Null),
            ),
        };

        let tunnel = match tunnel {
            Some(desc) => match desc.id {
                TunnelId::Network(id) => Some(TunnelInfo {
                    origin: "network".to_string(),
                    id: Some(id),
                    proto: desc.protocol,
                    mode: desc.mode,
                }),
                TunnelId::Channel(protocol) => Some(TunnelInfo {
                    origin: "channel".to_string(),
                    id: None,
                    proto: protocol,
                    mode: desc.mode,
                }),
            },
            None => None,
        };

        Self {
            timestamp,
            scope: scope.to_string(),
            tunnel,
            kind: kind_str.to_string(),
            data,
        }
    }
}

#[derive(Clone)]
pub struct TunnelEventBus {
    listeners: Arc<Mutex<Vec<SyncSender<TunnelEvent>>>>,
}

impl TunnelEventBus {
    pub fn new() -> Self {
        Self {
            listeners: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn register(&self) -> Receiver<TunnelEvent> {
        let (tx, rx) = sync_channel(EVENT_QUEUE_CAPACITY);
        let mut listeners = match self.listeners.lock() {
            Ok(listeners) => listeners,
            Err(poisoned) => poisoned.into_inner(),
        };
        listeners.push(tx);
        rx
    }

    pub fn has_listeners(&self) -> bool {
        let listeners = match self.listeners.lock() {
            Ok(listeners) => listeners,
            Err(poisoned) => poisoned.into_inner(),
        };
        !listeners.is_empty()
    }

    pub fn post(&self, event: TunnelEvent) {
        let mut listeners = match self.listeners.lock() {
            Ok(listeners) => listeners,
            Err(poisoned) => poisoned.into_inner(),
        };
        listeners.retain(|listener| match listener.try_send(event.clone()) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => true,
            Err(TrySendError::Disconnected(_)) => false,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_bus_delivers_to_multiple_listeners_and_drops_closed() {
        let bus = TunnelEventBus::new();
        let receiver_one = bus.register();
        let receiver_two = bus.register();
        drop(receiver_two);

        let descriptor = TunnelDescriptor {
            id: TunnelId::Network(1),
            protocol: UpstreamType::Tcp,
            mode: TunnelMode::Out,
        };
        let event = TunnelEvent::new_tunnel(
            "2025-01-01 00:00:00.000".to_string(),
            descriptor,
            TunnelEventKind::Log("hello".to_string()),
        );

        bus.post(event.clone());

        let received = receiver_one.recv().expect("event should arrive");
        assert!(bus.has_listeners());
        assert_eq!(received.timestamp, event.timestamp);
    }
}
