use crate::{TunnelMode, UpstreamType};
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
    pub sent_packets: u64,
    pub lost_packets: u64,
    pub lost_bytes: u64,
    pub congestion_events: u64,
    pub active_conns: u32,
    pub rtt_ms: u64,
    pub cwnd_bytes: u64,
    pub current_mtu: u16,
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
    pub id: TunnelId,
    pub proto: UpstreamType,
    pub mode: TunnelMode,
}

impl Display for TunnelDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}:{}", self.id, self.proto, self.mode)
    }
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum TunnelEventType {
    State(TunnelState),
    Log(String),
    Traffic(TunnelTraffic),
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub enum TunnelState {
    Connecting,
    Connected,
    Tunneling,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct TunnelEvent {
    pub timestamp: String,
    pub tunnel: TunnelInfo,
    #[serde(flatten)]
    pub event_type: TunnelEventType,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct TunnelInfo {
    pub source: TunnelSource,
    pub id: Option<usize>,
    pub proto: UpstreamType,
    pub mode: TunnelMode,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TunnelSource {
    Network,
    Channel,
}

impl TunnelEvent {
    pub fn new(timestamp: String, tunnel: TunnelDescriptor, event_type: TunnelEventType) -> Self {
        let tunnel = match tunnel.id {
            TunnelId::Network(id) => TunnelInfo {
                source: TunnelSource::Network,
                id: Some(id),
                proto: tunnel.proto,
                mode: tunnel.mode,
            },
            TunnelId::Channel(protocol) => TunnelInfo {
                source: TunnelSource::Channel,
                id: None,
                proto: protocol,
                mode: tunnel.mode,
            },
        };

        Self {
            timestamp,
            tunnel,
            event_type,
        }
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
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
            proto: UpstreamType::Tcp,
            mode: TunnelMode::Out,
        };
        let event = TunnelEvent::new(
            "2025-01-01 00:00:00.000".to_string(),
            descriptor,
            TunnelEventType::Log("hello".to_string()),
        );

        bus.post(event.clone());

        let received = receiver_one.recv().expect("event should arrive");
        assert!(bus.has_listeners());
        assert_eq!(received.timestamp, event.timestamp);
    }
}
