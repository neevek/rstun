use crate::{PooledBuffer, BUFFER_POOL, UDP_PACKET_SIZE};
use anyhow::{bail, Result};
use byte_pool::Block;
use bytes::{BufMut, Bytes, BytesMut};
use log::error;
use rs_utilities::log_and_bail;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

pub struct UdpPacket {
    pub payload: Block<'static, Vec<u8>>,
    pub addr: SocketAddr,
}

impl UdpPacket {
    pub fn new(payload: PooledBuffer, addr: SocketAddr) -> Self {
        Self { payload, addr }
    }

    pub fn serialize(&self) -> Bytes {
        let mut buf = BytesMut::new();

        match &self.addr {
            SocketAddr::V4(addr_v4) => {
                buf.put_u8(4);
                buf.extend_from_slice(&addr_v4.ip().octets());
                self.append_port_and_payload(&mut buf, addr_v4.port());
            }
            SocketAddr::V6(addr_v6) => {
                buf.put_u8(6);
                buf.extend_from_slice(&addr_v6.ip().octets());
                self.append_port_and_payload(&mut buf, addr_v6.port());
            }
        }

        buf.freeze()
    }

    fn append_port_and_payload(&self, buf: &mut BytesMut, port: u16) {
        buf.extend_from_slice(&port.to_be_bytes()); // 2-byte port in big-endian
        let payload_len = self.payload.len() as u16;
        buf.extend_from_slice(&payload_len.to_be_bytes()); // 2-byte payload length
        buf.extend_from_slice(&self.payload); // Payload data
    }

    pub fn deserialize(data: &[u8]) -> Result<UdpPacket> {
        let version = data[0]; // First byte is the version (4 or 6)
        let mut offset = 1;

        let addr = match version {
            4 => {
                let ip_bytes: [u8; 4] = data[offset..offset + 4].try_into()?;
                offset += 4;
                let port = u16::from_be_bytes(data[offset..offset + 2].try_into()?);
                SocketAddr::V4(SocketAddrV4::new(ip_bytes.into(), port))
            }
            6 => {
                let ip_bytes: [u8; 16] = data[offset..offset + 16].try_into()?;
                offset += 16;
                let port = u16::from_be_bytes(data[offset..offset + 2].try_into()?);
                SocketAddr::V6(SocketAddrV6::new(ip_bytes.into(), port, 0, 0))
            }
            _ => {
                log_and_bail!("invalid version");
            }
        };

        offset += 2; // Move past the port
        let payload_len = u16::from_be_bytes(data[offset..offset + 2].try_into()?) as usize;
        offset += 2;
        let remaining_len = data.len() - offset;
        if payload_len != remaining_len {
            log_and_bail!(
                "unexpected packet length, payload_len:{payload_len} != remaining:{remaining_len}"
            );
        }

        let mut payload = BUFFER_POOL.alloc(UDP_PACKET_SIZE);
        payload.extend_from_slice(&data[offset..offset + payload_len]);
        Ok(UdpPacket { payload, addr })
    }
}

impl From<UdpPacket> for Bytes {
    fn from(val: UdpPacket) -> Self {
        val.serialize()
    }
}

impl TryFrom<Bytes> for UdpPacket {
    type Error = anyhow::Error;

    fn try_from(data: Bytes) -> std::result::Result<Self, Self::Error> {
        UdpPacket::deserialize(&data)
    }
}

impl TryFrom<&[u8]> for UdpPacket {
    type Error = anyhow::Error;

    fn try_from(data: &[u8]) -> std::result::Result<Self, Self::Error> {
        UdpPacket::deserialize(data)
    }
}
