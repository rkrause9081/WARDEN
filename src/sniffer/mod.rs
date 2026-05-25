//! Packet sniffer module.
//!
//! Phase 2 goal:
//! - capture MQTT / CoAP packets
//! - parse application message type
//! - emit `PacketRecord` into the detection engine
//!
//! This uses `pcap` for packet capture and `etherparse` for IP/TCP/UDP parsing.
//!
//! Required Cargo dependencies:
//!
//! ```toml
//! pcap = "2"
//! etherparse = "0.15"
//! ```

pub mod coap;
pub mod mqtt;

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use pcap::{Capture, Device};

use crate::types::{MessageType, PacketRecord, Protocol};

const MQTT_PORT: u16 = 1883;
const COAP_PORT: u16 = 5683;

/// Captures MQTT and CoAP packets from one network interface.
#[derive(Debug)]
pub struct Sniffer {
    interface: String,
    dedup_window: Duration,
    seen: HashMap<PacketKey, SystemTime>,
    total_captured: u64,
    total_mqtt: u64,
    total_coap: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PacketKey {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: Protocol,
    msg_type: MessageType,
}

#[derive(Debug, Clone)]
pub struct SnifferStats {
    pub total: u64,
    pub mqtt: u64,
    pub coap: u64,
}

impl Sniffer {
    pub fn new(interface: impl Into<String>) -> Self {
        Self {
            interface: interface.into(),
            dedup_window: Duration::from_millis(10),
            seen: HashMap::new(),
            total_captured: 0,
            total_mqtt: 0,
            total_coap: 0,
        }
    }

    /// Start live capture.
    ///
    /// This blocks forever unless `pcap` returns an error.
    /// Later, this can run in its own thread and send `PacketRecord`s through
    /// an mpsc channel.
    pub fn start<F>(&mut self, mut on_packet: F) -> Result<(), pcap::Error>
    where
        F: FnMut(PacketRecord),
    {
        let device = self.resolve_device()?;

        let mut cap = Capture::from_device(device)?
            .promisc(true)
            .immediate_mode(true)
            .open()?;

        cap.filter(
            &format!("(tcp and port {MQTT_PORT}) or (udp and port {COAP_PORT})"),
            true,
        )?;

        println!(
            "Sniffer started on interface '{}' for MQTT/{MQTT_PORT} and CoAP/{COAP_PORT}",
            self.interface
        );

    loop {
        match cap.next_packet() {
            Ok(packet) => {
                if let Some(record) = self.parse_packet(packet.data) {
                    on_packet(record);
                }
            }

            Err(pcap::Error::TimeoutExpired) => {
                // normal idle timeout
                continue;
            }

            Err(error) => {
                eprintln!("pcap error: {error}");
                continue;
            }
        }
    }
    }

    /// Parse a raw packet into a `PacketRecord`.
    ///
    /// This is public enough for tests and future offline pcap replay support.
    pub fn parse_packet(&mut self, data: &[u8]) -> Option<PacketRecord> {
        let sliced = SlicedPacket::from_ethernet(data).ok()?;

        let (src_ip, dst_ip) = match sliced.net {
            Some(NetSlice::Ipv4(ipv4)) => (
                IpAddr::V4(ipv4.header().source_addr()),
                IpAddr::V4(ipv4.header().destination_addr()),
            ),
            Some(NetSlice::Ipv6(ipv6)) => (
                IpAddr::V6(ipv6.header().source_addr()),
                IpAddr::V6(ipv6.header().destination_addr()),
            ),
            _ => return None,
        };

        let (protocol, msg_type) = match sliced.transport {
            Some(TransportSlice::Tcp(tcp)) if tcp.destination_port() == MQTT_PORT => {
                let payload = tcp.payload();
                if payload.is_empty() {
                    return None;
                }

                self.total_mqtt += 1;
                (Protocol::MQTT, mqtt::parse_mqtt_type(payload))
            }

            Some(TransportSlice::Udp(udp)) if udp.destination_port() == COAP_PORT => {
                let payload = udp.payload();
                if payload.is_empty() {
                    return None;
                }

                self.total_coap += 1;
                (Protocol::CoAP, coap::parse_coap_method(payload))
            }

            _ => return None,
        };

        let record = PacketRecord::new(src_ip, dst_ip, protocol, msg_type);

        if self.is_duplicate(&record) {
            return None;
        }

        self.total_captured += 1;
        Some(record)
    }

    pub fn get_stats(&self) -> SnifferStats {
        SnifferStats {
            total: self.total_captured,
            mqtt: self.total_mqtt,
            coap: self.total_coap,
        }
    }

    fn is_duplicate(&mut self, record: &PacketRecord) -> bool {
        let key = PacketKey {
            src_ip: record.src_ip,
            dst_ip: record.dst_ip,
            protocol: record.protocol.clone(),
            msg_type: record.msg_type.clone(),
        };

        let now = record.timestamp;

        if let Some(last_seen) = self.seen.get(&key) {
            if now
                .duration_since(*last_seen)
                .map(|elapsed| elapsed < self.dedup_window)
                .unwrap_or(false)
            {
                return true;
            }
        }

        self.seen.insert(key, now);
        self.cleanup_seen_cache(now);
        false
    }

    fn cleanup_seen_cache(&mut self, now: SystemTime) {
        let max_age = Duration::from_secs(5);

        self.seen.retain(|_, timestamp| {
            now.duration_since(*timestamp)
                .map(|age| age <= max_age)
                .unwrap_or(true)
        });
    }

    fn resolve_device(&self) -> Result<Device, pcap::Error> {
        let devices = Device::list()?;

        devices
            .into_iter()
            .find(|device| device.name == self.interface)
            .ok_or_else(|| pcap::Error::PcapError(format!(
                "Network interface '{}' not found",
                self.interface
            )))
    }
}
