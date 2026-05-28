/*
 * mod.rs
 *
 * Purpose:
 *     Defines the WARDEN packet sniffer subsystem.
 *
 * Responsibilities:
 *     - Expose packet parsing modules
 *     - Centralize sniffer exports
 *     - Coordinate MQTT and CoAP parsing
 *     - Provide live packet capture interfaces
 *
 * Non-Responsibilities:
 *     - Intrusion detection analysis
 *     - Firewall mitigation
 *     - Blockchain anchoring
 *     - Dashboard rendering
 *
 * Architecture:
 *
 *      Network Interface
 *              ↓
 *          Packet Capture
 *              ↓
 *      MQTT / CoAP Parsing
 *              ↓
 *         PacketRecord
 *              ↓
 *        Detection Engine
 *
 * Dependencies:
 *
 *     pcap        - Live packet capture
 *     etherparse  - IP/TCP/UDP decoding
 */

/* -------------------------------------------------------------------------- */
/*                               Parser Modules                               */
/* -------------------------------------------------------------------------- */

pub mod coap;
pub mod mqtt;

/* -------------------------------------------------------------------------- */
/*                                 Imports                                    */
/* -------------------------------------------------------------------------- */

use std::collections::HashMap;

use std::net::IpAddr;

use std::time::{Duration, SystemTime};

use etherparse::{
    NetSlice,
    SlicedPacket,
    TransportSlice,
};

use pcap::{Capture, Device};

use crate::types::{
    MessageType,
    PacketRecord,
    Protocol,
};

/* -------------------------------------------------------------------------- */
/*                                Constants                                   */
/* -------------------------------------------------------------------------- */

/// Default MQTT TCP port.
const MQTT_PORT: u16 = 1883;

/// Default CoAP UDP port.
const COAP_PORT: u16 = 5683;

/* -------------------------------------------------------------------------- */
/*                                  Sniffer                                   */
/* -------------------------------------------------------------------------- */

/// Live MQTT/CoAP packet sniffer.
///
/// Captures packets from one network interface
/// and converts them into structured `PacketRecord`s.
#[derive(Debug)]
pub struct Sniffer {
    /// Network interface name.
    interface: String,

    /// Duplicate suppression window.
    dedup_window: Duration,

    /// Recently observed packet cache.
    seen: HashMap<PacketKey, SystemTime>,

    /// Total packets successfully captured.
    total_captured: u64,

    /// Total MQTT packets parsed.
    total_mqtt: u64,

    /// Total CoAP packets parsed.
    total_coap: u64,
}

/* -------------------------------------------------------------------------- */
/*                               Packet Keys                                  */
/* -------------------------------------------------------------------------- */

/// Packet deduplication tracking key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PacketKey {
    /// Source IP address.
    src_ip: IpAddr,

    /// Destination IP address.
    dst_ip: IpAddr,

    /// Packet protocol.
    protocol: Protocol,

    /// Parsed application message type.
    msg_type: MessageType,
}

/* -------------------------------------------------------------------------- */
/*                              Sniffer Stats                                 */
/* -------------------------------------------------------------------------- */

/// Runtime packet capture statistics.
#[derive(Debug, Clone)]
pub struct SnifferStats {
    /// Total packets captured.
    pub total: u64,

    /// Total MQTT packets parsed.
    pub mqtt: u64,

    /// Total CoAP packets parsed.
    pub coap: u64,
}

/* -------------------------------------------------------------------------- */
/*                         Sniffer Implementation                             */
/* -------------------------------------------------------------------------- */

impl Sniffer {
    /**
     * Creates a packet sniffer bound to one interface.
     *
     * # Arguments
     *
     * * `interface` - Network interface name
     */
    pub fn new(interface: impl Into<String>) -> Self {
        Self {
            interface: interface.into(),

            dedup_window:
                Duration::from_millis(10),

            seen: HashMap::new(),

            total_captured: 0,

            total_mqtt: 0,

            total_coap: 0,
        }
    }

    /**
     * Starts live packet capture.
     *
     * Captures:
     * - MQTT TCP traffic
     * - CoAP UDP traffic
     *
     * Current behavior:
     * - runs indefinitely
     * - invokes callback for each parsed packet
     *
     * Future direction:
     * - threaded capture
     * - async streaming
     * - offline PCAP replay
     */
    pub fn start<F>(
        &mut self,
        mut on_packet: F,
    ) -> Result<(), pcap::Error>
    where
        F: FnMut(PacketRecord),
    {
        let device = self.resolve_device()?;

        let mut cap = Capture::from_device(device)?
            .promisc(true)
            .immediate_mode(true)
            .open()?;

        cap.filter(
            &format!(
                "(tcp and port {MQTT_PORT}) \
                 or \
                 (udp and port {COAP_PORT})"
            ),
            true,
        )?;

        println!(
            "Sniffer started on interface '{}' \
             for MQTT/{MQTT_PORT} and CoAP/{COAP_PORT}",
            self.interface
        );

        loop {
            match cap.next_packet() {
                Ok(packet) => {
                    if let Some(record) =
                        self.parse_packet(packet.data)
                    {
                        on_packet(record);
                    }
                }

                Err(pcap::Error::TimeoutExpired) => {
                    // Normal idle timeout.
                    continue;
                }

                Err(error) => {
                    eprintln!("pcap error: {error}");
                    continue;
                }
            }
        }
    }

    /**
     * Parses a raw packet into a structured PacketRecord.
     *
     * Supports:
     * - IPv4
     * - IPv6
     * - MQTT over TCP
     * - CoAP over UDP
     *
     * Returns `None` for unsupported packets.
     */
    pub fn parse_packet(
        &mut self,
        data: &[u8],
    ) -> Option<PacketRecord> {
        let sliced =
            SlicedPacket::from_ethernet(data).ok()?;

        let (src_ip, dst_ip) = match sliced.net {
            Some(NetSlice::Ipv4(ipv4)) => (
                IpAddr::V4(
                    ipv4.header().source_addr()
                ),

                IpAddr::V4(
                    ipv4.header()
                        .destination_addr()
                ),
            ),

            Some(NetSlice::Ipv6(ipv6)) => (
                IpAddr::V6(
                    ipv6.header().source_addr()
                ),

                IpAddr::V6(
                    ipv6.header()
                        .destination_addr()
                ),
            ),

            _ => return None,
        };

        let (protocol, msg_type) = match sliced.transport {
            Some(TransportSlice::Tcp(tcp))
                if tcp.destination_port()
                    == MQTT_PORT =>
            {
                let payload = tcp.payload();

                if payload.is_empty() {
                    return None;
                }

                self.total_mqtt += 1;

                (
                    Protocol::MQTT,

                    mqtt::parse_mqtt_type(payload),
                )
            }

            Some(TransportSlice::Udp(udp))
                if udp.destination_port()
                    == COAP_PORT =>
            {
                let payload = udp.payload();

                if payload.is_empty() {
                    return None;
                }

                self.total_coap += 1;

                (
                    Protocol::CoAP,

                    coap::parse_coap_method(payload),
                )
            }

            _ => return None,
        };

        let record = PacketRecord::new(
            src_ip,
            dst_ip,
            protocol,
            msg_type,
        );

        if self.is_duplicate(&record) {
            return None;
        }

        self.total_captured += 1;

        Some(record)
    }

    /**
     * Returns runtime packet capture statistics.
     */
    pub fn get_stats(&self) -> SnifferStats {
        SnifferStats {
            total: self.total_captured,

            mqtt: self.total_mqtt,

            coap: self.total_coap,
        }
    }

    /**
     * Detects duplicate packets within the deduplication window.
     */
    fn is_duplicate(
        &mut self,
        record: &PacketRecord,
    ) -> bool {
        let key = PacketKey {
            src_ip: record.src_ip,

            dst_ip: record.dst_ip,

            protocol:
                record.protocol.clone(),

            msg_type:
                record.msg_type.clone(),
        };

        let now = record.timestamp;

        if let Some(last_seen) =
            self.seen.get(&key)
        {
            if now
                .duration_since(*last_seen)
                .map(|elapsed| {
                    elapsed < self.dedup_window
                })
                .unwrap_or(false)
            {
                return true;
            }
        }

        self.seen.insert(key, now);

        self.cleanup_seen_cache(now);

        false
    }

    /**
     * Removes stale deduplication cache entries.
     */
    fn cleanup_seen_cache(
        &mut self,
        now: SystemTime,
    ) {
        let max_age =
            Duration::from_secs(5);

        self.seen.retain(|_, timestamp| {
            now.duration_since(*timestamp)
                .map(|age| age <= max_age)
                .unwrap_or(true)
        });
    }

    /**
     * Resolves the configured network interface.
     */
    fn resolve_device(
        &self
    ) -> Result<Device, pcap::Error> {
        let devices = Device::list()?;

        devices
            .into_iter()
            .find(|device| {
                device.name == self.interface
            })
            .ok_or_else(|| {
                pcap::Error::PcapError(
                    format!(
                        "Network interface '{}' not found",
                        self.interface
                    )
                )
            })
    }
}