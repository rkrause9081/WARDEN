//! Shared data types for The Warden.
//!
//! These types are intentionally kept outside the engine so they can be reused by:
//! - sniffer
//! - detection engine
//! - mitigator
//! - dashboard
//! - future blockchain logger

use std::net::IpAddr;
use std::time::SystemTime;

/// Network protocol observed by the sniffer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Protocol {
    MQTT,
    CoAP,
}

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::MQTT => "MQTT",
            Protocol::CoAP => "CoAP",
        }
    }
}

/// Application-level message type extracted from the packet.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MessageType {
    Known(String),
    Unknown,
}

impl MessageType {
    pub fn as_str(&self) -> &str {
        match self {
            MessageType::Known(value) => value.as_str(),
            MessageType::Unknown => "UNKNOWN",
        }
    }
}

/// Lightweight packet metadata produced by the sniffer.
#[derive(Debug, Clone)]
pub struct PacketRecord {
    pub timestamp: SystemTime,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub protocol: Protocol,
    pub msg_type: MessageType,
}

impl PacketRecord {
    pub fn new(
        src_ip: IpAddr,
        dst_ip: IpAddr,
        protocol: Protocol,
        msg_type: MessageType,
    ) -> Self {
        Self {
            timestamp: SystemTime::now(),
            src_ip,
            dst_ip,
            protocol,
            msg_type,
        }
    }

    pub fn with_timestamp(
        timestamp: SystemTime,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        protocol: Protocol,
        msg_type: MessageType,
    ) -> Self {
        Self {
            timestamp,
            src_ip,
            dst_ip,
            protocol,
            msg_type,
        }
    }
}

/// Alert emitted when a source IP crosses the configured PPS threshold.
#[derive(Debug, Clone)]
pub struct AlertEvent {
    pub src_ip: IpAddr,
    pub protocol: Protocol,
    pub msg_type: MessageType,
    pub pps: f64,
    pub timestamp: SystemTime,

    /// Reserved for your future blockchain feature.
    ///
    /// Store detailed attack evidence off-chain, then commit only the evidence
    /// hash to the smart contract.
    pub evidence_hash: Option<[u8; 32]>,
}
