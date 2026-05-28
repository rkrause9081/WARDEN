/*
 * types.rs
 *
 * Purpose:
 *     Defines shared WARDEN data types used across the IDS pipeline.
 *
 * Responsibilities:
 *     - Represent supported protocols
 *     - Represent parsed application message types
 *     - Store packet metadata
 *     - Store alert metadata
 *     - Carry optional forensic evidence hashes
 *
 * Non-Responsibilities:
 *     - Packet capture
 *     - Attack detection
 *     - Mitigation
 *     - Blockchain submission
 *
 * Architecture:
 *
 *      Sniffer
 *        ↓
 *      PacketRecord
 *        ↓
 *      Engine
 *        ↓
 *      AlertEvent
 *        ↓
 *      Logging / Mitigation / Blockchain / Dashboard
 */

use std::net::IpAddr;
use std::time::SystemTime;

/* -------------------------------------------------------------------------- */
/*                                 Protocol                                   */
/* -------------------------------------------------------------------------- */

/**
 * Network/application protocols supported by WARDEN.
 */
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Protocol {
    MQTT,
    CoAP,
}

impl Protocol {
    /**
     * Returns a stable string representation.
     */
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::MQTT => "MQTT",
            Protocol::CoAP => "CoAP",
        }
    }
}

/* -------------------------------------------------------------------------- */
/*                               Message Type                                 */
/* -------------------------------------------------------------------------- */

/**
 * Application-level packet message classification.
 */
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MessageType {
    /// Known protocol message type.
    Known(String),

    /// Unknown or unsupported message type.
    Unknown,
}

impl MessageType {
    /**
     * Returns the message type as a display-safe string.
     */
    pub fn as_str(&self) -> &str {
        match self {
            MessageType::Known(value) => value.as_str(),
            MessageType::Unknown => "UNKNOWN",
        }
    }
}

/* -------------------------------------------------------------------------- */
/*                              Packet Record                                 */
/* -------------------------------------------------------------------------- */

/**
 * Lightweight packet metadata produced by the sniffer.
 */
#[derive(Debug, Clone)]
pub struct PacketRecord {
    /// Packet timestamp.
    pub timestamp: SystemTime,

    /// Source IP address.
    pub src_ip: IpAddr,

    /// Destination IP address.
    pub dst_ip: IpAddr,

    /// Parsed protocol.
    pub protocol: Protocol,

    /// Parsed application message type.
    pub msg_type: MessageType,
}

impl PacketRecord {
    /**
     * Creates a packet record using the current system time.
     */
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

    /**
     * Creates a packet record with an explicit timestamp.
     *
     * Used mainly for tests, demos, and replay-style workflows.
     */
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

/* -------------------------------------------------------------------------- */
/*                               Alert Event                                  */
/* -------------------------------------------------------------------------- */

/**
 * Detection alert emitted when traffic crosses the configured PPS threshold.
 */
#[derive(Debug, Clone)]
pub struct AlertEvent {
    /// Source IP that triggered the alert.
    pub src_ip: IpAddr,

    /// Protocol involved in the alert.
    pub protocol: Protocol,

    /// Application message type involved in the alert.
    pub msg_type: MessageType,

    /// Observed packets per second.
    pub pps: f64,

    /// Alert timestamp.
    pub timestamp: SystemTime,

    /**
     * Optional SHA-256 forensic evidence hash.
     *
     * Full evidence remains off-chain.
     * The hash can be written to JSONL logs and anchored on-chain.
     */
    pub evidence_hash: Option<[u8; 32]>,
}