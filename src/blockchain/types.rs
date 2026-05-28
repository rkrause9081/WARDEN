/*
 * types.rs
 *
 * Purpose:
 *     Defines blockchain-facing alert structures used
 *     for forensic evidence anchoring.
 *
 * Responsibilities:
 *     - Transform IDS alerts into blockchain-safe types
 *     - Normalize evidence payload formatting
 *     - Convert floating-point PPS metrics
 *     - Preserve immutable forensic metadata
 *
 * Non-Responsibilities:
 *     - Submitting blockchain transactions
 *     - IDS detection analysis
 *     - Packet inspection
 *     - Evidence verification
 *
 * Architecture:
 *
 *      AlertEvent
 *            ↓
 *      ChainAlert Conversion
 *            ↓
 *      Blockchain Client
 *            ↓
 *      Smart Contract Logging
 */

use crate::types::AlertEvent;

/* -------------------------------------------------------------------------- */
/*                               Chain Alert                                  */
/* -------------------------------------------------------------------------- */

/* 
 * Blockchain-compatible forensic alert payload.
 * This structure represents a compact, serialized version
 * of a WARDEN IDS alert suitable for smart contract logging.
*/
#[derive(Debug, Clone)]
pub struct ChainAlert {
    /// SHA-256 forensic evidence hash.
    pub evidence_hash: [u8; 32],

    /// Source IP associated with the alert.
    pub src_ip: String,

    /// Network/application protocol name.
    pub protocol: String,

    /// Protocol-specific message type.
    pub msg_type: String,

    /**
     * Packets-per-second multiplied by 1000.
     *
     * Used for fixed-point precision when converting
     * floating-point IDS metrics into Solidity-compatible integers.
     */
    pub pps_milli: u64,

    /// Indicates whether mitigation was applied.
    pub mitigated: bool,
}

/* -------------------------------------------------------------------------- */
/*                              Implementation                                */
/* -------------------------------------------------------------------------- */

impl ChainAlert {
    /**
     * Converts an internal IDS alert into a blockchain-compatible payload.
     *
     * Returns `None` if the alert does not contain
     * a finalized forensic evidence hash.
     *
     * # Arguments
     *
     * * `alert` - Original IDS alert event
     * * `mitigated` - Whether mitigation was applied
     */
    pub fn from_alert(alert: &AlertEvent, mitigated: bool) -> Option<Self> {
        let evidence_hash = alert.evidence_hash?;

        Some(Self {
            evidence_hash,
            src_ip: alert.src_ip.to_string(),
            protocol: alert.protocol.as_str().to_string(),
            msg_type: alert.msg_type.as_str().to_string(),

            // Convert floating-point PPS into fixed-point integer format.
            pps_milli: (alert.pps * 1000.0).round() as u64,

            mitigated,
        })
    }
}