/*
 * hash.rs
 *
 * Purpose:
 *     Provides SHA-256 forensic evidence hashing utilities
 *     for the WARDEN intrusion detection platform.
 *
 * Responsibilities:
 *     - Generate deterministic evidence hashes
 *     - Create tamper-evident forensic digests
 *     - Normalize alert serialization
 *     - Convert hashes into hexadecimal format
 *
 * Non-Responsibilities:
 *     - Blockchain transaction handling
 *     - IDS detection analysis
 *     - JSONL evidence storage
 *     - Smart contract interaction
 *
 * Architecture:
 *
 *      AlertEvent
 *            ↓
 *      Canonical Serialization
 *            ↓
 *      SHA-256 Digest
 *            ↓
 *      Evidence Hash
 *            ↓
 *      JSONL + Blockchain Verification
 */

/* -------------------------------------------------------------------------- */
/*                                 Imports                                    */
/* -------------------------------------------------------------------------- */

use sha2::{Digest, Sha256};

use crate::types::AlertEvent;

/* -------------------------------------------------------------------------- */
/*                           Evidence Hashing                                 */
/* -------------------------------------------------------------------------- */

/**
 * Computes a deterministic SHA-256 evidence hash for an IDS alert.
 *
 * The canonical evidence payload includes:
 *
 * - source IP
 * - protocol
 * - message type
 * - packets-per-second value
 * - timestamp in milliseconds
 *
 * Timestamp inclusion prevents repeated identical attacks
 * from generating duplicate hashes.
 *
 * This is important because duplicate blockchain evidence hashes
 * may trigger smart contract duplicate-entry protections.
 *
 * # Arguments
 *
 * * `alert` - IDS alert event to hash
 */
pub fn compute_alert_evidence_hash(
    alert: &AlertEvent
) -> [u8; 32] {
    let timestamp_millis = alert
        .timestamp
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);

    /*
     * Canonical forensic serialization format.
     *
     * Stable ordering is critical to ensure:
     * - deterministic hashes
     * - reproducible verification
     * - blockchain consistency
     */
    let canonical = format!(
        "src_ip={}|protocol={}|msg_type={}|pps={:.3}|timestamp_ms={}",
        alert.src_ip,
        alert.protocol.as_str(),
        alert.msg_type.as_str(),
        alert.pps,
        timestamp_millis,
    );

    let digest = Sha256::digest(canonical.as_bytes());

    let mut hash = [0u8; 32];

    hash.copy_from_slice(&digest);

    hash
}

/* -------------------------------------------------------------------------- */
/*                             Hex Conversion                                 */
/* -------------------------------------------------------------------------- */

/**
 * Converts a SHA-256 digest into hexadecimal format.
 *
 * # Arguments
 *
 * * `hash` - 32-byte SHA-256 digest
 */
pub fn hash_bytes_to_hex(hash: [u8; 32]) -> String {
    hash.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/* -------------------------------------------------------------------------- */
/*                                   Tests                                    */
/* -------------------------------------------------------------------------- */

#[cfg(test)]
mod tests {
    use super::*;

    use crate::types::{
        AlertEvent,
        MessageType,
        Protocol,
    };

    use std::net::{IpAddr, Ipv4Addr};

    use std::time::{Duration, SystemTime};

    /* ---------------------------------------------------------------------- */
    /*                              Test Helpers                              */
    /* ---------------------------------------------------------------------- */

    /// Helper for generating IPv4 addresses.
    fn ip(value: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(value))
    }

    /**
     * Creates a reusable IDS alert for hashing tests.
     */
    fn test_alert(timestamp: SystemTime) -> AlertEvent {
        AlertEvent {
            src_ip: ip([192, 168, 10, 90]),
            protocol: Protocol::MQTT,
            msg_type: MessageType::Known(
                "PUBLISH".to_string()
            ),
            pps: 42.0,
            timestamp,
            evidence_hash: None,
        }
    }

    /* ---------------------------------------------------------------------- */
    /*                              Hashing Tests                             */
    /* ---------------------------------------------------------------------- */

    #[test]
    fn same_alert_same_timestamp_produces_same_hash() {
        let timestamp =
            SystemTime::UNIX_EPOCH
            + Duration::from_secs(100);

        let alert_a = test_alert(timestamp);
        let alert_b = test_alert(timestamp);

        assert_eq!(
            compute_alert_evidence_hash(&alert_a),
            compute_alert_evidence_hash(&alert_b)
        );
    }

    #[test]
    fn same_alert_different_timestamp_produces_different_hash() {
        let alert_a = test_alert(
            SystemTime::UNIX_EPOCH
                + Duration::from_secs(100)
        );

        let alert_b = test_alert(
            SystemTime::UNIX_EPOCH
                + Duration::from_secs(101)
        );

        assert_ne!(
            compute_alert_evidence_hash(&alert_a),
            compute_alert_evidence_hash(&alert_b)
        );
    }

    #[test]
    fn hash_hex_is_64_chars() {
        let hash = compute_alert_evidence_hash(
            &test_alert(SystemTime::now())
        );

        let hex = hash_bytes_to_hex(hash);

        assert_eq!(hex.len(), 64);
    }

    #[test]
    fn different_pps_changes_hash() {
        let timestamp =
            SystemTime::UNIX_EPOCH
            + Duration::from_secs(100);

        let mut alert_a = test_alert(timestamp);
        let mut alert_b = test_alert(timestamp);

        alert_a.pps = 42.0;
        alert_b.pps = 43.0;

        assert_ne!(
            compute_alert_evidence_hash(&alert_a),
            compute_alert_evidence_hash(&alert_b)
        );
    }
}