//! SHA-256 evidence hashing helpers.

use sha2::{Digest, Sha256};

use crate::types::AlertEvent;

/// Compute a deterministic evidence hash for an alert.
///
/// This intentionally hashes stable forensic fields only:
/// - source IP
/// - protocol
/// - message type
/// - PPS rounded to 3 decimal places
///
/// The timestamp is excluded so tests and replay verification stay deterministic.
/// The JSONL log still stores `logged_at` separately.
pub fn compute_alert_evidence_hash(alert: &AlertEvent) -> [u8; 32] {
    let canonical = format!(
        "src_ip={}|protocol={}|msg_type={}|pps={:.3}",
        alert.src_ip,
        alert.protocol.as_str(),
        alert.msg_type.as_str(),
        alert.pps,
    );

    let digest = Sha256::digest(canonical.as_bytes());

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&digest);
    hash
}

pub fn hash_bytes_to_hex(hash: [u8; 32]) -> String {
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AlertEvent, MessageType, Protocol};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::SystemTime;

    fn ip(value: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(value))
    }

    fn test_alert() -> AlertEvent {
        AlertEvent {
            src_ip: ip([192, 168, 10, 90]),
            protocol: Protocol::MQTT,
            msg_type: MessageType::Known("PUBLISH".to_string()),
            pps: 42.0,
            timestamp: SystemTime::now(),
            evidence_hash: None,
        }
    }

    #[test]
    fn same_alert_produces_same_hash() {
        let alert_a = test_alert();
        let alert_b = test_alert();

        assert_eq!(
            compute_alert_evidence_hash(&alert_a),
            compute_alert_evidence_hash(&alert_b)
        );
    }

    #[test]
    fn hash_hex_is_64_chars() {
        let hash = compute_alert_evidence_hash(&test_alert());
        let hex = hash_bytes_to_hex(hash);

        assert_eq!(hex.len(), 64);
    }

    #[test]
    fn different_pps_changes_hash() {
        let mut alert_a = test_alert();
        let mut alert_b = test_alert();

        alert_a.pps = 42.0;
        alert_b.pps = 43.0;

        assert_ne!(
            compute_alert_evidence_hash(&alert_a),
            compute_alert_evidence_hash(&alert_b)
        );
    }
}
