//! SHA-256 evidence hashing helpers.

use sha2::{Digest, Sha256};

use crate::types::AlertEvent;

/// Compute a SHA-256 evidence hash for an alert.
///
/// The hash includes:
/// - source IP
/// - protocol
/// - message type
/// - PPS rounded to 3 decimal places
/// - alert timestamp in milliseconds
///
/// Including the timestamp prevents repeated identical attacks from producing
/// the same evidence hash, which avoids duplicate-hash contract reverts.
pub fn compute_alert_evidence_hash(alert: &AlertEvent) -> [u8; 32] {
    let timestamp_millis = alert
        .timestamp
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);

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

pub fn hash_bytes_to_hex(hash: [u8; 32]) -> String {
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AlertEvent, MessageType, Protocol};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, SystemTime};

    fn ip(value: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(value))
    }

    fn test_alert(timestamp: SystemTime) -> AlertEvent {
        AlertEvent {
            src_ip: ip([192, 168, 10, 90]),
            protocol: Protocol::MQTT,
            msg_type: MessageType::Known("PUBLISH".to_string()),
            pps: 42.0,
            timestamp,
            evidence_hash: None,
        }
    }

    #[test]
    fn same_alert_same_timestamp_produces_same_hash() {
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(100);

        let alert_a = test_alert(timestamp);
        let alert_b = test_alert(timestamp);

        assert_eq!(
            compute_alert_evidence_hash(&alert_a),
            compute_alert_evidence_hash(&alert_b)
        );
    }

    #[test]
    fn same_alert_different_timestamp_produces_different_hash() {
        let alert_a = test_alert(SystemTime::UNIX_EPOCH + Duration::from_secs(100));
        let alert_b = test_alert(SystemTime::UNIX_EPOCH + Duration::from_secs(101));

        assert_ne!(
            compute_alert_evidence_hash(&alert_a),
            compute_alert_evidence_hash(&alert_b)
        );
    }

    #[test]
    fn hash_hex_is_64_chars() {
        let hash = compute_alert_evidence_hash(&test_alert(SystemTime::now()));
        let hex = hash_bytes_to_hex(hash);

        assert_eq!(hex.len(), 64);
    }

    #[test]
    fn different_pps_changes_hash() {
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(100);

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