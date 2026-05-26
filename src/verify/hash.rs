//! Verifier-side hash helpers.
//!
//! Important:
//! This must match the evidence hash logic used when alerts are created.
//!
//! Current canonical format:
//! src_ip=<ip>|protocol=<protocol>|msg_type=<msg_type>|pps=<pps with 3 decimals>

use sha2::{Digest, Sha256};

pub fn compute_canonical_alert_hash(
    src_ip: &str,
    protocol: &str,
    msg_type: &str,
    pps: f64,
) -> [u8; 32] {
    let canonical = format!(
        "src_ip={}|protocol={}|msg_type={}|pps={:.3}",
        src_ip,
        protocol,
        msg_type,
        pps,
    );

    let digest = Sha256::digest(canonical.as_bytes());

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&digest);
    hash
}

pub fn hash_to_hex(hash: [u8; 32]) -> String {
    format!("0x{}", hash.iter().map(|byte| format!("{byte:02x}")).collect::<String>())
}

pub fn normalize_hex(value: &str) -> String {
    if value.starts_with("0x") {
        value.to_lowercase()
    } else {
        format!("0x{}", value.to_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_deterministic() {
        let a = compute_canonical_alert_hash("127.0.0.1", "MQTT", "PUBLISH", 1.0);
        let b = compute_canonical_alert_hash("127.0.0.1", "MQTT", "PUBLISH", 1.0);

        assert_eq!(a, b);
    }

    #[test]
    fn hash_changes_when_evidence_changes() {
        let a = compute_canonical_alert_hash("127.0.0.1", "MQTT", "PUBLISH", 1.0);
        let b = compute_canonical_alert_hash("127.0.0.1", "MQTT", "CONNECT", 1.0);

        assert_ne!(a, b);
    }

    #[test]
    fn hash_hex_has_0x_prefix_and_64_hex_chars() {
        let hash = compute_canonical_alert_hash("127.0.0.1", "MQTT", "PUBLISH", 1.0);
        let hex = hash_to_hex(hash);

        assert!(hex.starts_with("0x"));
        assert_eq!(hex.len(), 66);
    }
}
