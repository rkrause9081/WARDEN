/*
 * hash.rs
 *
 * Purpose:
 *     Provides verifier-side SHA-256 hash helpers.
 *
 * Responsibilities:
 *     - Recompute canonical alert evidence hashes
 *     - Support legacy no-timestamp hashes
 *     - Normalize hexadecimal hash formatting
 *     - Preserve compatibility with older JSONL logs
 *
 * Non-Responsibilities:
 *     - Parsing JSONL records
 *     - Reading files
 *     - Printing verification reports
 *     - Querying blockchain state
 *
 * Architecture:
 *
 *      Alert Fields
 *          ↓
 *      Canonical String
 *          ↓
 *      SHA-256 Digest
 *          ↓
 *      Hex Hash Comparison
 *
 * Important:
 *     This file must stay synchronized with the alert hash logic
 *     used when evidence is originally created.
 */

use sha2::{
    Digest,
    Sha256,
};

/* -------------------------------------------------------------------------- */
/*                            Canonical Hashing                               */
/* -------------------------------------------------------------------------- */

/**
 * Computes the current canonical alert evidence hash.
 *
 * Canonical format:
 *
 * src_ip=<ip>|protocol=<protocol>|msg_type=<msg_type>|pps=<pps with 3 decimals>|timestamp_ms=<alert timestamp ms>
 */
pub fn compute_canonical_alert_hash(
    src_ip: &str,
    protocol: &str,
    msg_type: &str,
    pps: f64,
    alert_timestamp_ms: u128,
) -> [u8; 32] {
    let canonical = format!(
        "src_ip={}|protocol={}|msg_type={}|pps={:.3}|timestamp_ms={}",
        src_ip,
        protocol,
        msg_type,
        pps,
        alert_timestamp_ms,
    );

    let digest = Sha256::digest(canonical.as_bytes());

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&digest);

    hash
}

/* -------------------------------------------------------------------------- */
/*                              Legacy Hashing                                */
/* -------------------------------------------------------------------------- */

/**
 * Computes the legacy alert evidence hash.
 *
 * This supports older logs created before `alert_timestamp_ms`
 * was added to the canonical evidence format.
 */
pub fn compute_legacy_alert_hash(
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

/* -------------------------------------------------------------------------- */
/*                             Hex Formatting                                 */
/* -------------------------------------------------------------------------- */

/**
 * Converts a raw 32-byte hash into a 0x-prefixed hex string.
 */
pub fn hash_to_hex(hash: [u8; 32]) -> String {
    format!(
        "0x{}",
        hash.iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

/**
 * Normalizes hash strings for reliable comparison.
 *
 * Ensures:
 * - lowercase hex
 * - 0x prefix
 */
pub fn normalize_hex(value: &str) -> String {
    if value.starts_with("0x") {
        value.to_lowercase()
    } else {
        format!("0x{}", value.to_lowercase())
    }
}

/* -------------------------------------------------------------------------- */
/*                                   Tests                                    */
/* -------------------------------------------------------------------------- */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_deterministic_with_same_timestamp() {
        let a = compute_canonical_alert_hash(
            "127.0.0.1",
            "MQTT",
            "PUBLISH",
            1.0,
            1000,
        );

        let b = compute_canonical_alert_hash(
            "127.0.0.1",
            "MQTT",
            "PUBLISH",
            1.0,
            1000,
        );

        assert_eq!(a, b);
    }

    #[test]
    fn hash_changes_when_timestamp_changes() {
        let a = compute_canonical_alert_hash(
            "127.0.0.1",
            "MQTT",
            "PUBLISH",
            1.0,
            1000,
        );

        let b = compute_canonical_alert_hash(
            "127.0.0.1",
            "MQTT",
            "PUBLISH",
            1.0,
            1001,
        );

        assert_ne!(a, b);
    }

    #[test]
    fn hash_hex_has_0x_prefix_and_64_hex_chars() {
        let hash = compute_canonical_alert_hash(
            "127.0.0.1",
            "MQTT",
            "PUBLISH",
            1.0,
            1000,
        );

        let hex = hash_to_hex(hash);

        assert!(hex.starts_with("0x"));
        assert_eq!(hex.len(), 66);
    }
}