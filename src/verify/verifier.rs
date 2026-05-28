/*
 * verifier.rs
 *
 * Purpose:
 *     Verifies WARDEN JSONL alert evidence against stored hashes.
 *
 * Responsibilities:
 *     - Read alert JSONL files
 *     - Parse individual alert records
 *     - Recompute expected evidence hashes
 *     - Detect tampering, missing hashes, and parse failures
 *     - Print CLI verification reports
 *
 * Non-Responsibilities:
 *     - Blockchain verification
 *     - Packet inspection
 *     - Evidence hash creation during IDS runtime
 *     - Dashboard rendering
 *
 * Architecture:
 *
 *      alerts.jsonl
 *          ↓
 *      AlertEvidenceRecord
 *          ↓
 *      Hash Recompute
 *          ↓
 *      Stored Hash Comparison
 *          ↓
 *      VerificationResult
 *
 * Verification Levels:
 *     - VALID: stored hash matches recomputed hash
 *     - TAMPERED: stored hash differs from recomputed hash
 *     - MISSING_HASH: record has no stored evidence hash
 *     - PARSE_ERROR: JSONL row could not be decoded
 */

use std::fs::File;
use std::io::{
    BufRead,
    BufReader,
};
use std::path::Path;

use serde::Deserialize;

use crate::verify::hash::{
    compute_canonical_alert_hash,
    compute_legacy_alert_hash,
    hash_to_hex,
    normalize_hex,
};

/* -------------------------------------------------------------------------- */
/*                           Alert Evidence Record                            */
/* -------------------------------------------------------------------------- */

/**
 * JSONL alert record used by the verifier.
 *
 * New records include `alert_timestamp_ms`.
 * Older records may omit it and are verified using legacy hashing.
 */
#[derive(Debug, Clone, Deserialize)]
pub struct AlertEvidenceRecord {
    /// Logger write timestamp.
    pub logged_at: Option<String>,

    /// Original alert timestamp used in canonical hash generation.
    pub alert_timestamp_ms: Option<u128>,

    /// Alert source IP.
    pub src_ip: String,

    /// Alert protocol.
    pub protocol: String,

    /// Alert message type.
    pub msg_type: String,

    /// Alert packets-per-second value.
    pub pps: f64,

    /// Stored evidence hash from the JSONL record.
    pub evidence_hash_hex: Option<String>,

    /// Optional log action, usually ALERT.
    pub action: Option<String>,
}

/* -------------------------------------------------------------------------- */
/*                           Verification Status                              */
/* -------------------------------------------------------------------------- */

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationStatus {
    Valid,
    Tampered,
    MissingHash,
    ParseError,
}

/* -------------------------------------------------------------------------- */
/*                           Verification Result                              */
/* -------------------------------------------------------------------------- */

#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub line_number: usize,
    pub status: VerificationStatus,
    pub src_ip: Option<String>,
    pub protocol: Option<String>,
    pub msg_type: Option<String>,
    pub stored_hash: Option<String>,
    pub recomputed_hash: Option<String>,
    pub error: Option<String>,
}

/* -------------------------------------------------------------------------- */
/*                              File Verification                             */
/* -------------------------------------------------------------------------- */

/**
 * Verifies every non-empty line in an alert JSONL file.
 */
pub fn verify_alert_log_file(
    path: impl AsRef<Path>,
) -> Result<Vec<VerificationResult>, std::io::Error> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let mut results = Vec::new();

    for (index, line) in reader.lines().enumerate() {
        let line_number = index + 1;
        let line = line?;

        if line.trim().is_empty() {
            continue;
        }

        results.push(
            verify_alert_log_line(line_number, &line)
        );
    }

    Ok(results)
}

/* -------------------------------------------------------------------------- */
/*                              Line Verification                             */
/* -------------------------------------------------------------------------- */

/**
 * Verifies one JSONL alert record.
 */
pub fn verify_alert_log_line(
    line_number: usize,
    line: &str,
) -> VerificationResult {
    let record =
        match serde_json::from_str::<AlertEvidenceRecord>(line) {
            Ok(record) => record,

            Err(error) => {
                return VerificationResult {
                    line_number,
                    status: VerificationStatus::ParseError,
                    src_ip: None,
                    protocol: None,
                    msg_type: None,
                    stored_hash: None,
                    recomputed_hash: None,
                    error: Some(error.to_string()),
                };
            }
        };

    let Some(stored_hash_raw) =
        record.evidence_hash_hex.clone()
    else {
        let recomputed_hash =
            record.alert_timestamp_ms.map(|alert_timestamp_ms| {
                hash_to_hex(compute_canonical_alert_hash(
                    &record.src_ip,
                    &record.protocol,
                    &record.msg_type,
                    record.pps,
                    alert_timestamp_ms,
                ))
            });

        return VerificationResult {
            line_number,
            status: VerificationStatus::MissingHash,
            src_ip: Some(record.src_ip),
            protocol: Some(record.protocol),
            msg_type: Some(record.msg_type),
            stored_hash: None,
            recomputed_hash,
            error: None,
        };
    };

    let stored_hash = normalize_hex(&stored_hash_raw);

    let recomputed_hash = match record.alert_timestamp_ms {
        Some(alert_timestamp_ms) => {
            hash_to_hex(compute_canonical_alert_hash(
                &record.src_ip,
                &record.protocol,
                &record.msg_type,
                record.pps,
                alert_timestamp_ms,
            ))
        }

        None => {
            hash_to_hex(compute_legacy_alert_hash(
                &record.src_ip,
                &record.protocol,
                &record.msg_type,
                record.pps,
            ))
        }
    };

    let status = if stored_hash == recomputed_hash {
        VerificationStatus::Valid
    } else {
        VerificationStatus::Tampered
    };

    VerificationResult {
        line_number,
        status,
        src_ip: Some(record.src_ip),
        protocol: Some(record.protocol),
        msg_type: Some(record.msg_type),
        stored_hash: Some(stored_hash),
        recomputed_hash: Some(recomputed_hash),
        error: None,
    }
}

/* -------------------------------------------------------------------------- */
/*                              Report Printing                               */
/* -------------------------------------------------------------------------- */

/**
 * Prints a human-readable verification report.
 */
pub fn print_verification_report(
    results: &[VerificationResult],
) {
    let mut valid = 0usize;
    let mut tampered = 0usize;
    let mut missing = 0usize;
    let mut parse_errors = 0usize;

    println!("Evidence verification report");
    println!("============================");

    for result in results {
        match result.status {
            VerificationStatus::Valid => valid += 1,
            VerificationStatus::Tampered => tampered += 1,
            VerificationStatus::MissingHash => missing += 1,
            VerificationStatus::ParseError => parse_errors += 1,
        }

        println!();
        println!("Record #{}", result.line_number);

        if let Some(src_ip) = &result.src_ip {
            println!("Source IP : {src_ip}");
        }

        if let Some(protocol) = &result.protocol {
            println!("Protocol  : {protocol}");
        }

        if let Some(msg_type) = &result.msg_type {
            println!("Msg Type  : {msg_type}");
        }

        if let Some(stored_hash) = &result.stored_hash {
            println!("Stored    : {stored_hash}");
        }

        if let Some(recomputed_hash) = &result.recomputed_hash {
            println!("Computed  : {recomputed_hash}");
        }

        if let Some(error) = &result.error {
            println!("Error     : {error}");
        }

        println!("Status    : {:?}", result.status);
    }

    println!();
    println!("Summary");
    println!("-------");
    println!("Valid       : {valid}");
    println!("Tampered    : {tampered}");
    println!("Missing hash: {missing}");
    println!("Parse errors: {parse_errors}");
}

/* -------------------------------------------------------------------------- */
/*                                   Tests                                    */
/* -------------------------------------------------------------------------- */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_valid_timestamped_line() {
        let line = r#"{"logged_at":"2026-05-26T03:29:36Z","alert_timestamp_ms":1000,"src_ip":"127.0.0.1","protocol":"MQTT","msg_type":"PUBLISH","pps":1.0,"evidence_hash_hex":"0xf36df10edfd673259ee13146d11e8cfdbe5b25fa24f304506b9daff06381afa9","action":"ALERT"}"#;

        let result = verify_alert_log_line(1, line);

        assert_eq!(
            result.status,
            VerificationStatus::Valid
        );
    }

    #[test]
    fn verifies_legacy_valid_line_without_timestamp() {
        let line = r#"{"logged_at":"2026-05-26T03:29:36Z","src_ip":"127.0.0.1","protocol":"MQTT","msg_type":"CONNECT","pps":1.0,"evidence_hash_hex":"0x96e0502eed7fad79c07f7620c13c026468418898f71af1b2fbd5c9c770a213ab","action":"ALERT"}"#;

        let result = verify_alert_log_line(1, line);

        assert_eq!(
            result.status,
            VerificationStatus::Valid
        );
    }

    #[test]
    fn detects_tampered_line() {
        let line = r#"{"logged_at":"2026-05-26T03:29:36Z","alert_timestamp_ms":1000,"src_ip":"127.0.0.1","protocol":"MQTT","msg_type":"PUBLISH","pps":999.0,"evidence_hash_hex":"0xf36df10edfd673259ee13146d11e8cfdbe5b25fa24f304506b9daff06381afa9","action":"ALERT"}"#;

        let result = verify_alert_log_line(1, line);

        assert_eq!(
            result.status,
            VerificationStatus::Tampered
        );
    }

    #[test]
    fn detects_missing_hash() {
        let line = r#"{"logged_at":"2026-05-26T03:29:36Z","alert_timestamp_ms":1000,"src_ip":"127.0.0.1","protocol":"MQTT","msg_type":"CONNECT","pps":1.0,"evidence_hash_hex":null,"action":"ALERT"}"#;

        let result = verify_alert_log_line(1, line);

        assert_eq!(
            result.status,
            VerificationStatus::MissingHash
        );
    }
}