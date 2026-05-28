/*
 * jsonl.rs
 *
 * Purpose:
 *     Implements WARDEN's persistent JSONL forensic logging backend.
 *
 * Responsibilities:
 *     - Persist alert evidence logs
 *     - Persist mitigation logs
 *     - Serialize structured forensic records
 *     - Maintain append-only audit history
 *     - Store blockchain-compatible evidence hashes
 *
 * Non-Responsibilities:
 *     - Intrusion detection
 *     - Packet inspection
 *     - Blockchain transaction submission
 *     - Evidence verification
 *     - Dashboard rendering
 *
 * Architecture:
 *
 *      IDS Alert / Mitigation
 *                ↓
 *         Structured Log Record
 *                ↓
 *           JSON Serialization
 *                ↓
 *          Append-Only JSONL
 *                ↓
 *      Verification / Blockchain
 *
 * Important Verifier Detail:
 *
 *     `alert_timestamp_ms` must be used during evidence verification.
 *
 *     The evidence hash is generated using the original IDS timestamp,
 *     NOT the filesystem write timestamp (`logged_at`).
 *
 *     `logged_at` may differ by micro/milliseconds and should never
 *     be used when recomputing forensic evidence hashes.
 */

/* -------------------------------------------------------------------------- */
/*                                 Imports                                    */
/* -------------------------------------------------------------------------- */

use std::fs::{create_dir_all, OpenOptions};

use std::io::Write;

use std::net::IpAddr;

use std::path::{Path, PathBuf};

use std::time::UNIX_EPOCH;

use chrono::{DateTime, Utc};

use serde::Serialize;

use crate::evidence::hash_bytes_to_hex;

use crate::types::AlertEvent;

/* -------------------------------------------------------------------------- */
/*                          Logger Configuration                              */
/* -------------------------------------------------------------------------- */

/// Runtime configuration for JSONL forensic logging.
#[derive(Debug, Clone)]
pub struct JsonlLoggerConfig {
    /// Root logging directory.
    pub log_dir: PathBuf,

    /// Alert evidence JSONL filename.
    pub alerts_file: String,

    /// Mitigation JSONL filename.
    pub bans_file: String,
}

/* -------------------------------------------------------------------------- */
/*                     JsonlLoggerConfig Implementation                       */
/* -------------------------------------------------------------------------- */

impl Default for JsonlLoggerConfig {
    /**
     * Creates the default logging configuration.
     *
     * Default paths:
     *
     * - logs/alerts.jsonl
     * - logs/bans.jsonl
     */
    fn default() -> Self {
        Self {
            log_dir: PathBuf::from("logs"),

            alerts_file: "alerts.jsonl".to_string(),

            bans_file: "bans.jsonl".to_string(),
        }
    }
}

/* -------------------------------------------------------------------------- */
/*                               JSONL Logger                                 */
/* -------------------------------------------------------------------------- */

/// Persistent append-only forensic logger.
///
/// Writes one JSON object per line for:
/// - IDS alerts
/// - mitigation events
/// - unban events
///
/// JSONL format simplifies:
/// - streaming
/// - parsing
/// - verification
/// - blockchain evidence replay
#[derive(Debug, Clone)]
pub struct JsonlLogger {
    /// Alert evidence log path.
    alerts_path: PathBuf,

    /// Ban/unban log path.
    bans_path: PathBuf,
}

/* -------------------------------------------------------------------------- */
/*                        JsonlLogger Implementation                          */
/* -------------------------------------------------------------------------- */

impl JsonlLogger {
    /**
     * Creates a new JSONL logger instance.
     *
     * Automatically creates the logging directory if missing.
     */
    pub fn new(
        config: JsonlLoggerConfig
    ) -> Result<Self, std::io::Error> {
        create_dir_all(&config.log_dir)?;

        Ok(Self {
            alerts_path:
                config.log_dir.join(config.alerts_file),

            bans_path:
                config.log_dir.join(config.bans_file),
        })
    }

    /**
     * Creates a logger using default filesystem paths.
     */
    pub fn default_logger()
        -> Result<Self, std::io::Error>
    {
        Self::new(JsonlLoggerConfig::default())
    }

    /**
     * Persists an IDS alert to alerts.jsonl.
     *
     * # Arguments
     *
     * * `alert` - IDS alert event
     */
    pub fn log_alert(
        &self,
        alert: &AlertEvent,
    ) -> Result<(), std::io::Error> {
        let record = AlertLogRecord::from(alert);

        append_jsonl(&self.alerts_path, &record)
    }

    /**
     * Persists a mitigation event to bans.jsonl.
     *
     * # Arguments
     *
     * * `src_ip` - Source IP address
     * * `protocol` - Network/application protocol
     * * `pps` - Packets-per-second value
     * * `ban_duration_seconds` - Ban duration
     * * `dry_run` - Whether mitigation was simulated
     * * `evidence_hash` - Optional forensic evidence hash
     */
    pub fn log_ban(
        &self,
        src_ip: IpAddr,
        protocol: String,
        pps: f64,
        ban_duration_seconds: f64,
        dry_run: bool,
        evidence_hash: Option<[u8; 32]>,
    ) -> Result<(), std::io::Error> {
        let record = BanLogRecord {
            logged_at: Utc::now(),

            src_ip: src_ip.to_string(),

            protocol,

            pps,

            ban_duration_seconds,

            dry_run,

            evidence_hash_hex:
                evidence_hash.map(hash_bytes_to_hex),

            action: "BAN".to_string(),
        };

        append_jsonl(&self.bans_path, &record)
    }

    /**
     * Persists an unban event to bans.jsonl.
     *
     * # Arguments
     *
     * * `src_ip` - Source IP address
     * * `dry_run` - Whether mitigation was simulated
     */
    pub fn log_unban(
        &self,
        src_ip: IpAddr,
        dry_run: bool,
    ) -> Result<(), std::io::Error> {
        let record = UnbanLogRecord {
            logged_at: Utc::now(),

            src_ip: src_ip.to_string(),

            dry_run,

            action: "UNBAN".to_string(),
        };

        append_jsonl(&self.bans_path, &record)
    }
}

/* -------------------------------------------------------------------------- */
/*                           Alert Log Records                                */
/* -------------------------------------------------------------------------- */

/// Serialized IDS alert evidence record.
#[derive(Debug, Clone, Serialize)]
struct AlertLogRecord {
    /// Filesystem write timestamp.
    logged_at: DateTime<Utc>,

    /**
     * Original IDS timestamp used during evidence hashing.
     *
     * Critical for deterministic forensic verification.
     */
    alert_timestamp_ms: u128,

    /// Source IP address.
    src_ip: String,

    /// Protocol associated with the alert.
    protocol: String,

    /// Protocol message classification.
    msg_type: String,

    /// Packets-per-second value.
    pps: f64,

    /// Optional SHA-256 evidence hash.
    evidence_hash_hex: Option<String>,

    /// Human-readable record type.
    action: String,
}

/* -------------------------------------------------------------------------- */
/*                    AlertLogRecord Implementation                           */
/* -------------------------------------------------------------------------- */

impl From<&AlertEvent> for AlertLogRecord {
    /**
     * Converts an IDS alert into a JSONL-safe log record.
     */
    fn from(alert: &AlertEvent) -> Self {
        let alert_timestamp_ms = alert
            .timestamp
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis())
            .unwrap_or(0);

        Self {
            logged_at: Utc::now(),

            alert_timestamp_ms,

            src_ip: alert.src_ip.to_string(),

            protocol:
                alert.protocol.as_str().to_string(),

            msg_type:
                alert.msg_type.as_str().to_string(),

            pps: alert.pps,

            evidence_hash_hex:
                alert.evidence_hash.map(hash_bytes_to_hex),

            action: "ALERT".to_string(),
        }
    }
}

/* -------------------------------------------------------------------------- */
/*                             Ban Log Records                                */
/* -------------------------------------------------------------------------- */

/// Serialized mitigation log entry.
#[derive(Debug, Clone, Serialize)]
struct BanLogRecord {
    /// Filesystem write timestamp.
    logged_at: DateTime<Utc>,

    /// Source IP address.
    src_ip: String,

    /// Protocol associated with the attack.
    protocol: String,

    /// Packets-per-second value.
    pps: f64,

    /// Ban duration in seconds.
    ban_duration_seconds: f64,

    /// Whether mitigation was simulated.
    dry_run: bool,

    /// Optional SHA-256 evidence hash.
    evidence_hash_hex: Option<String>,

    /// Human-readable record type.
    action: String,
}

/* -------------------------------------------------------------------------- */
/*                            Unban Log Records                               */
/* -------------------------------------------------------------------------- */

/// Serialized unban event.
#[derive(Debug, Clone, Serialize)]
struct UnbanLogRecord {
    /// Filesystem write timestamp.
    logged_at: DateTime<Utc>,

    /// Source IP address.
    src_ip: String,

    /// Whether mitigation was simulated.
    dry_run: bool,

    /// Human-readable record type.
    action: String,
}

/* -------------------------------------------------------------------------- */
/*                           JSONL Append Helper                              */
/* -------------------------------------------------------------------------- */

/**
 * Appends a serialized JSON object to a JSONL file.
 *
 * # Arguments
 *
 * * `path` - Target JSONL file
 * * `record` - Serializable forensic record
 */
fn append_jsonl<T: Serialize>(
    path: &Path,
    record: &T,
) -> Result<(), std::io::Error> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;

    serde_json::to_writer(&mut file, record)?;

    file.write_all(b"\n")?;

    file.flush()?;

    Ok(())
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

    use std::fs;

    use std::net::{IpAddr, Ipv4Addr};

    use std::time::SystemTime;

    /* ---------------------------------------------------------------------- */
    /*                              Test Helpers                              */
    /* ---------------------------------------------------------------------- */

    /// Helper for generating IPv4 addresses.
    fn ip(value: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(value))
    }

    /**
     * Creates a reusable IDS alert for logging tests.
     */
    fn test_alert(src_ip: IpAddr) -> AlertEvent {
        AlertEvent {
            src_ip,

            protocol: Protocol::MQTT,

            msg_type: MessageType::Known(
                "PUBLISH".to_string()
            ),

            pps: 42.0,

            timestamp: SystemTime::now(),

            evidence_hash: Some([7u8; 32]),
        }
    }

    /* ---------------------------------------------------------------------- */
    /*                               Logger Tests                             */
    /* ---------------------------------------------------------------------- */

    #[test]
    fn writes_alert_jsonl_with_hash_and_alert_timestamp() {
        let dir = std::env::temp_dir().join(
            format!(
                "warden-jsonl-alert-test-{}",
                std::process::id()
            )
        );

        let _ = fs::remove_dir_all(&dir);

        let logger = JsonlLogger::new(
            JsonlLoggerConfig {
                log_dir: dir.clone(),

                alerts_file:
                    "alerts.jsonl".to_string(),

                bans_file:
                    "bans.jsonl".to_string(),
            }
        ).unwrap();

        logger
            .log_alert(
                &test_alert(
                    ip([192, 168, 10, 90])
                )
            )
            .unwrap();

        let contents = fs::read_to_string(
            dir.join("alerts.jsonl")
        ).unwrap();

        assert!(
            contents.contains("\"action\":\"ALERT\"")
        );

        assert!(
            contents.contains("192.168.10.90")
        );

        assert!(
            contents.contains("\"evidence_hash_hex\"")
        );

        assert!(
            contents.contains("\"alert_timestamp_ms\"")
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn writes_ban_jsonl_with_hash() {
        let dir = std::env::temp_dir().join(
            format!(
                "warden-jsonl-ban-test-{}",
                std::process::id()
            )
        );

        let _ = fs::remove_dir_all(&dir);

        let logger = JsonlLogger::new(
            JsonlLoggerConfig {
                log_dir: dir.clone(),

                alerts_file:
                    "alerts.jsonl".to_string(),

                bans_file:
                    "bans.jsonl".to_string(),
            }
        ).unwrap();

        logger
            .log_ban(
                ip([192, 168, 10, 90]),

                "MQTT".to_string(),

                42.0,

                60.0,

                true,

                Some([7u8; 32]),
            )
            .unwrap();

        let contents = fs::read_to_string(
            dir.join("bans.jsonl")
        ).unwrap();

        assert!(
            contents.contains("\"action\":\"BAN\"")
        );

        assert!(
            contents.contains("192.168.10.90")
        );

        assert!(
            contents.contains("\"evidence_hash_hex\"")
        );

        let _ = fs::remove_dir_all(&dir);
    }
}