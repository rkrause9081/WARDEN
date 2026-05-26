//! JSONL logging backend.
//!
//! Writes one JSON object per line:
//!
//! logs/alerts.jsonl
//! logs/bans.jsonl
//!
//! Phase 7 adds cryptographic evidence hashes suitable for future blockchain anchoring.

use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::evidence::hash_bytes_to_hex;
use crate::types::AlertEvent;

#[derive(Debug, Clone)]
pub struct JsonlLoggerConfig {
    pub log_dir: PathBuf,
    pub alerts_file: String,
    pub bans_file: String,
}

impl Default for JsonlLoggerConfig {
    fn default() -> Self {
        Self {
            log_dir: PathBuf::from("logs"),
            alerts_file: "alerts.jsonl".to_string(),
            bans_file: "bans.jsonl".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct JsonlLogger {
    alerts_path: PathBuf,
    bans_path: PathBuf,
}

impl JsonlLogger {
    pub fn new(config: JsonlLoggerConfig) -> Result<Self, std::io::Error> {
        create_dir_all(&config.log_dir)?;

        Ok(Self {
            alerts_path: config.log_dir.join(config.alerts_file),
            bans_path: config.log_dir.join(config.bans_file),
        })
    }

    pub fn default_logger() -> Result<Self, std::io::Error> {
        Self::new(JsonlLoggerConfig::default())
    }

    pub fn log_alert(&self, alert: &AlertEvent) -> Result<(), std::io::Error> {
        let record = AlertLogRecord::from(alert);
        append_jsonl(&self.alerts_path, &record)
    }

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
            evidence_hash_hex: evidence_hash.map(hash_bytes_to_hex),
            action: "BAN".to_string(),
        };

        append_jsonl(&self.bans_path, &record)
    }

    pub fn log_unban(&self, src_ip: IpAddr, dry_run: bool) -> Result<(), std::io::Error> {
        let record = UnbanLogRecord {
            logged_at: Utc::now(),
            src_ip: src_ip.to_string(),
            dry_run,
            action: "UNBAN".to_string(),
        };

        append_jsonl(&self.bans_path, &record)
    }
}

#[derive(Debug, Clone, Serialize)]
struct AlertLogRecord {
    logged_at: DateTime<Utc>,
    src_ip: String,
    protocol: String,
    msg_type: String,
    pps: f64,
    evidence_hash_hex: Option<String>,
    action: String,
}

impl From<&AlertEvent> for AlertLogRecord {
    fn from(alert: &AlertEvent) -> Self {
        Self {
            logged_at: Utc::now(),
            src_ip: alert.src_ip.to_string(),
            protocol: alert.protocol.as_str().to_string(),
            msg_type: alert.msg_type.as_str().to_string(),
            pps: alert.pps,
            evidence_hash_hex: alert.evidence_hash.map(hash_bytes_to_hex),
            action: "ALERT".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct BanLogRecord {
    logged_at: DateTime<Utc>,
    src_ip: String,
    protocol: String,
    pps: f64,
    ban_duration_seconds: f64,
    dry_run: bool,
    evidence_hash_hex: Option<String>,
    action: String,
}

#[derive(Debug, Clone, Serialize)]
struct UnbanLogRecord {
    logged_at: DateTime<Utc>,
    src_ip: String,
    dry_run: bool,
    action: String,
}

fn append_jsonl<T: Serialize>(path: &Path, record: &T) -> Result<(), std::io::Error> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    serde_json::to_writer(&mut file, record)?;
    file.write_all(b"\n")?;
    file.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AlertEvent, MessageType, Protocol};
    use std::fs;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::SystemTime;

    fn ip(value: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(value))
    }

    fn test_alert(src_ip: IpAddr) -> AlertEvent {
        AlertEvent {
            src_ip,
            protocol: Protocol::MQTT,
            msg_type: MessageType::Known("PUBLISH".to_string()),
            pps: 42.0,
            timestamp: SystemTime::now(),
            evidence_hash: Some([7u8; 32]),
        }
    }

    #[test]
    fn writes_alert_jsonl_with_hash() {
        let dir = std::env::temp_dir().join(format!("warden-jsonl-alert-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        let logger = JsonlLogger::new(JsonlLoggerConfig {
            log_dir: dir.clone(),
            alerts_file: "alerts.jsonl".to_string(),
            bans_file: "bans.jsonl".to_string(),
        }).unwrap();

        logger.log_alert(&test_alert(ip([192, 168, 10, 90]))).unwrap();

        let contents = fs::read_to_string(dir.join("alerts.jsonl")).unwrap();
        assert!(contents.contains("\"action\":\"ALERT\""));
        assert!(contents.contains("192.168.10.90"));
        assert!(contents.contains("\"evidence_hash_hex\""));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn writes_ban_jsonl_with_hash() {
        let dir = std::env::temp_dir().join(format!("warden-jsonl-ban-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        let logger = JsonlLogger::new(JsonlLoggerConfig {
            log_dir: dir.clone(),
            alerts_file: "alerts.jsonl".to_string(),
            bans_file: "bans.jsonl".to_string(),
        }).unwrap();

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

        let contents = fs::read_to_string(dir.join("bans.jsonl")).unwrap();
        assert!(contents.contains("\"action\":\"BAN\""));
        assert!(contents.contains("192.168.10.90"));
        assert!(contents.contains("\"evidence_hash_hex\""));

        let _ = fs::remove_dir_all(&dir);
    }
}
