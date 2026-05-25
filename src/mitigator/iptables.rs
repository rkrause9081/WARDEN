//! iptables-based mitigation backend.
//!
//! This is the Rust port of the Python `mitigator.py` behavior:
//! - insert DROP rule for offending source IP
//! - avoid duplicate active bans
//! - automatically lift expired bans
//! - support dry-run mode
//!
//! Linux-only.

use std::collections::HashMap;
use std::net::IpAddr;
use std::process::Command;
use std::time::{Duration, SystemTime};

use crate::types::AlertEvent;

#[derive(Debug, Clone)]
pub struct MitigatorConfig {
    pub ban_duration_seconds: f64,
    pub dry_run: bool,
}

impl MitigatorConfig {
    pub fn new(ban_duration_seconds: f64, dry_run: bool) -> Self {
        Self {
            ban_duration_seconds,
            dry_run,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BanRecord {
    pub src_ip: IpAddr,
    pub protocol: String,
    pub pps: f64,
    pub banned_at: SystemTime,
    pub expires_at: SystemTime,
    pub ban_duration: Duration,
}

impl BanRecord {
    pub fn is_expired(&self) -> bool {
        SystemTime::now() >= self.expires_at
    }

    pub fn time_remaining(&self) -> Duration {
        self.expires_at
            .duration_since(SystemTime::now())
            .unwrap_or(Duration::ZERO)
    }
}

#[derive(Debug, Clone)]
pub struct MitigatorStats {
    pub active_bans: usize,
    pub total_bans: u64,
    pub total_unbans: u64,
    pub dry_run: bool,
}

#[derive(Debug)]
pub struct Mitigator {
    ban_duration: Duration,
    dry_run: bool,
    bans: HashMap<IpAddr, BanRecord>,
    total_bans: u64,
    total_unbans: u64,
}

impl Mitigator {
    pub fn ban_duration_seconds(&self) -> f64 {
    self.ban_duration.as_secs_f64()
    }
    pub fn new(config: MitigatorConfig) -> Self {
        Self {
            ban_duration: Duration::from_secs_f64(config.ban_duration_seconds),
            dry_run: config.dry_run,
            bans: HashMap::new(),
            total_bans: 0,
            total_unbans: 0,
        }
    }

    /// Start hook reserved for future janitor thread setup.
    ///
    /// In this phase, expired bans are cleaned opportunistically whenever
    /// `ban()` is called.
    pub fn start(&mut self) {
        if self.dry_run {
            println!("Mitigator started in DRY RUN mode. iptables will not be modified.");
        } else {
            println!("Mitigator started in LIVE mode. iptables rules may be modified.");
        }
    }

    /// Stop mitigation and lift all active bans.
    pub fn stop(&mut self) {
        let ips: Vec<IpAddr> = self.bans.keys().copied().collect();

        for ip in ips {
            if let Err(error) = self.lift_ban(ip) {
                eprintln!("Failed to lift ban for {ip}: {error}");
            }
        }
    }

    /// Ban the source IP from an alert.
    pub fn ban(&mut self, alert: &AlertEvent) -> Result<(), String> {
        self.lift_expired_bans();

        if self.bans.contains_key(&alert.src_ip) {
            return Ok(());
        }

        let banned_at = SystemTime::now();
        let expires_at = banned_at + self.ban_duration;

        let record = BanRecord {
            src_ip: alert.src_ip,
            protocol: alert.protocol.as_str().to_string(),
            pps: alert.pps,
            banned_at,
            expires_at,
            ban_duration: self.ban_duration,
        };

        self.issue_ban(alert.src_ip)?;

        println!(
            "BAN: {} for {:.0}s ({} @ {:.1} PPS)",
            alert.src_ip,
            self.ban_duration.as_secs_f64(),
            alert.protocol.as_str(),
            alert.pps
        );

        self.bans.insert(alert.src_ip, record);
        self.total_bans += 1;

        Ok(())
    }

    pub fn is_banned(&self, ip: IpAddr) -> bool {
        self.bans.contains_key(&ip)
    }

    pub fn get_active_bans(&self) -> HashMap<IpAddr, BanRecord> {
        self.bans.clone()
    }

    pub fn get_stats_snapshot(&self) -> MitigatorStats {
        MitigatorStats {
            active_bans: self.bans.len(),
            total_bans: self.total_bans,
            total_unbans: self.total_unbans,
            dry_run: self.dry_run,
        }
    }

    fn lift_expired_bans(&mut self) {
        let expired: Vec<IpAddr> = self
            .bans
            .iter()
            .filter_map(|(ip, record)| {
                if record.is_expired() {
                    Some(*ip)
                } else {
                    None
                }
            })
            .collect();

        for ip in expired {
            if let Err(error) = self.lift_ban(ip) {
                eprintln!("Failed to lift expired ban for {ip}: {error}");
            }
        }
    }

    fn lift_ban(&mut self, ip: IpAddr) -> Result<(), String> {
        if !self.bans.contains_key(&ip) {
            return Ok(());
        }

        self.remove_ban(ip)?;
        self.bans.remove(&ip);
        self.total_unbans += 1;

        println!("UNBAN: {ip}");
        Ok(())
    }

    fn issue_ban(&self, ip: IpAddr) -> Result<(), String> {
        if self.dry_run {
            println!("[DRY RUN] Would run: iptables -I INPUT -s {ip} -j DROP");
            return Ok(());
        }

        self.run_iptables(&["-I", "INPUT", "-s", &ip.to_string(), "-j", "DROP"])
    }

    fn remove_ban(&self, ip: IpAddr) -> Result<(), String> {
        if self.dry_run {
            println!("[DRY RUN] Would run: iptables -D INPUT -s {ip} -j DROP");
            return Ok(());
        }

        self.run_iptables(&["-D", "INPUT", "-s", &ip.to_string(), "-j", "DROP"])
    }

    fn run_iptables(&self, args: &[&str]) -> Result<(), String> {
        let output = Command::new("iptables")
            .args(args)
            .output()
            .map_err(|error| format!("failed to execute iptables: {error}"))?;

        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!("iptables failed: {stderr}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{MessageType, Protocol};
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(value: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(value))
    }

    fn test_alert(src_ip: IpAddr) -> AlertEvent {
        AlertEvent {
            src_ip,
            protocol: Protocol::MQTT,
            msg_type: MessageType::Known("PUBLISH".to_string()),
            pps: 50.0,
            timestamp: SystemTime::now(),
            evidence_hash: None,
        }
    }

    #[test]
    fn dry_run_ban_marks_ip_as_banned() {
        let src = ip([192, 168, 10, 90]);
        let mut mitigator = Mitigator::new(MitigatorConfig::new(60.0, true));

        mitigator.ban(&test_alert(src)).unwrap();

        assert!(mitigator.is_banned(src));

        let stats = mitigator.get_stats_snapshot();
        assert_eq!(stats.active_bans, 1);
        assert_eq!(stats.total_bans, 1);
    }

    #[test]
    fn dry_run_does_not_duplicate_active_ban() {
        let src = ip([192, 168, 10, 90]);
        let mut mitigator = Mitigator::new(MitigatorConfig::new(60.0, true));

        mitigator.ban(&test_alert(src)).unwrap();
        mitigator.ban(&test_alert(src)).unwrap();

        let stats = mitigator.get_stats_snapshot();
        assert_eq!(stats.active_bans, 1);
        assert_eq!(stats.total_bans, 1);
    }
}
