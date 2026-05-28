/*
 * iptables.rs
 *
 * Purpose:
 *     Implements WARDEN's Linux firewall mitigation backend
 *     using iptables-based blocking.
 *
 * Responsibilities:
 *     - Issue DROP rules for attackers
 *     - Prevent duplicate active bans
 *     - Automatically expire bans
 *     - Maintain mitigation statistics
 *     - Support dry-run simulation mode
 *
 * Non-Responsibilities:
 *     - IDS packet inspection
 *     - Blockchain anchoring
 *     - Dashboard rendering
 *     - Traffic analysis
 *     - Evidence hashing
 *
 * Architecture:
 *
 *      AlertEvent
 *            ↓
 *      Mitigator
 *            ↓
 *      Active Ban Tracking
 *            ↓
 *      iptables Commands
 *            ↓
 *      Linux Firewall Rules
 *
 * Notes:
 *     - Linux-only backend
 *     - Mirrors original Python mitigator behavior
 *     - Dry-run mode never modifies firewall rules
 */

/* -------------------------------------------------------------------------- */
/*                                 Imports                                    */
/* -------------------------------------------------------------------------- */

use std::collections::HashMap;

use std::net::IpAddr;

use std::process::Command;

use std::time::{Duration, SystemTime};

use crate::types::AlertEvent;

/* -------------------------------------------------------------------------- */
/*                          Mitigator Configuration                           */
/* -------------------------------------------------------------------------- */

/// Runtime mitigation configuration.
#[derive(Debug, Clone)]
pub struct MitigatorConfig {
    /// Duration of active bans.
    pub ban_duration_seconds: f64,

    /// Enables firewall simulation mode.
    pub dry_run: bool,
}

/* -------------------------------------------------------------------------- */
/*                    MitigatorConfig Implementation                          */
/* -------------------------------------------------------------------------- */

impl MitigatorConfig {
    /**
     * Creates mitigation configuration.
     *
     * # Arguments
     *
     * * `ban_duration_seconds` - Ban duration
     * * `dry_run` - Whether firewall commands are simulated
     */
    pub fn new(
        ban_duration_seconds: f64,
        dry_run: bool,
    ) -> Self {
        Self {
            ban_duration_seconds,
            dry_run,
        }
    }
}

/* -------------------------------------------------------------------------- */
/*                               Ban Records                                  */
/* -------------------------------------------------------------------------- */

/// Active mitigation record.
///
/// Stores metadata about blocked attackers.
#[derive(Debug, Clone)]
pub struct BanRecord {
    /// Source IP address currently blocked.
    pub src_ip: IpAddr,

    /// Protocol associated with the attack.
    pub protocol: String,

    /// PPS value observed during detection.
    pub pps: f64,

    /// Timestamp when the ban was applied.
    pub banned_at: SystemTime,

    /// Timestamp when the ban expires.
    pub expires_at: SystemTime,

    /// Total ban duration.
    pub ban_duration: Duration,
}

/* -------------------------------------------------------------------------- */
/*                      BanRecord Implementation                              */
/* -------------------------------------------------------------------------- */

impl BanRecord {
    /**
     * Returns whether the ban has expired.
     */
    pub fn is_expired(&self) -> bool {
        SystemTime::now() >= self.expires_at
    }

    /**
     * Returns remaining active ban time.
     */
    pub fn time_remaining(&self) -> Duration {
        self.expires_at
            .duration_since(SystemTime::now())
            .unwrap_or(Duration::ZERO)
    }
}

/* -------------------------------------------------------------------------- */
/*                           Mitigation Statistics                            */
/* -------------------------------------------------------------------------- */

/// Runtime mitigation statistics snapshot.
#[derive(Debug, Clone)]
pub struct MitigatorStats {
    /// Number of currently active bans.
    pub active_bans: usize,

    /// Total bans issued since startup.
    pub total_bans: u64,

    /// Total bans lifted since startup.
    pub total_unbans: u64,

    /// Whether dry-run mode is enabled.
    pub dry_run: bool,
}

/* -------------------------------------------------------------------------- */
/*                                Mitigator                                   */
/* -------------------------------------------------------------------------- */

/// Linux firewall mitigation engine.
///
/// Manages:
/// - active bans
/// - automatic expiration
/// - firewall interaction
/// - mitigation statistics
#[derive(Debug)]
pub struct Mitigator {
    /// Duration of active bans.
    ban_duration: Duration,

    /// Whether firewall actions are simulated.
    dry_run: bool,

    /// Active ban tracking table.
    bans: HashMap<IpAddr, BanRecord>,

    /// Total bans issued.
    total_bans: u64,

    /// Total bans lifted.
    total_unbans: u64,
}

/* -------------------------------------------------------------------------- */
/*                      Mitigator Implementation                              */
/* -------------------------------------------------------------------------- */

impl Mitigator {
    /**
     * Creates a mitigation engine instance.
     */
    pub fn new(config: MitigatorConfig) -> Self {
        Self {
            ban_duration:
                Duration::from_secs_f64(
                    config.ban_duration_seconds
                ),

            dry_run: config.dry_run,

            bans: HashMap::new(),

            total_bans: 0,

            total_unbans: 0,
        }
    }

    /**
     * Starts the mitigation subsystem.
     *
     * Reserved for future janitor-thread support.
     *
     * Current behavior:
     * - expired bans are cleaned opportunistically
     * - cleanup occurs during `ban()`
     */
    pub fn start(&mut self) {
        if self.dry_run {
            println!(
                "Mitigator started in DRY RUN mode. \
                 iptables will not be modified."
            );
        } else {
            println!(
                "Mitigator started in LIVE mode. \
                 iptables rules may be modified."
            );
        }
    }

    /**
     * Stops mitigation and lifts all active bans.
     */
    pub fn stop(&mut self) {
        let ips: Vec<IpAddr> =
            self.bans.keys().copied().collect();

        for ip in ips {
            if let Err(error) = self.lift_ban(ip) {
                eprintln!(
                    "Failed to lift ban for {ip}: {error}"
                );
            }
        }
    }

    /**
     * Applies mitigation for an alert source IP.
     *
     * Behavior:
     * - lifts expired bans first
     * - avoids duplicate bans
     * - issues firewall DROP rules
     * - stores active mitigation state
     *
     * # Arguments
     *
     * * `alert` - IDS alert event
     */
    pub fn ban(
        &mut self,
        alert: &AlertEvent,
    ) -> Result<(), String> {
        self.lift_expired_bans();

        if self.bans.contains_key(&alert.src_ip) {
            return Ok(());
        }

        let banned_at = SystemTime::now();

        let expires_at =
            banned_at + self.ban_duration;

        let record = BanRecord {
            src_ip: alert.src_ip,

            protocol:
                alert.protocol.as_str().to_string(),

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

    /**
     * Returns whether an IP is actively banned.
     */
    pub fn is_banned(&self, ip: IpAddr) -> bool {
        self.bans.contains_key(&ip)
    }

    /**
     * Returns all active bans.
     */
    pub fn get_active_bans(
        &self
    ) -> HashMap<IpAddr, BanRecord> {
        self.bans.clone()
    }

    /**
     * Returns configured ban duration in seconds.
     */
    pub fn ban_duration_seconds(&self) -> f64 {
        self.ban_duration.as_secs_f64()
    }

    /**
     * Returns whether dry-run mode is enabled.
     */
    pub fn is_dry_run(&self) -> bool {
        self.dry_run
    }

    /**
     * Returns mitigation runtime statistics.
     */
    pub fn get_stats_snapshot(
        &self
    ) -> MitigatorStats {
        MitigatorStats {
            active_bans: self.bans.len(),

            total_bans: self.total_bans,

            total_unbans: self.total_unbans,

            dry_run: self.dry_run,
        }
    }

    /**
     * Lifts all expired bans.
     */
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
                eprintln!(
                    "Failed to lift expired ban \
                     for {ip}: {error}"
                );
            }
        }
    }

    /**
     * Removes an active ban from an IP.
     */
    fn lift_ban(
        &mut self,
        ip: IpAddr,
    ) -> Result<(), String> {
        if !self.bans.contains_key(&ip) {
            return Ok(());
        }

        self.remove_ban(ip)?;

        self.bans.remove(&ip);

        self.total_unbans += 1;

        println!("UNBAN: {ip}");

        Ok(())
    }

    /**
     * Issues an iptables DROP rule.
     */
    fn issue_ban(
        &self,
        ip: IpAddr,
    ) -> Result<(), String> {
        if self.dry_run {
            println!(
                "[DRY RUN] Would run: \
                 iptables -I INPUT -s {ip} -j DROP"
            );

            return Ok(());
        }

        self.run_iptables(&[
            "-I",
            "INPUT",
            "-s",
            &ip.to_string(),
            "-j",
            "DROP",
        ])
    }

    /**
     * Removes an iptables DROP rule.
     */
    fn remove_ban(
        &self,
        ip: IpAddr,
    ) -> Result<(), String> {
        if self.dry_run {
            println!(
                "[DRY RUN] Would run: \
                 iptables -D INPUT -s {ip} -j DROP"
            );

            return Ok(());
        }

        self.run_iptables(&[
            "-D",
            "INPUT",
            "-s",
            &ip.to_string(),
            "-j",
            "DROP",
        ])
    }

    /**
     * Executes an iptables system command.
     *
     * # Arguments
     *
     * * `args` - iptables CLI arguments
     */
    fn run_iptables(
        &self,
        args: &[&str],
    ) -> Result<(), String> {
        let output = Command::new("iptables")
            .args(args)
            .output()
            .map_err(|error| {
                format!(
                    "failed to execute iptables: {error}"
                )
            })?;

        if output.status.success() {
            Ok(())
        } else {
            let stderr =
                String::from_utf8_lossy(
                    &output.stderr
                );

            Err(format!(
                "iptables failed: {stderr}"
            ))
        }
    }
}

/* -------------------------------------------------------------------------- */
/*                                   Tests                                    */
/* -------------------------------------------------------------------------- */

#[cfg(test)]
mod tests {
    use super::*;

    use crate::types::{
        MessageType,
        Protocol,
    };

    use std::net::{IpAddr, Ipv4Addr};

    /* ---------------------------------------------------------------------- */
    /*                              Test Helpers                              */
    /* ---------------------------------------------------------------------- */

    /// Helper for generating IPv4 addresses.
    fn ip(value: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(value))
    }

    /**
     * Creates reusable IDS alerts for mitigation tests.
     */
    fn test_alert(src_ip: IpAddr) -> AlertEvent {
        AlertEvent {
            src_ip,

            protocol: Protocol::MQTT,

            msg_type: MessageType::Known(
                "PUBLISH".to_string()
            ),

            pps: 50.0,

            timestamp: SystemTime::now(),

            evidence_hash: None,
        }
    }

    /* ---------------------------------------------------------------------- */
    /*                             Mitigation Tests                           */
    /* ---------------------------------------------------------------------- */

    #[test]
    fn dry_run_ban_marks_ip_as_banned() {
        let src = ip([192, 168, 10, 90]);

        let mut mitigator = Mitigator::new(
            MitigatorConfig::new(60.0, true)
        );

        mitigator
            .ban(&test_alert(src))
            .unwrap();

        assert!(mitigator.is_banned(src));

        let stats =
            mitigator.get_stats_snapshot();

        assert_eq!(stats.active_bans, 1);

        assert_eq!(stats.total_bans, 1);
    }

    #[test]
    fn dry_run_does_not_duplicate_active_ban() {
        let src = ip([192, 168, 10, 90]);

        let mut mitigator = Mitigator::new(
            MitigatorConfig::new(60.0, true)
        );

        mitigator
            .ban(&test_alert(src))
            .unwrap();

        mitigator
            .ban(&test_alert(src))
            .unwrap();

        let stats =
            mitigator.get_stats_snapshot();

        assert_eq!(stats.active_bans, 1);

        assert_eq!(stats.total_bans, 1);
    }
}