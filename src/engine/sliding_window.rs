/*
 * sliding_window.rs
 *
 * Purpose:
 *     Implements WARDEN's sliding-window intrusion detection engine.
 *
 * Responsibilities:
 *     - Track packets-per-second (PPS)
 *     - Detect MQTT flood attacks
 *     - Detect CoAP flood attacks
 *     - Enforce alert cooldowns
 *     - Maintain protocol-aware attack state
 *     - Generate IDS alert events
 *
 * Non-Responsibilities:
 *     - Packet capture
 *     - Firewall mitigation
 *     - Blockchain anchoring
 *     - Dashboard visualization
 *     - Evidence hashing
 *
 * Architecture:
 *
 *      Packet Stream
 *            ↓
 *      Sliding Window Tracking
 *            ↓
 *      PPS Calculation
 *            ↓
 *      Threshold Detection
 *            ↓
 *      Cooldown Enforcement
 *            ↓
 *      AlertEvent Generation
 *
 * Detection Notes:
 *     - MQTT and CoAP are tracked independently
 *     - Protocol cooldowns do not suppress each other
 *     - Dashboard PPS aggregates all protocols per IP
 */

/* -------------------------------------------------------------------------- */
/*                                 Imports                                    */
/* -------------------------------------------------------------------------- */

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use crate::types::{AlertEvent, PacketRecord, Protocol};

/* -------------------------------------------------------------------------- */
/*                                Attack Key                                  */
/* -------------------------------------------------------------------------- */

/// Unique tracking key for protocol-aware detection.
///
/// Prevents MQTT and CoAP traffic from sharing
/// cooldown or PPS tracking state.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AttackKey {
    /// Source IP being monitored.
    src_ip: IpAddr,

    /// Protocol associated with traffic.
    protocol: Protocol,
}

/* -------------------------------------------------------------------------- */
/*                             Per-IP Statistics                              */
/* -------------------------------------------------------------------------- */

/// Sliding-window statistics for one `(IP, protocol)` pair.
#[derive(Debug, Clone)]
struct IpStats {
    /// Packet timestamps currently inside the active window.
    timestamps: VecDeque<SystemTime>,

    /// Timestamp of the most recent alert.
    last_alert: Option<SystemTime>,

    /// Total packets observed for this key.
    total_packets: u64,
}

/* -------------------------------------------------------------------------- */
/*                         IpStats Implementation                             */
/* -------------------------------------------------------------------------- */

impl IpStats {
    /// Creates empty statistics tracking state.
    fn new() -> Self {
        Self {
            timestamps: VecDeque::new(),
            last_alert: None,
            total_packets: 0,
        }
    }
}

/* -------------------------------------------------------------------------- */
/*                           Engine Statistics Snapshot                       */
/* -------------------------------------------------------------------------- */

/// Snapshot of engine runtime statistics.
///
/// Used by:
/// - dashboard metrics
/// - CLI summaries
/// - monitoring panels
/// - forensic reporting
#[derive(Debug, Clone)]
pub struct EngineStatsSnapshot {
    /// Total packets ingested by the engine.
    pub total_ingested: u64,

    /// Total alerts generated.
    pub total_alerts: u64,

    /// Total unique tracked source IPs.
    pub tracked_ips: usize,

    /// Active PPS threshold.
    pub threshold_pps: f64,

    /// Active detection window size.
    pub window_seconds: f64,
}

/* -------------------------------------------------------------------------- */
/*                           Engine Configuration                             */
/* -------------------------------------------------------------------------- */

/// Runtime configuration for the detection engine.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// PPS threshold required to trigger alerts.
    pub threshold_pps: f64,

    /// Sliding-window duration in seconds.
    pub window_seconds: f64,

    /// Cooldown duration between alerts.
    pub cooldown_seconds: f64,

    /// Trusted IPs excluded from detection logic.
    pub whitelist: HashSet<IpAddr>,
}

/* -------------------------------------------------------------------------- */
/*                      EngineConfig Implementation                           */
/* -------------------------------------------------------------------------- */

impl EngineConfig {
    /**
     * Creates a new detection engine configuration.
     *
     * # Arguments
     *
     * * `threshold_pps` - Alert threshold
     * * `window_seconds` - Sliding window duration
     * * `cooldown_seconds` - Alert cooldown duration
     * * `whitelist` - Trusted IP addresses
     */
    pub fn new(
        threshold_pps: f64,
        window_seconds: f64,
        cooldown_seconds: f64,
        whitelist: impl IntoIterator<Item = IpAddr>,
    ) -> Self {
        Self {
            threshold_pps,
            window_seconds,
            cooldown_seconds,
            whitelist: whitelist.into_iter().collect(),
        }
    }
}

/* -------------------------------------------------------------------------- */
/*                              Detection Engine                              */
/* -------------------------------------------------------------------------- */

/// Core intrusion detection engine for WARDEN.
///
/// Maintains protocol-aware sliding windows
/// for packet-rate anomaly detection.
#[derive(Debug)]
pub struct Engine {
    /// PPS threshold required for alerting.
    threshold_pps: f64,

    /// Sliding detection window.
    window: Duration,

    /// Per-protocol alert cooldown duration.
    cooldown: Duration,

    /// Trusted IP addresses excluded from monitoring.
    whitelist: HashSet<IpAddr>,

    /**
     * Protocol-aware tracking map.
     *
     * Tracks `(source IP, protocol)` independently
     * so different protocols do not suppress each other.
     */
    stats_by_key: HashMap<AttackKey, IpStats>,

    /// Total packets ingested.
    total_ingested: u64,

    /// Total alerts generated.
    total_alerts: u64,
}

/* -------------------------------------------------------------------------- */
/*                         Engine Implementation                              */
/* -------------------------------------------------------------------------- */

impl Engine {
    /**
     * Creates a new detection engine instance.
     */
    pub fn new(config: EngineConfig) -> Self {
        Self {
            threshold_pps: config.threshold_pps,
            window: Duration::from_secs_f64(config.window_seconds),
            cooldown: Duration::from_secs_f64(config.cooldown_seconds),
            whitelist: config.whitelist,
            stats_by_key: HashMap::new(),
            total_ingested: 0,
            total_alerts: 0,
        }
    }

    /**
     * Processes one packet through the detection pipeline.
     *
     * Generates an alert only if:
     * - PPS threshold is exceeded
     * - cooldown has expired
     * - source IP is not whitelisted
     *
     * # Arguments
     *
     * * `record` - Captured packet metadata
     */
    pub fn ingest(
        &mut self,
        record: PacketRecord
    ) -> Option<AlertEvent> {
        if self.whitelist.contains(&record.src_ip) {
            return None;
        }

        let now = record.timestamp;

        let key = AttackKey {
            src_ip: record.src_ip,
            protocol: record.protocol.clone(),
        };

        let stats = self
            .stats_by_key
            .entry(key)
            .or_insert_with(IpStats::new);

        stats.total_packets += 1;
        stats.timestamps.push_back(now);

        self.total_ingested += 1;

        Self::prune_old_timestamps(
            &mut stats.timestamps,
            now,
            self.window,
        );

        let pps =
            stats.timestamps.len() as f64
            / self.window.as_secs_f64();

        if pps < self.threshold_pps {
            return None;
        }

        let cooldown_elapsed = match stats.last_alert {
            Some(last_alert) => now
                .duration_since(last_alert)
                .map(|elapsed| elapsed >= self.cooldown)
                .unwrap_or(false),

            None => true,
        };

        if !cooldown_elapsed {
            return None;
        }

        stats.last_alert = Some(now);

        self.total_alerts += 1;

        Some(AlertEvent {
            src_ip: record.src_ip,
            protocol: record.protocol,
            msg_type: record.msg_type,
            pps,
            timestamp: now,
            evidence_hash: None,
        })
    }

    /**
     * Returns total PPS for one source IP
     * aggregated across all protocols.
     */
    pub fn get_pps(&self, src_ip: &IpAddr) -> f64 {
        self.stats_by_key
            .iter()
            .filter(|(key, _)| &key.src_ip == src_ip)
            .map(|(_, stats)| self.get_stats_pps(stats))
            .sum()
    }

    /**
     * Returns PPS for one source IP and protocol.
     */
    pub fn get_protocol_pps(
        &self,
        src_ip: &IpAddr,
        protocol: &Protocol,
    ) -> f64 {
        self.stats_by_key
            .get(&AttackKey {
                src_ip: *src_ip,
                protocol: protocol.clone(),
            })
            .map(|stats| self.get_stats_pps(stats))
            .unwrap_or(0.0)
    }

    /**
     * Calculates active PPS for a statistics bucket.
     */
    fn get_stats_pps(&self, stats: &IpStats) -> f64 {
        let now = SystemTime::now();

        let active_count = stats
            .timestamps
            .iter()
            .filter(|timestamp| {
                now.duration_since(**timestamp)
                    .map(|age| age <= self.window)
                    .unwrap_or(false)
            })
            .count();

        active_count as f64 / self.window.as_secs_f64()
    }

    /**
     * Returns total PPS for all tracked IPs.
     */
    pub fn get_all_pps(&self) -> HashMap<IpAddr, f64> {
        let mut totals = HashMap::new();

        for (key, stats) in &self.stats_by_key {
            let pps = self.get_stats_pps(stats);

            *totals.entry(key.src_ip).or_insert(0.0) += pps;
        }

        totals
    }

    /**
     * Returns highest-traffic source IPs by PPS.
     *
     * # Arguments
     *
     * * `limit` - Maximum number of entries returned
     */
    pub fn get_top_talkers(
        &self,
        limit: usize
    ) -> Vec<(IpAddr, f64)> {
        let mut talkers: Vec<(IpAddr, f64)> =
            self.get_all_pps().into_iter().collect();

        talkers.sort_by(|(_, left_pps), (_, right_pps)| {
            right_pps
                .partial_cmp(left_pps)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        talkers.truncate(limit);

        talkers
    }

    /**
     * Clears tracking state for one source IP
     * across all protocols.
     */
    pub fn reset_ip(&mut self, src_ip: &IpAddr) {
        self.stats_by_key
            .retain(|key, _| &key.src_ip != src_ip);
    }

    /**
     * Returns a runtime statistics snapshot.
     */
    pub fn get_stats_snapshot(
        &self
    ) -> EngineStatsSnapshot {
        let tracked_ips = self
            .stats_by_key
            .keys()
            .map(|key| key.src_ip)
            .collect::<HashSet<_>>()
            .len();

        EngineStatsSnapshot {
            total_ingested: self.total_ingested,
            total_alerts: self.total_alerts,
            tracked_ips,
            threshold_pps: self.threshold_pps,
            window_seconds: self.window.as_secs_f64(),
        }
    }

    /**
     * Removes timestamps outside the active window.
     */
    fn prune_old_timestamps(
        timestamps: &mut VecDeque<SystemTime>,
        now: SystemTime,
        window: Duration,
    ) {
        while let Some(front) = timestamps.front() {
            let should_remove = now
                .duration_since(*front)
                .map(|age| age > window)
                .unwrap_or(false);

            if should_remove {
                timestamps.pop_front();
            } else {
                break;
            }
        }
    }
}

/* -------------------------------------------------------------------------- */
/*                                   Tests                                    */
/* -------------------------------------------------------------------------- */

#[cfg(test)]
mod tests {
    use super::*;

    use crate::types::{MessageType, Protocol};

    use std::net::{IpAddr, Ipv4Addr};

    /// Helper for IPv4 address generation.
    fn ip(value: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(value))
    }

    /**
     * Creates a timestamped packet record for testing.
     */
    fn test_record(
        src_ip: IpAddr,
        timestamp: SystemTime,
        protocol: Protocol,
        msg_type: &str,
    ) -> PacketRecord {
        PacketRecord::with_timestamp(
            timestamp,
            src_ip,
            ip([192, 168, 10, 1]),
            protocol,
            MessageType::Known(msg_type.to_string()),
        )
    }

    /* ---------------------------------------------------------------------- */
    /*                             Detection Tests                            */
    /* ---------------------------------------------------------------------- */

    #[test]
    fn does_not_alert_below_threshold() {
        let mut engine = Engine::new(
            EngineConfig::new(
                3.0,
                5.0,
                10.0,
                Vec::<IpAddr>::new(),
            )
        );

        let src = ip([192, 168, 10, 50]);

        let base =
            SystemTime::UNIX_EPOCH
            + Duration::from_secs(100);

        assert!(
            engine.ingest(
                test_record(
                    src,
                    base,
                    Protocol::MQTT,
                    "PUBLISH"
                )
            ).is_none()
        );

        assert!(
            engine.ingest(
                test_record(
                    src,
                    base + Duration::from_secs(1),
                    Protocol::MQTT,
                    "PUBLISH"
                )
            ).is_none()
        );

        let snapshot = engine.get_stats_snapshot();

        assert_eq!(snapshot.total_ingested, 2);
        assert_eq!(snapshot.total_alerts, 0);
    }
}