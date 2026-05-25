//! Sliding-window PPS detection engine.
//!
//! This is the Rust Phase 1 port of the Python `engine.py` logic.
//! It is synchronous for now so it stays easy to test.
//!
//! Later pipeline:
//! Sniffer -> PacketRecord -> Engine::ingest() -> Option<AlertEvent> -> Mitigator

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use crate::types::{AlertEvent, PacketRecord};

/// Per-IP sliding-window statistics.
#[derive(Debug, Clone)]
struct IpStats {
    timestamps: VecDeque<SystemTime>,
    last_alert: Option<SystemTime>,
    total_packets: u64,
}

impl IpStats {
    fn new() -> Self {
        Self {
            timestamps: VecDeque::new(),
            last_alert: None,
            total_packets: 0,
        }
    }
}

/// Snapshot used by the dashboard, logs, or CLI summary.
#[derive(Debug, Clone)]
pub struct EngineStatsSnapshot {
    pub total_ingested: u64,
    pub total_alerts: u64,
    pub tracked_ips: usize,
    pub threshold_pps: f64,
    pub window_seconds: f64,
}

/// Detection engine configuration.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub threshold_pps: f64,
    pub window_seconds: f64,
    pub cooldown_seconds: f64,
    pub whitelist: HashSet<IpAddr>,
}

impl EngineConfig {
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

/// Detection brain of The Warden.
#[derive(Debug)]
pub struct Engine {
    threshold_pps: f64,
    window: Duration,
    cooldown: Duration,
    whitelist: HashSet<IpAddr>,
    stats_by_ip: HashMap<IpAddr, IpStats>,
    total_ingested: u64,
    total_alerts: u64,
}

impl Engine {
    pub fn new(config: EngineConfig) -> Self {
        Self {
            threshold_pps: config.threshold_pps,
            window: Duration::from_secs_f64(config.window_seconds),
            cooldown: Duration::from_secs_f64(config.cooldown_seconds),
            whitelist: config.whitelist,
            stats_by_ip: HashMap::new(),
            total_ingested: 0,
            total_alerts: 0,
        }
    }

    /// Process one packet and return an alert when threshold + cooldown allow it.
    pub fn ingest(&mut self, record: PacketRecord) -> Option<AlertEvent> {
        if self.whitelist.contains(&record.src_ip) {
            return None;
        }

        let now = record.timestamp;

        let stats = self
            .stats_by_ip
            .entry(record.src_ip)
            .or_insert_with(IpStats::new);

        stats.total_packets += 1;
        stats.timestamps.push_back(now);
        self.total_ingested += 1;

        Self::prune_old_timestamps(&mut stats.timestamps, now, self.window);

        let pps = stats.timestamps.len() as f64 / self.window.as_secs_f64();

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

    /// Current PPS for one source IP.
    pub fn get_pps(&self, src_ip: &IpAddr) -> f64 {
        let Some(stats) = self.stats_by_ip.get(src_ip) else {
            return 0.0;
        };

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

    /// Current PPS for all tracked source IPs.
    pub fn get_all_pps(&self) -> HashMap<IpAddr, f64> {
        self.stats_by_ip
            .keys()
            .map(|ip| (*ip, self.get_pps(ip)))
            .collect()
    }

    /// Top talkers by current PPS, descending.
    pub fn get_top_talkers(&self, limit: usize) -> Vec<(IpAddr, f64)> {
        let mut talkers: Vec<(IpAddr, f64)> = self.get_all_pps().into_iter().collect();

        talkers.sort_by(|(_, left_pps), (_, right_pps)| {
            right_pps
                .partial_cmp(left_pps)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        talkers.truncate(limit);
        talkers
    }

    /// Clear tracking data for one source IP.
    pub fn reset_ip(&mut self, src_ip: &IpAddr) {
        self.stats_by_ip.remove(src_ip);
    }

    pub fn get_stats_snapshot(&self) -> EngineStatsSnapshot {
        EngineStatsSnapshot {
            total_ingested: self.total_ingested,
            total_alerts: self.total_alerts,
            tracked_ips: self.stats_by_ip.len(),
            threshold_pps: self.threshold_pps,
            window_seconds: self.window.as_secs_f64(),
        }
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{MessageType, Protocol};
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(value: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(value))
    }

    fn test_record(src_ip: IpAddr, timestamp: SystemTime) -> PacketRecord {
        PacketRecord::with_timestamp(
            timestamp,
            src_ip,
            ip([192, 168, 10, 1]),
            Protocol::MQTT,
            MessageType::Known("PUBLISH".to_string()),
        )
    }

    #[test]
    fn does_not_alert_below_threshold() {
        let mut engine = Engine::new(EngineConfig::new(
            3.0,
            5.0,
            10.0,
            Vec::<IpAddr>::new(),
        ));

        let src = ip([192, 168, 10, 50]);
        let base = SystemTime::UNIX_EPOCH + Duration::from_secs(100);

        assert!(engine.ingest(test_record(src, base)).is_none());
        assert!(engine.ingest(test_record(src, base + Duration::from_secs(1))).is_none());

        let snapshot = engine.get_stats_snapshot();
        assert_eq!(snapshot.total_ingested, 2);
        assert_eq!(snapshot.total_alerts, 0);
    }

    #[test]
    fn alerts_when_threshold_is_reached() {
        let mut engine = Engine::new(EngineConfig::new(
            1.0,
            5.0,
            10.0,
            Vec::<IpAddr>::new(),
        ));

        let src = ip([192, 168, 10, 90]);
        let base = SystemTime::UNIX_EPOCH + Duration::from_secs(100);

        for offset in 0..4 {
            assert!(engine
                .ingest(test_record(src, base + Duration::from_secs(offset)))
                .is_none());
        }

        let alert = engine.ingest(test_record(src, base + Duration::from_secs(4)));
        assert!(alert.is_some());

        let alert = alert.unwrap();
        assert_eq!(alert.src_ip, src);
        assert_eq!(alert.protocol, Protocol::MQTT);
        assert!((alert.pps - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn respects_alert_cooldown() {
        let mut engine = Engine::new(EngineConfig::new(
            1.0,
            5.0,
            10.0,
            Vec::<IpAddr>::new(),
        ));

        let src = ip([192, 168, 10, 90]);
        let base = SystemTime::UNIX_EPOCH + Duration::from_secs(100);

        for offset in 0..5 {
            engine.ingest(test_record(src, base + Duration::from_secs(offset)));
        }

        // Still above threshold, but cooldown has not elapsed.
        let alert = engine.ingest(test_record(src, base + Duration::from_secs(5)));
        assert!(alert.is_none());

        // Cooldown elapsed, but we need enough packets inside the current
        // 5-second window to reach 1 PPS again.
        for offset in 15..19 {
            assert!(engine
                .ingest(test_record(src, base + Duration::from_secs(offset)))
                .is_none());
        }

        let alert = engine.ingest(test_record(src, base + Duration::from_secs(19)));
        assert!(alert.is_some());
    }

    #[test]
    fn ignores_whitelisted_ips() {
        let broker = ip([192, 168, 10, 1]);

        let mut engine = Engine::new(EngineConfig::new(
            1.0,
            5.0,
            10.0,
            vec![broker],
        ));

        let base = SystemTime::UNIX_EPOCH + Duration::from_secs(100);

        for offset in 0..10 {
            assert!(engine
                .ingest(test_record(broker, base + Duration::from_secs(offset)))
                .is_none());
        }

        let snapshot = engine.get_stats_snapshot();
        assert_eq!(snapshot.total_ingested, 0);
        assert_eq!(snapshot.total_alerts, 0);
    }

    #[test]
    fn reset_ip_clears_tracking_data() {
        let src = ip([192, 168, 10, 90]);

        let mut engine = Engine::new(EngineConfig::new(
            1.0,
            5.0,
            10.0,
            Vec::<IpAddr>::new(),
        ));

        let base = SystemTime::UNIX_EPOCH + Duration::from_secs(100);

        engine.ingest(test_record(src, base));
        assert_eq!(engine.get_stats_snapshot().tracked_ips, 1);

        engine.reset_ip(&src);
        assert_eq!(engine.get_stats_snapshot().tracked_ips, 0);
    }
}
