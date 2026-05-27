//! Sliding-window PPS detection engine.
//!
//! Protocol-aware detection:
//! - MQTT and CoAP are tracked independently per source IP.
//! - A MQTT cooldown will not suppress a CoAP alert from the same IP.
//! - Dashboard PPS still reports total traffic per IP across protocols.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use crate::types::{AlertEvent, PacketRecord, Protocol};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AttackKey {
    src_ip: IpAddr,
    protocol: Protocol,
}

/// Per source-IP/protocol sliding-window statistics.
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

    /// Tracks traffic by `(source IP, protocol)` so MQTT and CoAP floods do not
    /// suppress each other through a shared cooldown.
    stats_by_key: HashMap<AttackKey, IpStats>,

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
            stats_by_key: HashMap::new(),
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

        let key = AttackKey {
            src_ip: record.src_ip,
            protocol: record.protocol.clone(),
        };

        let stats = self.stats_by_key.entry(key).or_insert_with(IpStats::new);

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

    /// Current total PPS for one source IP across all protocols.
    pub fn get_pps(&self, src_ip: &IpAddr) -> f64 {
        self.stats_by_key
            .iter()
            .filter(|(key, _)| &key.src_ip == src_ip)
            .map(|(_, stats)| self.get_stats_pps(stats))
            .sum()
    }

    /// Current PPS for one source IP and protocol.
    pub fn get_protocol_pps(&self, src_ip: &IpAddr, protocol: &Protocol) -> f64 {
        self.stats_by_key
            .get(&AttackKey {
                src_ip: *src_ip,
                protocol: protocol.clone(),
            })
            .map(|stats| self.get_stats_pps(stats))
            .unwrap_or(0.0)
    }

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

    /// Current total PPS for all tracked source IPs.
    pub fn get_all_pps(&self) -> HashMap<IpAddr, f64> {
        let mut totals = HashMap::new();

        for (key, stats) in &self.stats_by_key {
            let pps = self.get_stats_pps(stats);
            *totals.entry(key.src_ip).or_insert(0.0) += pps;
        }

        totals
    }

    /// Top talkers by current total PPS, descending.
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

    /// Clear tracking data for one source IP across all protocols.
    pub fn reset_ip(&mut self, src_ip: &IpAddr) {
        self.stats_by_key.retain(|key, _| &key.src_ip != src_ip);
    }

    pub fn get_stats_snapshot(&self) -> EngineStatsSnapshot {
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

        assert!(engine.ingest(test_record(src, base, Protocol::MQTT, "PUBLISH")).is_none());
        assert!(engine.ingest(test_record(src, base + Duration::from_secs(1), Protocol::MQTT, "PUBLISH")).is_none());

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
                .ingest(test_record(
                    src,
                    base + Duration::from_secs(offset),
                    Protocol::MQTT,
                    "PUBLISH",
                ))
                .is_none());
        }

        let alert = engine.ingest(test_record(
            src,
            base + Duration::from_secs(4),
            Protocol::MQTT,
            "PUBLISH",
        ));
        assert!(alert.is_some());

        let alert = alert.unwrap();
        assert_eq!(alert.src_ip, src);
        assert_eq!(alert.protocol, Protocol::MQTT);
        assert!((alert.pps - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn protocol_cooldowns_are_independent() {
        let mut engine = Engine::new(EngineConfig::new(
            1.0,
            5.0,
            10.0,
            Vec::<IpAddr>::new(),
        ));

        let src = ip([127, 0, 0, 1]);
        let base = SystemTime::UNIX_EPOCH + Duration::from_secs(100);

        for offset in 0..5 {
            engine.ingest(test_record(
                src,
                base + Duration::from_secs(offset),
                Protocol::MQTT,
                "PUBLISH",
            ));
        }

        for offset in 0..4 {
            assert!(engine
                .ingest(test_record(
                    src,
                    base + Duration::from_secs(offset),
                    Protocol::CoAP,
                    "GET",
                ))
                .is_none());
        }

        let coap_alert = engine.ingest(test_record(
            src,
            base + Duration::from_secs(4),
            Protocol::CoAP,
            "GET",
        ));

        assert!(coap_alert.is_some());
        assert_eq!(coap_alert.unwrap().protocol, Protocol::CoAP);
    }

    #[test]
    fn respects_alert_cooldown_per_protocol() {
        let mut engine = Engine::new(EngineConfig::new(
            1.0,
            5.0,
            10.0,
            Vec::<IpAddr>::new(),
        ));

        let src = ip([192, 168, 10, 90]);
        let base = SystemTime::UNIX_EPOCH + Duration::from_secs(100);

        for offset in 0..5 {
            engine.ingest(test_record(
                src,
                base + Duration::from_secs(offset),
                Protocol::MQTT,
                "PUBLISH",
            ));
        }

        let alert = engine.ingest(test_record(
            src,
            base + Duration::from_secs(5),
            Protocol::MQTT,
            "PUBLISH",
        ));
        assert!(alert.is_none());

        for offset in 15..19 {
            assert!(engine
                .ingest(test_record(
                    src,
                    base + Duration::from_secs(offset),
                    Protocol::MQTT,
                    "PUBLISH",
                ))
                .is_none());
        }

        let alert = engine.ingest(test_record(
            src,
            base + Duration::from_secs(19),
            Protocol::MQTT,
            "PUBLISH",
        ));
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
                .ingest(test_record(
                    broker,
                    base + Duration::from_secs(offset),
                    Protocol::MQTT,
                    "PUBLISH",
                ))
                .is_none());
        }

        let snapshot = engine.get_stats_snapshot();
        assert_eq!(snapshot.total_ingested, 0);
        assert_eq!(snapshot.total_alerts, 0);
    }

    #[test]
    fn reset_ip_clears_tracking_data_for_all_protocols() {
        let src = ip([192, 168, 10, 90]);

        let mut engine = Engine::new(EngineConfig::new(
            1.0,
            5.0,
            10.0,
            Vec::<IpAddr>::new(),
        ));

        let base = SystemTime::UNIX_EPOCH + Duration::from_secs(100);

        engine.ingest(test_record(src, base, Protocol::MQTT, "PUBLISH"));
        engine.ingest(test_record(src, base, Protocol::CoAP, "GET"));
        assert_eq!(engine.get_stats_snapshot().tracked_ips, 1);

        engine.reset_ip(&src);
        assert_eq!(engine.get_stats_snapshot().tracked_ips, 0);
    }
}
