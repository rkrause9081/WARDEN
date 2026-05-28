/*
 * web.rs
 *
 * Purpose:
 *     Implements the WARDEN Axum-powered SOC dashboard backend.
 *
 * Responsibilities:
 *     - Serve dashboard HTML/CSS/JS assets
 *     - Store shared live dashboard state
 *     - Track packet, alert, ban, blockchain, and verification telemetry
 *     - Expose JSON API endpoints for the browser dashboard
 *     - Provide browser-based alerts.jsonl verification
 *
 * Non-Responsibilities:
 *     - Capturing packets
 *     - Detecting attacks
 *     - Applying firewall rules
 *     - Submitting blockchain transactions
 *
 * Architecture:
 *
 *      Sniffer / Engine / Mitigator / Blockchain
 *                      ↓
 *               DashboardState
 *                      ↓
 *                 Axum Routes
 *                      ↓
 *              Browser Dashboard
 */

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    body::Bytes,
    extract::State,
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::evidence::hash_bytes_to_hex;
use crate::types::{AlertEvent, Protocol};
use crate::verify::verifier::verify_alert_log_line;
use crate::verify::{VerificationResult, VerificationStatus};

/* -------------------------------------------------------------------------- */
/*                              Shared State Type                             */
/* -------------------------------------------------------------------------- */

pub type SharedDashboardState = Arc<Mutex<DashboardState>>;

/* -------------------------------------------------------------------------- */
/*                                  Constants                                 */
/* -------------------------------------------------------------------------- */

const MAX_RECENT_ITEMS: usize = 50;
const MAX_HISTORY_POINTS: usize = 120;

const INDEX_HTML: &str = include_str!("templates/index.html");
const APP_JS: &str = include_str!("static/app.js");
const STYLES_CSS: &str = include_str!("static/styles.css");

/* -------------------------------------------------------------------------- */
/*                              Dashboard State                               */
/* -------------------------------------------------------------------------- */

#[derive(Debug, Clone, Serialize)]
pub struct DashboardState {
    pub packets_seen: u64,
    pub alerts_seen: u64,
    pub bans_seen: u64,
    pub blockchain_events_seen: u64,
    pub verifications_seen: u64,

    pub mqtt_packets: u64,
    pub coap_packets: u64,

    pub peak_pps: f64,
    pub current_pps: f64,
    pub dry_run: Option<bool>,

    pub last_alert: Option<AlertView>,
    pub top_talkers: HashMap<String, f64>,
    pub active_bans: HashMap<String, BanView>,

    pub recent_packets: Vec<PacketView>,
    pub recent_alerts: Vec<AlertView>,
    pub recent_bans: Vec<BanView>,
    pub blockchain_events: Vec<BlockchainEventView>,
    pub timeline: Vec<TimelineEventView>,

    pub packet_history: Vec<MetricPoint>,
    pub alert_history: Vec<MetricPoint>,
    pub pps_history: Vec<MetricPointF64>,

    pub protocol_counts: ProtocolCounts,
}

impl DashboardState {
    /**
     * Creates an empty dashboard state snapshot.
     */
    pub fn new() -> Self {
        Self {
            packets_seen: 0,
            alerts_seen: 0,
            bans_seen: 0,
            blockchain_events_seen: 0,
            verifications_seen: 0,

            mqtt_packets: 0,
            coap_packets: 0,

            peak_pps: 0.0,
            current_pps: 0.0,
            dry_run: None,

            last_alert: None,
            top_talkers: HashMap::new(),
            active_bans: HashMap::new(),

            recent_packets: Vec::new(),
            recent_alerts: Vec::new(),
            recent_bans: Vec::new(),
            blockchain_events: Vec::new(),
            timeline: Vec::new(),

            packet_history: Vec::new(),
            alert_history: Vec::new(),
            pps_history: Vec::new(),

            protocol_counts: ProtocolCounts::default(),
        }
    }

    /**
     * Creates thread-safe shared dashboard state.
     */
    pub fn shared() -> SharedDashboardState {
        Arc::new(Mutex::new(Self::new()))
    }

    /**
     * Records whether mitigation is running in dry-run or live mode.
     */
    pub fn set_mitigator_mode(&mut self, dry_run: bool) {
        self.dry_run = Some(dry_run);

        self.record_timeline(
            "MITIGATOR".to_string(),
            if dry_run {
                "Mitigator started in dry-run mode".to_string()
            } else {
                "Mitigator started in live enforcement mode".to_string()
            },
            if dry_run { "WARN" } else { "INFO" },
        );
    }

    /**
     * Records live packet telemetry for dashboard rendering.
     */
    pub fn record_packet(
        &mut self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        protocol: Protocol,
        pps: f64,
    ) {
        self.packets_seen += 1;
        self.current_pps = round_2(pps);
        self.peak_pps = self.peak_pps.max(pps);
        self.top_talkers.insert(src_ip.to_string(), round_2(pps));

        match protocol {
            Protocol::MQTT => {
                self.mqtt_packets += 1;
                self.protocol_counts.mqtt += 1;
            }
            Protocol::CoAP => {
                self.coap_packets += 1;
                self.protocol_counts.coap += 1;
            }
        }

        push_capped(
            &mut self.recent_packets,
            PacketView {
                timestamp: now_rfc3339(),
                src_ip: src_ip.to_string(),
                dst_ip: dst_ip.to_string(),
                protocol: protocol.as_str().to_string(),
                pps: round_2(pps),
            },
            MAX_RECENT_ITEMS,
        );

        push_capped(
            &mut self.packet_history,
            MetricPoint {
                label: time_label(),
                value: self.packets_seen,
            },
            MAX_HISTORY_POINTS,
        );

        push_capped(
            &mut self.pps_history,
            MetricPointF64 {
                label: time_label(),
                value: round_2(pps),
            },
            MAX_HISTORY_POINTS,
        );
    }

    /**
     * Records IDS alert telemetry.
     */
    pub fn record_alert(&mut self, alert: &AlertEvent) {
        self.alerts_seen += 1;

        let view = AlertView {
            timestamp: now_rfc3339(),
            src_ip: alert.src_ip.to_string(),
            protocol: alert.protocol.as_str().to_string(),
            msg_type: alert.msg_type.as_str().to_string(),
            pps: round_2(alert.pps),
            severity: severity_for_pps(alert.pps).to_string(),
            evidence_hash: alert.evidence_hash.map(hash_bytes_to_hex),
        };

        self.last_alert = Some(view.clone());

        push_capped(&mut self.recent_alerts, view.clone(), MAX_RECENT_ITEMS);

        push_capped(
            &mut self.alert_history,
            MetricPoint {
                label: time_label(),
                value: self.alerts_seen,
            },
            MAX_HISTORY_POINTS,
        );

        self.record_timeline(
            "DETECTION".to_string(),
            format!(
                "{} flood detected from {} at {:.2} PPS",
                view.protocol, view.src_ip, view.pps
            ),
            &view.severity,
        );
    }

    /**
     * Records mitigation activity.
     */
    pub fn record_ban(
        &mut self,
        src_ip: IpAddr,
        protocol: String,
        pps: f64,
        seconds: f64,
        dry_run: bool,
    ) {
        self.bans_seen += 1;
        self.dry_run = Some(dry_run);

        let view = BanView {
            timestamp: now_rfc3339(),
            src_ip: src_ip.to_string(),
            protocol,
            pps: round_2(pps),
            remaining_seconds: round_2(seconds),
            dry_run,
            action: if dry_run { "DRY_RUN_BAN" } else { "BAN" }.to_string(),
        };

        self.active_bans.insert(src_ip.to_string(), view.clone());

        push_capped(&mut self.recent_bans, view.clone(), MAX_RECENT_ITEMS);

        self.record_timeline(
            "MITIGATION".to_string(),
            if dry_run {
                format!("Dry-run ban simulated for {}", view.src_ip)
            } else {
                format!("iptables ban applied for {}", view.src_ip)
            },
            "CRITICAL",
        );
    }

    /**
     * Records ban removal.
     */
    pub fn record_unban(&mut self, src_ip: IpAddr) {
        self.active_bans.remove(&src_ip.to_string());

        self.record_timeline(
            "MITIGATION".to_string(),
            format!("Ban lifted for {src_ip}"),
            "INFO",
        );
    }

    /**
     * Records successful blockchain evidence anchoring.
     */
    pub fn record_blockchain_event(
        &mut self,
        tx_hash: String,
        evidence_hash: Option<[u8; 32]>,
        registry_address: Option<String>,
        src_ip: String,
        protocol: String,
        status: String,
    ) {
        self.blockchain_events_seen += 1;

        let event = BlockchainEventView {
            timestamp: now_rfc3339(),
            tx_hash,
            evidence_hash: evidence_hash.map(hash_bytes_to_hex),
            registry_address,
            src_ip,
            protocol,
            status,
            anchored: true,
        };

        push_capped(&mut self.blockchain_events, event.clone(), MAX_RECENT_ITEMS);

        self.record_timeline(
            "BLOCKCHAIN".to_string(),
            format!("Evidence anchored on-chain in tx {}", event.tx_hash),
            "INFO",
        );
    }

    /**
     * Records failed blockchain anchoring.
     */
    pub fn record_blockchain_error(
        &mut self,
        src_ip: String,
        protocol: String,
        error: String,
    ) {
        push_capped(
            &mut self.blockchain_events,
            BlockchainEventView {
                timestamp: now_rfc3339(),
                tx_hash: "N/A".to_string(),
                evidence_hash: None,
                registry_address: None,
                src_ip,
                protocol,
                status: format!("ERROR: {error}"),
                anchored: false,
            },
            MAX_RECENT_ITEMS,
        );

        self.record_timeline(
            "BLOCKCHAIN".to_string(),
            "Blockchain anchoring failed".to_string(),
            "WARN",
        );
    }

    /**
     * Records the result of a browser-side JSONL verification request.
     */
    pub fn record_verification_summary(&mut self, summary: &VerificationSummary) {
        self.verifications_seen += 1;

        self.record_timeline(
            "VERIFICATION".to_string(),
            format!(
                "Evidence verification complete: {} valid, {} tampered, {} missing hashes, {} parse errors",
                summary.valid,
                summary.tampered,
                summary.missing_hash,
                summary.parse_errors
            ),
            if summary.tampered > 0 || summary.parse_errors > 0 {
                "CRITICAL"
            } else {
                "INFO"
            },
        );
    }

    /**
     * Records one incident timeline entry.
     */
    pub fn record_timeline(&mut self, stage: String, message: String, severity: &str) {
        push_capped(
            &mut self.timeline,
            TimelineEventView {
                timestamp: now_rfc3339(),
                stage,
                message,
                severity: severity.to_string(),
            },
            MAX_RECENT_ITEMS,
        );
    }
}

/* -------------------------------------------------------------------------- */
/*                             Dashboard DTO Types                            */
/* -------------------------------------------------------------------------- */

#[derive(Debug, Clone, Serialize)]
pub struct PacketView {
    pub timestamp: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub protocol: String,
    pub pps: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AlertView {
    pub timestamp: String,
    pub src_ip: String,
    pub protocol: String,
    pub msg_type: String,
    pub pps: f64,
    pub severity: String,
    pub evidence_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BanView {
    pub timestamp: String,
    pub src_ip: String,
    pub protocol: String,
    pub pps: f64,
    pub remaining_seconds: f64,
    pub dry_run: bool,
    pub action: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BlockchainEventView {
    pub timestamp: String,
    pub tx_hash: String,
    pub evidence_hash: Option<String>,
    pub registry_address: Option<String>,
    pub src_ip: String,
    pub protocol: String,
    pub status: String,
    pub anchored: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TimelineEventView {
    pub timestamp: String,
    pub stage: String,
    pub message: String,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MetricPoint {
    pub label: String,
    pub value: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct MetricPointF64 {
    pub label: String,
    pub value: f64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ProtocolCounts {
    pub mqtt: u64,
    pub coap: u64,
}

#[derive(Debug, Clone, Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct VerificationResponse {
    summary: VerificationSummary,
    results: Vec<VerificationResultView>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerificationSummary {
    total: usize,
    valid: usize,
    tampered: usize,
    missing_hash: usize,
    parse_errors: usize,
    overall_status: String,
}

#[derive(Debug, Clone, Serialize)]
struct VerificationResultView {
    line_number: usize,
    status: String,
    src_ip: Option<String>,
    protocol: Option<String>,
    msg_type: Option<String>,
    stored_hash: Option<String>,
    recomputed_hash: Option<String>,
    error: Option<String>,
}

/* -------------------------------------------------------------------------- */
/*                               Axum Server                                  */
/* -------------------------------------------------------------------------- */

pub async fn start_dashboard(
    state: SharedDashboardState,
    bind_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = Router::new()
        .route("/", get(index))
        .route("/health", get(health))
        .route("/stats", get(stats))
        .route("/api/verify", post(verify_upload))
        .route("/static/app.js", get(app_js))
        .route("/static/styles.css", get(styles_css))
        .with_state(state);

    println!("Dashboard listening on http://{bind_addr}");

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;

    axum::serve(listener, app).await?;

    Ok(())
}

/* -------------------------------------------------------------------------- */
/*                              Route Handlers                                */
/* -------------------------------------------------------------------------- */

async fn index() -> impl IntoResponse {
    Html(INDEX_HTML)
}

async fn app_js() -> Response {
    (
        [(header::CONTENT_TYPE, "application/javascript; charset=utf-8")],
        APP_JS,
    )
        .into_response()
}

async fn styles_css() -> Response {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        STYLES_CSS,
    )
        .into_response()
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: "the-warden",
    })
}

async fn stats(State(state): State<SharedDashboardState>) -> Json<DashboardState> {
    let snapshot = state
        .lock()
        .map(|guard| guard.clone())
        .unwrap_or_else(|_| DashboardState::new());

    Json(snapshot)
}

async fn verify_upload(
    State(state): State<SharedDashboardState>,
    body: Bytes,
) -> Result<Json<VerificationResponse>, StatusCode> {
    let contents = String::from_utf8(body.to_vec()).map_err(|_| StatusCode::BAD_REQUEST)?;

    let results: Vec<VerificationResult> = contents
        .lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let trimmed = line.trim();

            if trimmed.is_empty() {
                None
            } else {
                Some(verify_alert_log_line(index + 1, trimmed))
            }
        })
        .collect();

    let response = build_verification_response(results);

    if let Ok(mut state) = state.lock() {
        state.record_verification_summary(&response.summary);
    }

    Ok(Json(response))
}

/* -------------------------------------------------------------------------- */
/*                           Verification Helpers                             */
/* -------------------------------------------------------------------------- */

fn build_verification_response(results: Vec<VerificationResult>) -> VerificationResponse {
    let mut summary = VerificationSummary {
        total: results.len(),
        valid: 0,
        tampered: 0,
        missing_hash: 0,
        parse_errors: 0,
        overall_status: "VALID".to_string(),
    };

    let result_views = results
        .into_iter()
        .map(|result| {
            match result.status {
                VerificationStatus::Valid => summary.valid += 1,
                VerificationStatus::Tampered => summary.tampered += 1,
                VerificationStatus::MissingHash => summary.missing_hash += 1,
                VerificationStatus::ParseError => summary.parse_errors += 1,
            }

            VerificationResultView {
                line_number: result.line_number,
                status: format!("{:?}", result.status),
                src_ip: result.src_ip,
                protocol: result.protocol,
                msg_type: result.msg_type,
                stored_hash: result.stored_hash,
                recomputed_hash: result.recomputed_hash,
                error: result.error,
            }
        })
        .collect();

    summary.overall_status = if summary.parse_errors > 0 || summary.tampered > 0 {
        "TAMPERED".to_string()
    } else if summary.missing_hash > 0 {
        "MISSING_HASH".to_string()
    } else {
        "VALID".to_string()
    };

    VerificationResponse {
        summary,
        results: result_views,
    }
}

/* -------------------------------------------------------------------------- */
/*                              Utility Helpers                               */
/* -------------------------------------------------------------------------- */

fn push_capped<T>(items: &mut Vec<T>, item: T, max_items: usize) {
    items.push(item);

    if items.len() > max_items {
        let extra = items.len() - max_items;
        items.drain(0..extra);
    }
}

fn now_rfc3339() -> String {
    let now: DateTime<Utc> = SystemTime::now().into();

    now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn time_label() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let seconds = now % 86_400;
    let h = seconds / 3600;
    let m = (seconds % 3600) / 60;
    let s = seconds % 60;

    format!("{h:02}:{m:02}:{s:02}")
}

fn severity_for_pps(pps: f64) -> &'static str {
    if pps >= 100.0 {
        "CRITICAL"
    } else if pps >= 25.0 {
        "WARN"
    } else {
        "INFO"
    }
}

fn round_2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}