//! Minimal Axum web dashboard for The Warden.
//!
//! Phase 5 goals:
//! - expose health/status endpoint
//! - expose packet/alert/ban stats
//! - serve a simple browser dashboard
//!
//! Required Cargo dependencies:
//!
//! ```toml
//! axum = "0.7"
//! tokio = { version = "1", features = ["full"] }
//! serde = { version = "1", features = ["derive"] }
//! serde_json = "1"
//! ```

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use axum::{
    extract::State,
    response::{Html, IntoResponse},
    routing::get,
    Json, Router,
};
use serde::Serialize;

use crate::types::AlertEvent;

pub type SharedDashboardState = Arc<Mutex<DashboardState>>;

#[derive(Debug, Clone, Serialize)]
pub struct DashboardState {
    pub packets_seen: u64,
    pub alerts_seen: u64,
    pub bans_seen: u64,
    pub last_alert: Option<AlertView>,
    pub top_talkers: HashMap<String, f64>,
    pub active_bans: HashMap<String, BanView>,
}

impl DashboardState {
    pub fn new() -> Self {
        Self {
            packets_seen: 0,
            alerts_seen: 0,
            bans_seen: 0,
            last_alert: None,
            top_talkers: HashMap::new(),
            active_bans: HashMap::new(),
        }
    }

    pub fn shared() -> SharedDashboardState {
        Arc::new(Mutex::new(Self::new()))
    }

    pub fn record_packet(&mut self, src_ip: IpAddr, pps: f64) {
        self.packets_seen += 1;
        self.top_talkers.insert(src_ip.to_string(), pps);
    }

    pub fn record_alert(&mut self, alert: &AlertEvent) {
        self.alerts_seen += 1;
        self.last_alert = Some(AlertView {
            src_ip: alert.src_ip.to_string(),
            protocol: alert.protocol.as_str().to_string(),
            msg_type: alert.msg_type.as_str().to_string(),
            pps: alert.pps,
        });
    }

    pub fn record_ban(&mut self, src_ip: IpAddr, protocol: String, pps: f64, seconds: f64) {
        self.bans_seen += 1;
        self.active_bans.insert(
            src_ip.to_string(),
            BanView {
                src_ip: src_ip.to_string(),
                protocol,
                pps,
                remaining_seconds: seconds,
            },
        );
    }

    pub fn record_unban(&mut self, src_ip: IpAddr) {
        self.active_bans.remove(&src_ip.to_string());
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AlertView {
    pub src_ip: String,
    pub protocol: String,
    pub msg_type: String,
    pub pps: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct BanView {
    pub src_ip: String,
    pub protocol: String,
    pub pps: f64,
    pub remaining_seconds: f64,
}

#[derive(Debug, Clone, Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
}

pub async fn start_dashboard(
    state: SharedDashboardState,
    bind_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = Router::new()
        .route("/", get(index))
        .route("/health", get(health))
        .route("/stats", get(stats))
        .with_state(state);

    println!("Dashboard listening on http://{bind_addr}");

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn index() -> impl IntoResponse {
    Html(INDEX_HTML)
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

const INDEX_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>The Warden</title>
<style>
    body {
        margin: 0;
        background: #080c10;
        color: #c8d8e8;
        font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    }

    header {
        padding: 18px 24px;
        border-bottom: 1px solid #1e2d3d;
        background: #0d1117;
    }

    h1 {
        margin: 0;
        color: #00ff88;
        letter-spacing: 3px;
        font-size: 24px;
    }

    main {
        padding: 24px;
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 16px;
    }

    .card {
        background: #0d1117;
        border: 1px solid #1e2d3d;
        border-radius: 10px;
        padding: 18px;
    }

    .label {
        color: #4a6070;
        font-size: 12px;
        letter-spacing: 2px;
        text-transform: uppercase;
    }

    .value {
        font-size: 34px;
        color: #00ff88;
        margin-top: 8px;
    }

    .wide {
        grid-column: 1 / -1;
    }

    pre {
        white-space: pre-wrap;
        word-break: break-word;
        color: #c8d8e8;
    }

    .danger {
        color: #ff3366;
    }
</style>
</head>
<body>
<header>
    <h1>THE WARDEN <span style="color:#4a6070;font-size:14px">Rust IPS Dashboard</span></h1>
</header>

<main>
    <section class="card">
        <div class="label">Packets Seen</div>
        <div class="value" id="packets">0</div>
    </section>

    <section class="card">
        <div class="label">Alerts Seen</div>
        <div class="value danger" id="alerts">0</div>
    </section>

    <section class="card">
        <div class="label">Bans Seen</div>
        <div class="value danger" id="bans">0</div>
    </section>

    <section class="card wide">
        <div class="label">Last Alert</div>
        <pre id="last-alert">None</pre>
    </section>

    <section class="card wide">
        <div class="label">Top Talkers</div>
        <pre id="top-talkers">{}</pre>
    </section>

    <section class="card wide">
        <div class="label">Active Bans</div>
        <pre id="active-bans">{}</pre>
    </section>
</main>

<script>
async function refresh() {
    const res = await fetch('/stats');
    const data = await res.json();

    document.getElementById('packets').textContent = data.packets_seen;
    document.getElementById('alerts').textContent = data.alerts_seen;
    document.getElementById('bans').textContent = data.bans_seen;
    document.getElementById('last-alert').textContent =
        data.last_alert ? JSON.stringify(data.last_alert, null, 2) : 'None';
    document.getElementById('top-talkers').textContent =
        JSON.stringify(data.top_talkers, null, 2);
    document.getElementById('active-bans').textContent =
        JSON.stringify(data.active_bans, null, 2);
}

setInterval(refresh, 1000);
refresh();
</script>
</body>
</html>
"#;
