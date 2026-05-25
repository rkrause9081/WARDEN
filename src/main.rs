//! The Warden — Rust Phase 5 web dashboard.
//!
//! Usage:
//!
//! ```bash
//! cargo run -- demo
//! sudo ./target/debug/WARDEN sniff
//! sudo ./target/debug/WARDEN pipeline
//! sudo ./target/debug/WARDEN dashboard
//! ```

mod config;
mod engine;
mod mitigator;
mod pipeline;
mod sniffer;
mod types;
mod ui;

use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::thread;
use std::time::{Duration, SystemTime};

use config::Settings;
use engine::{Engine, EngineConfig};
use mitigator::{Mitigator, MitigatorConfig};
use pipeline::run_live_pipeline;
use sniffer::Sniffer;
use types::{MessageType, PacketRecord, Protocol};
use ui::{DashboardState, start_dashboard};

fn ip(value: [u8; 4]) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(value))
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let settings = Settings::from_file("config/settings.yaml")
        .expect("failed to load config/settings.yaml");

    match args.get(1).map(String::as_str) {
        Some("sniff") => run_live_sniffer(&settings),
        Some("pipeline") => run_pipeline(&settings, false),
        Some("dashboard") => run_pipeline(&settings, true),
        _ => run_demo(&settings),
    }
}

fn build_engine(settings: &Settings) -> Engine {
    let config = EngineConfig::new(
        settings.engine.threshold_pps,
        settings.engine.window_seconds,
        settings.engine.cooldown_seconds,
        settings.engine.whitelist.clone(),
    );

    Engine::new(config)
}

fn run_demo(settings: &Settings) {
    let mut engine = build_engine(settings);

    let attacker_ip = ip([192, 168, 10, 90]);
    let dst_ip = ip([192, 168, 10, 1]);
    let base = SystemTime::now();

    println!("The Warden Rust Phase 5 demo");
    println!("Feeding sample MQTT packets from {attacker_ip}...");

    for offset in 0..5 {
        let record = PacketRecord::with_timestamp(
            base + Duration::from_secs(offset),
            attacker_ip,
            dst_ip,
            Protocol::MQTT,
            MessageType::Known("PUBLISH".to_string()),
        );

        handle_record(&mut engine, record);
    }

    print_summary(&engine);
}

fn run_live_sniffer(settings: &Settings) {
    let mut engine = build_engine(settings);
    let mut sniffer = Sniffer::new(&settings.interface);

    println!("The Warden Rust Phase 5 direct sniffer");
    println!("Interface: {}", settings.interface);
    println!("Press Ctrl+C to stop.");

    let result = sniffer.start(|record| {
        println!(
            "PACKET: {} {} {} -> {}",
            record.protocol.as_str(),
            record.msg_type.as_str(),
            record.src_ip,
            record.dst_ip
        );

        handle_record(&mut engine, record);
    });

    if let Err(error) = result {
        eprintln!("Sniffer error: {error}");
    }

    print_summary(&engine);

    let sniffer_stats = sniffer.get_stats();
    println!("Captured packets : {}", sniffer_stats.total);
    println!("MQTT packets     : {}", sniffer_stats.mqtt);
    println!("CoAP packets     : {}", sniffer_stats.coap);
}

fn run_pipeline(settings: &Settings, with_dashboard: bool) {
    println!("The Warden Rust Phase 5 pipeline");
    println!("Interface : {}", settings.interface);
    println!(
        "Mode      : {}",
        if settings.mitigator.dry_run {
            "DRY RUN"
        } else {
            "ENFORCE"
        }
    );

    let dashboard_state = if with_dashboard {
        let state = DashboardState::shared();
        let dashboard_state = state.clone();

        thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new()
                .expect("failed to create tokio runtime");

            let addr: SocketAddr = "127.0.0.1:5000"
                .parse()
                .expect("invalid dashboard bind address");

            runtime.block_on(async move {
                if let Err(error) = start_dashboard(dashboard_state, addr).await {
                    eprintln!("Dashboard error: {error}");
                }
            });
        });

        println!("Dashboard enabled at http://127.0.0.1:5000");
        Some(state)
    } else {
        None
    };

    println!("Press Ctrl+C to stop.");

    let engine = build_engine(settings);

    let mitigator = Mitigator::new(MitigatorConfig::new(
        settings.mitigator.ban_duration_seconds,
        settings.mitigator.dry_run,
    ));

    if let Err(error) = run_live_pipeline(
        settings.interface.clone(),
        engine,
        mitigator,
        dashboard_state,
    ) {
        eprintln!("Pipeline error: {error}");
    }
}

fn handle_record(engine: &mut Engine, record: PacketRecord) {
    if let Some(alert) = engine.ingest(record) {
        println!(
            "ALERT: {} flood from {} at {:.1} PPS, message type: {}",
            alert.protocol.as_str(),
            alert.src_ip,
            alert.pps,
            alert.msg_type.as_str(),
        );
    }
}

fn print_summary(engine: &Engine) {
    let stats = engine.get_stats_snapshot();

    println!();
    println!("Session summary");
    println!("Packets ingested : {}", stats.total_ingested);
    println!("Alerts fired     : {}", stats.total_alerts);
    println!("Tracked IPs      : {}", stats.tracked_ips);
    println!("Threshold PPS    : {:.1}", stats.threshold_pps);
    println!("Window seconds   : {:.1}", stats.window_seconds);
}
