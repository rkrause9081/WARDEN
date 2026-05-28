/*
 * main.rs
 *
 * Purpose:
 *     Provides the WARDEN application entry point.
 *
 * Responsibilities:
 *     - Parse CLI mode arguments
 *     - Load runtime configuration
 *     - Build major runtime components
 *     - Start demo, sniffer, pipeline, dashboard, or verifier workflows
 *
 * Non-Responsibilities:
 *     - Implementing detection logic
 *     - Implementing packet parsing
 *     - Implementing mitigation internals
 *     - Implementing dashboard route handlers
 *
 * Architecture:
 *
 *      CLI Arguments
 *            ↓
 *      Settings Loader
 *            ↓
 *      Component Builders
 *            ↓
 *      Runtime Mode
 *
 * Runtime Modes:
 *     - demo
 *     - sniff
 *     - pipeline
 *     - dashboard
 *     - verify
 */

mod blockchain;
mod config;
mod engine;
mod evidence;
mod logging;
mod mitigator;
mod pipeline;
mod sniffer;
mod types;
mod ui;
mod verify;

use std::env;
use std::net::{
    IpAddr,
    Ipv4Addr,
    SocketAddr,
};
use std::thread;
use std::time::{
    Duration,
    SystemTime,
};

use blockchain::{
    BlockchainClient,
    BlockchainConfig,
};
use config::Settings;
use engine::{
    Engine,
    EngineConfig,
};
use logging::JsonlLogger;
use mitigator::{
    Mitigator,
    MitigatorConfig,
};
use pipeline::run_live_pipeline;
use sniffer::Sniffer;
use types::{
    MessageType,
    PacketRecord,
    Protocol,
};
use ui::{
    start_dashboard,
    DashboardState,
};
use verify::verifier::{
    print_verification_report,
    verify_alert_log_file,
};

/* -------------------------------------------------------------------------- */
/*                              Helper Functions                              */
/* -------------------------------------------------------------------------- */

/**
 * Creates an IPv4 address from four octets.
 */
fn ip(value: [u8; 4]) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(value))
}

/* -------------------------------------------------------------------------- */
/*                              Application Main                              */
/* -------------------------------------------------------------------------- */

fn main() {
    let args: Vec<String> = env::args().collect();

    let settings = Settings::from_file("config/settings.yaml")
        .expect("failed to load config/settings.yaml");

    match args.get(1).map(String::as_str) {
        Some("sniff") => run_live_sniffer(&settings),

        Some("pipeline") => run_pipeline(&settings, false),

        Some("dashboard") => run_pipeline(&settings, true),

        Some("verify") => {
            let path = args
                .get(2)
                .map(String::as_str)
                .unwrap_or("logs/alerts.jsonl");

            run_verify(path);
        }

        _ => run_demo(&settings),
    }
}

/* -------------------------------------------------------------------------- */
/*                            Component Builders                              */
/* -------------------------------------------------------------------------- */

/**
 * Builds the detection engine from YAML settings.
 */
fn build_engine(settings: &Settings) -> Engine {
    let config = EngineConfig::new(
        settings.engine.threshold_pps,
        settings.engine.window_seconds,
        settings.engine.cooldown_seconds,
        settings.engine.whitelist.clone(),
    );

    Engine::new(config)
}

/**
 * Builds the default JSONL logger.
 */
fn build_logger() -> Option<JsonlLogger> {
    match JsonlLogger::default_logger() {
        Ok(logger) => {
            println!("JSONL logging enabled: logs/alerts.jsonl, logs/bans.jsonl");
            Some(logger)
        }

        Err(error) => {
            eprintln!("JSONL logging disabled: {error}");
            None
        }
    }
}

/**
 * Builds the optional blockchain client from environment variables.
 */
fn build_blockchain_client() -> Option<BlockchainClient> {
    let config = match BlockchainConfig::from_env() {
        Ok(config) => config,

        Err(error) => {
            println!("Blockchain logging disabled: {error}");
            return None;
        }
    };

    if !config.enabled {
        println!(
            "Blockchain logging disabled: WARDEN_BLOCKCHAIN_ENABLED is not true"
        );

        return None;
    }

    let runtime = tokio::runtime::Runtime::new()
        .expect("failed to create tokio runtime for blockchain client");

    match runtime.block_on(BlockchainClient::from_config(config)) {
        Ok(client) => {
            println!("Blockchain logging enabled.");
            Some(client)
        }

        Err(error) => {
            eprintln!("Blockchain logging disabled: {error}");
            None
        }
    }
}

/* -------------------------------------------------------------------------- */
/*                                Demo Mode                                   */
/* -------------------------------------------------------------------------- */

/**
 * Runs a local synthetic MQTT alert demo.
 */
fn run_demo(settings: &Settings) {
    let mut engine = build_engine(settings);

    let attacker_ip = ip([192, 168, 10, 90]);
    let dst_ip = ip([192, 168, 10, 1]);
    let base = SystemTime::now();

    println!("The Warden Rust Phase 10 demo");
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

/* -------------------------------------------------------------------------- */
/*                              Sniffer Mode                                  */
/* -------------------------------------------------------------------------- */

/**
 * Runs packet sniffing directly without the full mitigation pipeline.
 */
fn run_live_sniffer(settings: &Settings) {
    let mut engine = build_engine(settings);
    let mut sniffer = Sniffer::new(&settings.interface);

    println!("The Warden Rust Phase 10 direct sniffer");
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

/* -------------------------------------------------------------------------- */
/*                              Verify Mode                                   */
/* -------------------------------------------------------------------------- */

/**
 * Runs JSONL evidence verification.
 */
fn run_verify(path: &str) {
    match verify_alert_log_file(path) {
        Ok(results) => print_verification_report(&results),

        Err(error) => eprintln!("Verification failed: {error}"),
    }
}

/* -------------------------------------------------------------------------- */
/*                             Pipeline Mode                                  */
/* -------------------------------------------------------------------------- */

/**
 * Runs the full live WARDEN pipeline.
 */
fn run_pipeline(
    settings: &Settings,
    with_dashboard: bool,
) {
    println!("The Warden Rust Phase 10 pipeline");
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
                if let Err(error) =
                    start_dashboard(dashboard_state, addr).await
                {
                    eprintln!("Dashboard error: {error}");
                }
            });
        });

        println!("Dashboard enabled at http://127.0.0.1:5000");

        Some(state)
    } else {
        None
    };

    let logger = build_logger();
    let blockchain_client = build_blockchain_client();

    println!("Press Ctrl+C to stop.");

    let engine = build_engine(settings);

    let mitigator = Mitigator::new(
        MitigatorConfig::new(
            settings.mitigator.ban_duration_seconds,
            settings.mitigator.dry_run,
        )
    );

    if let Err(error) = run_live_pipeline(
        settings.interface.clone(),
        engine,
        mitigator,
        dashboard_state,
        logger,
        blockchain_client,
    ) {
        eprintln!("Pipeline error: {error}");
    }
}

/* -------------------------------------------------------------------------- */
/*                              Record Handling                               */
/* -------------------------------------------------------------------------- */

/**
 * Processes one packet through the demo/direct-sniffer engine path.
 */
fn handle_record(
    engine: &mut Engine,
    record: PacketRecord,
) {
    if let Some(mut alert) = engine.ingest(record) {
        alert.evidence_hash =
            Some(crate::evidence::compute_alert_evidence_hash(&alert));

        println!(
            "ALERT: {} flood from {} at {:.1} PPS, message type: {}",
            alert.protocol.as_str(),
            alert.src_ip,
            alert.pps,
            alert.msg_type.as_str(),
        );
    }
}

/* -------------------------------------------------------------------------- */
/*                              Summary Output                                */
/* -------------------------------------------------------------------------- */

/**
 * Prints a short session summary.
 */
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