//! Runtime pipeline for The Warden.
//!
//! Phase 9:
//! Sniffer -> Engine -> JSONL -> Mitigator -> optional blockchain anchoring

use std::sync::mpsc;
use std::thread;

use crate::blockchain::{BlockchainClient, ChainAlert};
use crate::engine::Engine;
use crate::evidence::compute_alert_evidence_hash;
use crate::logging::JsonlLogger;
use crate::mitigator::Mitigator;
use crate::sniffer::Sniffer;
use crate::types::{AlertEvent, PacketRecord};
use crate::ui::SharedDashboardState;

pub fn run_live_pipeline(
    interface: impl Into<String>,
    mut engine: Engine,
    mut mitigator: Mitigator,
    dashboard_state: Option<SharedDashboardState>,
    logger: Option<JsonlLogger>,
    blockchain_client: Option<BlockchainClient>,
) -> Result<(), Box<dyn std::error::Error>> {
    let interface = interface.into();

    let (packet_tx, packet_rx) = mpsc::channel::<PacketRecord>();
    let (alert_tx, alert_rx) = mpsc::channel::<AlertEvent>();

    let engine_dashboard = dashboard_state.clone();
    let engine_logger = logger.clone();

    let engine_handle = thread::spawn(move || {
        println!("Engine thread started.");

        while let Ok(record) = packet_rx.recv() {
            println!(
                "PACKET: {} {} {} -> {}",
                record.protocol.as_str(),
                record.msg_type.as_str(),
                record.src_ip,
                record.dst_ip
            );

            let src_ip = record.src_ip;

            if let Some(mut alert) = engine.ingest(record) {
                let evidence_hash = compute_alert_evidence_hash(&alert);
                alert.evidence_hash = Some(evidence_hash);

                println!(
                    "ALERT: {} flood from {} at {:.1} PPS, message type: {}",
                    alert.protocol.as_str(),
                    alert.src_ip,
                    alert.pps,
                    alert.msg_type.as_str(),
                );

                if let Some(logger) = &engine_logger {
                    if let Err(error) = logger.log_alert(&alert) {
                        eprintln!("Failed to write alert log: {error}");
                    }
                }

                if let Some(state) = &engine_dashboard {
                    if let Ok(mut state) = state.lock() {
                        state.record_alert(&alert);
                    }
                }

                if alert_tx.send(alert).is_err() {
                    eprintln!("Alert channel closed. Engine thread exiting.");
                    break;
                }
            }

            if let Some(state) = &engine_dashboard {
                let pps = engine.get_pps(&src_ip);

                if let Ok(mut state) = state.lock() {
                    state.record_packet(src_ip, pps);
                }
            }
        }

        println!("Engine thread stopped.");
    });

    let mitigator_dashboard = dashboard_state.clone();
    let mitigator_logger = logger.clone();

    let mitigator_handle = thread::spawn(move || {
        println!("Mitigator thread started.");

        mitigator.start();

        let runtime = tokio::runtime::Runtime::new()
            .expect("failed to create blockchain tokio runtime");

        while let Ok(alert) = alert_rx.recv() {
            let mitigated = mitigator.ban(&alert).is_ok();

            if !mitigated {
                eprintln!("Mitigator failed for {}", alert.src_ip);
            }

            if let Some(logger) = &mitigator_logger {
                if let Err(error) = logger.log_ban(
                    alert.src_ip,
                    alert.protocol.as_str().to_string(),
                    alert.pps,
                    mitigator.ban_duration_seconds(),
                    mitigator.is_dry_run(),
                    alert.evidence_hash,
                ) {
                    eprintln!("Failed to write ban log: {error}");
                }
            }

            if let Some(client) = &blockchain_client {
                if client.is_enabled() {
                    if let Some(chain_alert) = ChainAlert::from_alert(&alert, mitigated) {
                        let result = runtime.block_on(client.log_attack(chain_alert));

                        match result {
                            Ok(tx_hash) => {
                                println!("CHAIN: attack evidence anchored in tx {tx_hash:?}");
                            }
                            Err(error) => {
                                eprintln!("Blockchain logging failed: {error}");
                            }
                        }
                    }
                }
            }

            if let Some(state) = &mitigator_dashboard {
                if let Ok(mut state) = state.lock() {
                    state.record_ban(
                        alert.src_ip,
                        alert.protocol.as_str().to_string(),
                        alert.pps,
                        mitigator.ban_duration_seconds(),
                    );
                }
            }
        }

        mitigator.stop();
        println!("Mitigator thread stopped.");
    });

    let mut sniffer = Sniffer::new(interface);
    let sniffer_result = sniffer.start(move |record| {
        if packet_tx.send(record).is_err() {
            eprintln!("Packet channel closed. Sniffer cannot continue sending records.");
        }
    });

    let _ = engine_handle.join();
    let _ = mitigator_handle.join();

    sniffer_result.map_err(|error| Box::new(error) as Box<dyn std::error::Error>)
}
