//! Runtime pipeline for The Warden.
//!
//! Phase 5 architecture:
//!
//! Sniffer thread/main loop
//!     -> packet channel
//! Engine thread
//!     -> alert channel
//! Mitigator thread
//!     -> dashboard state updates

use std::sync::mpsc;
use std::thread;

use crate::engine::Engine;
use crate::mitigator::Mitigator;
use crate::sniffer::Sniffer;
use crate::types::{AlertEvent, PacketRecord};
use crate::ui::SharedDashboardState;

/// Runs the full live IPS pipeline.
///
/// This blocks while the sniffer is running.
/// Stop with Ctrl+C.
pub fn run_live_pipeline(
    interface: impl Into<String>,
    mut engine: Engine,
    mut mitigator: Mitigator,
    dashboard_state: Option<SharedDashboardState>,
) -> Result<(), Box<dyn std::error::Error>> {
    let interface = interface.into();

    let (packet_tx, packet_rx) = mpsc::channel::<PacketRecord>();
    let (alert_tx, alert_rx) = mpsc::channel::<AlertEvent>();

    let engine_dashboard = dashboard_state.clone();

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

            if let Some(alert) = engine.ingest(record) {
                println!(
                    "ALERT: {} flood from {} at {:.1} PPS, message type: {}",
                    alert.protocol.as_str(),
                    alert.src_ip,
                    alert.pps,
                    alert.msg_type.as_str(),
                );

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

    let mitigator_handle = thread::spawn(move || {
        println!("Mitigator thread started.");

        mitigator.start();

        while let Ok(alert) = alert_rx.recv() {
            if let Err(error) = mitigator.ban(&alert) {
                eprintln!("Mitigator error: {error}");
            } else if let Some(state) = &mitigator_dashboard {
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
