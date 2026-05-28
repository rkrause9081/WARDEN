/*
 * mod.rs
 *
 * Purpose:
 *     Defines the WARDEN detection engine module.
 *
 * Responsibilities:
 *     - Expose detection engine implementations
 *     - Centralize detection module exports
 *     - Provide IDS engine entry points
 *
 * Non-Responsibilities:
 *     - Packet capture
 *     - Mitigation execution
 *     - Blockchain anchoring
 *     - Dashboard rendering
 *
 * Architecture:
 *
 *      Packet Sniffer
 *            ↓
 *      Detection Engine
 *         └── sliding_window.rs
 *            ↓
 *      Alert Generation
 *            ↓
 *      Mitigation / Logging
 */

/* -------------------------------------------------------------------------- */
/*                               Module Imports                               */
/* -------------------------------------------------------------------------- */

pub mod sliding_window;

/* -------------------------------------------------------------------------- */
/*                              Public Re-Exports                             */
/* -------------------------------------------------------------------------- */

pub use sliding_window::{Engine, EngineConfig};
