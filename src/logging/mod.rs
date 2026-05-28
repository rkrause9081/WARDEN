/*
 * mod.rs
 *
 * Purpose:
 *     Defines the WARDEN persistent logging module.
 *
 * Responsibilities:
 *     - Expose JSONL logging backends
 *     - Centralize logging module exports
 *     - Provide persistent forensic logging interfaces
 *
 * Non-Responsibilities:
 *     - IDS packet inspection
 *     - Blockchain transaction handling
 *     - Evidence hashing logic
 *     - Dashboard visualization
 *
 * Architecture:
 *
 *      Alert / Ban Events
 *              ↓
 *      Persistent Logging Module
 *           └── jsonl.rs
 *              ↓
 *         JSONL Evidence Logs
 *              ↓
 *      Verification / Blockchain
 */

/* -------------------------------------------------------------------------- */
/*                               Module Imports                               */
/* -------------------------------------------------------------------------- */

pub mod jsonl;

/* -------------------------------------------------------------------------- */
/*                              Public Re-Exports                             */
/* -------------------------------------------------------------------------- */

pub use jsonl::{
    JsonlLogger,
    JsonlLoggerConfig,
};