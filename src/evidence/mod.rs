/*
 * mod.rs
 *
 * Purpose:
 *     Defines the WARDEN cryptographic hashing module.
 *
 * Responsibilities:
 *     - Expose evidence hashing utilities
 *     - Centralize cryptographic helper exports
 *     - Provide forensic hashing interfaces
 *
 * Non-Responsibilities:
 *     - Blockchain transaction submission
 *     - IDS packet inspection
 *     - Dashboard visualization
 *     - JSONL evidence storage
 *
 * Architecture:
 *
 *      AlertEvent
 *            ↓
 *      SHA-256 Hashing
 *            ↓
 *      Evidence Digest
 *            ↓
 *      JSONL + Blockchain Anchoring
 */

/* -------------------------------------------------------------------------- */
/*                               Module Imports                               */
/* -------------------------------------------------------------------------- */

pub mod hash;

/* -------------------------------------------------------------------------- */
/*                              Public Re-Exports                             */
/* -------------------------------------------------------------------------- */

pub use hash::{
    compute_alert_evidence_hash,
    hash_bytes_to_hex,
};