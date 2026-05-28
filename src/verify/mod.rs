/*
 * mod.rs
 *
 * Purpose:
 *     Defines the WARDEN evidence verification module.
 *
 * Responsibilities:
 *     - Expose verifier hash helpers
 *     - Expose JSONL verification logic
 *     - Centralize verification module exports
 *
 * Non-Responsibilities:
 *     - IDS packet inspection
 *     - Blockchain transaction submission
 *     - Firewall mitigation
 *     - Dashboard rendering
 *
 * Architecture:
 *
 *      alerts.jsonl
 *          ↓
 *      Verifier
 *       ├── hash.rs
 *       └── verifier.rs
 *          ↓
 *      VerificationResult
 */

/* -------------------------------------------------------------------------- */
/*                               Module Imports                               */
/* -------------------------------------------------------------------------- */

pub mod hash;
pub mod verifier;

/* -------------------------------------------------------------------------- */
/*                              Public Re-Exports                             */
/* -------------------------------------------------------------------------- */

pub use verifier::{
    verify_alert_log_file,
    VerificationResult,
    VerificationStatus,
};