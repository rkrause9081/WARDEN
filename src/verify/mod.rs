//! Evidence verification module.
//!
//! Phase 10 verifies local JSONL evidence against hashes anchored on-chain.

pub mod hash;
pub mod verifier;

pub use verifier::{verify_alert_log_file, VerificationResult, VerificationStatus};
