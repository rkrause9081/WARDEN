//! Cryptographic evidence hashing.
//!
//! Phase 7 creates deterministic SHA-256 hashes for attack evidence.
//! These hashes become the bridge between off-chain JSONL evidence and
//! future on-chain smart contract audit records.

pub mod hash;

pub use hash::{compute_alert_evidence_hash, hash_bytes_to_hex};
