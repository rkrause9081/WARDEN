//! Blockchain integration module.
//!
//! Phase 9 sends Warden evidence hashes to the local Hardhat smart contract.

pub mod client;
pub mod types;

pub use client::{BlockchainClient, BlockchainConfig};
pub use types::ChainAlert;
