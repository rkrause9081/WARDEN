/*
 * mod.rs
 *
 * Purpose:
 *     Defines the WARDEN blockchain integration module.
 *
 * Responsibilities:
 *     - Expose blockchain client functionality
 *     - Expose blockchain-compatible alert types
 *     - Centralize blockchain module exports
 *
 * Non-Responsibilities:
 *     - Executing blockchain transactions directly
 *     - Managing IDS detection logic
 *     - Performing forensic hashing
 *     - Handling dashboard rendering
 *
 * Architecture:
 *
 *      WARDEN IDS
 *            ↓
 *      Blockchain Module
 *         ├── client.rs
 *         └── types.rs
 *            ↓
 *      Ethereum / Hardhat
 */

/* -------------------------------------------------------------------------- */
/*                               Module Imports                               */
/* -------------------------------------------------------------------------- */

pub mod client;
pub mod types;

/* -------------------------------------------------------------------------- */
/*                              Public Re-Exports                             */
/* -------------------------------------------------------------------------- */

pub use client::{BlockchainClient, BlockchainConfig};
pub use types::ChainAlert;