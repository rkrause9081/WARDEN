/*
 * mod.rs
 *
 * Purpose:
 *     Defines the WARDEN mitigation subsystem.
 *
 * Responsibilities:
 *     - Expose mitigation backends
 *     - Centralize mitigation exports
 *     - Provide ban/unban interfaces
 *
 * Non-Responsibilities:
 *     - IDS packet inspection
 *     - Blockchain anchoring
 *     - Evidence hashing
 *     - Dashboard visualization
 *
 * Architecture:
 *
 *      AlertEvent
 *            ↓
 *      Mitigation Module
 *         └── iptables.rs
 *            ↓
 *      Firewall Enforcement
 *            ↓
 *      Active Ban Tracking
 */

/* -------------------------------------------------------------------------- */
/*                               Module Imports                               */
/* -------------------------------------------------------------------------- */

pub mod iptables;

/* -------------------------------------------------------------------------- */
/*                              Public Re-Exports                             */
/* -------------------------------------------------------------------------- */

pub use iptables::{
    BanRecord,
    Mitigator,
    MitigatorConfig,
    MitigatorStats,
};