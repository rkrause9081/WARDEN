/*
 * mod.rs
 *
 * Purpose:
 *     Defines the WARDEN web dashboard subsystem.
 *
 * Responsibilities:
 *     - Expose dashboard server functionality
 *     - Centralize web module exports
 *     - Provide shared dashboard state interfaces
 *
 * Non-Responsibilities:
 *     - IDS packet inspection
 *     - Firewall mitigation
 *     - Blockchain transaction submission
 *     - Packet parsing
 *
 * Architecture:
 *
 *      IDS / Mitigation / Blockchain
 *                    ↓
 *            DashboardState
 *                    ↓
 *               Axum Server
 *                    ↓
 *            Browser Dashboard
 */

/* -------------------------------------------------------------------------- */
/*                               Module Imports                               */
/* -------------------------------------------------------------------------- */

pub mod web;

/* -------------------------------------------------------------------------- */
/*                              Public Re-Exports                             */
/* -------------------------------------------------------------------------- */

pub use web::{
    DashboardState,
    SharedDashboardState,
    start_dashboard,
};
