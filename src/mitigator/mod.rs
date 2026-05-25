//! Mitigation module.
//!
//! Receives alert events from the engine and blocks offending IPs.
//! The default backend shells out to `iptables`, matching the Python project.

pub mod iptables;

pub use iptables::{BanRecord, Mitigator, MitigatorConfig, MitigatorStats};
