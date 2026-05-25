//! Configuration loader for The Warden.
//!
//! Loads runtime settings from YAML.

use std::fs;
use std::net::IpAddr;
use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Settings {
    pub interface: String,
    pub engine: EngineSettings,
    pub mitigator: MitigatorSettings,
}

impl Settings {
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = fs::read_to_string(path)?;
        let settings = serde_yaml::from_str::<Settings>(&contents)?;
        Ok(settings)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct EngineSettings {
    pub threshold_pps: f64,
    pub window_seconds: f64,
    pub cooldown_seconds: f64,
    pub whitelist: Vec<IpAddr>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MitigatorSettings {
    pub ban_duration_seconds: f64,
    pub dry_run: bool,
}