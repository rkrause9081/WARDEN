/*
 * config.rs
 *
 * Purpose:
 *     Loads WARDEN runtime configuration from YAML.
 *
 * Responsibilities:
 *     - Read configuration files from disk
 *     - Deserialize runtime settings
 *     - Store sniffer, engine, and mitigator settings
 *
 * Non-Responsibilities:
 *     - Validating network interface availability
 *     - Starting IDS services
 *     - Applying mitigation
 *     - Managing dashboard state
 *
 * Architecture:
 *
 *      config/settings.yaml
 *              ↓
 *      Settings::from_file()
 *              ↓
 *      Runtime Components
 */

use std::fs;
use std::net::IpAddr;
use std::path::Path;

use serde::Deserialize;

/* -------------------------------------------------------------------------- */
/*                                  Settings                                  */
/* -------------------------------------------------------------------------- */

/**
 * Top-level WARDEN runtime settings.
 */
#[derive(Debug, Clone, Deserialize)]
pub struct Settings {
    /// Network interface used by the packet sniffer.
    pub interface: String,

    /// Detection engine settings.
    pub engine: EngineSettings,

    /// Mitigation backend settings.
    pub mitigator: MitigatorSettings,
}

impl Settings {
    /**
     * Loads settings from a YAML configuration file.
     */
    pub fn from_file(
        path: impl AsRef<Path>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = fs::read_to_string(path)?;
        let settings = serde_yaml::from_str::<Settings>(&contents)?;

        Ok(settings)
    }
}

/* -------------------------------------------------------------------------- */
/*                              Engine Settings                               */
/* -------------------------------------------------------------------------- */

/**
 * Runtime settings for the sliding-window detection engine.
 */
#[derive(Debug, Clone, Deserialize)]
pub struct EngineSettings {
    /// PPS threshold required to trigger an alert.
    pub threshold_pps: f64,

    /// Sliding-window duration in seconds.
    pub window_seconds: f64,

    /// Cooldown duration between repeated alerts.
    pub cooldown_seconds: f64,

    /// Trusted IPs ignored by detection logic.
    pub whitelist: Vec<IpAddr>,
}

/* -------------------------------------------------------------------------- */
/*                            Mitigator Settings                              */
/* -------------------------------------------------------------------------- */

/**
 * Runtime settings for the mitigation backend.
 */
#[derive(Debug, Clone, Deserialize)]
pub struct MitigatorSettings {
    /// Ban duration in seconds.
    pub ban_duration_seconds: f64,

    /// Whether firewall commands are simulated.
    pub dry_run: bool,
}