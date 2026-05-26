//! Blockchain-facing alert types.

use crate::types::AlertEvent;

#[derive(Debug, Clone)]
pub struct ChainAlert {
    pub evidence_hash: [u8; 32],
    pub src_ip: String,
    pub protocol: String,
    pub msg_type: String,
    pub pps_milli: u64,
    pub mitigated: bool,
}

impl ChainAlert {
    pub fn from_alert(alert: &AlertEvent, mitigated: bool) -> Option<Self> {
        let evidence_hash = alert.evidence_hash?;

        Some(Self {
            evidence_hash,
            src_ip: alert.src_ip.to_string(),
            protocol: alert.protocol.as_str().to_string(),
            msg_type: alert.msg_type.as_str().to_string(),
            pps_milli: (alert.pps * 1000.0).round() as u64,
            mitigated,
        })
    }
}
