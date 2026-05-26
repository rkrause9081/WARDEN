//! ethers-rs client for WardenEvidence.sol.
//!
//! Designed for local Hardhat first.
//!
//! Required Cargo dependencies:
//!
//! ```toml
//! ethers = "2"
//! tokio = { version = "1", features = ["full"] }
//! hex = "0.4"
//! ```
//!
//! Environment variables:
//!
//! ```text
//! WARDEN_RPC_URL=http://127.0.0.1:8545
//! WARDEN_PRIVATE_KEY=<hardhat account private key>
//! WARDEN_EVIDENCE_ADDRESS=<deployed WardenEvidence address>
//! WARDEN_CHAIN_ID=31337
//! ```

use std::env;
use std::sync::Arc;
use std::time::Duration;

use ethers::abi::Abi;
use ethers::contract::Contract;
use ethers::middleware::SignerMiddleware;
use ethers::providers::{Http, Provider};
use ethers::signers::{LocalWallet, Signer};
use ethers::types::{Address, H256, U256};
use ethers::utils::hex;

use crate::blockchain::types::ChainAlert;

const WARDEN_EVIDENCE_ABI: &str = r#"
[
  {
    "inputs": [
      { "internalType": "bytes32", "name": "evidenceHash", "type": "bytes32" },
      { "internalType": "string", "name": "sourceIp", "type": "string" },
      { "internalType": "string", "name": "protocol", "type": "string" },
      { "internalType": "string", "name": "messageType", "type": "string" },
      { "internalType": "uint256", "name": "ppsMilli", "type": "uint256" },
      { "internalType": "bool", "name": "mitigated", "type": "bool" }
    ],
    "name": "logAttack",
    "outputs": [
      { "internalType": "uint256", "name": "recordId", "type": "uint256" }
    ],
    "stateMutability": "nonpayable",
    "type": "function"
  }
]
"#;

#[derive(Debug, Clone)]
pub struct BlockchainConfig {
    pub rpc_url: String,
    pub private_key: String,
    pub evidence_contract: Address,
    pub chain_id: u64,
    pub enabled: bool,
}

impl BlockchainConfig {
    pub fn from_env() -> Result<Self, String> {
        let enabled = env::var("WARDEN_BLOCKCHAIN_ENABLED")
            .unwrap_or_else(|_| "false".to_string())
            .eq_ignore_ascii_case("true");

        let rpc_url = env::var("WARDEN_RPC_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8545".to_string());

        let private_key = env::var("WARDEN_PRIVATE_KEY")
            .map_err(|_| "missing WARDEN_PRIVATE_KEY".to_string())?;

        let evidence_contract_raw = env::var("WARDEN_EVIDENCE_ADDRESS")
            .map_err(|_| "missing WARDEN_EVIDENCE_ADDRESS".to_string())?;

        let evidence_contract = evidence_contract_raw
            .parse::<Address>()
            .map_err(|error| format!("invalid WARDEN_EVIDENCE_ADDRESS: {error}"))?;

        let chain_id = env::var("WARDEN_CHAIN_ID")
            .unwrap_or_else(|_| "31337".to_string())
            .parse::<u64>()
            .map_err(|error| format!("invalid WARDEN_CHAIN_ID: {error}"))?;

        Ok(Self {
            rpc_url,
            private_key,
            evidence_contract,
            chain_id,
            enabled,
        })
    }
}

#[derive(Clone)]
pub struct BlockchainClient {
    contract: Contract<SignerMiddleware<Provider<Http>, LocalWallet>>,
    enabled: bool,
}

impl BlockchainClient {
    pub async fn from_config(config: BlockchainConfig) -> Result<Self, String> {
        let provider = Provider::<Http>::try_from(config.rpc_url.as_str())
            .map_err(|error| format!("failed to create provider: {error}"))?
            .interval(Duration::from_millis(10));

        let wallet = config
            .private_key
            .parse::<LocalWallet>()
            .map_err(|error| format!("failed to parse private key: {error}"))?
            .with_chain_id(config.chain_id);

        let client = Arc::new(SignerMiddleware::new(provider, wallet));

        let abi: Abi = serde_json::from_str(WARDEN_EVIDENCE_ABI)
            .map_err(|error| format!("failed to parse ABI: {error}"))?;

        let contract = Contract::new(config.evidence_contract, abi, client);

        Ok(Self {
            contract,
            enabled: config.enabled,
        })
    }

    pub async fn from_env() -> Result<Self, String> {
        let config = BlockchainConfig::from_env()?;
        Self::from_config(config).await
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub async fn log_attack(&self, alert: ChainAlert) -> Result<H256, String> {
        if !self.enabled {
            return Err("blockchain logging is disabled".to_string());
        }

        let evidence_hash = H256::from(alert.evidence_hash);

        let call = self
            .contract
            .method::<_, U256>(
                "logAttack",
                (
                    evidence_hash,
                    alert.src_ip,
                    alert.protocol,
                    alert.msg_type,
                    U256::from(alert.pps_milli),
                    alert.mitigated,
                ),
            )
            .map_err(|error| format!("failed to build logAttack call: {error}"))?;

        let pending_tx = call
            .send()
            .await
            .map_err(|error| format!("failed to send logAttack tx: {error}"))?;

        let tx_hash = pending_tx.tx_hash();

        Ok(tx_hash)
    }

    pub fn hash_hex(hash: [u8; 32]) -> String {
        format!("0x{}", hex::encode(hash))
    }
}
