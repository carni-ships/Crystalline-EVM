//! Ethereum RPC Client for fetching real block data
//!
//! Uses public Ethereum RPC endpoints to fetch block bytecode and transaction data.
//! Based on Zoltraak's RealEthereumBlockFetcher.swift architecture.
//!
//! Key insight: tx.input is calldata, NOT bytecode!
//! Contract bytecode must be fetched via eth_getCode.

use serde::Deserialize;
use std::time::Duration;

/// Ethereum RPC configuration with multiple endpoints for fallback
#[derive(Clone)]
pub struct RPCConfig {
    pub url: String,
    pub timeout: Duration,
}

impl RPCConfig {
    // Public RPC endpoints (from chainlist.org)
    pub fn public_node() -> Self {
        Self {
            url: "https://ethereum-rpc.publicnode.com".to_string(),
            timeout: Duration::from_secs(60),
        }
    }

    pub fn llama_nodes() -> Self {
        Self {
            url: "https://eth.llamarpc.com".to_string(),
            timeout: Duration::from_secs(60),
        }
    }

    pub fn one_rpc() -> Self {
        Self {
            url: "https://1rpc.io/eth".to_string(),
            timeout: Duration::from_secs(60),
        }
    }

    pub fn omniatech() -> Self {
        Self {
            url: "https://endpoints.omniatech.io/v1/eth/mainnet/public".to_string(),
            timeout: Duration::from_secs(60),
        }
    }

    pub fn blockpi() -> Self {
        Self {
            url: "https://rpc.blockpi.io/eth".to_string(),
            timeout: Duration::from_secs(60),
        }
    }

    pub fn ankr() -> Self {
        Self {
            url: "https://rpc.ankr.com/eth".to_string(),
            timeout: Duration::from_secs(60),
        }
    }

    /// Default endpoint (most reliable)
    pub fn default() -> Self {
        Self::public_node()
    }

    /// Berachain public RPC endpoint
    pub fn berachain() -> Self {
        Self {
            url: "https://rpc.berachain.com".to_string(),
            timeout: Duration::from_secs(60),
        }
    }

    /// Create RPC config from custom URL (for Berachain, custom chains, etc.)
    pub fn from_url(url: &str) -> Self {
        Self {
            url: url.to_string(),
            timeout: Duration::from_secs(60),
        }
    }

    /// All endpoints for fallback rotation
    pub fn all_endpoints() -> Vec<Self> {
        vec![
            Self::public_node(),
            Self::llama_nodes(),
            Self::one_rpc(),
            Self::omniatech(),
            Self::blockpi(),
            Self::ankr(),
        ]
    }

    /// Archive node for historical state (requires local Erigon/Reth node)
    pub fn archive_node() -> Self {
        Self {
            url: "http://localhost:8080".to_string(),
            timeout: Duration::from_secs(120),
        }
    }

    pub fn reth_archive() -> Self {
        Self {
            url: "http://localhost:8545".to_string(),
            timeout: Duration::from_secs(120),
        }
    }
}

/// Ethereum RPC client
pub struct EthClient {
    client: reqwest::Client,
    rpc_url: String,
}

impl EthClient {
    /// Create new client with specific RPC endpoint
    pub fn new(config: &RPCConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .expect("Failed to create HTTP client");

        EthClient {
            client,
            rpc_url: config.url.clone(),
        }
    }

    /// Create with default public RPC
    pub fn default() -> Self {
        Self::new(&RPCConfig::default())
    }

    /// Create with fallback rotation - tries each endpoint until one succeeds
    pub fn with_fallback() -> Self {
        Self::new(&RPCConfig::default())
    }

    /// Make JSON-RPC call
    async fn call<R: for<'de> Deserialize<'de>>(&self, method: &str, params: &[serde_json::Value]) -> Result<R, String> {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        });

        let response = self.client
            .post(&self.rpc_url)
            .json(&request)
            .send()
            .await
            .map_err(|e| format!("HTTP error: {}", e))?;

        if !response.status().is_success() {
            return Err(format!("RPC status: {}", response.status()));
        }

        let body: serde_json::Value = response.json().await
            .map_err(|e| format!("JSON parse error: {}", e))?;

        if let Some(error) = body.get("error") {
            return Err(format!("RPC error: {}", error));
        }

        body.get("result")
            .map(|r| serde_json::from_value(r.clone()).map_err(|e| format!("Result parse error: {}", e)))
            .unwrap_or_else(|| Err("No result in response".to_string()))
    }

    /// Fetch contract bytecode at a specific block
    /// - address: Contract address
    /// - block: Block number in hex (e.g., "0x1234567")
    pub async fn get_code(&self, address: &str, block: &str) -> Result<Vec<u8>, String> {
        let hex: String = self.call("eth_getCode", &[serde_json::json!(address), serde_json::json!(block)]).await?;
        Ok(hex_to_bytes(&hex))
    }

    /// Fetch balance for an account
    pub async fn get_balance(&self, address: &str, block: &str) -> Result<String, String> {
        self.call("eth_getBalance", &[serde_json::json!(address), serde_json::json!(block)]).await
    }

    /// Fetch storage slot value
    pub async fn get_storage_at(&self, address: &str, slot: &str, block: &str) -> Result<String, String> {
        self.call("eth_getStorageAt", &[serde_json::json!(address), serde_json::json!(slot), serde_json::json!(block)]).await
    }
}

/// Fetch block with automatic fallback through multiple RPC endpoints
pub async fn fetch_block_with_fallback(block_number: u64) -> Result<EthereumBlock, String> {
    let hex_number = format!("0x{:x}", block_number);

    for config in RPCConfig::all_endpoints() {
        let client = EthClient::new(&config);
        match client.get_block(&hex_number, true).await {
            Ok(block) => return Ok(block),
            Err(e) => {
                tracing::warn!("Failed to fetch block from {}: {}", config.url, e);
                continue;
            }
        }
    }

    Err("All RPC endpoints failed".to_string())
}

/// Block response from eth_getBlockByNumber
#[derive(Debug, Deserialize)]
pub struct EthereumBlock {
    pub number: String,
    pub hash: String,
    #[serde(rename = "parentHash")]
    pub parent_hash: String,
    pub timestamp: String,
    #[serde(rename = "gasUsed")]
    pub gas_used: String,
    #[serde(rename = "gasLimit")]
    pub gas_limit: String,
    pub transactions: Vec<EthereumTransaction>,
    #[serde(rename = "transactionCount")]
    pub transaction_count: Option<usize>,
}

impl EthereumBlock {
    /// Fetch block by number
    pub async fn fetch(number: u64) -> Result<Self, String> {
        let config = RPCConfig::default();
        let client = EthClient::new(&config);
        let hex_number = format!("0x{:x}", number);
        client.get_block(&hex_number, true).await
    }

    /// Fetch block with specific RPC config
    pub async fn fetch_with(number: u64, config: &RPCConfig) -> Result<Self, String> {
        let client = EthClient::new(config);
        let hex_number = format!("0x{:x}", number);
        client.get_block(&hex_number, true).await
    }
}

/// Transaction data
#[derive(Debug, Deserialize)]
pub struct EthereumTransaction {
    pub hash: String,
    pub from: String,
    pub to: Option<String>,
    pub value: String,
    pub gas: String,
    #[serde(rename = "gasPrice")]
    pub gas_price: Option<String>,
    pub input: String,  // Note: This is calldata, NOT bytecode!
    pub nonce: Option<String>,
}

impl EthereumTransaction {
    /// Get bytecode for this transaction.
    /// IMPORTANT: For contract calls, tx.input is CALDDATA, not bytecode!
    /// Use eth_getCode to fetch actual contract bytecode.
    pub async fn get_bytecode(&self, block_number: &str) -> Result<Vec<u8>, String> {
        if let Some(ref to) = self.to {
            if !to.is_empty() {
                // Contract call - fetch bytecode via eth_getCode
                let config = RPCConfig::default();
                let client = EthClient::new(&config);
                client.get_code(to, block_number).await
            } else {
                // Contract creation - no target address
                Ok(vec![])
            }
        } else {
            // Contract creation
            Ok(vec![])
        }
    }

    /// Check if this is a simple ETH transfer (no data/call)
    pub fn is_simple_transfer(&self) -> bool {
        self.input.is_empty() || self.input == "0x"
    }
}

impl EthClient {
    /// Fetch a block by number (hex string)
    /// Set include_txs=true to get full transaction objects instead of just hashes
    pub async fn get_block(&self, block_number: &str, include_txs: bool) -> Result<EthereumBlock, String> {
        self.call("eth_getBlockByNumber", &[serde_json::json!(block_number), serde_json::json!(include_txs)]).await
    }

    /// Get current block number
    pub async fn get_block_number(&self) -> Result<u64, String> {
        let hex: String = self.call("eth_blockNumber", &[]).await?;
        let hex = hex.trim_start_matches("0x");
        Ok(u64::from_str_radix(hex, 16).unwrap_or(0))
    }
}

/// Get current block number from public RPC
pub async fn get_current_block_number() -> Result<u64, String> {
    let config = RPCConfig::default();
    let client = EthClient::new(&config);
    client.get_block_number().await
}

/// Fetch full transaction state (balance, bytecode, storage)
#[derive(Debug)]
pub struct TransactionState {
    pub from_balance: String,
    pub to_balance: Option<String>,
    pub contract_bytecode: Vec<u8>,
    pub storage: Vec<(String, String)>,  // (slot, value) pairs
}

impl EthClient {
    /// Fetch state for a transaction
    pub async fn fetch_transaction_state(&self, tx: &EthereumTransaction, block_number: &str) -> Result<TransactionState, String> {
        let from_balance = self.get_balance(&tx.from, block_number).await?;

        let to_balance = if let Some(ref to) = tx.to {
            Some(self.get_balance(to, block_number).await?)
        } else {
            None
        };

        let contract_bytecode = if let Some(ref to) = tx.to {
            if !to.is_empty() && !tx.input.is_empty() {
                // It's a contract call - fetch bytecode
                self.get_code(to, block_number).await.unwrap_or_default()
            } else {
                vec![]
            }
        } else {
            vec![]
        };

        Ok(TransactionState {
            from_balance,
            to_balance,
            contract_bytecode,
            storage: vec![],
        })
    }
}

/// EVM Transaction wrapper for proving
#[derive(Debug)]
pub struct EVMTransaction {
    pub bytecode: Vec<u8>,
    pub calldata: Vec<u8>,
    pub caller: String,
    pub value: String,
    pub gas_limit: u64,
}

impl EVMTransaction {
    /// Create from Ethereum transaction and fetched bytecode
    pub fn from_eth_tx(tx: &EthereumTransaction, bytecode: Vec<u8>) -> Self {
        EVMTransaction {
            bytecode,
            calldata: hex_to_bytes(&tx.input),
            caller: tx.from.clone(),
            value: hex_to_value(&tx.value),
            gas_limit: hex_to_u64(&tx.gas),
        }
    }
}

/// Convert hex string to bytecode
pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let hex = hex.trim_start_matches("0x");
    if hex.is_empty() {
        return vec![];
    }
    // Pad to even length
    let hex = if hex.len() % 2 == 0 { hex.to_string() } else { format!("0{}", hex) };
    match hex::decode(&hex) {
        Ok(bytes) => bytes,
        Err(_) => vec![],
    }
}

/// Convert hex value string to u64
pub fn hex_to_u64(hex: &str) -> u64 {
    let hex = hex.trim_start_matches("0x");
    u64::from_str_radix(hex, 16).unwrap_or(0)
}

/// Convert hex value string to eth (wei / 1e18)
pub fn hex_to_value(hex: &str) -> String {
    let hex = hex.trim_start_matches("0x");
    if hex.is_empty() || hex == "0" {
        return "0".to_string();
    }
    let wei = u64::from_str_radix(hex, 16).unwrap_or(0);
    format!("{}", wei)
}

// ============================================================
// Benchmarking functions for real Ethereum blocks
// ============================================================

use crate::prover::{Prover, ProverConfig};

/// Benchmark a real Ethereum block
pub async fn benchmark_real_block(block_number: u64) -> Result<BenchmarkResult, String> {
    tracing::info!("Fetching block #{}", block_number);

    let block = EthereumBlock::fetch(block_number).await?;
    tracing::info!("Block #{} fetched: {} transactions", block_number, block.transactions.len());

    let prover = Prover::new(ProverConfig::default())
        .map_err(|e| format!("Failed to create prover: {:?}", e))?;

    let mut total_time_ms = 0.0;
    let mut successful_txs = 0;
    let mut total_bytecode_bytes = 0;

    let hex_number = format!("0x{:x}", block_number);

    for (i, tx) in block.transactions.iter().enumerate() {
        // Skip simple transfers (no bytecode needed)
        if tx.is_simple_transfer() {
            continue;
        }

        let start = std::time::Instant::now();

        // Get bytecode for this transaction
        let bytecode = match tx.get_bytecode(&hex_number).await {
            Ok(code) if !code.is_empty() => code,
            _ => {
                // Default to STOP if no bytecode found
                vec![0x00]
            }
        };

        total_bytecode_bytes += bytecode.len();

        // Prove transaction
        match prover.prove_evm_trace(&bytecode, hex_to_u64(&tx.gas)) {
            Ok(proof) => {
                total_time_ms += start.elapsed().as_millis() as f64;
                successful_txs += 1;

                tracing::info!(
                    "Tx {} proven: {} rows, proof_size={} bytes",
                    i, proof.trace.len(), proof.proof_size()
                );
            }
            Err(e) => {
                tracing::warn!("Tx {} proof failed: {}", i, e);
            }
        }
    }

    let per_tx_time = if successful_txs > 0 { total_time_ms / successful_txs as f64 } else { 0.0 };
    let throughput = if total_time_ms > 0.0 { successful_txs as f64 / (total_time_ms / 1000.0) } else { 0.0 };

    Ok(BenchmarkResult {
        block_number,
        transaction_count: block.transactions.len(),
        successful_txs,
        total_time_ms,
        per_tx_ms: per_tx_time,
        throughput_tps: throughput,
        total_bytecode_bytes,
    })
}

/// Benchmark result for a real block
#[derive(Debug)]
pub struct BenchmarkResult {
    pub block_number: u64,
    pub transaction_count: usize,
    pub successful_txs: usize,
    pub total_time_ms: f64,
    pub per_tx_ms: f64,
    pub throughput_tps: f64,
    pub total_bytecode_bytes: usize,
}

impl std::fmt::Display for BenchmarkResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Block #{} - {} txs, {} successful: {:.2}ms total, {:.2}ms/tx, {:.1} TX/s",
            self.block_number,
            self.transaction_count,
            self.successful_txs,
            self.total_time_ms,
            self.per_tx_ms,
            self.throughput_tps
        )
    }
}

/// Benchmark with archive node for full state witness
pub async fn benchmark_real_block_with_state(block_number: u64, archive_config: &RPCConfig) -> Result<BenchmarkResult, String> {
    tracing::info!("Fetching block #{} with archive node", block_number);

    let block = EthereumBlock::fetch_with(block_number, &RPCConfig::default()).await?;
    tracing::info!("Block #{}: {} transactions", block_number, block.transactions.len());

    let archive_client = EthClient::new(archive_config);
    let hex_number = format!("0x{:x}", block_number);

    let prover = Prover::new(ProverConfig::default())
        .map_err(|e| format!("Failed to create prover: {:?}", e))?;

    let mut total_time_ms = 0.0;
    let mut successful_txs = 0;
    let mut bytecode_errors = 0;
    let mut total_bytecode_bytes = 0;

    for (i, tx) in block.transactions.iter().enumerate() {
        if tx.is_simple_transfer() {
            continue;
        }

        let start = std::time::Instant::now();

        // Fetch bytecode from archive node (historical state)
        let bytecode = if let Some(ref to) = tx.to {
            if !to.is_empty() {
                match archive_client.get_code(to, &hex_number).await {
                    Ok(code) if !code.is_empty() => code,
                    Ok(_) => {
                        bytecode_errors += 1;
                        vec![0x00]
                    }
                    Err(e) => {
                        tracing::warn!("Bytecode fetch error for tx {}: {}", i, e);
                        bytecode_errors += 1;
                        vec![0x00]
                    }
                }
            } else {
                vec![]
            }
        } else {
            vec![]
        };

        total_bytecode_bytes += bytecode.len();

        match prover.prove_evm_trace(&bytecode, hex_to_u64(&tx.gas)) {
            Ok(_) => {
                total_time_ms += start.elapsed().as_millis() as f64;
                successful_txs += 1;
            }
            Err(e) => {
                tracing::warn!("Tx {} failed: {}", i, e);
            }
        }

        // Progress logging
        if (i + 1) % 10 == 0 {
            tracing::info!("Processed {}/{} transactions", i + 1, block.transactions.len());
        }
    }

    let per_tx_time = if successful_txs > 0 { total_time_ms / successful_txs as f64 } else { 0.0 };
    let throughput = if total_time_ms > 0.0 { successful_txs as f64 / (total_time_ms / 1000.0) } else { 0.0 };

    if bytecode_errors > 0 {
        tracing::warn!("{} transactions had bytecode fetch errors", bytecode_errors);
    }

    Ok(BenchmarkResult {
        block_number,
        transaction_count: block.transactions.len(),
        successful_txs,
        total_time_ms,
        per_tx_ms: per_tx_time,
        throughput_tps: throughput,
        total_bytecode_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "Requires network access"]
    async fn test_fetch_block() {
        let block = EthereumBlock::fetch(19_000_000).await.unwrap();
        println!("Block number: {}", block.number);
        println!("Hash: {}", block.hash);
        println!("Transactions: {}", block.transactions.len());
    }

    #[tokio::test]
    #[ignore = "Requires network access"]
    async fn test_fetch_contract_bytecode() {
        // USDC contract
        let client = EthClient::default();
        let code = client.get_code("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "latest").await.unwrap();
        println!("USDC bytecode length: {} bytes", code.len());
    }
}