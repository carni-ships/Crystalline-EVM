//! Verifier for Lattice-based zkEVM
//!
//! Uses Orion's Labrador protocol for proof verification.

pub mod snark_verifier;

use orion_backend::labrador::LabradorVerifier;
use orion_sys::{LatticeZKProof, LatticeZKVerificationKey, LatticeZKProvingKey};

pub use snark_verifier::{SNARKVerifier, VerificationResult, CompactVerifier};

/// Verifier configuration (without VK since it can't be cloned)
pub struct VerifierConfig {
    /// Number of trace columns
    pub trace_width: usize,
    /// Trace length
    pub trace_length: usize,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        VerifierConfig {
            trace_width: 4,
            trace_length: 256,
        }
    }
}

/// Lattice EVM Verifier using Labrador protocol
pub struct Verifier {
    config: VerifierConfig,
    labrador_verifier: LabradorVerifier,
}

impl Verifier {
    /// Create new verifier from verification key
    pub fn new(config: VerifierConfig, vk: LatticeZKVerificationKey) -> Self {
        let labrador_verifier = LabradorVerifier::new(vk);

        Verifier {
            config,
            labrador_verifier,
        }
    }

    /// Create from proving key (for testing)
    pub fn from_proving_key(pk: &LatticeZKProvingKey) -> Self {
        let vk = LatticeZKVerificationKey {
            q: pk.q,
            k: pk.k,
            l: pk.l,
            n: pk.n,
        };
        let config = VerifierConfig {
            trace_width: pk.l as usize,
            trace_length: pk.n as usize,
        };
        Self::new(config, vk)
    }

    /// Create from default verification key
    pub fn with_defaults() -> Self {
        let vk = LatticeZKVerificationKey::default();
        Self::new(VerifierConfig::default(), vk)
    }

    /// Verify a proof
    pub fn verify(&self, proof: &LatticeZKProof) -> Result<bool, orion_backend::BackendError> {
        self.labrador_verifier.verify(proof)
    }

    /// Get configuration
    pub fn config(&self) -> &VerifierConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verifier_creation() {
        let verifier = Verifier::with_defaults();
        assert_eq!(verifier.config().trace_width, 4);
    }
}