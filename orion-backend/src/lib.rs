//! Orion Backend for Lattice ZK
//!
//! Lattice-based proving backend using Labrador SNARK protocol:
//! - **Labrador** for SNARK proof generation
//! - **LatticeOps** for ANE-accelerated MatVec operations

pub mod labrador;
pub mod lattice_ops;
pub mod error;

#[cfg(feature = "mock")]
pub mod mock_orion_sys;

pub use error::BackendError;

/// Field element representation (Dilithium-3 field)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FieldElement(pub u32);

impl FieldElement {
    pub fn new(val: u32) -> Self {
        FieldElement(val % 8383489) // Dilithium-3 modulus
    }
}

/// Black box functions mapped to hardware acceleration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlackBoxFunc {
    MatVec,
    NTT,
    CRT,
    Poseidon2,
    Keccak256,
    SHA256,
    ECDSAVerify,
    SchnorrVerify,
    PermutationCheck,
}

impl BlackBoxFunc {
    /// Returns true if this function should use ANE acceleration
    pub fn uses_ane(&self) -> bool {
        matches!(self, BlackBoxFunc::MatVec | BlackBoxFunc::PermutationCheck)
    }

    /// Returns true if this function should use GPU acceleration
    pub fn uses_gpu(&self) -> bool {
        matches!(self, BlackBoxFunc::NTT)
    }
}
