//! Orion Backend for Noir ACIR
//!
//! An ACIR backend for lattice-based ZK using:
//! - Orion ANE for high-throughput MatVec
//! - Orion GPU NTT for polynomial multiplication
//! - Labrador/Greyhound protocols for proof system
//!
//! # Architecture
//!
//! ```text
//! Noir Code → ACIR (msgpack-compact) → Orion Backend → Proof
//!                                       ├── ANE MatVec
//!                                       ├── GPU NTT
//!                                       └── CRT Reconstruction
//! ```

pub mod acir_parser;
pub mod opcode_handler;
pub mod lattice_ops;
pub mod brillig_runner;
pub mod error;
pub mod labrador;

/// Mock FFI module for testing (enabled with `mock` feature)
#[cfg(feature = "mock")]
pub mod mock_orion_sys;

pub use error::BackendError;

/// ACIR opcode types supported by Orion backend
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpcodeType {
    AssertZero,
    BlackBoxFuncCall,
    MemoryOp,
    BrilligCall,
    Call,
}

/// Black box functions that map to hardware acceleration
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
    PermutationCheck,  // For memory/storage cross-row verification
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

/// Witness in ACIR (field element index)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Witness(pub u32);

/// Field element representation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FieldElement(pub u32);

impl FieldElement {
    pub fn new(val: u32) -> Self {
        FieldElement(val % 8383489) // Dilithium-3 modulus
    }
}

/// ACIR circuit representation
#[derive(Debug, Clone)]
pub struct Circuit {
    /// Opcodes in execution order
    pub opcodes: Vec<Opcode>,
    /// Private input witnesses
    pub private_parameters: Vec<Witness>,
    /// Public input witnesses
    pub public_parameters: Vec<Witness>,
}

/// Single ACIR opcode
#[derive(Debug, Clone)]
pub enum Opcode {
    AssertZero(FieldElement),
    BlackBoxFuncCall(BlackBoxFunc, Vec<Witness>, Vec<Witness>),
    MemoryOp(MemoryOperation),
    BrilligCall(Vec<u8>),
    Call { function: String, args: Vec<Witness> },
}

/// Memory operation (simplified array model)
#[derive(Debug, Clone)]
pub struct MemoryOperation {
    pub operation: MemoryOpType,
    pub address: Witness,
    pub value: Witness,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryOpType {
    Write,
    Read,
}

/// Complete ACIR program
#[derive(Debug, Clone)]
pub struct AcirProgram {
    pub circuits: Vec<Circuit>,
    pub return_values: Vec<Witness>,
}

impl AcirProgram {
    /// Parse ACIR from msgpack-compact format
    pub fn from_msgpack(data: &[u8]) -> Result<Self, BackendError> {
        acir_parser::parse_msgpack(data)
    }
}