//! Lattice EVM Verifier Binary

use lattice_evm::Verifier;
use orion_sys::{LatticeZKVerificationKey, LATTICEZK_K, LATTICEZK_L, LATTICEZK_N, LATTICEZK_Q};

fn main() {
    tracing_subscriber::fmt::init();

    tracing::info!("Lattice EVM Verifier starting...");

    let vk = LatticeZKVerificationKey {
        q: LATTICEZK_Q as u64,
        k: LATTICEZK_K as i32,
        l: LATTICEZK_L as i32,
        n: LATTICEZK_N as i32,
    };

    let verifier = Verifier::new(lattice_evm::verifier::VerifierConfig::default(), vk);

    tracing::info!("Verifier created successfully");
    tracing::info!("Trace width: {}", verifier.config().trace_width);
    tracing::info!("Trace length: {}", verifier.config().trace_length);
}