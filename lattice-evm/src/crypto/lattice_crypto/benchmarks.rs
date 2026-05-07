//! Benchmarks for Lattice-Based Cryptography Exploration
//!
//! This module compares lattice-based approaches against the existing
//! Poseidon/Keccak implementations to evaluate feasibility and performance.

use std::time::Instant;
use super::dilithium_merkle::{build_lattice_merkle_tree, LatticeMerkleConfig};
use super::lattice_fiat_shamir::{LatticeHash, LatticeFiatShamirConfig};

/// Compare lattice Merkle tree construction vs Poseidon Merkle tree
pub fn benchmark_lattice_merkle_vs_poseidon(leaf_count: usize) {
    println!("=== Lattice Merkle vs Poseidon Merkle ===");
    println!("Leaf count: {}", leaf_count);

    // Generate test leaves
    let leaves: Vec<u32> = (0..leaf_count as u32).map(|i| i * 12345).collect();

    // Benchmark Poseidon-based (existing)
    let start = Instant::now();
    let _poseidon_tree = crate::crypto::BatchMerkleTree::build(&leaves);
    let poseidon_time = start.elapsed().as_micros() as f64 / 1000.0;

    println!("Poseidon Merkle: {:.3}ms", poseidon_time);

    // Benchmark lattice-based (exploration)
    let lattice_config = LatticeMerkleConfig::default();
    let start = Instant::now();
    let _lattice_nodes = build_lattice_merkle_tree(&leaves, &lattice_config);
    let lattice_time = start.elapsed().as_micros() as f64 / 1000.0;

    println!("Lattice Merkle: {:.3}ms", lattice_time);

    // Note: the current lattice implementation just uses Poseidon internally
    // so times will be similar. The real cost would be in actual LWE ops.
    println!("Note: Current impl uses Poseidon internally - real LWE would be 10-100x slower");
}

/// Compare lattice Fiat-Shamir vs Poseidon Fiat-Shamir
pub fn benchmark_lattice_fiat_shamir_vs_poseidon(iterations: usize) {
    println!("\n=== Lattice Fiat-Shamir vs Poseidon ===");
    println!("Iterations: {}", iterations);

    let hasher = LatticeHash::new(LatticeFiatShamirConfig::default());

    // Benchmark lattice Fiat-Shamir
    let start = Instant::now();
    let mut lattice_result = 0u32;
    for i in 0..iterations {
        lattice_result = hasher.hash(i as u32, (i + 1) as u32);
    }
    let lattice_time = start.elapsed().as_micros() as f64 / 1000.0;

    println!("Lattice FS: {:.3}ms ({} ops)", lattice_time, iterations);
    println!("Lattice result: {:08x}", lattice_result);

    // Benchmark Poseidon Fiat-Shamir
    let start = Instant::now();
    let mut poseidon_result = 0u32;
    for i in 0..iterations {
        poseidon_result = crate::crypto::Poseidon2::hash_pair(i as u32, (i + 1) as u32);
    }
    let poseidon_time = start.elapsed().as_micros() as f64 / 1000.0;

    println!("Poseidon FS: {:.3}ms ({} ops)", poseidon_time, iterations);
    println!("Poseidon result: {:08x}", poseidon_result);

    // Ratio
    let ratio = lattice_time / poseidon_time;
    println!("Ratio: {:.2}x", ratio);
}

/// Run all exploration benchmarks
pub fn run_all_benchmarks() {
    println!("\n╔════════════════════════════════════════════════════════════╗");
    println!("║     Lattice Cryptography Exploration Benchmarks           ║");
    println!("╚════════════════════════════════════════════════════════════╝\n");

    // Merkle tree benchmarks
    for leaf_count in [64, 256, 1024] {
        benchmark_lattice_merkle_vs_poseidon(leaf_count);
    }

    // Fiat-Shamir benchmarks
    benchmark_lattice_fiat_shamir_vs_poseidon(10000);

    println!("\n=== Analysis ===");
    println!("Current lattice implementations use Poseidon internally.");
    println!("Real lattice-based crypto would be significantly slower but quantum-resistant.");
    println!("The value proposition is not speed - it's unified security assumptions.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "exploration benchmark only"]
    fn test_benchmark_lattice_merkle() {
        benchmark_lattice_merkle_vs_poseidon(256);
    }

    #[test]
    #[ignore = "exploration benchmark only"]
    fn test_benchmark_lattice_fiat_shamir() {
        benchmark_lattice_fiat_shamir_vs_poseidon(10000);
    }
}