//! Benchmarks for Lattice-Based Cryptography Exploration
//!
//! This module compares lattice-based approaches against the existing
//! Poseidon/Keccak implementations to evaluate feasibility and performance.

use std::time::Instant;
use super::dilithium_merkle::{build_lattice_merkle_tree, LatticeMerkleConfig};
use super::lattice_fiat_shamir::{LatticeHash, LatticeFiatShamirConfig};
use super::lattice_merkle::build_lwe_merkle_tree;

/// Compare LWE-based Merkle tree vs Poseidon Merkle tree
pub fn benchmark_lattice_merkle_vs_poseidon(leaf_count: usize) {
    println!("=== LWE Merkle vs Poseidon Merkle ===");
    println!("Leaf count: {}", leaf_count);

    // Generate test leaves
    let leaves: Vec<u32> = (0..leaf_count as u32).map(|i| i * 12345).collect();

    // Benchmark Poseidon-based (existing)
    let start = Instant::now();
    let _poseidon_tree = crate::crypto::BatchMerkleTree::build(&leaves);
    let poseidon_time = start.elapsed().as_micros() as f64 / 1000.0;

    println!("Poseidon Merkle: {:.3}ms", poseidon_time);

    // Benchmark LWE-based (uses hash_lwe from Orion)
    let start = Instant::now();
    let _lwe_tree = build_lwe_merkle_tree(&leaves);
    let lwe_time = start.elapsed().as_micros() as f64 / 1000.0;

    println!("LWE Merkle: {:.3}ms", lwe_time);

    // Ratio
    if lwe_time > 0.0 {
        let ratio = lwe_time / poseidon_time;
        println!("Ratio: {:.2}x (LWE vs Poseidon)", ratio);
    }
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

    #[test]
    #[ignore = "exploration benchmark only - requires ANE"]
    fn test_benchmark_lwe_merkle_real() {
        use super::super::lattice_merkle::{build_lwe_merkle_tree, get_root, generate_membership_proof, verify_membership_proof};

        let leaf_count = 256;
        let leaves: Vec<u32> = (0..leaf_count as u32).map(|i| i * 12345).collect();

        let start = Instant::now();
        let tree = build_lwe_merkle_tree(&leaves);
        let build_time = start.elapsed().as_micros() as f64 / 1000.0;

        let root = get_root(&tree).expect("should have root");

        // Benchmark membership proof generation
        let start = Instant::now();
        let proof = generate_membership_proof(&tree, 42, leaf_count);
        let prove_time = start.elapsed().as_micros() as f64 / 1000.0;

        // Benchmark verification
        let start = Instant::now();
        let valid = verify_membership_proof(root, 42 * 12345, 42, &proof);
        let verify_time = start.elapsed().as_micros() as f64 / 1000.0;

        println!("\n=== LWE Merkle Real Benchmark ===");
        println!("Leaves: {}", leaf_count);
        println!("Tree nodes: {}", tree.len());
        println!("Build time: {:.3}ms", build_time);
        println!("Proof generation: {:.3}ms", prove_time);
        println!("Verification: {:.3}ms", verify_time);
        println!("Proof valid: {}", valid);
    }
}