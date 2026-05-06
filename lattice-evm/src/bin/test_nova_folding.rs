// test_nova_folding.rs - Test NovaIVC folding with CORRECT implementation
// Run: cargo run --bin test_nova_folding

use lattice_evm::prover::recursive_prove::{
    NovaIVCProof, LCCCS, CCCS, FoldingChain, AugmentedProof, verify_nova_proof,
};
use lattice_evm::crypto::Poseidon2;

fn main() {
    println!("=== Testing NovaIVC with Correct Implementation ===\n");

    // Test with n = 4 (power of 2)
    println!("--- Test with n=4 (power of 2) ---");
    let proof4 = create_proof(4, 12345);
    let result4 = verify_nova_proof(&proof4);
    println!("n=4: verification = {}", result4);

    // Test with n = 3 (non-power of 2)
    println!("\n--- Test with n=3 (non-power of 2) ---");
    let proof3 = create_proof(3, 12345);
    let result3 = verify_nova_proof(&proof3);
    println!("n=3: verification = {}", result3);

    // Test with n = 1 (single fold)
    println!("\n--- Test with n=1 (single fold) ---");
    let proof1 = create_proof(1, 12345);
    let result1 = verify_nova_proof(&proof1);
    println!("n=1: verification = {}", result1);

    // Test with n = 16 (larger power of 2)
    println!("\n--- Test with n=16 (power of 2) ---");
    let proof16 = create_proof(16, 12345);
    let result16 = verify_nova_proof(&proof16);
    println!("n=16: verification = {}", result16);

    println!("\n=== Summary ===");
    println!("If ALL verification = true, the scheme is working correctly.");
    println!("If any shows false, there's a bug in the implementation.");
}

fn create_proof(n_proofs: usize, initial_state: u32) -> NovaIVCProof {
    // Build a legitimate folding chain
    let mut chain = FoldingChain::new();
    let mut running_comm_w = 0u32;

    for i in 0..n_proofs {
        let comm_w_cccs = Poseidon2::hash_pair(i as u32, i as u32 * 2);

        // Compute challenge r = Hash(running_comm_w, comm_w_cccs)
        let r = Poseidon2::hash_pair(running_comm_w, comm_w_cccs);

        // Save comm_w_old BEFORE the fold (for the chain)
        let comm_w_old = running_comm_w;

        // Compute NEW running comm_w = r * running_comm_w + comm_w_cccs
        let mul_result = (running_comm_w as u64).wrapping_mul(r as u64);
        let new_comm_w = mul_result.wrapping_add(comm_w_cccs as u64) as u32;

        // Add to chain with CORRECT values: comm_w_old is the value BEFORE this fold
        chain.add_fold(r, comm_w_old, comm_w_cccs, Poseidon2::hash_pair(initial_state, i as u32));

        // Update running comm_w for next iteration
        running_comm_w = new_comm_w;
    }

    let final_u = Poseidon2::hash_pair(initial_state, n_proofs as u32);
    let last_r = chain.challenges.last().copied().unwrap_or(0);
    let last_comm_w_old = chain.comm_w_old_list.last().copied().unwrap_or(0);
    let last_comm_w_cccs = chain.comm_w_cccs_list.last().copied().unwrap_or(0);
    let chain_commit = chain.chain_commitment();

    // The augmented proof verifies the FINAL folding step
    // It shows that: running_comm_w = r * comm_w_old + comm_w_cccs (last fold)
    let augmented = AugmentedProof::prove(
        running_comm_w,   // comm_w_new = the accumulated result after ALL folds
        last_r,            // r = challenge from last fold
        last_comm_w_old,  // comm_w_old = value BEFORE last fold
        last_comm_w_cccs, // comm_w_cccs = CCCS from last fold
        n_proofs,
        chain_commit,
    );

    NovaIVCProof {
        running: LCCCS { u: final_u, comm_w: running_comm_w, C: 0, n: n_proofs },
        final_step: CCCS { u: final_u, comm_w: running_comm_w },
        augmented_proof: augmented.to_bytes(),
        folding_chain: chain,
    }
}