// attempt_break_proof.rs - Test if we can create a fake NovaIVC proof
// Run: cargo run --bin attempt_break_proof

use lattice_evm::prover::recursive_prove::{
    NovaIVCProof, LCCCS, CCCS, FoldingChain, AugmentedProof, verify_nova_proof,
};
use lattice_evm::crypto::Poseidon2;

fn create_valid_proof(n_proofs: usize, initial_state: u32) -> NovaIVCProof {
    let mut chain = FoldingChain::new();
    let mut running_comm_w = 0u32;

    for i in 0..n_proofs {
        let comm_w_cccs = Poseidon2::hash_pair(i as u32, i as u32 * 2);
        let r = Poseidon2::hash_pair(running_comm_w, comm_w_cccs);
        let comm_w_old = running_comm_w;
        let mul_result = (running_comm_w as u64).wrapping_mul(r as u64);
        let new_comm_w = mul_result.wrapping_add(comm_w_cccs as u64) as u32;
        chain.add_fold(r, comm_w_old, comm_w_cccs, Poseidon2::hash_pair(initial_state, i as u32));
        running_comm_w = new_comm_w;
    }

    let final_u = Poseidon2::hash_pair(initial_state, n_proofs as u32);
    let chain_commit = chain.chain_commitment();
    let last_r = chain.challenges.last().copied().unwrap_or(0);
    let last_comm_w_old = chain.comm_w_old_list.last().copied().unwrap_or(0);
    let last_comm_w_cccs = chain.comm_w_cccs_list.last().copied().unwrap_or(0);

    NovaIVCProof {
        running: LCCCS { u: final_u, comm_w: running_comm_w, C: 0, n: n_proofs },
        final_step: CCCS { u: final_u, comm_w: running_comm_w },
        augmented_proof: AugmentedProof::prove(
            running_comm_w, last_r, last_comm_w_old, last_comm_w_cccs, n_proofs, chain_commit
        ).to_bytes(),
        folding_chain: chain,
    }
}

fn main() {
    println!("=== Attempting to Break NovaIVC Proof Verification ===\n");

    // Create a legitimate proof
    let legit_proof = create_valid_proof(3, 12345);
    println!("Legitimate proof verification: {}", verify_nova_proof(&legit_proof));

    // ATTEMPT 1: Flip a bit in comm_w
    println!("\n--- Attempt 1: Flip bit in running.comm_w ---");
    let mut fake1 = legit_proof.clone();
    fake1.running.comm_w ^= 0x1;
    println!("Verification: {}", verify_nova_proof(&fake1));

    // ATTEMPT 2: Change final_u to not match running.u
    println!("\n--- Attempt 2: Mismatch final_u and running.u ---");
    let mut fake2 = legit_proof.clone();
    fake2.final_step.u ^= 0x1;
    println!("Verification: {}", verify_nova_proof(&fake2));

    // ATTEMPT 3: Create entirely fake proof with zeros
    println!("\n--- Attempt 3: Create fake proof from scratch ---");
    let fake_proof = NovaIVCProof {
        running: LCCCS { u: 0, comm_w: 0, C: 0, n: 0 },
        final_step: CCCS { u: 0, comm_w: 0 },
        augmented_proof: vec![],
        folding_chain: FoldingChain::new(),
    };
    println!("Zero proof verification: {}", verify_nova_proof(&fake_proof));

    // ATTEMPT 4: Tamper with folding chain (change challenge ONLY)
    println!("\n--- Attempt 4: Tamper with folding chain (change challenge ONLY) ---");
    let mut fake4 = legit_proof.clone();
    println!("Before: challenges = {:?}", legit_proof.folding_chain.challenges);
    if let Some(challenge) = fake4.folding_chain.challenges.first_mut() {
        *challenge ^= 0x1;
    }
    println!("After:  challenges = {:?}", fake4.folding_chain.challenges);
    println!("Verification: {}", verify_nova_proof(&fake4));

    // ATTEMPT 5: Change n in running (length mismatch)
    println!("\n--- Attempt 5: Change n in running (length mismatch) ---");
    let mut fake5 = legit_proof.clone();
    fake5.running.n = 999;  // Wrong n
    println!("Verification: {}", verify_nova_proof(&fake5));

    // ATTEMPT 6: Try to craft proof with manipulated comm_w but valid chain
    println!("\n--- Attempt 6: Try to craft proof with manipulated comm_w ---");
    let mut fake6 = legit_proof.clone();
    fake6.running.comm_w = Poseidon2::hash_pair(999, 999);
    println!("Verification: {}", verify_nova_proof(&fake6));

    // ATTEMPT 7: Empty augmented proof (should fall back to basic checks)
    println!("\n--- Attempt 7: Empty augmented proof ---");
    let mut fake7 = legit_proof.clone();
    fake7.augmented_proof = vec![];
    println!("Note: Empty augmented proof skips sumcheck verification");
    println!("Verification: {}", verify_nova_proof(&fake7));

    // ATTEMPT 8: Tamper with cccs (should fail at compute_final_comm_w)
    println!("\n--- Attempt 8: Tamper with cccs value (should fail) ---");
    let mut fake8 = legit_proof.clone();
    if let Some(cccs) = fake8.folding_chain.comm_w_cccs_list.first_mut() {
        *cccs ^= 0x1;
    }
    println!("Verification: {}", verify_nova_proof(&fake8));

    println!("\n=== Summary ===");
    println!("If attempts 4, 5, 7, 8 still PASS, the vulnerability still exists.");
    println!("After the fix, ALL attempts should FAIL (verification = false).");
}