// debug_chain_commit.rs - Debug chain commitment behavior
use lattice_evm::prover::recursive_prove::FoldingChain;
use lattice_evm::crypto::Poseidon2;

fn main() {
    println!("=== Debug Chain Commitment ===\n");

    // Create chain with 3 folds
    let mut chain = FoldingChain::new();
    let challenges = [1661894u32, 3595766, 5307453];

    for (i, &r) in challenges.iter().enumerate() {
        chain.add_fold(r, i as u32 * 100, i as u32 * 200, i as u32 * 300);
    }

    println!("Original challenges: {:?}", chain.challenges);
    let original_commit = chain.chain_commitment();
    println!("Original chain_commitment: {:08x}", original_commit);

    // Tamper with challenge[0]
    chain.challenges[0] ^= 0x1;
    println!("\nTampered challenges: {:?}", chain.challenges);
    let tampered_commit = chain.chain_commitment();
    println!("Tampered chain_commitment: {:08x}", tampered_commit);

    println!("\nAre they equal? {}", original_commit == tampered_commit);

    // Now test what happens in verify
    println!("\n=== Test Verify Flow ===");

    // Simulate what happens in verify_nova_proof
    let stored_chain_commit_in_augmented = original_commit;  // This was stored during proving
    let computed_chain_commit_from_tampered = tampered_commit;  // This is recomputed from tampered chain

    println!("stored (in augmented): {:08x}", stored_chain_commit_in_augmented);
    println!("computed (from tampered): {:08x}", computed_chain_commit_from_tampered);
    println!("Should be NOT equal: {}", stored_chain_commit_in_augmented != computed_chain_commit_from_tampered);
}