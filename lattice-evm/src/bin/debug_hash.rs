// debug_hash.rs - Debug Poseidon2 hash behavior
use lattice_evm::crypto::Poseidon2;

fn main() {
    println!("=== Debug Poseidon2 hash_pair ===\n");

    // Simple inputs
    let a = 1661894u32;
    let b = 0u32;
    let c = 1661895u32;  // a with LSB flipped

    let h1 = Poseidon2::hash_pair(a, b);
    let h2 = Poseidon2::hash_pair(c, b);

    println!("hash_pair({}, {}) = {:08x}", a, b, h1);
    println!("hash_pair({}, {}) = {:08x}", c, b, h2);
    println!("Are they equal? {}", h1 == h2);

    // Now test with accumulator pattern
    println!("\n=== Chain Hash Test ===");
    let mut h_acc = 0u32;
    h_acc = Poseidon2::hash_pair(h_acc, a);
    println!("After adding {}: {:08x}", a, h_acc);

    let original_chain = h_acc;

    let mut h_acc2 = 0u32;
    h_acc2 = Poseidon2::hash_pair(h_acc2, c);
    println!("After adding {}: {:08x}", c, h_acc2);

    println!("Original chain: {:08x}", original_chain);
    println!("New chain: {:08x}", h_acc2);
    println!("Equal? {}", original_chain == h_acc2);
}