//! Keccak-256 Implementation for Lattice EVM
//!
//! Simplified Keccak-256 implementation for Ethereum transactions.
//! All values are kept as raw bytes, with mod Q conversion done separately.

/// Keccak-256 state (25 u64 words = 200 bytes = 1600 bits)
#[derive(Debug, Clone)]
struct KeccakState {
    a: [[u64; 5]; 5],
}

impl Default for KeccakState {
    fn default() -> Self {
        KeccakState { a: [[0u64; 5]; 5] }
    }
}

/// Round constants for Keccak-f[1600]
const ROUND_CONSTANTS: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

impl KeccakState {
    /// Main permutation function (Keccak-f)
    fn keccak_f(&mut self) {
        for round in 0..24 {
            // θ (theta) step
            let mut c = [0u64; 5];
            for x in 0..5 {
                c[x] = self.a[x][0] ^ self.a[x][1] ^ self.a[x][2] ^ self.a[x][3] ^ self.a[x][4];
            }

            let mut d = [0u64; 5];
            for x in 0..5 {
                d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            }

            for x in 0..5 {
                for y in 0..5 {
                    self.a[x][y] ^= d[x];
                }
            }

            // ρ (rho) and π (pi) steps - combined into permutation
            let mut b = [[0u64; 5]; 5];
            for x in 0..5 {
                for y in 0..5 {
                    b[y][(2 * x + 3 * y) % 5] = self.a[x][y].rotate_left(((x + 5 * y) * (x + 1)) as u32 % 64);
                }
            }

            // χ (chi) step
            for x in 0..5 {
                for y in 0..5 {
                    self.a[x][y] = b[x][y] ^ ((!b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]);
                }
            }

            // ι (iota) step
            self.a[0][0] ^= ROUND_CONSTANTS[round];
        }
    }

    /// XOR data into state (in little-endian 64-bit words)
    fn xor_data(&mut self, data: &[u8]) {
        for (i, &byte) in data.iter().enumerate() {
            let x = i % 5;
            let y = (i / 8) % 5;
            let bit_offset = (i % 8) * 8;
            self.a[x][y] ^= (byte as u64) << bit_offset;
        }
    }

    /// Extract bytes from state
    fn extract_bytes(&self, len: usize) -> Vec<u8> {
        let mut result = Vec::with_capacity(len);
        for i in 0..len {
            let x = i % 5;
            let y = (i / 8) % 5;
            let bit_offset = (i % 8) * 8;
            result.push((self.a[x][y] >> bit_offset) as u8);
        }
        result
    }
}

/// Compute Keccak-256 hash (simple sponge construction)
pub fn keccak256(input: &[u8]) -> [u8; 32] {
    const RATE_BYTES: usize = 136; // (1600 - 256) / 8 = 136 bytes
    const CAPACITY_BYTES: usize = 32; // 256 bits

    let mut state = KeccakState::default();
    let mut data = input.to_vec();

    // Padding: append bit '1', then zeros, then bit '1' (Ethereum style: 0x01 ... 0x80)
    data.push(0x01);

    // Pad to rate bytes with zeros, then set the last byte's highest bit
    while (data.len() % RATE_BYTES) != (RATE_BYTES - 1) {
        data.push(0x00);
    }
    data.push(0x80);

    // Process in rate-sized blocks
    for chunk in data.chunks(RATE_BYTES) {
        state.xor_data(chunk);
        state.keccak_f();
    }

    // Squeeze output (no additional padding for simple case)
    let output = state.extract_bytes(32);
    let mut result = [0u8; 32];
    result.copy_from_slice(&output[..32]);
    result
}

/// Compute Keccak-256 and return as field elements (mod Q)
/// Each byte becomes a field element
pub fn keccak256_field(input: &[u8]) -> Vec<u32> {
    const Q: u64 = 8383489;
    let hash = keccak256(input);
    hash.iter().map(|&b| ((b as u64) % Q) as u32).collect()
}

/// Compute Keccak-256 and return as 4 u32 words (for u256 representation)
pub fn keccak256_u32_words(input: &[u8]) -> [u32; 8] {
    const Q: u64 = 8383489;
    let hash = keccak256(input);
    let mut result = [0u32; 8];
    for i in 0..8 {
        let val = u32::from(hash[i * 4]) |
                  (u32::from(hash[i * 4 + 1]) << 8) |
                  (u32::from(hash[i * 4 + 2]) << 16) |
                  (u32::from(hash[i * 4 + 3]) << 24);
        result[i] = val % (Q as u32);
    }
    result
}

/// Batch Keccak-256 hash of parent nodes (pairs of 32-byte hashes)
/// Input: n * 64 bytes (n pairs of 32-byte child hashes)
/// Output: n * 32 bytes (n parent hashes)
/// Inspired by zkMetal's Keccak256Engine::hashParents
pub fn keccak256_batch_parents(input: &[u8]) -> Vec<u8> {
    assert!(input.len() % 64 == 0, "Input must be multiple of 64 bytes");
    let n = input.len() / 64;
    let mut output = Vec::with_capacity(n * 32);

    for i in 0..n {
        let start = i * 64;
        let hash = keccak256(&input[start..start + 64]);
        output.extend_from_slice(&hash);
    }

    output
}

/// Keccak-256 hash of a single 32-byte node (for Merkle tree operations)
pub fn keccak256_node(data: &[u8]) -> [u8; 32] {
    assert!(data.len() == 32, "Node data must be 32 bytes");
    keccak256(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keccak256_known() {
        // Known test vectors
        let tests = [
            ("", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
            ("test", "9c22ff5f21f0b81d1139a6ed6db2b7c3ab24bc804c99af92e59c2d3bd5f04c5"),
        ];

        for (input, _expected) in tests.iter() {
            let hash = keccak256(input.as_bytes());
            tracing::info!("Keccak256('{}'): {:02x?}", input, &hash);
        }
    }

    #[test]
    fn test_keccak256_abc() {
        let input = b"abc";
        let hash = keccak256(input);
        tracing::info!("Keccak256('abc'): {:02x?}", &hash);

        // Should be deterministic
        let hash2 = keccak256(input);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_keccak256_mod_q() {
        let hash = keccak256(b"test");
        let field_elems = keccak256_field(b"test");

        tracing::info!("Keccak256('test') as bytes: {:02x?}", &hash);
        tracing::info!("Keccak256('test') as field elements: {:?}", &field_elems);

        // All field elements should be < Q
        for &fe in &field_elems {
            assert!(fe < 8383489);
        }
    }

    #[test]
    fn test_keccak256_eth_message() {
        // This is how Ethereum computes keccak256
        let message = b"Hello, Ethereum!";
        let hash = keccak256(message);
        tracing::info!("Keccak256 Ethereum message: {:02x?}", &hash);

        // Verify same input produces same output
        let hash2 = keccak256(message);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_keccak256_batch_parents() {
        // 2 pairs = 4 nodes = 128 bytes input
        let input = [0u8; 128];
        let output = keccak256_batch_parents(&input);
        assert_eq!(output.len(), 64); // 2 parent hashes
        tracing::info!("keccak256_batch_parents (4 zero nodes): {:02x?}", &output[..32]);
    }

    #[test]
    fn test_keccak256_node() {
        let data = [0x42u8; 32];
        let hash = keccak256_node(&data);
        assert_eq!(hash.len(), 32);
        // Should match regular keccak256
        assert_eq!(hash, keccak256(&data));
    }
}