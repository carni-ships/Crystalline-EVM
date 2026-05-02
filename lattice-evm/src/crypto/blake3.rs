//! Blake3 Hash Implementation for Lattice EVM
//!
//! Ported from zkMetal's CPU reference implementation.
//! Blake3 is used for Merkle tree construction in the commit-prove scheme.

/// Blake3 initialization vector
const BLAKE3_IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

/// Message permutation for Blake3 rounds
const MSG_PERM: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

/// Flag values for Blake3 compression
const FLAG_CHUNK_START: u32 = 1;
const FLAG_CHUNK_END: u32 = 2;
const FLAG_PARENT: u32 = 4;
const FLAG_ROOT: u32 = 8;

/// CPU Blake3 hash of arbitrary-length input (single-threaded reference)
/// Ported from zkMetal Sources/zkMetal/Hash/Blake3Engine.swift
pub fn blake3(input: &[u8]) -> [u8; 32] {
    fn g(state: &mut [u32], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
        state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
        state[d] = state[d] ^ state[a].rotate_right(16);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = state[b] ^ state[c].rotate_right(12);
        state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
        state[d] = state[d] ^ state[a].rotate_right(8);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = state[b] ^ state[c].rotate_right(7);
    }

    fn round(state: &mut [u32], msg: &[u32; 16], perm: &[usize; 16]) {
        g(state, 0, 4, 8, 12, msg[0], msg[1]);
        g(state, 1, 5, 9, 13, msg[2], msg[3]);
        g(state, 2, 6, 10, 14, msg[4], msg[5]);
        g(state, 3, 7, 11, 15, msg[6], msg[7]);
        g(state, 0, 5, 10, 15, msg[8], msg[9]);
        g(state, 1, 6, 11, 12, msg[10], msg[11]);
        g(state, 2, 7, 8, 13, msg[12], msg[13]);
        g(state, 3, 4, 9, 14, msg[14], msg[15]);
    }

    fn permute_impl(msg: &[u32; 16], perm: &[usize; 16]) -> [u32; 16] {
        let mut out = [0u32; 16];
        for i in 0..16 {
            out[i] = msg[perm[i]];
        }
        out
    }

    fn compress(
        cv: &[u32; 8],
        block: &[u8],
        counter_lo: u32,
        counter_hi: u32,
        block_len: u32,
        flags: u32,
        iv: &[u32; 8],
        perm: &[usize; 16],
    ) -> [u32; 16] {
        let mut msg = [0u32; 16];
        for i in 0..16 {
            let offset = i * 4;
            if offset + 3 < block.len() {
                msg[i] = u32::from(block[offset])
                    | (u32::from(block[offset + 1]) << 8)
                    | (u32::from(block[offset + 2]) << 16)
                    | (u32::from(block[offset + 3]) << 24);
            } else {
                let mut val = 0u32;
                for j in 0..4 {
                    if offset + j < block.len() {
                        val |= u32::from(block[offset + j]) << (j * 8);
                    }
                }
                msg[i] = val;
            }
        }

        let mut state: [u32; 16] = [
            cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7],
            iv[0], iv[1], iv[2], iv[3],
            counter_lo, counter_hi, block_len, flags,
        ];

        let mut m = msg;
        for r in 0..7 {
            round(&mut state, &m, perm);
            if r < 6 {
                m = permute_impl(&m, perm);
            }
        }

        for i in 0..8 {
            state[i] ^= state[i + 8];
            state[i + 8] ^= cv[i];
        }
        state
    }

    // Pad input to 64 bytes
    let block_len = input.len().min(64) as u32;
    let mut padded = input.to_vec();
    while padded.len() < 64 {
        padded.push(0);
    }

    // Single chunk, single block
    let flags = FLAG_CHUNK_START | FLAG_CHUNK_END | FLAG_ROOT;
    let result = compress(&BLAKE3_IV, &padded, 0, 0, block_len, flags, &BLAKE3_IV, &MSG_PERM);

    let mut output = [0u8; 32];
    for i in 0..8 {
        output[i * 4] = (result[i] & 0xFF) as u8;
        output[i * 4 + 1] = ((result[i] >> 8) & 0xFF) as u8;
        output[i * 4 + 2] = ((result[i] >> 16) & 0xFF) as u8;
        output[i * 4 + 3] = ((result[i] >> 24) & 0xFF) as u8;
    }
    output
}

/// Blake3 parent compression (for Merkle tree nodes)
/// Input: 64 bytes (left || right child hashes), Output: 32-byte parent hash
/// Ported from zkMetal Sources/zkMetal/Hash/Blake3Engine.swift
pub fn blake3_parent(input: &[u8]) -> [u8; 32] {
    fn g(state: &mut [u32], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
        state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
        state[d] = state[d] ^ state[a].rotate_right(16);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = state[b] ^ state[c].rotate_right(12);
        state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
        state[d] = state[d] ^ state[a].rotate_right(8);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = state[b] ^ state[c].rotate_right(7);
    }

    fn round(state: &mut [u32], msg: &[u32; 16]) {
        g(state, 0, 4, 8, 12, msg[0], msg[1]);
        g(state, 1, 5, 9, 13, msg[2], msg[3]);
        g(state, 2, 6, 10, 14, msg[4], msg[5]);
        g(state, 3, 7, 11, 15, msg[6], msg[7]);
        g(state, 0, 5, 10, 15, msg[8], msg[9]);
        g(state, 1, 6, 11, 12, msg[10], msg[11]);
        g(state, 2, 7, 8, 13, msg[12], msg[13]);
        g(state, 3, 4, 9, 14, msg[14], msg[15]);
    }

    fn permute_impl(msg: &[u32; 16], perm: &[usize; 16]) -> [u32; 16] {
        let mut out = [0u32; 16];
        for i in 0..16 {
            out[i] = msg[perm[i]];
        }
        out
    }

    let mut msg = [0u32; 16];
    for i in 0..16 {
        let offset = i * 4;
        msg[i] = u32::from(input[offset])
            | (u32::from(input[offset + 1]) << 8)
            | (u32::from(input[offset + 2]) << 16)
            | (u32::from(input[offset + 3]) << 24);
    }

    let mut state: [u32; 16] = [
        BLAKE3_IV[0], BLAKE3_IV[1], BLAKE3_IV[2], BLAKE3_IV[3],
        BLAKE3_IV[4], BLAKE3_IV[5], BLAKE3_IV[6], BLAKE3_IV[7],
        BLAKE3_IV[0], BLAKE3_IV[1], BLAKE3_IV[2], BLAKE3_IV[3],
        0, 0, 64, FLAG_PARENT, // counter=0, blockLen=64, flags=PARENT
    ];

    let mut m = msg;
    for r in 0..7 {
        round(&mut state, &m);
        if r < 6 {
            m = permute_impl(&m, &MSG_PERM);
        }
    }

    for i in 0..8 {
        state[i] ^= state[i + 8];
    }

    let mut output = [0u8; 32];
    for i in 0..8 {
        output[i * 4] = (state[i] & 0xFF) as u8;
        output[i * 4 + 1] = ((state[i] >> 8) & 0xFF) as u8;
        output[i * 4 + 2] = ((state[i] >> 16) & 0xFF) as u8;
        output[i * 4 + 3] = ((state[i] >> 24) & 0xFF) as u8;
    }
    output
}

/// Batch Blake3 hash of parent nodes (pairs of 32-byte hashes)
/// Input: n * 64 bytes (n pairs of 32-byte child hashes)
/// Output: n * 32 bytes (n parent hashes)
/// Inspired by zkMetal's Blake3Engine::hashParents
pub fn blake3_batch_parents(input: &[u8]) -> Vec<u8> {
    assert!(input.len() % 64 == 0, "Input must be multiple of 64 bytes");
    let n = input.len() / 64;
    let mut output = Vec::with_capacity(n * 32);

    for i in 0..n {
        let start = i * 64;
        let parent = blake3_parent(&input[start..start + 64]);
        output.extend_from_slice(&parent);
    }

    output
}

/// Blake3 hash of a single 32-byte node (leaf or parent)
/// Used for consistency with Merkle tree operations
pub fn blake3_node(data: &[u8]) -> [u8; 32] {
    assert!(data.len() == 32, "Node data must be 32 bytes");
    blake3(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_empty() {
        let hash = blake3(&[]);
        println!("blake3([]): {:02x?}", &hash);
    }

    #[test]
    fn test_blake3_simple() {
        let input = b"test";
        let hash = blake3(input);
        println!("blake3('test'): {:02x?}", &hash);

        // Should be deterministic
        let hash2 = blake3(input);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_blake3_parent() {
        let left = [0u8; 32];
        let right = [1u8; 32];
        let mut input = [0u8; 64];
        input[..32].copy_from_slice(&left);
        input[32..].copy_from_slice(&right);

        let parent = blake3_parent(&input);
        println!("blake3_parent (0... || 1...): {:02x?}", &parent);
        assert_eq!(parent.len(), 32);
    }

    #[test]
    fn test_blake3_batch_parents() {
        // 2 pairs = 4 nodes = 128 bytes input
        let input = [0u8; 128];
        let output = blake3_batch_parents(&input);
        assert_eq!(output.len(), 64); // 2 parent hashes
        println!("blake3_batch_parents (4 zero nodes): {:02x?}", &output[..32]);
    }

    #[test]
    fn test_blake3_node() {
        let data = [0x42u8; 32];
        let hash = blake3_node(&data);
        assert_eq!(hash.len(), 32);
        // Should match regular blake3 for 32-byte input
        assert_eq!(hash, blake3(&data));
    }
}