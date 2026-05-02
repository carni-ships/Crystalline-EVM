//! Sparse Merkle Tree for Lattice Field Storage
//!
//! Implements a SNARK-friendly Sparse Merkle Tree using Poseidon2 hash.
//! This provides proper state proofs for ZK verification.

use crate::crypto::Poseidon2;
use std::collections::HashMap;

/// Empty node hash for SMT
const EMPTY_HASH: u32 = 0;

/// Sparse Merkle Tree for storage
/// Uses binary tree structure with Poseidon2 hashing
pub struct SparseMerkleTree {
    /// Depth of the tree (bits per slot)
    depth: usize,
    /// Leaf nodes: maps slot -> value_hash
    leaves: HashMap<u32, u32>,
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl SparseMerkleTree {
    /// Create new empty SMT
    pub fn new() -> Self {
        SparseMerkleTree {
            depth: 256, // 256 bits per slot
            leaves: HashMap::new(),
        }
    }

    /// Create SMT with custom depth
    pub fn with_depth(depth: usize) -> Self {
        SparseMerkleTree {
            depth,
            leaves: HashMap::new(),
        }
    }

    /// Hash of empty subtree at given depth
    fn empty_hash_at_depth(&self, depth: usize) -> u32 {
        if depth == 0 {
            return EMPTY_HASH;
        }
        let mut h = EMPTY_HASH;
        for _ in 0..depth {
            h = Poseidon2::hash_pair(h, h);
        }
        h
    }

    /// Insert a slot-value pair into the tree
    pub fn insert(&mut self, slot: u32, value: u32) {
        if value == 0 {
            self.leaves.remove(&slot);
        } else {
            let value_hash = Poseidon2::hash_pair(slot, value);
            self.leaves.insert(slot, value_hash);
        }
    }

    /// Get the root hash of the tree
    pub fn root(&self) -> u32 {
        if self.leaves.is_empty() {
            return self.empty_hash_at_depth(self.depth);
        }

        // Build tree bottom-up using binary tree structure
        // Each level halves the number of nodes
        let mut current: HashMap<u32, u32> = self.leaves.clone();
        let mut level = 0;

        while level < self.depth {
            let mut next: HashMap<u32, u32> = HashMap::new();

            // Iterate through all slots at this level
            let slots: Vec<u32> = current.keys().copied().collect();
            for &slot in &slots {
                // Compute sibling position
                let sibling = slot ^ 1;

                // Get or compute hash for current slot
                let current_hash = current[&slot];

                // Get or compute hash for sibling
                let sibling_hash = current.get(&sibling).copied()
                    .unwrap_or_else(|| self.empty_hash_at_depth(level));

                // Parent is at half the slot index
                let parent = slot >> 1;

                // Hash this pair (order matters for Poseidon2)
                let (left, right) = if slot & 1 == 0 {
                    (current_hash, sibling_hash)
                } else {
                    (sibling_hash, current_hash)
                };

                let parent_hash = Poseidon2::hash_pair(left, right);

                // Insert parent if not already present
                next.entry(parent).or_insert(parent_hash);
            }

            current = next;
            level += 1;
        }

        current.get(&0).copied().unwrap_or(self.empty_hash_at_depth(self.depth))
    }

    /// Generate a Merkle proof for a slot
    pub fn proof(&self, slot: u32) -> Option<SMTProof> {
        let value_hash = self.leaves.get(&slot).copied();

        let mut proof_hashes = Vec::with_capacity(self.depth);
        let mut current_slot = slot;
        let mut level = 0;

        // Walk up the tree collecting sibling hashes
        while level < self.depth {
            let sibling_slot = current_slot ^ 1;

            // Get sibling hash from current leaves or compute empty
            let sibling_hash = self.leaves.get(&sibling_slot).copied()
                .unwrap_or_else(|| self.empty_hash_at_depth(level));

            proof_hashes.push(sibling_hash);

            current_slot >>= 1;
            level += 1;
        }

        Some(SMTProof {
            slot,
            value_hash,
            proof_hashes,
            root: self.root(),
        })
    }

    /// Verify a Merkle proof
    pub fn verify_proof(proof: &SMTProof) -> bool {
        let mut current_hash = proof.value_hash.unwrap_or(EMPTY_HASH);
        let mut slot = proof.slot;

        for (level, &sibling_hash) in proof.proof_hashes.iter().enumerate() {
            current_hash = if slot & 1 == 0 {
                Poseidon2::hash_pair(current_hash, sibling_hash)
            } else {
                Poseidon2::hash_pair(sibling_hash, current_hash)
            };
            slot >>= 1;
        }

        current_hash == proof.root
    }

    /// Apply a state diff to create a new SMT
    pub fn apply_diff(&self, changes: &[(u32, u32)]) -> Self {
        let mut new_tree = SparseMerkleTree {
            depth: self.depth,
            leaves: self.leaves.clone(),
        };
        for &(slot, value) in changes {
            new_tree.insert(slot, value);
        }
        new_tree
    }

    /// Clone the SMT
    pub fn clone(&self) -> Self {
        SparseMerkleTree {
            depth: self.depth,
            leaves: self.leaves.clone(),
        }
    }
}

/// Merkle proof for a storage slot
#[derive(Debug, Clone)]
pub struct SMTProof {
    /// The slot being proven
    pub slot: u32,
    /// Hash of the value at this slot (None if slot is empty)
    pub value_hash: Option<u32>,
    /// Sibling hashes at each level (bottom to top)
    pub proof_hashes: Vec<u32>,
    /// Root hash being proven against
    pub root: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_tree_root() {
        let tree = SparseMerkleTree::new();
        let root = tree.root();
        println!("Empty tree root: {}", root);
        // Root should be deterministic
        assert_eq!(root, tree.root());
    }

    #[test]
    fn test_single_insert() {
        let mut tree = SparseMerkleTree::new();
        tree.insert(0, 42);

        let root = tree.root();
        println!("Tree with slot=0, value=42: root={}", root);
        assert_ne!(root, 0);
    }

    #[test]
    fn test_proof_for_existing_slot() {
        let mut tree = SparseMerkleTree::new();
        tree.insert(0, 42);

        let root = tree.root();
        let proof = tree.proof(0).expect("Should have proof");
        println!("Proof for slot 0: root={}", root);
        assert_eq!(proof.root, root);
        assert!(SparseMerkleTree::verify_proof(&proof));
    }

    #[test]
    fn test_proof_for_empty_slot() {
        let mut tree = SparseMerkleTree::new();
        tree.insert(0, 42);

        let root = tree.root();
        let proof = tree.proof(1).expect("Should have proof for empty slot");
        println!("Proof for empty slot 1: root={}", root);
        assert_eq!(proof.root, root);
        assert!(SparseMerkleTree::verify_proof(&proof));
    }

    #[test]
    fn test_apply_diff() {
        let mut tree = SparseMerkleTree::new();
        tree.insert(0, 42);

        let root1 = tree.root();
        println!("Root before diff: {}", root1);

        // Remove slot 0, add slot 1
        let new_tree = tree.apply_diff(&[(0, 0), (1, 99)]);
        let root2 = new_tree.root();
        println!("Root after diff: {}", root2);

        assert_ne!(root1, root2, "Roots should differ after state change");
    }

    #[test]
    fn test_two_sibling_slots() {
        let mut tree = SparseMerkleTree::new();
        // Insert two sibling slots that share a parent
        tree.insert(0, 1);
        tree.insert(1, 2);

        let root = tree.root();
        println!("Root with siblings (0,1): {}", root);
        assert_ne!(root, 0);

        // Both proofs should verify
        let proof0 = tree.proof(0).expect("Should have proof for slot 0");
        let proof1 = tree.proof(1).expect("Should have proof for slot 1");

        assert!(SparseMerkleTree::verify_proof(&proof0));
        assert!(SparseMerkleTree::verify_proof(&proof1));
    }
}