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
    /// Cached root hash (invalidated on mutations)
    cached_root: Option<u32>,
    /// Dirty node slots that need rehashing (level -> slot)
    dirty: HashMap<usize, Vec<u32>>,
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
            cached_root: None,
            dirty: HashMap::new(),
        }
    }

    /// Create SMT with custom depth
    pub fn with_depth(depth: usize) -> Self {
        SparseMerkleTree {
            depth,
            leaves: HashMap::new(),
            cached_root: None,
            dirty: HashMap::new(),
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
        // Invalidate cache and mark path as dirty
        self.cached_root = None;
        self.dirty.clear();
        // Mark all ancestor slots dirty
        let mut current = slot;
        for level in 0..self.depth {
            self.dirty.entry(level).or_insert_with(Vec::new).push(current);
            current >>= 1;
        }
    }

    /// Get the root hash of the tree
    pub fn root(&self) -> u32 {
        if self.leaves.is_empty() {
            return self.empty_hash_at_depth(self.depth);
        }
        self.compute_root()
    }

    /// Compute root from current leaves (full rebuild, no caching issues)
    ///
    /// SECURITY: Uses full rebuild to avoid dirty-tracking bugs that cause
    /// incorrect proof verification. Performance is acceptable since this is
    /// only called when cached_root is None (after insertions).
    fn compute_root(&self) -> u32 {
        if self.leaves.is_empty() {
            return self.empty_hash_at_depth(self.depth);
        }

        let mut current: HashMap<u32, u32> = self.leaves.clone();
        let mut level = 0;

        while level < self.depth {
            let mut next: HashMap<u32, u32> = HashMap::new();

            // Collect all slots at this level
            let mut slots: Vec<u32> = current.keys().copied().collect();
            slots.sort_unstable();  // Ensure deterministic order

            // Group slots by parent
            let mut slots_by_parent: HashMap<u32, Vec<u32>> = HashMap::new();
            for &slot in &slots {
                let parent = slot >> 1;
                slots_by_parent.entry(parent).or_insert_with(Vec::new).push(slot);
            }

            // Process each parent - compute hash from its children
            for (&parent, children) in &slots_by_parent {
                // Sort children to ensure [even, odd] order
                let mut sorted_children = children.clone();
                sorted_children.sort_unstable();

                // Check which children exist
                let even_slot = parent << 1;
                let odd_slot = even_slot | 1;
                let has_even = sorted_children.contains(&even_slot);
                let has_odd = sorted_children.contains(&odd_slot);

                let (left_hash, right_hash) = if has_even && has_odd {
                    // Both children exist - hash them together
                    (current[&even_slot], current[&odd_slot])
                } else if has_even {
                    // Only even child - hash with empty
                    let empty_hash = self.empty_hash_at_depth(level);
                    (current[&even_slot], empty_hash)
                } else if has_odd {
                    // Only odd child - hash with empty
                    let empty_hash = self.empty_hash_at_depth(level);
                    (empty_hash, current[&odd_slot])
                } else {
                    continue;
                };

                let parent_hash = Poseidon2::hash_pair(left_hash, right_hash);
                next.insert(parent, parent_hash);
            }

            current = next;
            level += 1;
        }

        current.get(&0).copied().unwrap_or(self.empty_hash_at_depth(self.depth))
    }

    /// Generate a Merkle proof for a slot
    ///
    /// SECURITY FIX: Now correctly computes sibling hashes at each level using
    /// precomputed level data, matching how compute_root() builds the tree.
    /// Previously used raw leaf hashes for all levels, causing verification
    /// to fail when internal nodes had different hashes than leaves.
    pub fn proof(&self, slot: u32) -> Option<SMTProof> {
        if self.leaves.is_empty() {
            return Some(SMTProof {
                slot,
                value_hash: None,
                proof_hashes: vec![EMPTY_HASH; self.depth],
                root: self.empty_hash_at_depth(self.depth),
            });
        }

        // Precompute all level hashes (like compute_root does)
        // levels[level] = HashMap<slot, hash> at that level
        let mut levels: Vec<HashMap<u32, u32>> = Vec::with_capacity(self.depth);
        levels.push(self.leaves.clone());  // Level 0 = leaves

        for level in 0..self.depth {
            let current = &levels[level];
            if current.is_empty() {
                // No more nodes, all remaining levels are empty
                for _ in level..self.depth {
                    levels.push(HashMap::new());
                }
                break;
            }

            let mut next: HashMap<u32, u32> = HashMap::new();

            // Group slots by parent
            let mut slots_by_parent: HashMap<u32, Vec<u32>> = HashMap::new();
            for &slot in current.keys() {
                let parent = slot >> 1;
                slots_by_parent.entry(parent).or_insert_with(Vec::new).push(slot);
            }

            // Compute parent hashes
            for (&parent, children) in &slots_by_parent {
                let mut sorted_children = children.clone();
                sorted_children.sort_unstable();

                let even_slot = parent << 1;
                let odd_slot = even_slot | 1;
                let has_even = sorted_children.contains(&even_slot);
                let has_odd = sorted_children.contains(&odd_slot);

                let (left_hash, right_hash) = if has_even && has_odd {
                    (current[&even_slot], current[&odd_slot])
                } else if has_even {
                    let empty_hash = self.empty_hash_at_depth(level);
                    (current[&even_slot], empty_hash)
                } else if has_odd {
                    let empty_hash = self.empty_hash_at_depth(level);
                    (empty_hash, current[&odd_slot])
                } else {
                    continue;
                };

                let parent_hash = Poseidon2::hash_pair(left_hash, right_hash);
                next.insert(parent, parent_hash);
            }

            levels.push(next);
        }

        // Build proof using precomputed levels
        let value_hash = self.leaves.get(&slot).copied();
        let mut proof_hashes = Vec::with_capacity(self.depth);
        let mut current_slot = slot;

        for level in 0..self.depth {
            // Sibling slot at this level
            let sibling_slot = current_slot ^ 1;

            // Get sibling hash from the computed level, not raw leaves
            // levels[level] has the hashes at that level (level 0 = leaves)
            // At level 0, sibling hash comes from leaves directly if sibling exists
            // At higher levels, sibling hash comes from internal nodes computed at that level
            let sibling_hash = if level < levels.len() {
                let level_hashes = &levels[level];
                // If sibling exists at this level, use its computed hash
                // Otherwise use empty hash for this level
                level_hashes.get(&sibling_slot).copied()
                    .unwrap_or_else(|| self.empty_hash_at_depth(level))
            } else {
                self.empty_hash_at_depth(level)
            };

            proof_hashes.push(sibling_hash);
            current_slot >>= 1;
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

        for (_level, &sibling_hash) in proof.proof_hashes.iter().enumerate() {
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
            cached_root: None,
            dirty: HashMap::new(),
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
            cached_root: self.cached_root,
            dirty: HashMap::new(),
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