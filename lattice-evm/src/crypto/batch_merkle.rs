//! Batch Merkle Tree Builder
//!
//! Inspired by zkMetal's pattern, this module provides a complete binary Merkle tree
//! builder that constructs all levels in a single efficient pass.

use crate::crypto::Poseidon2;

/// Complete Merkle tree with all nodes accessible in O(1)
///
/// Stores all nodes in breadth-first order within a single flat vector.
/// Level offsets are precomputed for efficient random access.
///
/// # Structure
/// - Level 0: leaves (n nodes)
/// - Level 1: parents (ceil(n/2) nodes)
/// - ...
/// - Last level: root (1 node)
#[derive(Debug, Clone)]
pub struct BatchMerkleTree {
    /// All nodes in breadth-first order, starting from leaves
    /// Level 0: leaves (n nodes)
    /// Level 1: parents (ceil(n/2) nodes)
    /// ...
    /// Last level: root (1 node)
    pub nodes: Vec<u32>,
    /// Number of leaves
    pub leaf_count: usize,
    /// Level offsets for O(1) access to any level
    /// level_offsets[l] = starting index of level l in nodes Vec
    level_offsets: Vec<usize>,
    /// Number of levels (height)
    pub height: usize,
}

impl BatchMerkleTree {
    /// Build a complete Merkle tree from leaves in a single efficient pass.
    ///
    /// This follows zkMetal's pattern: compute all parent hashes in parallel since
    /// each pair is independent, then compute the next level, etc.
    ///
    /// # Arguments
    /// * `leaves` - Slice of u32 field elements representing the leaf values
    ///
    /// # Returns
    /// A `BatchMerkleTree` with all nodes accessible via `get_node(level, index)`
    ///
    /// # Example
    /// ```
    /// use lattice_evm::crypto::BatchMerkleTree;
    /// let leaves = vec![1u32, 2, 3, 4];
    /// let tree = BatchMerkleTree::build(&leaves);
    /// let root = tree.root();
    /// assert!(root != 0);
    /// ```
    pub fn build(leaves: &[u32]) -> Self {
        if leaves.is_empty() {
            return BatchMerkleTree {
                nodes: vec![0],
                leaf_count: 0,
                level_offsets: vec![0],
                height: 1,
            };
        }

        let n = leaves.len();
        let mut all_nodes: Vec<u32> = Vec::with_capacity(n * 2); // Rough estimate
        let mut level_offsets: Vec<usize> = Vec::new();

        // Level 0: leaves
        level_offsets.push(all_nodes.len());
        all_nodes.extend_from_slice(leaves);

        // Build upward level by level
        let mut current_level = leaves.to_vec();

        while current_level.len() > 1 {
            level_offsets.push(all_nodes.len());

            let mut next_level = Vec::new();

            // Hash pairs in parallel (each pair is independent)
            // For odd last element, pass through unchanged (like original MerkleTree)
            for chunk in current_level.chunks(2) {
                if chunk.len() == 2 {
                    next_level.push(Poseidon2::hash_pair(chunk[0], chunk[1]));
                } else {
                    // Odd element - pass through unchanged (NOT hashed with itself)
                    next_level.push(chunk[0]);
                }
            }

            all_nodes.extend_from_slice(&next_level);
            current_level = next_level;
        }

        let height = level_offsets.len();

        BatchMerkleTree {
            nodes: all_nodes,
            leaf_count: n,
            level_offsets,
            height,
        }
    }

    /// Get the root hash of the Merkle tree
    pub fn root(&self) -> u32 {
        self.nodes.last().copied().unwrap_or(0)
    }

    /// Get node at specific level and index
    ///
    /// # Arguments
    /// * `level` - Level index (0 = leaves)
    /// * `index` - Node index within the level
    ///
    /// # Returns
    /// The u32 value of the node, or None if out of bounds
    pub fn get_node(&self, level: usize, index: usize) -> Option<u32> {
        if level >= self.height {
            return None;
        }
        let offset = self.level_offsets[level];
        let len = self.level_length(level);
        if index >= len {
            return None;
        }
        self.nodes.get(offset + index).copied()
    }

    /// Get the length (number of nodes) at a given level
    ///
    /// # Arguments
    /// * `level` - Level index (0 = leaves)
    ///
    /// # Returns
    /// Number of nodes at that level
    pub fn level_length(&self, level: usize) -> usize {
        if level >= self.height {
            return 0;
        }
        if level == 0 {
            return self.leaf_count;
        }
        // ceil(leaf_count / 2^level)
        (self.leaf_count + (1 << level) - 1) >> level
    }

    /// Get all nodes at a specific level
    ///
    /// # Arguments
    /// * `level` - Level index (0 = leaves)
    ///
    /// # Returns
    /// Slice of nodes at that level
    pub fn get_level(&self, level: usize) -> Option<&[u32]> {
        if level >= self.height {
            return None;
        }
        let offset = self.level_offsets[level];
        let len = self.level_length(level);
        Some(&self.nodes[offset..offset + len])
    }

    /// Get authentication path for a leaf index
    ///
    /// Returns sibling values needed to compute the root from leaf[index].
    /// Each tuple is (level, sibling_value).
    ///
    /// # Arguments
    /// * `leaf_index` - Index of the leaf (0-based)
    ///
    /// # Returns
    /// Vector of (level, sibling) tuples from leaf to root
    pub fn auth_path(&self, leaf_index: usize) -> Vec<(usize, u32)> {
        let mut path = Vec::new();
        let mut idx = leaf_index;

        for level in 0..self.height - 1 {
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            let sibling = if sibling_idx < self.level_length(level) {
                self.get_node(level, sibling_idx).unwrap_or(0)
            } else {
                0
            };
            path.push((level, sibling));
            idx /= 2;
        }

        path
    }

    /// Verify an authentication path from a leaf to the root
    ///
    /// # Arguments
    /// * `leaf_index` - Index of the leaf
    /// * `leaf_value` - Value of the leaf
    ///
    /// # Returns
    /// true if the path correctly computes to the root
    pub fn verify_path(&self, leaf_index: usize, leaf_value: u32) -> bool {
        let mut current = leaf_value;
        let mut idx = leaf_index;

        for level in 0..self.height - 1 {
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            let sibling = if sibling_idx < self.level_length(level) {
                self.get_node(level, sibling_idx).unwrap_or(0)
            } else {
                current // When sibling doesn't exist, hash with self
            };

            // Determine order: even idx means leaf is left child, odd means leaf is right child
            let (left, right) = if idx % 2 == 0 {
                (current, sibling) // leaf is left
            } else {
                (sibling, current) // leaf is right
            };

            current = Poseidon2::hash_pair(left, right);
            idx /= 2;
        }

        current == self.root()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{MerkleTree, MultilinearPolynomial};

    #[test]
    fn test_batch_merkle_empty() {
        let tree = BatchMerkleTree::build(&[]);
        assert_eq!(tree.root(), 0);
        assert_eq!(tree.height, 1);
        assert_eq!(tree.leaf_count, 0);
    }

    #[test]
    fn test_batch_merkle_single_leaf() {
        let leaves = vec![42u32];
        let tree = BatchMerkleTree::build(&leaves);
        assert_eq!(tree.height, 1);
        assert_eq!(tree.leaf_count, 1);
        assert_eq!(tree.root(), 42); // Single leaf is the root
    }

    #[test]
    fn test_batch_merkle_two_leaves() {
        let leaves = vec![1u32, 2];
        let tree = BatchMerkleTree::build(&leaves);
        assert_eq!(tree.height, 2);
        assert_eq!(tree.leaf_count, 2);

        // Level 0: [1, 2]
        assert_eq!(tree.get_level(0).unwrap(), &[1, 2]);

        // Level 1: [hash(1,2)]
        let expected_root = Poseidon2::hash_pair(1, 2);
        assert_eq!(tree.root(), expected_root);
    }

    #[test]
    fn test_batch_merkle_four_leaves() {
        let leaves = vec![1u32, 2, 3, 4];
        let tree = BatchMerkleTree::build(&leaves);
        assert_eq!(tree.height, 3);
        assert_eq!(tree.leaf_count, 4);

        // Level 0: leaves
        assert_eq!(tree.get_level(0).unwrap(), &[1, 2, 3, 4]);

        // Level 1: [hash(1,2), hash(3,4)]
        let h12 = Poseidon2::hash_pair(1, 2);
        let h34 = Poseidon2::hash_pair(3, 4);
        assert_eq!(tree.get_level(1).unwrap(), &[h12, h34]);

        // Level 2: root = hash(h12, h34)
        let expected_root = Poseidon2::hash_pair(h12, h34);
        assert_eq!(tree.root(), expected_root);
    }

    #[test]
    fn test_batch_merkle_odd_leaves() {
        // 5 leaves - odd elements pass through until paired
        let leaves = vec![1u32, 2, 3, 4, 5];
        let tree = BatchMerkleTree::build(&leaves);

        // Level 0: 5 leaves
        assert_eq!(tree.level_length(0), 5);
        assert_eq!(tree.get_level(0).unwrap(), &[1, 2, 3, 4, 5]);

        // Level 1: ceil(5/2) = 3 nodes: [hash(1,2), hash(3,4), 5]
        let h12 = Poseidon2::hash_pair(1, 2);
        let h34 = Poseidon2::hash_pair(3, 4);
        assert_eq!(tree.get_level(1).unwrap(), &[h12, h34, 5]);

        // Level 2: ceil(3/2) = 2 nodes: [hash(h12, h34), 5]
        let h1234 = Poseidon2::hash_pair(h12, h34);
        assert_eq!(tree.get_level(2).unwrap(), &[h1234, 5]);

        // Level 3: 1 node (root) = hash(h1234, 5)
        let expected_root = Poseidon2::hash_pair(h1234, 5);
        assert_eq!(tree.root(), expected_root);
    }

    #[test]
    fn test_root_matches_original_merkle_tree() {
        // Test that BatchMerkleTree root matches MerkleTree::build root
        let test_cases = vec![
            vec![1u32, 2, 3, 4],
            vec![1u32, 2],
            vec![1u32],
            vec![1u32, 2, 3, 4, 5, 6, 7, 8],
        ];

        for leaves in test_cases {
            let batch_tree = BatchMerkleTree::build(&leaves);

            // Create MultilinearPolynomial for original MerkleTree
            // Use log2 of actual leaf count since this is what BatchMerkleTree uses
            let num_vars = (leaves.len() as f64).log2() as usize;
            let poly = MultilinearPolynomial::from_evals(num_vars, leaves.clone()).unwrap();

            let original_tree = MerkleTree::build(&poly);

            assert_eq!(
                batch_tree.root(),
                original_tree.root(),
                "Root mismatch for leaves {:?}",
                leaves
            );
        }
    }

    #[test]
    fn test_auth_path_single_leaf() {
        let tree = BatchMerkleTree::build(&[42u32]);
        let path = tree.auth_path(0);
        assert!(path.is_empty()); // No siblings for single leaf
        assert!(tree.verify_path(0, 42));
    }

    #[test]
    fn test_auth_path_four_leaves() {
        let leaves = vec![1u32, 2, 3, 4];
        let tree = BatchMerkleTree::build(&leaves);

        // Leaf 0: path should be [(0, 2), (1, hash(3,4))]
        let path0 = tree.auth_path(0);
        assert_eq!(path0.len(), 2);
        assert_eq!(path0[0], (0, 2)); // sibling at level 0
        // path0[1] is sibling at level 1
        assert!(tree.verify_path(0, 1));

        // Leaf 1: path should be [(0, 1), (1, hash(3,4))]
        let path1 = tree.auth_path(1);
        assert_eq!(path1.len(), 2);
        assert_eq!(path1[0], (0, 1)); // sibling at level 0
        assert!(tree.verify_path(1, 2));

        // Leaf 2: path should be [(0, 4), (1, hash(1,2))]
        let path2 = tree.auth_path(2);
        assert_eq!(path2.len(), 2);
        assert_eq!(path2[0], (0, 4)); // sibling at level 0
        assert!(tree.verify_path(2, 3));

        // Leaf 3: path should be [(0, 3), (1, hash(1,2))]
        let path3 = tree.auth_path(3);
        assert_eq!(path3.len(), 2);
        assert_eq!(path3[0], (0, 3)); // sibling at level 0
        assert!(tree.verify_path(3, 4));
    }

    #[test]
    fn test_verify_path_wrong_leaf() {
        let leaves = vec![1u32, 2, 3, 4];
        let tree = BatchMerkleTree::build(&leaves);

        // Verify with wrong leaf value should fail
        assert!(!tree.verify_path(0, 999)); // wrong leaf value
    }

    #[test]
    fn test_get_node_bounds() {
        let leaves = vec![1u32, 2, 3, 4];
        let tree = BatchMerkleTree::build(&leaves);

        // Valid access
        assert_eq!(tree.get_node(0, 0), Some(1));
        assert_eq!(tree.get_node(0, 3), Some(4));
        assert_eq!(tree.get_node(2, 0), Some(tree.root()));

        // Out of bounds
        assert_eq!(tree.get_node(0, 4), None); // leaf index out of bounds
        assert_eq!(tree.get_node(3, 0), None); // level out of bounds
    }

    #[test]
    fn test_level_offsets() {
        // 4 leaves: offsets should be [0, 4, 6]
        // Height = 3 (levels 0, 1, 2)
        let leaves = vec![1u32, 2, 3, 4];
        let tree = BatchMerkleTree::build(&leaves);

        assert_eq!(tree.height, 3);
        assert_eq!(tree.level_offsets.len(), 3);

        assert_eq!(tree.level_offsets[0], 0);  // leaves start at 0
        assert_eq!(tree.level_offsets[1], 4);  // parents start at 4
        assert_eq!(tree.level_offsets[2], 6);  // root starts at 6

        // Verify level lengths
        assert_eq!(tree.level_length(0), 4);  // 4 leaves
        assert_eq!(tree.level_length(1), 2);  // 2 parents
        assert_eq!(tree.level_length(2), 1);  // 1 root
    }

    #[test]
    fn test_height_calculation() {
        // Height = log2(n) rounded up, plus 1 for leaves
        assert_eq!(BatchMerkleTree::build(&[1]).height, 1);   // 1 leaf
        assert_eq!(BatchMerkleTree::build(&[1, 2]).height, 2);  // 2 leaves
        assert_eq!(BatchMerkleTree::build(&[1, 2, 3]).height, 3);  // 3 leaves
        assert_eq!(BatchMerkleTree::build(&[1, 2, 3, 4]).height, 3);  // 4 leaves
        assert_eq!(BatchMerkleTree::build(&[1, 2, 3, 4, 5]).height, 4);  // 5 leaves
        assert_eq!(BatchMerkleTree::build(&[1, 2, 3, 4, 5, 6, 7, 8]).height, 4);  // 8 leaves
    }

    #[test]
    fn test_large_tree() {
        // Test with 64 leaves (full binary tree of height 7)
        let leaves: Vec<u32> = (0..64).map(|i| (i + 1) as u32).collect();
        let tree = BatchMerkleTree::build(&leaves);

        assert_eq!(tree.height, 7);
        assert_eq!(tree.leaf_count, 64);

        // Verify we can access all levels
        for level in 0..tree.height {
            let len = tree.level_length(level);
            assert!(len >= 1);
            for idx in 0..len {
                assert!(tree.get_node(level, idx).is_some());
            }
        }

        // Verify root is non-zero for non-trivial input
        assert!(tree.root() != 0);
    }
}