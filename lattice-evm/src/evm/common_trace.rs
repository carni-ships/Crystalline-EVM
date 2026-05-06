//! Common EVM Trace Format for Cross-Prover Benchmarks
//!
//! This module defines a canonical trace format that can be produced by
//! any EVM implementation (revm, SP1, RISC Zero) and used as input
//! for any proving backend.
//!
//! The format captures essential EVM state for each executed opcode:
//! - Program counter and opcode
//! - Gas state (before/after)
//! - Stack contents (top values)
//! - Memory operations (for verification)
//! - Storage operations (for verification)
//!
//! # Example
//!
//! ```ignore
//! // Execute EVM bytecode with any implementation
//! let trace = execute_evm_bytecode(bytecode, env);
//!
//! // Convert to common format
//! let common_trace: Vec<CommonTraceRow> = trace.into_iter()
//!     .map(|row| CommonTraceRow::from_revm_row(row))
//!     .collect();
//!
//! // Serialize and use with any prover
//! let bytes = serde_json::to_vec(&common_trace).unwrap();
//! ```

use serde::{Deserialize, Serialize};
use revm::primitives::U256;
use crate::evm::full_evm::RevmTraceRow;

/// Q constant for field element conversion (lattice field modulus)
pub const Q: u64 = 8383489;

/// Common trace row format - canonical representation of EVM execution state
/// This format is designed to be:
/// - Serializable (for passing between systems)
/// - Minimal (enough for verification, not full state)
/// - Compatible (works with any EVM implementation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommonTraceRow {
    /// Program counter
    pub pc: u32,
    /// Opcode being executed (0x00-0xff)
    pub opcode: u8,
    /// Gas remaining BEFORE this opcode
    pub gas_before: u64,
    /// Gas remaining AFTER this opcode
    pub gas_after: u64,
    /// Stack top values (up to 16 items for typical operations)
    /// Stored as field elements (mod Q)
    pub stack_top: Vec<u32>,
    /// Memory operations: (offset, value) pairs as field elements
    pub memory_ops: Vec<(u32, u32)>,
    /// Storage operations: (key, value) pairs as field elements
    pub storage_ops: Vec<(u32, u32)>,
    /// Call depth
    pub call_depth: u8,
}

impl CommonTraceRow {
    /// Create from revm's RevmTraceRow
    pub fn from_revm(trace: &RevmTraceRow) -> Self {
        let stack_top: Vec<u32> = trace.stack.iter()
            .take(16) // Keep top 16 stack items
            .map(|u256| u256_to_field(u256))
            .collect();

        CommonTraceRow {
            pc: trace.pc as u32,
            opcode: trace.opcode,
            gas_before: trace.gas_before,
            gas_after: trace.gas_after,
            stack_top,
            memory_ops: vec![], // revm Inspector doesn't track per-op memory in minimal trace
            storage_ops: vec![], // revm Inspector doesn't track per-op storage in minimal trace
            call_depth: 0, // Would need to track in inspector
        }
    }

    /// Convert to field elements for lattice prover (256-element chunks)
    pub fn to_field_elements(&self) -> Vec<u32> {
        let mut fields = Vec::with_capacity(256);

        // Fixed-size fields
        fields.push(self.pc);
        fields.push(self.opcode as u32);
        fields.push(self.gas_before as u32);
        fields.push(self.gas_after as u32);
        fields.push(self.call_depth as u32);

        // Stack top values (pad to 16)
        for i in 0..16 {
            fields.push(if i < self.stack_top.len() { self.stack_top[i] } else { 0 });
        }

        // Memory ops (up to 4)
        for i in 0..4 {
            if i < self.memory_ops.len() {
                fields.push(self.memory_ops[i].0);
                fields.push(self.memory_ops[i].1);
            } else {
                fields.push(0);
                fields.push(0);
            }
        }

        // Storage ops (up to 4)
        for i in 0..4 {
            if i < self.storage_ops.len() {
                fields.push(self.storage_ops[i].0);
                fields.push(self.storage_ops[i].1);
            } else {
                fields.push(0);
                fields.push(0);
            }
        }

        // Pad to 256 elements
        while fields.len() < 256 {
            fields.push(0);
        }

        fields.truncate(256);
        fields
    }

    /// Compact conversion: ~9 elements per row, packs ~28 rows per 256-element chunk
    /// Use this for better efficiency when not needing the full 256-element format
    pub fn to_field_elements_compact(&self) -> Vec<u32> {
        let mut fields = Vec::with_capacity(9);

        // PC (mod Q)
        fields.push(self.pc % 8383489);

        // Opcode
        fields.push(self.opcode as u32);

        // Gas before/after
        fields.push((self.gas_before % 8383489) as u32);
        fields.push((self.gas_after % 8383489) as u32);

        // Stack: top 4 items as field elements
        let stack_len = self.stack_top.len().min(4);
        fields.push(stack_len as u32);

        for i in 0..4 {
            if i < stack_len {
                fields.push(self.stack_top[i]);
            } else {
                fields.push(0);
            }
        }

        fields
    }

    /// Get total field elements needed for this trace
    pub fn field_elements_size(&self) -> usize {
        256 // Always 256 per row
    }
}

/// Convert U256 to field element (mod Q)
fn u256_to_field(u256: &U256) -> u32 {
    // Take bottom 32 bits of U256 and reduce mod Q
    // U256 is represented as 4 x 64-bit limbs in little-endian
    // We just need the bottom 32 bits, which is limbs[0] truncated to u32
    let bottom = u256.as_limbs()[0];
    (bottom % Q) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_elements_conversion() {
        let row = CommonTraceRow {
            pc: 10,
            opcode: 0x01, // ADD
            gas_before: 100,
            gas_after: 97,
            stack_top: vec![10, 20],
            memory_ops: vec![],
            storage_ops: vec![],
            call_depth: 1,
        };

        let fields = row.to_field_elements();
        assert_eq!(fields.len(), 256);
        assert_eq!(fields[0], 10); // pc
        assert_eq!(fields[1], 1);  // opcode
        assert_eq!(fields[2], 100); // gas_before
    }
}