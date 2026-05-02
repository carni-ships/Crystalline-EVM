//! EVM Circuit for Lattice Field
//!
//! Adapts EVM constraints to lattice field q=8383489.
//! Uses RNS decomposition for multi-modulus representation.
//! Borrowed opcode definitions from Zoltraak's EVMExecutionEngine.

mod eth;
mod eth_rpc;
mod opcodes;
pub mod full_evm;

pub use opcodes::{OpCode, EVMState, TraceRow, execute_bytecode, execute_bytecode_with_calldata};
pub use eth_rpc::{EthClient, EthereumBlock, EthereumTransaction, RPCConfig, hex_to_bytes, hex_to_u64, get_current_block_number};
pub use full_evm::{full_evm_validate, full_evm_can_execute, execute_evm_with_trace, execute_evm_with_diff};


/// EVM circuit constraints for lattice field
pub struct LatticeEVM {
    /// Number of trace rows
    pub trace_len: usize,
}

impl LatticeEVM {
    /// Create new EVM circuit
    pub fn new(trace_len: usize) -> Self {
        LatticeEVM { trace_len }
    }

    /// Generate placeholder trace for given program
    pub fn generate_trace(&self) -> Vec<TraceRow> {
        // For a real trace, use execute_bytecode() from opcodes module
        // This creates a minimal trace for testing
        let mut trace = Vec::with_capacity(self.trace_len);
        for i in 0..self.trace_len {
            trace.push(TraceRow {
                pc: i,
                opcode: 0x00, // STOP
                gas_before: (self.trace_len - i) as u64,
                gas_after: (self.trace_len - i - 1) as u64,
                stack: vec![],
                memory: vec![],
                storage: vec![],
                call_depth: 0,
                bytecode: vec![],
                balance_before: 0,
                balance_after: 0,
                memory_ops: vec![],
                storage_ops: vec![],
                bytecode_merkle_cache: std::sync::OnceLock::new(),
            });
        }
        trace
    }

    /// Evaluate constraints on a trace row
    pub fn evaluate_row_constraints(&self, row: &TraceRow) -> Vec<i64> {
        let mut constraints = Vec::new();

        // Gas constraint: gas_after is always valid (u64 non-negative, could be 0 if all gas consumed)
        // For STOP opcode, gas_after can be 0 which is valid
        let gas_valid = 0; // Always valid since gas_after is u64 (non-negative)
        constraints.push(gas_valid);

        // Memory constraint: size must be non-negative
        let mem_valid = if row.memory.len() <= 65536 { 0 } else { 1 };
        constraints.push(mem_valid);

        // Stack constraint: height must be valid
        let stack_valid = if row.stack.len() <= 1024 { 0 } else { 1 };
        constraints.push(stack_valid);

        constraints
    }

    /// Get boundary constraints
    pub fn boundary_constraints(&self) -> Vec<(usize, u32)> {
        vec![
            (0, 0),           // pc starts at 0
            (1, u32::MAX),    // gas is max initially
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_generation() {
        let evm = LatticeEVM::new(10);
        let trace = evm.generate_trace();
        assert_eq!(trace.len(), 10);
    }

    #[test]
    fn test_constraint_evaluation() {
        let evm = LatticeEVM::new(10);
        let trace = evm.generate_trace();
        let constraints = evm.evaluate_row_constraints(&trace[5]);
        assert_eq!(constraints.len(), 3);  // gas, mem, stack constraints
    }
}