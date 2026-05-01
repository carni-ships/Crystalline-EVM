//! Full EVM Bridge using revm
//!
//! Provides bytecode execution and step-by-step trace generation using revm.
//! StateDiff mode uses revm for fast execution.
//! Full/Minimal/Medium modes use revm's Inspector for tracing.

use revm::{
    db::CacheDB,
    primitives::{AccountInfo, Bytecode, Bytes, SpecId, TransactTo, U256, ExecutionResult, Output, Address, address},
    EVM, Inspector,
};
use revm::interpreter::{Interpreter, CallInputs, CreateInputs, InstructionResult, Gas};

/// State diff from EVM execution - extracted for StateDiff proving
#[derive(Debug, Clone, Default)]
pub struct StateDiff {
    /// Storage changes: (slot, old_value, new_value)
    pub storage_changes: Vec<(u32, u32, u32)>,
    /// Gas used
    pub gas_used: u64,
    /// Whether execution succeeded
    pub success: bool,
}

/// Trace row data extracted from revm Inspector
#[derive(Debug, Clone)]
pub struct RevmTraceRow {
    pub pc: usize,
    pub opcode: u8,
    pub gas_before: u64,
    pub gas_after: u64,
    pub stack: Vec<u32>,
    pub memory: Vec<u8>,
    pub storage: Vec<(u32, u32)>,
}

/// Precompile call record for verification
#[derive(Debug, Clone)]
pub struct PrecompileCall {
    pub address: Address,
    pub input: Vec<u8>,
    pub output: Vec<u8>,
    pub gas_used: u64,
    pub success: bool,
}

/// Inspector that captures step-by-step trace data
pub struct TraceInspector {
    pub trace: Vec<RevmTraceRow>,
    pub memory_ops: Vec<(u32, u32)>,
    pub storage_ops: Vec<(u32, u32)>,
    pub precompile_calls: Vec<PrecompileCall>,
    current_call_depth: usize,
    gas_before_op: u64,
    precompile_gas_before: u64,
}

impl Default for TraceInspector {
    fn default() -> Self {
        TraceInspector {
            trace: Vec::new(),
            memory_ops: Vec::new(),
            storage_ops: Vec::new(),
            precompile_calls: Vec::new(),
            current_call_depth: 0,
            gas_before_op: 0,
            precompile_gas_before: 0,
        }
    }
}

impl TraceInspector {
    /// Create a new trace inspector
    pub fn new() -> Self {
        Self::default()
    }

    /// Get collected trace
    pub fn into_trace(self) -> Vec<RevmTraceRow> {
        self.trace
    }

    /// Convert RevmTraceRow to our TraceRow format
    pub fn to_trace_rows(&self, bytecode: &[u8]) -> Vec<crate::evm::TraceRow> {
        self.trace.iter().map(|row| {
            crate::evm::TraceRow {
                pc: row.pc,
                opcode: row.opcode,
                gas_before: row.gas_before,
                gas_after: row.gas_after,
                stack: row.stack.clone(),
                memory: row.memory.clone(),
                storage: row.storage.clone(),
                call_depth: self.current_call_depth,
                bytecode: bytecode.to_vec(),
                balance_before: 0,
                balance_after: 0,
                memory_ops: self.memory_ops.clone(),
                storage_ops: self.storage_ops.clone(),
                bytecode_merkle_cache: std::sync::OnceLock::new(),
            }
        }).collect()
    }
}

impl<DB: revm::Database> Inspector<DB> for TraceInspector {
    fn step(&mut self, interp: &mut Interpreter, _data: &mut revm::EVMData<'_, DB>) -> InstructionResult {
        // Capture gas BEFORE this opcode
        self.gas_before_op = interp.gas.remaining();
        InstructionResult::Continue
    }

    fn step_end(
        &mut self,
        interp: &mut Interpreter,
        _data: &mut revm::EVMData<'_, DB>,
        _eval: InstructionResult,
    ) -> InstructionResult {
        let gas_after = interp.gas.remaining();
        let pc = interp.program_counter();

        // Get current opcode using the method on Interpreter
        let opcode = interp.current_opcode();

        // Get stack as Vec<u32> (mod q)
        let stack_data = interp.stack().data();
        let mut stack = Vec::with_capacity(stack_data.len());
        for v in stack_data {
            // Convert U256 to u32 via first limb
            let val: u32 = (v.as_limbs()[0] % 8383489) as u32;
            stack.push(val);
        }

        // Get memory
        let memory = interp.memory.data().to_vec();

        // Track memory operations
        match opcode {
            0x51 => { // MLOAD
                if !stack.is_empty() {
                    let offset = (stack[0] % 8383489) as u32;
                    self.memory_ops.push((offset, 0u32));
                }
            }
            0x52 => { // MSTORE
                if stack.len() >= 2 {
                    let offset = (stack[0] % 8383489) as u32;
                    let value: u32 = stack[1];
                    self.memory_ops.push((offset, value));
                }
            }
            0x59 => { // MSTORE8
                if stack.len() >= 2 {
                    let offset = (stack[0] % 8383489) as u32;
                    let value = (stack[1] % 256) as u32;
                    self.memory_ops.push((offset, value));
                }
            }
            _ => {}
        }

        // Track storage operations
        match opcode {
            0x54 => { // SLOAD
                if !stack.is_empty() {
                    let key: u32 = stack[0];
                    self.storage_ops.push((key, 0u32));
                }
            }
            0x55 => { // SSTORE
                if stack.len() >= 2 {
                    let key: u32 = stack[0];
                    let value: u32 = stack[1];
                    self.storage_ops.push((key, value));
                }
            }
            _ => {}
        }

        let trace_row = RevmTraceRow {
            pc,
            opcode,
            gas_before: self.gas_before_op,
            gas_after,
            stack,
            memory,
            storage: Vec::new(),
        };

        self.trace.push(trace_row);
        InstructionResult::Continue
    }

    fn call(
        &mut self,
        _data: &mut revm::EVMData<'_, DB>,
        _inputs: &mut CallInputs,
    ) -> (InstructionResult, Gas, Bytes) {
        self.current_call_depth += 1;
        // Check if this call is to a precompile (address starts with 0x00...01 to 0x00...0a)
        // We capture the gas before precompile call for tracking
        self.precompile_gas_before = 0; // Will be set in call_end
        (InstructionResult::Continue, Gas::new(0), Bytes::new())
    }

    fn call_end(
        &mut self,
        data: &mut revm::EVMData<'_, DB>,
        inputs: &CallInputs,
        remaining_gas: Gas,
        ret: InstructionResult,
        out: Bytes,
    ) -> (InstructionResult, Gas, Bytes) {
        if self.current_call_depth > 0 {
            self.current_call_depth -= 1;
        }

        // Track precompile calls
        // Precompile addresses: 0x01-0x0a (with leading zeros: 0x0000...01 to 0x0000...0a)
        // Address supports indexing like [u8; 20]
        let addr = inputs.contract;
        // Check if first 18 bytes are zero (precompile address check)
        let is_precompile = addr[..18].iter().all(|&b| b == 0);
        if is_precompile {
            let precompile_num = u16::from_be_bytes([addr[18], addr[19]]);
            if precompile_num >= 1 && precompile_num <= 10 {
                // Calculate gas used
                let gas_limit = inputs.gas_limit;
                let gas_used = gas_limit.saturating_sub(remaining_gas.limit());

                self.precompile_calls.push(PrecompileCall {
                    address: inputs.contract,
                    input: inputs.input.to_vec(),
                    output: out.to_vec(),
                    gas_used,
                    success: matches!(ret, InstructionResult::Continue | InstructionResult::Return),
                });
            }
        }

        (ret, remaining_gas, out)
    }

    fn create(
        &mut self,
        _data: &mut revm::EVMData<'_, DB>,
        _inputs: &mut CreateInputs,
    ) -> (InstructionResult, Option<Address>, Gas, Bytes) {
        self.current_call_depth += 1;
        (InstructionResult::Continue, None, Gas::new(0), Bytes::default())
    }

    fn create_end(
        &mut self,
        _data: &mut revm::EVMData<'_, DB>,
        _inputs: &CreateInputs,
        ret: InstructionResult,
        address: Option<Address>,
        remaining_gas: Gas,
        out: Bytes,
    ) -> (InstructionResult, Option<Address>, Gas, Bytes) {
        if self.current_call_depth > 0 {
            self.current_call_depth -= 1;
        }
        (ret, address, remaining_gas, out)
    }
}

/// Execute bytecode using revm EVM with step-by-step tracing (for Full/Minimal/Medium modes)
pub fn execute_evm_with_trace(
    bytecode: &[u8],
    calldata: &[u8],
    gas_limit: u64,
) -> Result<(StateDiff, Vec<RevmTraceRow>), &'static str> {
    let mut evm = EVM::new();

    evm.env.cfg.spec_id = SpecId::BERLIN;
    evm.env.block.gas_limit = U256::from(gas_limit);

    // Use the address! macro from revm::primitives
    let caller = address!("0000000000000000000000000000000000000001");
    let contract_addr = address!("00000000000000000000000000000000000000FF");
    evm.env.tx.caller = caller;
    evm.env.tx.value = U256::ZERO;
    evm.env.tx.data = Bytes::copy_from_slice(calldata);
    evm.env.tx.transact_to = TransactTo::Call(contract_addr);
    evm.env.tx.gas_limit = gas_limit;

    let bytecode = Bytecode::new_raw(Bytes::copy_from_slice(bytecode));
    let caller_acc_info = AccountInfo {
        nonce: 0,
        balance: U256::MAX,
        code: Some(Bytecode::new_raw(Bytes::new())),
        code_hash: Default::default(),
    };
    let contract_acc_info = AccountInfo {
        nonce: 0,
        balance: U256::MAX,
        code: Some(bytecode),
        code_hash: Default::default(),
    };

    let mut cache_db = CacheDB::new(revm::db::EmptyDB::default());
    cache_db.insert_account_info(caller, caller_acc_info);
    cache_db.insert_account_info(contract_addr, contract_acc_info);

    evm.database(cache_db);

    // Create inspector
    let mut inspector = TraceInspector::new();

    // Execute with inspector
    let result = evm.inspect(&mut inspector);

    match result {
        Ok(result_and_state) => {
            let gas_used = result_and_state.result.gas_used();

            // Extract storage changes from state
            let mut storage_changes = Vec::new();
            for (_address, account) in &result_and_state.state {
                for (slot, value) in &account.storage {
                    if !value.present_value().is_zero() {
                        let slot_u32: u32 = (slot.as_limbs()[0] % 8383489) as u32;
                        let value_u32: u32 = (value.present_value().as_limbs()[0] % 8383489) as u32;
                        storage_changes.push((slot_u32, 0u32, value_u32));
                    }
                }
            }

            let success = match result_and_state.result {
                ExecutionResult::Success { .. } => true,
                ExecutionResult::Revert { .. } | ExecutionResult::Halt { .. } => false,
            };

            let state_diff = StateDiff {
                storage_changes,
                gas_used,
                success,
            };

            Ok((state_diff, inspector.trace))
        }
        Err(_) => Err("EVM execution failed"),
    }
}

/// Execute bytecode using revm EVM and extract state diff (for StateDiff mode)
pub fn execute_evm_with_diff(
    bytecode: &[u8],
    calldata: &[u8],
    gas_limit: u64,
) -> Result<StateDiff, &'static str> {
    let mut evm = EVM::new();

    evm.env.cfg.spec_id = SpecId::BERLIN;
    evm.env.block.gas_limit = U256::from(gas_limit);

    let caller = address!("0000000000000000000000000000000000000001");
    evm.env.tx.caller = caller;
    evm.env.tx.value = U256::ZERO;
    evm.env.tx.data = Bytes::copy_from_slice(calldata);
    evm.env.tx.transact_to = TransactTo::Call(caller);
    evm.env.tx.gas_limit = gas_limit;

    let bytecode = Bytecode::new_raw(Bytes::copy_from_slice(bytecode));
    let acc_info = AccountInfo {
        nonce: 0,
        balance: U256::MAX,
        code: Some(bytecode),
        code_hash: Default::default(),
    };

    let mut cache_db = CacheDB::new(revm::db::EmptyDB::default());
    cache_db.insert_account_info(caller, acc_info);

    evm.database(cache_db);

    let result = evm.transact();

    match result {
        Ok(result_and_state) => {
            let gas_used = result_and_state.result.gas_used();

            let mut storage_changes = Vec::new();
            for (_address, account) in &result_and_state.state {
                for (slot, value) in &account.storage {
                    if !value.present_value().is_zero() {
                        let slot_u32: u32 = (slot.as_limbs()[0] % 8383489) as u32;
                        let value_u32: u32 = (value.present_value().as_limbs()[0] % 8383489) as u32;
                        storage_changes.push((slot_u32, 0u32, value_u32));
                    }
                }
            }

            let success = match result_and_state.result {
                ExecutionResult::Success { .. } => true,
                ExecutionResult::Revert { .. } | ExecutionResult::Halt { .. } => false,
            };

            Ok(StateDiff {
                storage_changes,
                gas_used,
                success,
            })
        }
        Err(_) => Err("EVM execution failed"),
    }
}

/// Simple execution that validates bytecode runs without error
pub fn full_evm_validate(bytecode: &[u8], calldata: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut evm = EVM::new();

    evm.env.cfg.spec_id = SpecId::BERLIN;

    let caller = address!("0000000000000000000000000000000000000001");
    evm.env.tx.caller = caller;
    evm.env.tx.value = U256::ZERO;
    evm.env.tx.data = Bytes::copy_from_slice(calldata);
    evm.env.tx.transact_to = TransactTo::Call(caller);

    let bytecode = Bytecode::new_raw(Bytes::copy_from_slice(bytecode));
    let acc_info = AccountInfo {
        nonce: 0,
        balance: U256::MAX,
        code: Some(bytecode),
        code_hash: Default::default(),
    };

    let mut cache_db = CacheDB::new(revm::db::EmptyDB::default());
    cache_db.insert_account_info(caller, acc_info);

    evm.database(cache_db);

    let result = evm.transact();
    match result {
        Ok(result_and_state) => {
            match result_and_state.result {
                ExecutionResult::Success { output, .. } => match output {
                    Output::Call(bytes) => Ok(bytes.to_vec()),
                    Output::Create(bytes, _) => Ok(bytes.to_vec()),
                },
                ExecutionResult::Revert { .. } => Err("EVM reverted"),
                ExecutionResult::Halt { .. } => Err("EVM halted"),
            }
        }
        Err(_) => Err("EVM execution failed"),
    }
}

/// Check if bytecode can be executed by full EVM
pub fn full_evm_can_execute(bytecode: &[u8], calldata: &[u8]) -> bool {
    full_evm_validate(bytecode, calldata).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_generation() {
        let bytecode = vec![0x60, 0x0A, 0x60, 0x14, 0x01, 0x00];
        let result = execute_evm_with_trace(&bytecode, &[], 1_000_000);
        assert!(result.is_ok());
        let (diff, trace) = result.unwrap();
        println!("Gas used: {}", diff.gas_used);
        println!("Trace rows: {}", trace.len());
        assert!(diff.success);
        assert!(!trace.is_empty());
    }

    #[test]
    fn test_simple_execution() {
        let bytecode = vec![0x60, 0x0A, 0x60, 0x14, 0x01, 0x00];
        let result = execute_evm_with_diff(&bytecode, &[], 1_000_000);
        assert!(result.is_ok());
        assert!(result.unwrap().success);
    }

    #[test]
    fn test_sstore_trace() {
        // Simple bytecode: PUSH1 10, PUSH1 0, SSTORE, STOP
        let bytecode = vec![0x60, 0x0A, 0x60, 0x00, 0x55, 0x00];
        let result = execute_evm_with_trace(&bytecode, &[], 1_000_000);
        assert!(result.is_ok());
        let (diff, trace) = result.unwrap();
        println!("Gas used: {}", diff.gas_used);
        println!("Trace rows: {}", trace.len());
        println!("Storage ops: {:?}", trace.last().map(|r| r.opcode));
    }
}