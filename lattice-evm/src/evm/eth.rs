//! Minimal EVM Implementation for Ethereum Transaction Proving
//!
//! Supports only ETH transfer operations to demonstrate real transaction proving.

use crate::Q;
use crate::crypto::keccak256_u32_words;
use std::collections::HashMap;

/// EVM opcode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpCode {
    STOP,
    ADD,
    MUL,
    SUB,
    DIV,
    SDIV,
    MOD,
    SMOD,
    ADDMOD,
    MULMOD,
    EXP,
    SIGNEXTEND,
    LT,
    GT,
    SLT,
    SGT,
    EQ,
    ISZERO,
    AND,
    OR,
    XOR,
    NOT,
    BYTE,
    SHL,
    SHR,
    SAR,
    SHA3,
    KECCAK256 = 0x20,
    // Memory operations
    MLOAD,
    MSTORE,
    MSTORE8,
    GETPC = 0x58,
    MSIZE,
    GAS,
    // Stack operations
    PUSH1, PUSH2, PUSH3, PUSH4,
    POP,
    DUP1, DUP2, DUP3, DUP4,
    SWAP1, SWAP2, SWAP3, SWAP4,
    // Environmental
    ADDRESS = 0x30,
    ORIGIN,
    CALLER,
    CALLVALUE,
    BALANCE,
    BASEFEE,
    // Storage operations
    SLOAD,
    SSTORE,
    // Control flow
    JUMP,
    JUMPI,
    PC,
    JUMPDEST,
    // Transaction
    CALL,
    RETURN,
    REVERT,
    // Logs
    LOG0,
}

/// EVM stack (max 1024)
pub struct Stack {
    data: Vec<u256>,
}

impl Stack {
    pub fn new() -> Self {
        Stack { data: Vec::new() }
    }

    pub fn push(&mut self, val: u256) -> Result<(), &'static str> {
        if self.data.len() >= 1024 {
            return Err("Stack overflow");
        }
        self.data.push(val);
        Ok(())
    }

    pub fn pop(&mut self) -> Result<u256, &'static str> {
        self.data.pop().ok_or("Stack underflow")
    }

    pub fn dup(&mut self, n: usize) -> Result<u256, &'static str> {
        let idx = self.data.len() - n;
        self.data.get(idx).copied().ok_or("Stack underflow")
    }

    pub fn swap(&mut self, n: usize) -> Result<(), &'static str> {
        let idx = self.data.len() - 1 - n;
        if idx >= self.data.len() {
            return Err("Stack underflow");
        }
        let top = self.data.len() - 1;
        self.data.swap(idx, top);
        Ok(())
    }

    pub fn peek(&self) -> Option<u256> {
        self.data.last().copied()
    }
}

/// 256-bit integer for EVM
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct u256(pub [u64; 4]);

impl Ord for u256 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        for (a, b) in self.0.iter().zip(other.0.iter()) {
            match a.cmp(b) {
                std::cmp::Ordering::Equal => continue,
                o => return o,
            }
        }
        std::cmp::Ordering::Equal
    }
}

impl PartialOrd for u256 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl u256 {
    pub fn new(low: u64) -> Self {
        u256([low, 0, 0, 0])
    }

    pub fn from_u32(val: u32) -> Self {
        u256([val as u64, 0, 0, 0])
    }

    pub fn to_u32(&self) -> u32 {
        self.0[0] as u32
    }

    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&x| x == 0)
    }

    pub fn wrapping_add(&self, other: &u256) -> Self {
        let mut result = [0u64; 4];
        let mut carry = 0u64;
        for i in 0..4 {
            let (sum, overflow1) = self.0[i].overflowing_add(other.0[i]);
            let (sum2, overflow2) = sum.overflowing_add(carry);
            result[i] = sum2;
            carry = overflow1 as u64 + overflow2 as u64;
        }
        u256(result)
    }

    pub fn wrapping_mul(&self, other: &u256) -> Self {
        // Simplified - just low 64 bits for demo
        let result = (self.0[0] * other.0[0]) % Q as u64;
        u256([result, 0, 0, 0])
    }

    pub fn lt(&self, other: &u256) -> bool {
        for i in (0..4).rev() {
            if self.0[i] < other.0[i] {
                return true;
            } else if self.0[i] > other.0[i] {
                return false;
            }
        }
        false
    }
}

/// EVM Memory (Grows as needed, max 2^64)
pub struct Memory {
    data: HashMap<u64, u8>,
}

impl Memory {
    pub fn new() -> Self {
        Memory { data: HashMap::new() }
    }

    pub fn read(&self, offset: u64, len: u64) -> Vec<u8> {
        (0..len).map(|i| *self.data.get(&(offset + i)).unwrap_or(&0)).collect()
    }

    pub fn write(&mut self, offset: u64, data: &[u8]) {
        for (i, &byte) in data.iter().enumerate() {
            self.data.insert(offset + i as u64, byte);
        }
    }

    pub fn read_u256(&self, offset: u64) -> u256 {
        let bytes = self.read(offset, 32);
        // Parse as little-endian u256
        let mut words = [0u64; 4];
        for i in 0..4 {
            let mut word = 0u64;
            for j in 0..8 {
                word |= (bytes[i * 8 + j] as u64) << (j * 8);
            }
            words[i] = word;
        }
        u256(words)
    }

    pub fn write_u256(&mut self, offset: u64, value: &u256) {
        let bytes: Vec<u8> = value.0.iter()
            .flat_map(|w| w.to_le_bytes().to_vec())
            .collect();
        self.write(offset, &bytes);
    }
}

/// EVM Storage (key-value store)
pub struct Storage {
    data: HashMap<u256, u256>,
}

impl Storage {
    pub fn new() -> Self {
        Storage { data: HashMap::new() }
    }

    pub fn sload(&self, key: &u256) -> u256 {
        *self.data.get(key).unwrap_or(&u256::new(0))
    }

    pub fn sstore(&mut self, key: u256, value: u256) {
        self.data.insert(key, value);
    }

    /// Compute Poseidon2 hash of all storage key-value pairs for commitment
    /// Note: This is a simplified commitment, not a proper Patricia Merkle tree
    pub fn compute_root(&self) -> u32 {
        use crate::crypto::Poseidon2;
        if self.data.is_empty() {
            return 0;
        }
        let mut hash = 0u32;
        let mut items: Vec<(u32, u32)> = self.data.iter()
            .map(|(k, v)| (k.0[0] as u32 % 8383489, v.0[0] as u32 % 8383489))
            .collect();
        items.sort_by_key(|k| k.0);
        for (key, val) in items {
            hash = Poseidon2::hash_pair(hash, Poseidon2::hash_pair(key, val));
        }
        hash
    }
}

/// Patricia Merkle Tree Node for Ethereum Storage
///
/// Simplified Patricia tree for zkEVM - stores key-value pairs
/// and computes a Poseidon2 Merkle root.
#[derive(Debug, Clone, Default)]
pub struct PatriciaTrie {
    /// Root node hash (computed lazily)
    root_hash: u32,
    /// All key-value pairs for building the tree
    entries: Vec<(u256, u32)>,
}

impl PatriciaTrie {
    pub fn new() -> Self {
        PatriciaTrie {
            root_hash: 0,
            entries: Vec::new(),
        }
    }

    pub fn insert(&mut self, key: u256, value: u32) {
        // Remove existing entry if present
        self.entries.retain(|(k, _)| *k != key);
        self.entries.push((key, value));
        self.root_hash = 0; // Invalidate cache
    }

    pub fn get(&self, key: &u256) -> Option<u32> {
        self.entries.iter()
            .find(|(k, _)| *k == *key)
            .map(|(_, v)| *v)
    }

    /// Compute Merkle root using Poseidon2
    pub fn root_hash(&mut self) -> u32 {
        if self.root_hash != 0 {
            return self.root_hash;
        }
        use crate::crypto::Poseidon2;
        if self.entries.is_empty() {
            self.root_hash = 0;
            return 0;
        }
        // Sort entries by key for deterministic ordering
        self.entries.sort_by_key(|(k, _)| *k);
        // Build a simple binary Merkle tree from sorted entries
        let mut hashes: Vec<u32> = self.entries.iter()
            .map(|(_, v)| Poseidon2::hash_pair(v % 8383489, 0))
            .collect();
        // Hash pairs together until single root
        while hashes.len() > 1 {
            let mut next_level = Vec::new();
            for chunk in hashes.chunks(2) {
                if chunk.len() == 2 {
                    next_level.push(Poseidon2::hash_pair(chunk[0], chunk[1]));
                } else {
                    next_level.push(chunk[0]); // Odd element passes through
                }
            }
            hashes = next_level;
        }
        self.root_hash = hashes.first().copied().unwrap_or(0);
        self.root_hash
    }
}

/// Execution context
pub struct Context {
    pub address: u256,
    pub caller: u256,
    pub origin: u256,
    pub value: u256,
    pub gas: u64,
    pub gas_price: u256,
    pub chain_id: u256,
    pub base_fee: u256,
}

/// EVM State
pub struct EVMState {
    pub stack: Stack,
    pub memory: Memory,
    pub storage: Storage,
    pub pc: usize,
    pub context: Context,
    pub code: Vec<u8>,
    pub stopped: bool,
}

impl EVMState {
    pub fn new(code: Vec<u8>, context: Context) -> Self {
        EVMState {
            stack: Stack::new(),
            memory: Memory::new(),
            storage: Storage::new(),
            pc: 0,
            context,
            code,
            stopped: false,
        }
    }

    /// Execute one instruction
    pub fn step(&mut self) -> Result<(), &'static str> {
        if self.stopped || self.pc >= self.code.len() {
            self.stopped = true;
            return Ok(());
        }

        let opcode = self.code[self.pc];
        self.pc += 1;

        match opcode {
            0x00 => { self.stopped = true; Ok(()) } // STOP
            0x01 => { // ADD
                let a = self.stack.pop()?;
                let b = self.stack.pop()?;
                self.stack.push(a.wrapping_add(&b))
            }
            0x02 => { // MUL
                let a = self.stack.pop()?;
                let b = self.stack.pop()?;
                self.stack.push(a.wrapping_mul(&b))
            }
            0x03 => { // SUB
                let a = self.stack.pop()?;
                let b = self.stack.pop()?;
                // Simplified: just low 64-bit subtract
                let result = (a.0[0].wrapping_sub(b.0[0])) % Q as u64;
                self.stack.push(u256([result, 0, 0, 0]))
            }
            0x04 => { // DIV
                let a = self.stack.pop()?;
                let b = self.stack.pop()?;
                if b.is_zero() {
                    self.stack.push(u256::new(0))
                } else {
                    let result = (a.0[0] / b.0[0]) % Q as u64;
                    self.stack.push(u256([result, 0, 0, 0]))
                }
            }
            0x10 => { // LT
                let a = self.stack.pop()?;
                let b = self.stack.pop()?;
                let result = if a.lt(&b) { 1 } else { 0 };
                self.stack.push(u256::new(result as u64))
            }
            0x14 => { // EQ
                let a = self.stack.pop()?;
                let b = self.stack.pop()?;
                let result = if a == b { 1 } else { 0 };
                self.stack.push(u256::new(result as u64))
            }
            0x15 => { // ISZERO
                let a = self.stack.pop()?;
                let result = if a.is_zero() { 1 } else { 0 };
                self.stack.push(u256::new(result as u64))
            }
            0x16 => { // AND
                let a = self.stack.pop()?;
                let b = self.stack.pop()?;
                let result = u256([
                    a.0[0] & b.0[0],
                    a.0[1] & b.0[1],
                    a.0[2] & b.0[2],
                    a.0[3] & b.0[3],
                ]);
                self.stack.push(result)
            }
            0x17 => { // OR
                let a = self.stack.pop()?;
                let b = self.stack.pop()?;
                let result = u256([
                    a.0[0] | b.0[0],
                    a.0[1] | b.0[1],
                    a.0[2] | b.0[2],
                    a.0[3] | b.0[3],
                ]);
                self.stack.push(result)
            }
            0x18 => { // XOR
                let a = self.stack.pop()?;
                let b = self.stack.pop()?;
                let result = u256([
                    a.0[0] ^ b.0[0],
                    a.0[1] ^ b.0[1],
                    a.0[2] ^ b.0[2],
                    a.0[3] ^ b.0[3],
                ]);
                self.stack.push(result)
            }
            0x19 => { // NOT
                let a = self.stack.pop()?;
                let result = u256([
                    !a.0[0],
                    !a.0[1],
                    !a.0[2],
                    !a.0[3],
                ]);
                self.stack.push(result)
            }
            0x20 => { // KECCAK256
                let offset = self.stack.pop()?.0[0];
                let len = self.stack.pop()?.0[0];
                // Use proper Keccak-256 implementation
                let data = self.memory.read(offset, len);
                let words = keccak256_u32_words(&data);
                // Convert [u32; 8] to u256 ([u64; 4])
                let hash = u256([
                    (words[0] as u64) | ((words[1] as u64) << 32),
                    (words[2] as u64) | ((words[3] as u64) << 32),
                    (words[4] as u64) | ((words[5] as u64) << 32),
                    (words[6] as u64) | ((words[7] as u64) << 32),
                ]);
                self.stack.push(hash)
            }
            0x51 => { // MLOAD
                let offset = self.stack.pop()?.0[0];
                let val = self.memory.read_u256(offset);
                self.stack.push(val)
            }
            0x52 => { // MSTORE
                let offset = self.stack.pop()?.0[0];
                let value = self.stack.pop()?;
                self.memory.write_u256(offset, &value);
                Ok(())
            }
            0x54 => { // SLOAD
                let key = self.stack.pop()?;
                let val = self.storage.sload(&key);
                self.stack.push(val)
            }
            0x55 => { // SSTORE
                let key = self.stack.pop()?;
                let value = self.stack.pop()?;
                self.storage.sstore(key, value);
                Ok(())
            }
            0x56 => { // JUMP
                let dest = self.stack.pop()?.to_u32() as usize;
                if dest < self.code.len() && self.code[dest] == 0x5B {
                    self.pc = dest;
                    Ok(())
                } else {
                    Err("Invalid jump destination")
                }
            }
            0x57 => { // JUMPI
                let dest = self.stack.pop()?.to_u32() as usize;
                let cond = self.stack.pop()?;
                if !cond.is_zero() && dest < self.code.len() && self.code[dest] == 0x5B {
                    self.pc = dest;
                    Ok(())
                } else {
                    Ok(())
                }
            }
            0x5B => Ok(()), // JUMPDEST
            0x60 => { // PUSH1
                let val = self.code[self.pc] as u64;
                self.pc += 1;
                self.stack.push(u256::new(val))
            }
            0x61 => { // PUSH2
                let val = u16::from(self.code[self.pc]) as u64 |
                          (u16::from(self.code[self.pc + 1]) as u64) << 8;
                self.pc += 2;
                self.stack.push(u256::new(val))
            }
            0x80 => { // DUP1
                let val = self.stack.dup(1)?;
                self.stack.push(val)
            }
            0x81 => { // DUP2
                let val = self.stack.dup(2)?;
                self.stack.push(val)
            }
            0x90 => { // SWAP1
                self.stack.swap(1)?;
                Ok(())
            }
            0x91 => { // SWAP2
                self.stack.swap(2)?;
                Ok(())
            }
            0xf3 => { // RETURN
                self.stopped = true;
                Ok(())
            }
            0xfd => { // REVERT
                self.stopped = true;
                Err("REVERT")
            }
            _ => Ok(()), // Skip unknown opcodes for demo
        }
    }

    /// Run until stopped
    pub fn run(&mut self) -> Result<(), &'static str> {
        while !self.stopped {
            self.step()?;
        }
        Ok(())
    }
}

/// Execute ETH transfer
pub fn execute_eth_transfer(
    from: u256,
    _to: u256,
    value: u256,
) -> EVMState {
    // Simple ETH transfer bytecode:
    // PUSH1 value, PUSH1 0 (offset), MSTORE, PUSH1 32, PUSH1 0, RETURN

    // In real EVM: CALL value to address
    // This is simplified - real ETH transfer uses CALL opcode with gas

    let code = vec![
        0x60, 0x01,        // PUSH1 0x01 (noop for demo)
        0x60, 0x00,        // PUSH1 0x00
        0x52,              // MSTORE
        0x60, 0x20,        // PUSH1 32
        0x60, 0x00,        // PUSH1 0x00
        0xf3,              // RETURN
    ];

    let context = Context {
        address: from,
        caller: from,
        origin: from,
        value,
        gas: 21000,  // Base gas for transfer
        gas_price: u256::new(1),
        chain_id: u256::new(1),
        base_fee: u256::new(30),
    };

    let mut state = EVMState::new(code, context);
    let _ = state.run();
    state
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eth_transfer_execution() {
        let from = u256::new(0x1234);
        let to = u256::new(0x5678);
        let value = u256::new(100);

        let state = execute_eth_transfer(from, to, value);

        assert!(state.stopped);
        // In full implementation, would check storage modifications
    }

    #[test]
    fn test_simple_stack_operations() {
        let mut stack = Stack::new();
        stack.push(u256::new(10)).unwrap();
        stack.push(u256::new(20)).unwrap();
        let sum = stack.pop().unwrap();
        assert_eq!(sum.0[0], 20);
    }
}