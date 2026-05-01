//! Brillig Bytecode Runner
//!
//! Executes Brillig bytecode - Noir's unconstrained execution model.
//! Brillig is a simple stack-based VM for operations that don't need
//! constraint proving (hashes, signatures, etc.)
//!
//! # Brillig Opcodes
//! - LOAD/STORE: Memory operations
//! - ADD, SUB, MUL, DIV: Arithmetic
//! - NEG, NOT: Unary ops
//! - EQ, LT, LTE, GT, GTE: Comparison
//! - AND, OR, XOR: Bitwise
//! - CAST: Type conversion
//! - JUMP, JUMPI: Control flow
//! - CALL, RETURN: Functions

use super::FieldElement;
use super::error::BackendError;

/// Brillig VM state
pub struct BrilligRunner {
    pc: usize,
    /// Stack for VM operations
    pub stack: Vec<FieldElement>,
    /// Memory for VM operations
    pub memory: Vec<FieldElement>,
    /// Condition flags for jumps
    pub flags: Flags,
}

#[derive(Debug, Clone, Default)]
pub struct Flags {
    pub zero: bool,
    pub non_zero: bool,
    pub overflow: bool,
}

impl BrilligRunner {
    /// Create new Brillig runner
    pub fn new() -> Self {
        BrilligRunner {
            pc: 0,
            stack: Vec::new(),
            memory: Vec::new(),
            flags: Flags::default(),
        }
    }

    /// Execute Brillig bytecode
    pub fn execute(&mut self, bytecode: &[u8], witnesses: &mut Vec<FieldElement>) -> Result<(), BackendError> {
        // Brillig bytecode format:
        // [opcode (1 byte)] [operands...]
        //
        // Opcodes:
        // 0x00: HALT
        // 0x01: LOAD (register index)
        // 0x02: STORE (register index)
        // 0x03: PUSH
        // 0x04: POP
        // 0x05: ADD
        // 0x06: SUB
        // 0x07: MUL
        // 0x08: DIV
        // 0x09: NEG
        // 0x0A: NOT
        // 0x0B: EQ
        // 0x0C: LT
        // 0x0D: JUMP (label)
        // 0x0E: JUMPI (label)
        // 0x0F: CALL (offset)
        // 0x10: RETURN
        // 0x11: CAST

        self.pc = 0;

        while self.pc < bytecode.len() {
            let opcode = bytecode[self.pc];
            self.pc += 1;

            match opcode {
                0x00 => {
                    // HALT - end of execution
                    break;
                }
                0x01 => {
                    // LOAD - push memory[operand] onto stack
                    let idx = bytecode[self.pc] as usize;
                    self.pc += 1;
                    let val = if idx < self.memory.len() {
                        self.memory[idx]
                    } else {
                        FieldElement(0)
                    };
                    self.stack.push(val);
                }
                0x02 => {
                    // STORE - pop stack to memory[operand]
                    let idx = bytecode[self.pc] as usize;
                    self.pc += 1;
                    if let Some(val) = self.stack.pop() {
                        if idx >= self.memory.len() {
                            self.memory.resize(idx + 1, FieldElement(0));
                        }
                        self.memory[idx] = val;
                    }
                }
                0x03 => {
                    // PUSH immediate value
                    if self.pc + 4 > bytecode.len() {
                        return Err(BackendError::BrilligError("PUSH needs 4-byte operand".to_string()));
                    }
                    let val = u32::from_le_bytes([
                        bytecode[self.pc],
                        bytecode[self.pc + 1],
                        bytecode[self.pc + 2],
                        bytecode[self.pc + 3],
                    ]);
                    self.pc += 4;
                    self.stack.push(FieldElement(val));
                }
                0x04 => {
                    // POP - discard top of stack
                    self.stack.pop();
                }
                0x05 => {
                    // ADD - pop two, push sum
                    if let (Some(a), Some(b)) = (self.stack.pop(), self.stack.pop()) {
                        self.stack.push(FieldElement(a.0.wrapping_add(b.0)));
                    }
                }
                0x06 => {
                    // SUB - pop two, push a - b
                    if let (Some(a), Some(b)) = (self.stack.pop(), self.stack.pop()) {
                        self.stack.push(FieldElement(a.0.wrapping_sub(b.0)));
                    }
                }
                0x07 => {
                    // MUL - pop two, push product
                    if let (Some(a), Some(b)) = (self.stack.pop(), self.stack.pop()) {
                        self.stack.push(FieldElement(a.0.wrapping_mul(b.0)));
                    }
                }
                0x08 => {
                    // DIV - pop two, push a / b (floor division)
                    if let (Some(a), Some(b)) = (self.stack.pop(), self.stack.pop()) {
                        if b.0 == 0 {
                            return Err(BackendError::BrilligError("Division by zero".to_string()));
                        }
                        self.stack.push(FieldElement(a.0 / b.0));
                    }
                }
                0x09 => {
                    // NEG - pop one, push -a
                    if let Some(a) = self.stack.pop() {
                        self.stack.push(FieldElement(a.0 ^ 0xFFFFFFFF));
                    }
                }
                0x0A => {
                    // NOT - pop one, push ~a
                    if let Some(a) = self.stack.pop() {
                        self.stack.push(FieldElement(!a.0));
                    }
                }
                0x0B => {
                    // EQ - pop two, set flags and push result
                    if let (Some(a), Some(b)) = (self.stack.pop(), self.stack.pop()) {
                        let eq = a.0 == b.0;
                        self.flags.zero = eq;
                        self.flags.non_zero = !eq;
                        self.stack.push(FieldElement(if eq { 1 } else { 0 }));
                    }
                }
                0x0C => {
                    // LT - pop two, push a < b
                    if let (Some(a), Some(b)) = (self.stack.pop(), self.stack.pop()) {
                        let lt = a.0 < b.0;
                        self.stack.push(FieldElement(if lt { 1 } else { 0 }));
                    }
                }
                0x0D => {
                    // JUMP - unconditional jump to label (2-byte address)
                    if self.pc + 2 > bytecode.len() {
                        return Err(BackendError::BrilligError("JUMP needs 2-byte operand".to_string()));
                    }
                    let target = u16::from_le_bytes([bytecode[self.pc], bytecode[self.pc + 1]]) as usize;
                    self.pc = target;
                }
                0x0E => {
                    // JUMPI - conditional jump (jump if top of stack is non-zero)
                    if self.pc + 2 > bytecode.len() {
                        return Err(BackendError::BrilligError("JUMPI needs 2-byte operand".to_string()));
                    }
                    let target = u16::from_le_bytes([bytecode[self.pc], bytecode[self.pc + 1]]) as usize;
                    self.pc += 2;
                    if let Some(cond) = self.stack.pop() {
                        if cond.0 != 0 {
                            self.pc = target;
                        }
                    }
                }
                0x0F => {
                    // CALL - save PC, jump to offset
                    if self.pc + 2 > bytecode.len() {
                        return Err(BackendError::BrilligError("CALL needs 2-byte operand".to_string()));
                    }
                    let target = u16::from_le_bytes([bytecode[self.pc], bytecode[self.pc + 1]]) as usize;
                    self.pc += 2;
                    // For now, just jump (real implementation would handle return addresses)
                    self.pc = target;
                }
                0x10 => {
                    // RETURN - pop return address and jump back
                    // For now, just halt
                    break;
                }
                0x11 => {
                    // CAST - type cast (no-op for field elements)
                }
                _ => {
                    return Err(BackendError::BrilligError(format!(
                        "Unknown opcode 0x{:02x} at position {}",
                        opcode,
                        self.pc - 1
                    )));
                }
            }
        }

        // Copy any stack outputs back to witnesses
        // For Brillig, convention is that outputs are left on stack
        let output_count = std::env::var("BRILLIG_OUTPUTS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        for i in 0..output_count.min(self.stack.len()) {
            let idx = witnesses.len() + i;
            if idx >= witnesses.len() {
                witnesses.push(self.stack[self.stack.len() - 1 - i]);
            }
        }

        Ok(())
    }
}

impl Default for BrilligRunner {
    fn default() -> Self {
        Self::new()
    }
}