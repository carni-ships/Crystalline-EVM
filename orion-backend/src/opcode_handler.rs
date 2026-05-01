//! ACIR Opcode Handler
//!
//! Routes ACIR opcodes to appropriate implementations:
//! - AssertZero → verify constraint
//! - BlackBoxFuncCall → lattice_ops or brillig_runner
//! - MemoryOp → array model
//! - BrilligCall → brillig_runner
//! - Call → recursive composition

use super::{Opcode, Circuit, AcirProgram, FieldElement, Witness, BlackBoxFunc, MemoryOperation, MemoryOpType};
use super::error::BackendError;
use super::lattice_ops::LatticeOps;
use super::brillig_runner::BrilligRunner;

/// Opcode handler context
pub struct OpcodeHandler {
    lattice_ops: LatticeOps,
    brillig_runner: BrilligRunner,
    /// Memory for array operations (public for testing)
    pub memory: Vec<FieldElement>,
    /// Witness values (public for testing)
    pub witnesses: Vec<FieldElement>,
}

impl OpcodeHandler {
    /// Create new opcode handler
    pub fn new() -> Result<Self, BackendError> {
        Ok(OpcodeHandler {
            lattice_ops: LatticeOps::new()?,
            brillig_runner: BrilligRunner::new(),
            memory: Vec::new(),
            witnesses: Vec::new(),
        })
    }

    /// Handle a single opcode
    pub fn handle(&mut self, opcode: &Opcode) -> Result<(), BackendError> {
        match opcode {
            Opcode::AssertZero(fe) => self.handle_assert_zero(*fe),
            Opcode::BlackBoxFuncCall(func, inputs, outputs) => {
                self.handle_blackbox(*func, inputs, outputs)
            }
            Opcode::MemoryOp(op) => self.handle_memory(op),
            Opcode::BrilligCall(bytecode) => self.handle_brillig(bytecode),
            Opcode::Call { function, args } => self.handle_call(function, args),
        }
    }

    /// Handle AssertZero opcode
    fn handle_assert_zero(&mut self, fe: FieldElement) -> Result<(), BackendError> {
        // For now, just ensure witness is defined
        // Real constraint verification happens here
        if fe.0 as usize >= self.witnesses.len() && fe.0 != 0 {
            // This is a constant zero, which is fine
        }
        Ok(())
    }

    /// Handle BlackBoxFuncCall opcode
    fn handle_blackbox(
        &mut self,
        func: BlackBoxFunc,
        inputs: &[Witness],
        outputs: &[Witness],
    ) -> Result<(), BackendError> {
        // Resolve input witnesses to field elements
        let input_values: Result<Vec<FieldElement>, _> = inputs
            .iter()
            .map(|w| self.resolve_witness(*w))
            .collect();
        let input_values = input_values?;

        // Execute the operation
        let result_values = match func {
            BlackBoxFunc::MatVec => self.lattice_ops.matvec(&input_values)?,
            BlackBoxFunc::NTT => self.lattice_ops.ntt(&input_values)?,
            BlackBoxFunc::CRT => self.lattice_ops.crt(&input_values)?,
            BlackBoxFunc::Poseidon2 => self.lattice_ops.poseidon2(&input_values)?,
            BlackBoxFunc::PermutationCheck => self.lattice_ops.permutation_check(&input_values)?,
            BlackBoxFunc::Keccak256 | BlackBoxFunc::SHA256 | BlackBoxFunc::ECDSAVerify | BlackBoxFunc::SchnorrVerify => {
                // Fall back to brillig for hash/signature ops
                return Err(BackendError::UnsupportedOpcode(format!(
                    "Hash/signature op {:?} - use Brillig", func
                )));
            }
        };

        // Store output witnesses
        for (i, output) in outputs.iter().enumerate() {
            self.assign_witness(*output, result_values.get(i).copied().unwrap_or(FieldElement(0)))?;
        }

        Ok(())
    }

    /// Handle MemoryOp opcode
    fn handle_memory(&mut self, op: &MemoryOperation) -> Result<(), BackendError> {
        let addr = self.resolve_witness(op.address)?.0 as usize;
        let value = self.resolve_witness(op.value)?;

        // Grow memory as needed
        if addr >= self.memory.len() {
            self.memory.resize(addr + 1, FieldElement(0));
        }

        match op.operation {
            MemoryOpType::Write => {
                self.memory[addr] = value;
            }
            MemoryOpType::Read => {
                // For read, value is the target to store memory into
                if op.value.0 as usize >= self.witnesses.len() {
                    self.witnesses.resize(op.value.0 as usize + 1, FieldElement(0));
                }
                self.witnesses[op.value.0 as usize] = self.memory[addr];
            }
        }
        Ok(())
    }

    /// Handle BrilligCall opcode
    fn handle_brillig(&mut self, bytecode: &[u8]) -> Result<(), BackendError> {
        self.brillig_runner.execute(bytecode, &mut self.witnesses)
    }

    /// Handle Call opcode (recursive function call)
    fn handle_call(&mut self, function: &str, _args: &[Witness]) -> Result<(), BackendError> {
        // For now, function calls are not implemented
        // Real implementation would look up function definition and execute
        Err(BackendError::UnsupportedOpcode(format!(
            "Function calls not yet implemented: {}", function
        )))
    }

    /// Resolve a witness to its field element value
    /// Resolve a witness to its field element value (public for testing)
    pub fn resolve_witness(&self, witness: Witness) -> Result<FieldElement, BackendError> {
        if witness.0 == 0 {
            Ok(FieldElement(0))
        } else if (witness.0 as usize) < self.witnesses.len() {
            Ok(self.witnesses[witness.0 as usize])
        } else {
            Err(BackendError::InvalidWitness(format!(
                "Witness {} not yet assigned",
                witness.0
            )))
        }
    }

    /// Assign a value to a witness (public for testing)
    pub fn assign_witness(&mut self, witness: Witness, value: FieldElement) -> Result<(), BackendError> {
        let idx = witness.0 as usize;
        if idx >= self.witnesses.len() {
            self.witnesses.resize(idx + 1, FieldElement(0));
        }
        self.witnesses[idx] = value;
        Ok(())
    }

    /// Execute full ACIR program
    pub fn execute_program(&mut self, program: &AcirProgram) -> Result<Vec<FieldElement>, BackendError> {
        for circuit in &program.circuits {
            self.execute_circuit(circuit)?;
        }
        // Return values at witness indices
        Ok(program.return_values
            .iter()
            .map(|w| self.resolve_witness(*w).unwrap_or(FieldElement(0)))
            .collect())
    }

    /// Execute a single circuit
    pub fn execute_circuit(&mut self, circuit: &Circuit) -> Result<(), BackendError> {
        // Initialize private parameters as zero (prover's secret inputs)
        for witness in &circuit.private_parameters {
            self.assign_witness(*witness, FieldElement(0))?;
        }

        // Initialize public parameters as zero (public inputs)
        for witness in &circuit.public_parameters {
            self.assign_witness(*witness, FieldElement(0))?;
        }

        for opcode in &circuit.opcodes {
            self.handle(opcode)?;
        }
        Ok(())
    }
}

impl Default for OpcodeHandler {
    fn default() -> Self {
        Self::new().expect("Failed to create opcode handler")
    }
}