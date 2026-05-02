//! AIR to Multilinear Polynomial Encoding
//!
//! Converts AIR constraints into multilinear polynomials for SNARK proving.
//! This follows the Hyrax approach where:
//! - Each trace row becomes an evaluation point
//! - Each constraint becomes a polynomial identity
//! - Sumcheck proves all constraints are satisfied
//!
//! Reference: "Doubly-Efficient zkSNARKs Without Trusted Setup" (Hyrax, Wahby et al.)

use crate::crypto::{MultilinearPolynomial, MultilinearPCS, Q};
use crate::evm::TraceRow;

/// Trace values extracted for SNARK proving
/// These are the key values that appear in constraints
#[derive(Debug, Clone)]
pub struct TraceValues {
    /// Program counter at each row
    pub pc: Vec<usize>,
    /// Opcode at each row
    pub opcode: Vec<u8>,
    /// Gas before at each row
    pub gas_before: Vec<u64>,
    /// Gas after at each row
    pub gas_after: Vec<u64>,
    /// Stack height at each row
    pub stack_height: Vec<usize>,
    /// Call depth at each row
    pub call_depth: Vec<usize>,
    /// Bytecode hash at each row
    pub bytecode_hash: Vec<u32>,
}

impl TraceValues {
    /// Extract key values from trace rows
    pub fn from_trace(trace: &[TraceRow]) -> Self {
        let mut pc = Vec::with_capacity(trace.len());
        let mut opcode = Vec::with_capacity(trace.len());
        let mut gas_before = Vec::with_capacity(trace.len());
        let mut gas_after = Vec::with_capacity(trace.len());
        let mut stack_height = Vec::with_capacity(trace.len());
        let mut call_depth = Vec::with_capacity(trace.len());
        let mut bytecode_hash = Vec::with_capacity(trace.len());

        for row in trace {
            pc.push(row.pc);
            opcode.push(row.opcode);
            gas_before.push(row.gas_before);
            gas_after.push(row.gas_after);
            stack_height.push(row.stack.len());
            call_depth.push(row.call_depth);
            bytecode_hash.push(row.compute_bytecode_hash());
        }

        TraceValues {
            pc,
            opcode,
            gas_before,
            gas_after,
            stack_height,
            call_depth,
            bytecode_hash,
        }
    }

    /// Number of rows in trace
    pub fn len(&self) -> usize {
        self.pc.len()
    }

    /// Check if trace is empty
    pub fn is_empty(&self) -> bool {
        self.pc.is_empty()
    }
}

/// Encoded trace as multilinear polynomial
/// Uses log-sized encoding: one variable per bit of row index
#[derive(Debug, Clone)]
pub struct TracePolynomial {
    /// Number of rows in trace
    pub num_rows: usize,
    /// Number of variables for encoding
    pub num_vars: usize,
    /// Multilinear polynomial encoding the trace
    pub poly: MultilinearPolynomial,
}

impl TracePolynomial {
    /// Create trace polynomial from execution trace
    /// Uses multilinear extension: f(b_1, ..., b_log_n) = trace[row_index][col_index]
    pub fn from_trace(trace: &[TraceRow]) -> Result<Self, &'static str> {
        if trace.is_empty() {
            return Err("Empty trace");
        }

        let num_rows = trace.len();
        let num_vars = (num_rows as f64).log2() as usize;

        // Build evaluations at all 2^num_vars Boolean points
        // Point (b_1, ..., b_n) corresponds to row index Σ b_i * 2^{n-i}
        let mut evaluations = Vec::with_capacity(1 << num_vars);

        for i in 0..(1 << num_vars) {
            // Decode binary index to row number
            let mut row_idx = 0usize;
            let mut bit_place = 1usize;
            let mut tmp = i;
            for _ in 0..num_vars {
                if tmp & 1 == 1 {
                    row_idx += bit_place;
                }
                bit_place <<= 1;
                tmp >>= 1;
            }

            // Encode trace row as a single field element
            // We use a simple folding: hash of (pc, opcode, gas_before, gas_after, stack_height)
            let value = if row_idx < num_rows {
                let row = &trace[row_idx];
                Self::hash_trace_row(row)
            } else {
                0
            };
            evaluations.push(value);
        }

        let poly = MultilinearPolynomial::new(num_vars, evaluations)?;
        Ok(TracePolynomial { num_rows, num_vars, poly })
    }

    /// Create trace polynomial from a SINGLE trace row (per-opcode lattice proving)
    ///
    /// For per-opcode proving, each row needs its own polynomial.
    /// We use num_vars=1 (2^1=2 points) where:
    /// - f(0) = the actual row hash
    /// - f(1) = 0 (padding)
    pub fn from_single_row(row: &TraceRow) -> Result<Self, &'static str> {
        let num_vars = 1;  // Single row needs only 1 variable
        let num_rows = 1;

        // f(0) = hash of the row, f(1) = 0
        let hash = Self::hash_trace_row(row);
        let evaluations = vec![hash, 0];

        let poly = MultilinearPolynomial::new(num_vars, evaluations)?;
        Ok(TracePolynomial { num_rows, num_vars, poly })
    }
    fn hash_trace_row(row: &TraceRow) -> u32 {
        use crate::crypto::Poseidon2;
        // Simple fold: hash(pc, opcode, gas_before mod Q, gas_after mod Q, stack_height)
        let h0 = (row.pc % Q as usize) as u32;
        let h1 = row.opcode as u32;
        let h2 = (row.gas_before % Q as u64) as u32;
        let h3 = (row.gas_after % Q as u64) as u32;
        let h4 = (row.stack.len() % Q as usize) as u32;

        let mut hash = Poseidon2::hash_pair(h0, h1);
        hash = Poseidon2::hash_pair(hash, h2);
        hash = Poseidon2::hash_pair(hash, h3);
        Poseidon2::hash_pair(hash, h4)
    }

    /// Evaluate at a trace row index
    pub fn evaluate_at_row(&self, row_idx: usize) -> u32 {
        // Convert row_idx to Boolean point
        let mut point = Vec::with_capacity(self.num_vars);
        let mut remaining = row_idx;
        for _ in 0..self.num_vars {
            point.push((remaining & 1) as u32);
            remaining >>= 1;
        }
        self.poly.evaluate(&point)
    }
}

/// Constraint polynomial that should be zero on all satisfying assignments
#[derive(Debug, Clone)]
pub struct ConstraintPolynomial {
    /// Constraint type identifier
    pub constraint_id: u32,
    /// Polynomial evaluations at Boolean points
    pub evaluations: Vec<u32>,
    /// Number of variables
    pub num_vars: usize,
}

impl ConstraintPolynomial {
    /// Create constraint polynomial from evaluator function
    /// The evaluator function should return 0 when constraint is satisfied
    pub fn from_evaluator<F>(
        num_vars: usize,
        trace: &[TraceRow],
        mut evaluator: F,
    ) -> Self
    where
        F: FnMut(&TraceRow) -> bool,
    {
        let mut evaluations = Vec::with_capacity(1 << num_vars);

        for i in 0..(1 << num_vars) {
            // Decode row index
            let mut row_idx = 0usize;
            let mut bit_place = 1usize;
            let mut tmp = i;
            for _ in 0..num_vars {
                if tmp & 1 == 1 {
                    row_idx += bit_place;
                }
                bit_place <<= 1;
                tmp >>= 1;
            }

            let eval = if row_idx < trace.len() {
                if evaluator(&trace[row_idx]) {
                    0
                } else {
                    1 // Constraint violated
                }
            } else {
                0 // Padding is valid
            };
            evaluations.push(eval);
        }

        let _poly = MultilinearPolynomial::new(num_vars, evaluations.clone()).unwrap();
        ConstraintPolynomial {
            constraint_id: 1,
            evaluations,
            num_vars,
        }
    }

    /// Build gas conservation constraint polynomial
    /// Constraint: gas_before >= gas_after (no gas creation)
    pub fn gas_conservation(trace: &[TraceRow]) -> Self {
        let num_vars = (trace.len() as f64).log2() as usize;
        Self::from_evaluator(num_vars, trace, |row| row.gas_before >= row.gas_after)
    }

    /// Build stack bounds constraint polynomial
    /// Constraint: stack_height <= 1024
    pub fn stack_bounds(trace: &[TraceRow]) -> Self {
        let num_vars = (trace.len() as f64).log2() as usize;
        Self::from_evaluator(num_vars, trace, |row| row.stack.len() <= 1024)
    }

    /// Build bytecode exists constraint polynomial
    /// Constraint: bytecode_hash != 0
    pub fn bytecode_exists(trace: &[TraceRow]) -> Self {
        let num_vars = (trace.len() as f64).log2() as usize;
        Self::from_evaluator(num_vars, trace, |row| row.compute_bytecode_hash() != 0)
    }

    /// Build call depth constraint polynomial
    /// Constraint: call_depth <= 1024
    pub fn call_depth_bounds(trace: &[TraceRow]) -> Self {
        let num_vars = (trace.len() as f64).log2() as usize;
        Self::from_evaluator(num_vars, trace, |row| row.call_depth <= 1024)
    }
}

/// Combined constraints polynomial
/// P(x) should be 0 on all satisfying points if all constraints are satisfied
#[derive(Debug, Clone)]
pub struct ConstraintsPolynomial {
    /// Number of variables
    pub num_vars: usize,
    /// Combined polynomial (sum of squared constraints)
    pub poly: MultilinearPolynomial,
    /// List of constraint polynomials
    pub constraints: Vec<ConstraintPolynomial>,
}

impl ConstraintsPolynomial {
    /// Build all constraints from trace
    pub fn from_trace(trace: &[TraceRow]) -> Result<Self, &'static str> {
        if trace.is_empty() {
            return Err("Empty trace");
        }

        let num_vars = (trace.len() as f64).log2() as usize;
        let mut constraints = Vec::new();

        // Gas conservation: gas_initial >= gas_final
        constraints.push(ConstraintPolynomial::gas_conservation(trace));

        // Stack bounds: stack_height <= 1024
        constraints.push(ConstraintPolynomial::stack_bounds(trace));

        // Bytecode exists: bytecode_hash != 0
        constraints.push(ConstraintPolynomial::bytecode_exists(trace));

        // Call depth bounds: call_depth <= 1024
        constraints.push(ConstraintPolynomial::call_depth_bounds(trace));

        // Combine: P(x) = Σ_i C_i(x)^2 (sum of squares ensures P=0 iff all C_i=0)
        let mut combined_evals = vec![0u32; 1 << num_vars];
        for cp in &constraints {
            for (i, &eval) in cp.evaluations.iter().enumerate() {
                // Square the constraint value (violation = 1, satisfied = 0)
                let sq = (eval as u64 * eval as u64) % Q as u64;
                combined_evals[i] = (combined_evals[i] as u64 + sq) as u32 % Q as u32;
            }
        }

        let poly = MultilinearPolynomial::new(num_vars, combined_evals)?;
        Ok(ConstraintsPolynomial { num_vars, poly, constraints })
    }

    /// Check if all constraints are satisfied
    pub fn verify(&self) -> bool {
        self.poly.evaluations.iter().all(|&e| e == 0)
    }
}

/// Witness builder for SNARK proving
pub struct WitnessBuilder {
    pcs: MultilinearPCS,
}

impl WitnessBuilder {
    pub fn new(num_vars: usize) -> Self {
        WitnessBuilder { pcs: MultilinearPCS::new(num_vars) }
    }

    /// Build witness polynomial from trace
    pub fn build_witness(&self, trace: &[TraceRow]) -> Result<(u32, crate::crypto::MerkleTree), &'static str> {
        let trace_poly = TracePolynomial::from_trace(trace)?;
        let (root, tree) = self.pcs.commit(&trace_poly.poly);
        Ok((root, tree))
    }

    /// Build witness from a SINGLE trace row (per-opcode lattice proving)
    ///
    /// This is the key to lattice-native zkEVM: each opcode execution
    /// gets its own witness commitment.
    pub fn build_witness_for_row(&self, row: &TraceRow) -> Result<(u32, crate::crypto::MerkleTree), &'static str> {
        let trace_poly = TracePolynomial::from_single_row(row)?;
        let (root, tree) = self.pcs.commit(&trace_poly.poly);
        Ok((root, tree))
    }

    /// Build constraints polynomial from trace
    pub fn build_constraints(&self, trace: &[TraceRow]) -> Result<ConstraintsPolynomial, &'static str> {
        ConstraintsPolynomial::from_trace(trace)
    }

    /// Prove that trace polynomial satisfies constraints at a random point
    pub fn prove_constraints(
        &self,
        trace: &[TraceRow],
        challenge: &[u32],
    ) -> Result<crate::crypto::OpeningProof, &'static str> {
        let trace_poly = TracePolynomial::from_trace(trace)?;
        let constraints = ConstraintsPolynomial::from_trace(trace)?;

        let (_root, tree) = self.pcs.commit(&trace_poly.poly);

        // Evaluate constraints at challenge point
        let value = constraints.poly.evaluate(challenge);

        // Create opening proof
        let proof = self.pcs.prove(&trace_poly.poly, challenge, value, &tree);
        Ok(proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evm::OpCode;

    fn create_test_trace() -> Vec<TraceRow> {
        use crate::evm::OpCode;
        vec![
            TraceRow {
                pc: 0,
                opcode: OpCode::PUSH1 as u8,
                gas_before: 100,
                gas_after: 97,
                stack: vec![1],
                memory: vec![],
                storage: vec![],
                call_depth: 0,
                bytecode: vec![0x60, 0x01],
                balance_before: 0,
                balance_after: 0,
                memory_ops: vec![],
                storage_ops: vec![],
                bytecode_merkle_cache: std::sync::OnceLock::new(),
            },
            TraceRow {
                pc: 1,
                opcode: OpCode::ADD as u8,
                gas_before: 97,
                gas_after: 96,
                stack: vec![2],
                memory: vec![],
                storage: vec![],
                call_depth: 0,
                bytecode: vec![],
                balance_before: 0,
                balance_after: 0,
                memory_ops: vec![],
                storage_ops: vec![],
                bytecode_merkle_cache: std::sync::OnceLock::new(),
            },
        ]
    }

    #[test]
    fn test_trace_values_extraction() {
        let trace = create_test_trace();
        let values = TraceValues::from_trace(&trace);

        assert_eq!(values.len(), 2);
        assert_eq!(values.pc[0], 0);
        assert_eq!(values.pc[1], 1);
    }

    #[test]
    fn test_trace_polynomial_creation() {
        let trace = create_test_trace();
        let trace_poly = TracePolynomial::from_trace(&trace);

        assert!(trace_poly.is_ok());
        let tp = trace_poly.unwrap();
        assert!(tp.num_rows >= 2);
    }

    #[test]
    fn test_gas_conservation_constraint() {
        let trace = create_test_trace();
        let constraint = ConstraintPolynomial::gas_conservation(&trace);

        // Both rows satisfy gas conservation
        assert!(constraint.evaluations.iter().all(|&e| e == 0));
    }

    #[test]
    fn test_stack_bounds_constraint() {
        let trace = create_test_trace();
        let constraint = ConstraintPolynomial::stack_bounds(&trace);

        // Both rows satisfy stack bounds
        assert!(constraint.evaluations.iter().all(|&e| e == 0));
    }

    #[test]
    fn test_bytecode_exists_constraint() {
        let trace = create_test_trace();
        let constraint = ConstraintPolynomial::bytecode_exists(&trace);

        // First row has bytecode (vec![0x60, 0x01]), second has empty bytecode
        // Empty bytecode gives bytecode_hash == 0, so constraint is violated
        // At least one row should have violation
        let violations: usize = constraint.evaluations.iter().filter(|&&e| e != 0).count();
        assert!(violations > 0, "Expected at least one bytecode violation");
    }

    #[test]
    fn test_constraints_polynomial_combined() {
        // Create trace where all constraints are satisfied
        let trace = vec![
            TraceRow {
                pc: 0,
                opcode: OpCode::PUSH1 as u8,
                gas_before: 100,
                gas_after: 97,
                stack: vec![1],
                memory: vec![],
                storage: vec![],
                call_depth: 0,
                bytecode: vec![0x60, 0x01], // Non-empty bytecode
                balance_before: 0,
                balance_after: 0,
                memory_ops: vec![],
                storage_ops: vec![],
                bytecode_merkle_cache: std::sync::OnceLock::new(),
            },
        ];
        let constraints = ConstraintsPolynomial::from_trace(&trace);

        assert!(constraints.is_ok());
        let cp = constraints.unwrap();

        // All constraints satisfied, so combined polynomial should be zero
        assert!(cp.verify());
    }

    #[test]
    fn test_witness_builder() {
        let trace = create_test_trace();
        let builder = WitnessBuilder::new(2);

        let result = builder.build_witness(&trace);
        assert!(result.is_ok());
    }
}
