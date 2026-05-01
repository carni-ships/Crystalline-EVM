//! Lattice AIR (Algebraic Intermediate Representation)
//!
//! Defines constraints for the lattice-based zkEVM.
//! Adapted from Circle STARK's BlockAIR for lattice field q=8383489.

pub mod constraints;
pub mod polynomial_encoder;

pub use constraints::*;
pub use polynomial_encoder::*;
pub use orion_backend::FieldElement;

/// AIR constraint for lattice field
#[derive(Debug, Clone)]
pub struct Constraint {
    /// Column index for constraint
    pub column: usize,
    /// Constraint polynomial coefficients (in field elements)
    pub coeffs: Vec<u32>,
}

impl Constraint {
    pub fn new(column: usize, coeffs: Vec<u32>) -> Self {
        Constraint { column, coeffs }
    }

    /// Evaluate constraint at given trace value
    pub fn evaluate(&self, trace_value: u32) -> u32 {
        const Q: u64 = 8383489;
        // Simple evaluation: sum of coeffs * trace_value^i mod Q
        let mut result = 0u64;
        for (i, &c) in self.coeffs.iter().enumerate() {
            let power = (trace_value as u64).wrapping_pow(i as u32) % Q;
            result = result.wrapping_add((c as u64).wrapping_mul(power));
        }
        (result % Q) as u32
    }
}

/// Trait for AIR-based provers
pub trait LatticeAIR {
    /// Generate trace execution trace
    fn generate_trace(&self) -> Vec<Vec<u32>>;

    /// Evaluate constraints at trace index
    fn evaluate_constraints(&self, trace: &[Vec<u32>], idx: usize) -> Vec<u32>;

    /// Boundary constraints (initial and final register values)
    fn boundary_constraints(&self) -> Vec<(usize, u32)>;

    /// Number of columns in trace
    fn num_columns(&self) -> usize;

    /// Trace length
    fn trace_length(&self) -> usize;
}

/// Lattice AIR implementation for EVM
pub struct LatticeEVMAIR {
    trace_width: usize,
    trace_length: usize,
    constraints: Vec<Constraint>,
    initial_values: Vec<Vec<u32>>,
}

impl LatticeEVMAIR {
    pub fn new(trace_width: usize, trace_length: usize) -> Self {
        // Default constraints for EVM
        let constraints = vec![
            Constraint::new(0, vec![1]),  // pc constraint
            Constraint::new(1, vec![1]),  // gas constraint
        ];

        LatticeEVMAIR {
            trace_width,
            trace_length,
            constraints,
            initial_values: Vec::new(),
        }
    }

    /// Add a custom constraint
    pub fn add_constraint(&mut self, constraint: Constraint) {
        self.constraints.push(constraint);
    }

    /// Set initial trace values
    pub fn set_initial_values(&mut self, values: Vec<Vec<u32>>) {
        self.initial_values = values;
    }
}

impl LatticeAIR for LatticeEVMAIR {
    fn generate_trace(&self) -> Vec<Vec<u32>> {
        const Q: u64 = 8383489;
        let mut trace = Vec::with_capacity(self.trace_length);

        for i in 0..self.trace_length {
            let mut row = vec![0u32; self.trace_width];

            // Fill with deterministic pattern based on index
            for j in 0..self.trace_width {
                row[j] = ((i * self.trace_width + j) as u32).wrapping_mul(12345) % Q as u32;
            }

            // Override with initial values if available
            if i < self.initial_values.len() {
                for (j, &val) in self.initial_values[i].iter().enumerate() {
                    if j < self.trace_width {
                        row[j] = val;
                    }
                }
            }

            trace.push(row);
        }

        trace
    }

    fn evaluate_constraints(&self, trace: &[Vec<u32>], idx: usize) -> Vec<u32> {
        if idx >= trace.len() {
            return Vec::new();
        }

        let row = &trace[idx];
        self.constraints
            .iter()
            .map(|c| {
                if c.column < row.len() {
                    c.evaluate(row[c.column])
                } else {
                    0
                }
            })
            .collect()
    }

    fn boundary_constraints(&self) -> Vec<(usize, u32)> {
        vec![
            (0, 0),  // pc starts at 0
        ]
    }

    fn num_columns(&self) -> usize {
        self.trace_width
    }

    fn trace_length(&self) -> usize {
        self.trace_length
    }
}

/// Convert trace to field elements for ANE processing
pub fn trace_to_field_elements(trace: &[Vec<u32>]) -> Vec<FieldElement> {
    trace
        .iter()
        .flat_map(|row| row.iter().map(|&v| FieldElement(v)))
        .collect()
}

/// Convert field elements back to trace
pub fn field_elements_to_trace(fes: &[FieldElement], width: usize) -> Vec<Vec<u32>> {
    fes.chunks(width)
        .map(|chunk| chunk.iter().map(|fe| fe.0).collect())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_air_creation() {
        let air = LatticeEVMAIR::new(4, 256);
        assert_eq!(air.num_columns(), 4);
        assert_eq!(air.trace_length(), 256);
    }

    #[test]
    fn test_trace_generation() {
        let air = LatticeEVMAIR::new(4, 16);
        let trace = air.generate_trace();
        assert_eq!(trace.len(), 16);
        assert_eq!(trace[0].len(), 4);
    }

    #[test]
    fn test_constraint_evaluation() {
        let air = LatticeEVMAIR::new(4, 16);
        let trace = air.generate_trace();
        let constraints = air.evaluate_constraints(&trace, 5);
        assert_eq!(constraints.len(), 2);  // 2 default constraints
    }

    #[test]
    fn test_boundary_constraints() {
        let air = LatticeEVMAIR::new(4, 256);
        let bounds = air.boundary_constraints();
        assert!(!bounds.is_empty());
    }
}