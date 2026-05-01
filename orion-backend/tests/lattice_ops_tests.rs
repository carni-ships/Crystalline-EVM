//! Unit tests for Lattice Operations
//!
//! Tests MatVec, NTT, and CRT operations.
//!
//! Note: These tests use the actual library which may call stubbed FFI functions.
//! Some tests may fail if the real Orion library is not available.

use orion_backend::{FieldElement, BlackBoxFunc, BackendError};
use orion_backend::lattice_ops::LatticeOps;

// ============================================================================
// LatticeOps Construction Tests
// ============================================================================

mod construction {
    use super::*;

    #[test]
    fn test_lattice_ops_new() {
        // With stubbed FFI, GPU init returns null but we handle that gracefully
        let ops = LatticeOps::new();
        assert!(ops.is_ok());
    }

    #[test]
    fn test_lattice_ops_default() {
        // Should succeed even with stubbed FFI
        let ops = LatticeOps::default();
        // If we get here without panic, the test passes
    }
}

// ============================================================================
// MatVec Tests (with stubbed FFI)
// ============================================================================

mod matvec_tests {
    use super::*;

    #[test]
    fn test_matvec_insufficient_inputs() {
        let ops = LatticeOps::new().unwrap();

        // Too few inputs
        let result = ops.matvec(&[FieldElement(1)]);
        assert!(result.is_err());
    }

    #[test]
    fn test_matvec_wrong_dimensions() {
        let ops = LatticeOps::new().unwrap();

        // k=2, l=2, but only provide 3 elements instead of 4+2=6
        let inputs = vec![
            FieldElement(2), // k
            FieldElement(2), // l
            FieldElement(1), // A[0,0]
            FieldElement(2), // A[0,1]
            FieldElement(3), // A[1,0]
                      // missing A[1,1], s[0], s[1]
        ];
        let result = ops.matvec(&inputs);
        assert!(result.is_err());
    }

    #[test]
    fn test_matvec_valid_small() {
        let ops = LatticeOps::new().unwrap();

        // k=1, l=1 matrix: [[5]]
        // s = [3]
        let inputs = vec![
            FieldElement(1), // k
            FieldElement(1), // l
            FieldElement(5), // A[0,0]
            FieldElement(3), // s[0]
        ];

        let result = ops.matvec(&inputs);
        // With stubbed FFI, this returns zeros - that's expected
        assert!(result.is_ok());
        let output = result.unwrap();
        assert_eq!(output.len(), 1);
    }

    #[test]
    fn test_matvec_valid_2x2() {
        let ops = LatticeOps::new().unwrap();

        // k=2, l=2 matrix
        let inputs = vec![
            FieldElement(2), // k
            FieldElement(2), // l
            FieldElement(1), // A[0,0]
            FieldElement(2), // A[0,1]
            FieldElement(3), // A[1,0]
            FieldElement(4), // A[1,1]
            FieldElement(1), // s[0]
            FieldElement(1), // s[1]
        ];

        let result = ops.matvec(&inputs);
        assert!(result.is_ok());
        let output = result.unwrap();
        assert_eq!(output.len(), 2);
    }

    #[test]
    fn test_matvec_valid_3x2() {
        let ops = LatticeOps::new().unwrap();

        // k=3, l=2 matrix
        let inputs = vec![
            FieldElement(3), // k
            FieldElement(2), // l
            FieldElement(1), // A[0,0]
            FieldElement(2), // A[0,1]
            FieldElement(3), // A[1,0]
            FieldElement(4), // A[1,1]
            FieldElement(5), // A[2,0]
            FieldElement(6), // A[2,1]
            FieldElement(10), // s[0]
            FieldElement(20), // s[1]
        ];

        let result = ops.matvec(&inputs);
        assert!(result.is_ok());
        let output = result.unwrap();
        assert_eq!(output.len(), 3);
    }
}

// ============================================================================
// NTT Tests (may fail with stubbed FFI)
// ============================================================================

mod ntt_tests {
    use super::*;

    #[test]
    fn test_ntt_insufficient_coefficients() {
        let ops = LatticeOps::new().unwrap();

        // Need 256 coefficients
        let inputs = vec![FieldElement(1); 100];
        let result = ops.ntt(&inputs);
        // With stubbed FFI returning null for GPU context, this will error
        assert!(result.is_err());
    }

    #[test]
    #[ignore = "Requires GPU hardware"]
    fn test_ntt_exact_coefficients() {
        let ops = LatticeOps::new().unwrap();

        // With real FFI, this may succeed if GPU is available
        let inputs: Vec<FieldElement> = (0..256).map(|i| FieldElement(i as u32)).collect();
        let result = ops.ntt(&inputs);
        // If GPU is available, should succeed; otherwise GPU error
        if ops.gpu_available() {
            assert!(result.is_ok(), "NTT should succeed with GPU");
        } else {
            assert!(result.is_err(), "NTT should fail without GPU");
        }
    }
}

// ============================================================================
// CRT Tests
// ============================================================================

mod crt_tests {
    use super::*;

    #[test]
    fn test_crt_insufficient_inputs() {
        let ops = LatticeOps::new().unwrap();

        // Not enough inputs for CRT
        let inputs = vec![FieldElement(1), FieldElement(2)];
        let result = ops.crt(&inputs);
        assert!(result.is_err());
    }

    #[test]
    fn test_crt_single_modulus() {
        let ops = LatticeOps::new().unwrap();

        // n_mods=1, mod0=100, res0=50
        let inputs = vec![
            FieldElement(1), // n_mods
            FieldElement(100), // mod0
            FieldElement(50), // res0
        ];

        let result = ops.crt(&inputs);
        assert!(result.is_ok());
        let output = result.unwrap();
        assert_eq!(output.len(), 1);
    }

    #[test]
    fn test_crt_two_moduli() {
        let ops = LatticeOps::new().unwrap();

        // n_mods=2
        let inputs = vec![
            FieldElement(2), // n_mods
            FieldElement(100), // mod0
            FieldElement(50), // res0
            FieldElement(200), // mod1
            FieldElement(150), // res1
        ];

        let result = ops.crt(&inputs);
        assert!(result.is_ok());
        let output = result.unwrap();
        assert_eq!(output.len(), 1);
    }
}

// ============================================================================
// Poseidon2 Tests
// ============================================================================

mod poseidon2_tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_poseidon2_empty_inputs() {
        let ops = LatticeOps::new().unwrap();

        let result = ops.poseidon2(&[]);
        assert!(result.is_ok());
        let output = result.unwrap();
        assert_eq!(output.len(), 1);
    }

    #[test]
    fn test_poseidon2_single_input() {
        let ops = LatticeOps::new().unwrap();

        let inputs = vec![FieldElement(42)];
        let result = ops.poseidon2(&inputs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_poseidon2_multiple_inputs() {
        let ops = LatticeOps::new().unwrap();

        let inputs = vec![
            FieldElement(1),
            FieldElement(2),
            FieldElement(3),
            FieldElement(4),
        ];
        let result = ops.poseidon2(&inputs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_poseidon2_ane_vs_cpu() {
        let ops = LatticeOps::new().unwrap();

        println!("ANE available: {}", ops.ane_available());
        println!("GPU available: {}", ops.gpu_available());

        // Create test state (8 elements for MDS_SIZE=8)
        let state: Vec<FieldElement> = (0..8).map(|i| FieldElement((i * 12345) % 8383489)).collect();

        // Warm up both paths
        for _ in 0..10 {
            let _ = ops.poseidon2(&state);
            let _ = ops.poseidon2_cpu(&state);
        }

        // Benchmark ANE
        let iterations = 1000;
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = ops.poseidon2(&state);
        }
        let ane_time = start.elapsed();

        // Benchmark CPU
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = ops.poseidon2_cpu(&state);
        }
        let cpu_time = start.elapsed();

        println!("Poseidon2 MDS (8x8) - {} iterations:", iterations);
        println!("  ANE: {:.3} ms total, {:.3} us/op",
            ane_time.as_millis() as f64,
            ane_time.as_micros() as f64 / iterations as f64);
        println!("  CPU: {:.3} ms total, {:.3} us/op",
            cpu_time.as_millis() as f64,
            cpu_time.as_micros() as f64 / iterations as f64);
        println!("  Speedup: {:.2}x", cpu_time.as_micros() as f64 / ane_time.as_micros() as f64);
    }
}

// ============================================================================
// Execute Function Tests
// ============================================================================

mod execute_tests {
    use super::*;

    #[test]
    fn test_execute_matvec() {
        let ops = LatticeOps::new().unwrap();

        let inputs = vec![
            FieldElement(1),
            FieldElement(1),
            FieldElement(5),
            FieldElement(3),
        ];

        let result = ops.execute(BlackBoxFunc::MatVec, &inputs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_execute_poseidon2() {
        let ops = LatticeOps::new().unwrap();

        let inputs = vec![FieldElement(1), FieldElement(2)];
        let result = ops.execute(BlackBoxFunc::Poseidon2, &inputs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_execute_unsupported() {
        let ops = LatticeOps::new().unwrap();

        let inputs = vec![FieldElement(1)];
        let result = ops.execute(BlackBoxFunc::Keccak256, &inputs);
        assert!(result.is_err());

        if let Err(BackendError::UnsupportedOpcode(msg)) = result {
            assert!(msg.contains("not implemented"));
        } else {
            panic!("Expected UnsupportedOpcode error");
        }
    }
}

// ============================================================================
// FieldElement Tests
// ============================================================================

mod field_element_tests {
    use super::*;

    #[test]
    fn test_field_element_equality() {
        let a = FieldElement(42);
        let b = FieldElement(42);
        let c = FieldElement(43);

        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_field_element_default() {
        let fe = FieldElement::default();
        assert_eq!(fe.0, 0);
    }

    #[test]
    fn test_field_element_new() {
        let fe = FieldElement::new(100);
        assert_eq!(fe.0, 100);
    }

    #[test]
    fn test_field_element_modulo() {
        // Test modulo behavior
        let fe = FieldElement::new(8383489); // Should wrap to 0
        assert_eq!(fe.0, 0);

        let fe = FieldElement::new(8383490); // Should wrap to 1
        assert_eq!(fe.0, 1);
    }
}
