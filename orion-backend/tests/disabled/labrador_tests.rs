//! Unit tests for Labrador Protocol
//!
//! Tests prover/verifier with deterministic randomness.

use orion_backend::labrador::{LabradorProver, LabradorVerifier, sample_short_vector, random_field_element};
use orion_backend::FieldElement;
use orion_sys::{
    LatticeZKProvingKey, LatticeZKVerificationKey, LatticeZKProof,
    LATTICEZK_K, LATTICEZK_L, LATTICEZK_N, LATTICEZK_Q,
};

// ============================================================================
// Constants Tests
// ============================================================================

mod constants_tests {
    use super::*;

    #[test]
    fn test_latticezk_constants() {
        assert_eq!(LATTICEZK_K, 4);
        assert_eq!(LATTICEZK_L, 4);
        assert_eq!(LATTICEZK_N, 256);
        assert_eq!(LATTICEZK_Q, 8383489);
    }
}

// ============================================================================
// Prover Tests
// ============================================================================

mod prover_tests {
    use super::*;

    #[test]
    fn test_prover_new() {
        let pk = LatticeZKProvingKey {
            seed: [0u8; 32],
            q: LATTICEZK_Q as u64,
            k: LATTICEZK_K as i32,
            l: LATTICEZK_L as i32,
            n: LATTICEZK_N as i32,
        };

        let prover = LabradorProver::new(pk);
        // Should succeed
        assert_eq!(prover.pk.q, LATTICEZK_Q as u64);
    }

    #[test]
    fn test_prover_prove() {
        let pk = LatticeZKProvingKey {
            seed: [0u8; 32],
            q: LATTICEZK_Q as u64,
            k: LATTICEZK_K as i32,
            l: LATTICEZK_L as i32,
            n: LATTICEZK_N as i32,
        };

        let prover = LabradorProver::new(pk);
        let s = sample_short_vector(2, LATTICEZK_L as usize);

        let proof = prover.prove(&s);
        assert!(proof.is_ok());

        let proof = proof.unwrap();
        // Check proof structure is initialized
        assert_eq!(proof.commitment.len(), 32);
        assert_eq!(proof.challenge.len(), 32);
        assert_eq!(proof.response.len(), 4);
    }

    #[test]
    fn test_prove_wrong_length() {
        let pk = LatticeZKProvingKey {
            seed: [0u8; 32],
            q: LATTICEZK_Q as u64,
            k: LATTICEZK_K as i32,
            l: LATTICEZK_L as i32,
            n: LATTICEZK_N as i32,
        };

        let prover = LabradorProver::new(pk);
        // Wrong length witness
        let s = vec![1u64, 2, 3]; // Should be LATTICEZK_L = 4

        let result = prover.prove(&s);
        assert!(result.is_err());
    }
}

// ============================================================================
// Verifier Tests
// ============================================================================

mod verifier_tests {
    use super::*;

    #[test]
    fn test_verifier_new() {
        let vk = LatticeZKVerificationKey {
            q: LATTICEZK_Q as u64,
            k: LATTICEZK_K as i32,
            l: LATTICEZK_L as i32,
            n: LATTICEZK_N as i32,
        };

        let verifier = LabradorVerifier::new(vk);
        // Should succeed
    }

    #[test]
    fn test_verifier_verify_valid() {
        let vk = LatticeZKVerificationKey {
            q: LATTICEZK_Q as u64,
            k: LATTICEZK_K as i32,
            l: LATTICEZK_L as i32,
            n: LATTICEZK_N as i32,
        };

        let verifier = LabradorVerifier::new(vk);

        // Create a valid proof
        let proof = LatticeZKProof {
            commitment: [0u8; 32],
            challenge: [1u8; 32],
            response: [100, 200, 300, 400], // All less than q
        };

        let result = verifier.verify(&proof);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_verifier_verify_response_too_large() {
        let vk = LatticeZKVerificationKey {
            q: LATTICEZK_Q as u64,
            k: LATTICEZK_K as i32,
            l: LATTICEZK_L as i32,
            n: LATTICEZK_N as i32,
        };

        let verifier = LabradorVerifier::new(vk);

        // Create proof with response >= q
        let proof = LatticeZKProof {
            commitment: [0u8; 32],
            challenge: [1u8; 32],
            response: [100, LATTICEZK_Q as u64 + 1, 300, 400], // Second value >= q
        };

        let result = verifier.verify(&proof);
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Should fail verification
    }
}

// ============================================================================
// Prove-Verify Integration Tests
// ============================================================================

mod integration_tests {
    use super::*;

    #[test]
    fn test_prove_and_verify() {
        let pk = LatticeZKProvingKey {
            seed: [0u8; 32],
            q: LATTICEZK_Q as u64,
            k: LATTICEZK_K as i32,
            l: LATTICEZK_L as i32,
            n: LATTICEZK_N as i32,
        };

        let vk = LatticeZKVerificationKey {
            q: LATTICEZK_Q as u64,
            k: LATTICEZK_K as i32,
            l: LATTICEZK_L as i32,
            n: LATTICEZK_N as i32,
        };

        let prover = LabradorProver::new(pk);
        let verifier = LabradorVerifier::new(vk);

        // Create a short vector witness
        let s = sample_short_vector(2, LATTICEZK_L as usize);

        // Generate proof
        let proof = prover.prove(&s).expect("Proving should succeed");

        // Verify proof
        let is_valid = verifier.verify(&proof).expect("Verification should succeed");
        assert!(is_valid, "Proof should be valid");
    }

    #[test]
    fn test_prove_and_verify_deterministic() {
        let pk = LatticeZKProvingKey {
            seed: [0u8; 32],
            q: LATTICEZK_Q as u64,
            k: LATTICEZK_K as i32,
            l: LATTICEZK_L as i32,
            n: LATTICEZK_N as i32,
        };

        let prover = LabradorProver::new(pk);

        // Same witness should produce same proof structure
        let s = sample_short_vector(2, LATTICEZK_L as usize);
        let proof1 = prover.prove(&s).unwrap();

        // Create new prover with same key (need to construct new since LatticeZKProvingKey is moved)
        let pk2 = LatticeZKProvingKey {
            seed: [0u8; 32],
            q: LATTICEZK_Q as u64,
            k: LATTICEZK_K as i32,
            l: LATTICEZK_L as i32,
            n: LATTICEZK_N as i32,
        };
        let prover2 = LabradorProver::new(pk2);
        let proof2 = prover2.prove(&s).unwrap();

        // Response should be the same (deterministic)
        assert_eq!(proof1.response, proof2.response);
    }
}

// ============================================================================
// Random Function Tests
// ============================================================================

mod random_tests {
    use super::*;

    #[test]
    fn test_random_field_element() {
        let val = random_field_element(100);
        assert!(val < 100);
    }

    #[test]
    fn test_sample_short_vector() {
        let vec = sample_short_vector(5, 10);
        assert_eq!(vec.len(), 10);

        // All elements should be within [-5, 5] range (approximately)
        for val in &vec {
            assert!(*val <= 11); // 5 * 2 + 1 = 11
        }
    }

    #[test]
    fn test_sample_short_vector_length() {
        let vec = sample_short_vector(3, 4);
        assert_eq!(vec.len(), 4);

        let vec = sample_short_vector(10, 100);
        assert_eq!(vec.len(), 100);
    }
}

// ============================================================================
// Error Handling Tests
// ============================================================================

mod error_tests {
    use super::*;

    #[test]
    fn test_prover_rejects_wrong_witness_length() {
        let pk = LatticeZKProvingKey {
            seed: [0u8; 32],
            q: LATTICEZK_Q as u64,
            k: LATTICEZK_K as i32,
            l: LATTICEZK_L as i32,
            n: LATTICEZK_N as i32,
        };

        let prover = LabradorProver::new(pk);

        // Too short
        let s = vec![1u64, 2];
        let result = prover.prove(&s);
        assert!(result.is_err());

        // Too long
        let s = vec![1u64; 10];
        let result = prover.prove(&s);
        assert!(result.is_err());
    }
}

// ============================================================================
// Key Structure Tests
// ============================================================================

mod key_tests {
    use super::*;

    #[test]
    fn test_proving_key_default() {
        let pk = LatticeZKProvingKey::default();
        assert_eq!(pk.q, 0);
        assert_eq!(pk.k, 0);
    }

    #[test]
    fn test_verification_key_default() {
        let vk = LatticeZKVerificationKey::default();
        assert_eq!(vk.q, 0);
        assert_eq!(vk.l, 0);
    }

    #[test]
    fn test_proof_default() {
        let proof = LatticeZKProof::default();
        assert_eq!(proof.commitment, [0u8; 32]);
        assert_eq!(proof.challenge, [0u8; 32]);
        assert_eq!(proof.response, [0u64; 4]);
    }

    #[test]
    fn test_proving_key_with_values() {
        let pk = LatticeZKProvingKey {
            seed: [1u8; 32],
            q: 8383489,
            k: 4,
            l: 4,
            n: 256,
        };

        assert_eq!(pk.q, 8383489);
        assert_eq!(pk.k, 4);
        assert_eq!(pk.seed[0], 1);
    }

    #[test]
    fn test_proof_with_values() {
        let proof = LatticeZKProof {
            commitment: [0xAAu8; 32],
            challenge: [0xBBu8; 32],
            response: [1, 2, 3, 4],
        };

        assert_eq!(proof.commitment[0], 0xAA);
        assert_eq!(proof.challenge[0], 0xBB);
        assert_eq!(proof.response[0], 1);
        assert_eq!(proof.response[3], 4);
    }
}
