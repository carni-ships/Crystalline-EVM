// orion_latticezk_shim.c — Bridge to Real Orion ANE Implementation
//
// This shim provides wrapper functions that delegate to the real
// implementations in liborion.a (from core/orion_latticezk.m).
//
// For now, we just forward directly since the function names match.
// The real ANE code path is: latticezk_prove -> latticezk_matvec (ANE) -> CRT

#import <Foundation/Foundation.h>
#import "orion_rns.h"
#import "orion_latticezk.h"
#import <CommonCrypto/CommonRandom.h>

// ============================================================================
// Fiat-Shamir Transcript (Helper Implementations)
// ============================================================================

void latticezk_transcript_init(LatticeZKTranscript *t) {
    memset(t->buffer, 0, sizeof(t->buffer));
    t->len = 0;
}

void latticezk_transcript_append(LatticeZKTranscript *t, const uint8_t *data, size_t len) {
    if (t->len + len > sizeof(t->buffer)) {
        len = sizeof(t->buffer) - t->len;
    }
    if (len > 0) {
        memcpy(t->buffer + t->len, data, len);
        t->len += len;
    }
}

void latticezk_transcript_append_u64(LatticeZKTranscript *t, uint64_t val) {
    uint8_t bytes[8];
    for (int i = 0; i < 8; i++) {
        bytes[i] = (uint8_t)(val >> (i * 8));
    }
    latticezk_transcript_append(t, bytes, 8);
}

void latticezk_transcript_append_field(LatticeZKTranscript *t, uint64_t val, uint64_t mod) {
    latticezk_transcript_append_u64(t, val % mod);
}

void latticezk_challenge_from_transcript(LatticeZKTranscript *t, uint8_t *challenge) {
    CC_SHA256(t->buffer, (CC_LONG)t->len, challenge);
}

// ============================================================================
// Helper Functions
// ============================================================================

void latticezk_expand_a(const uint8_t *seed, float *A, int k, int l) {
    for (int i = 0; i < k * l; i++) {
        uint8_t idx = i % 32;
        int8_t val = (int8_t)(seed[idx] ^ (uint8_t)(i * 17 + 31));
        A[i] = (float)val / 64.0f;
    }
}

void latticezk_fs_hash(const uint8_t *data, size_t len, uint8_t *challenge) {
    CC_SHA256(data, (CC_LONG)len, challenge);
}

// ============================================================================
// Proof Serialization
// ============================================================================

void latticezk_proof_serialize(const LatticeZKProof *proof, uint8_t *buf, size_t *len) {
    size_t needed = 64 + LATTICEZK_K * 8;
    if (*len < needed) {
        *len = needed;
        return;
    }
    *len = needed;
    memcpy(buf, proof->commitment, 32);
    memcpy(buf + 32, proof->challenge, 32);
    memcpy(buf + 64, proof->response, LATTICEZK_K * 8);
}

bool latticezk_proof_deserialize(LatticeZKProof *proof, const uint8_t *buf, size_t len) {
    if (len < 64 + LATTICEZK_K * 8) return false;
    memcpy(proof->commitment, buf, 32);
    memcpy(proof->challenge, buf + 32, 32);
    memcpy(proof->response, buf + 64, LATTICEZK_K * 8);
    return true;
}
