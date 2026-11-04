/*
 * C interface to the policy reveal verifier of ghost-proofs (statement S4,
 * spec 10, section 5), added by the ghostverifier crate (src/lib.rs) beside
 * the coin reveal verifiers of ghost_proofs.h. Unlike ghost_proofs.h this
 * header is not a copy of the ghost repository's: ghost-proofs has no C
 * interface for the policy reveal.
 *
 * Written by hand; every constant here must equal its namesake in src/lib.rs
 * or ghost_proofs.h, and tests/policy_reveal.rs checks the Rust side.
 *
 * ABI: as ghost_proofs.h. The function is thread-safe, keeps no state between
 * calls, reads its buffers only during the call and never unwinds into the
 * caller: a caught panic returns GHOST_PROOFS_PANICKED. Only
 * GHOST_PROOFS_ACCEPTED accepts; every other status rejects.
 *
 * Chain parameters, GHOST_PROOFS_CHAIN_PARAMS_BYTES bytes: as ghost_proofs.h.
 *
 * Statement, GHOST_POLICY_REVEAL_BYTES bytes:
 *   root 32, marker 32, remainder 32, out 32, fee 32, policy_address 20,
 *   policy_codehash 32, params_hash 32, action_tag 32, action_salt 32,
 *   instr 32, remainder_note 380, in that order. out and fee are 32-byte
 *   amount words. There is no recipient and no rule.
 *
 * Proof: as ghost_proofs.h, 1 to GHOST_PROOFS_PROOF_MAX_BYTES bytes, one
 * serialized proof optionally followed by zero bytes.
 */
#ifndef GHOST_POLICY_H
#define GHOST_POLICY_H

#include "ghost_proofs.h"

#define GHOST_POLICY_REVEAL_BYTES 720

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Verifies a policy reveal proof against the statement and the chain
 * parameters. Each non-null pointer must point to at least its length of
 * readable bytes. A null pointer, or parameters or a statement of the wrong
 * length, returns GHOST_PROOFS_BAD_ARGUMENT; an empty or oversized proof, or
 * one that is not a serialized proof followed only by zero bytes, returns
 * GHOST_PROOFS_MALFORMED_INPUT.
 */
int32_t ghost_verify_policy_reveal(const uint8_t *params, size_t params_len,
                                   const uint8_t *statement, size_t statement_len,
                                   const uint8_t *proof, size_t proof_len);

#ifdef __cplusplus
}
#endif

#endif /* GHOST_POLICY_H */
