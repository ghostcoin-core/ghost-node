/*
 * C interface to the policy action verifier of ghost-proofs (statement
 * KNOW_ACTION_v1, spec 10, section 8.2), added by the ghostverifier crate
 * (src/lib.rs) beside the reveal verifiers of ghost_proofs.h and
 * ghost_policy.h. ghost-proofs has no C interface for it.
 *
 * Written by hand; every constant here must equal its namesake in src/lib.rs
 * or ghost_proofs.h, and tests/know_action.rs checks the Rust side.
 *
 * ABI: as ghost_proofs.h. The function is thread-safe, keeps no state between
 * calls, reads its buffers only during the call and never unwinds into the
 * caller: a caught panic returns GHOST_PROOFS_PANICKED. Only
 * GHOST_PROOFS_ACCEPTED accepts; every other status rejects.
 *
 * Chain parameters, GHOST_PROOFS_CHAIN_PARAMS_BYTES bytes: as ghost_proofs.h,
 * with version 1.
 *
 * Statement, GHOST_ACTION_STATEMENT_BYTES bytes:
 *   policy_address 20, marker 32, action_nonce 8 (big endian), action_tag 32,
 *   action_salt 32, expected_remaining 32, debit 32, expiry 8 (big endian),
 *   calldata_hash 32, in that order, the order of the binding.
 *   expected_remaining and debit are 32-byte amount words.
 *
 * Proof: 1 to GHOST_ACTION_PROOF_BYTES bytes, one serialized proof optionally
 * followed by zero bytes, as the action's proof field holds it.
 */
#ifndef GHOST_ACTION_H
#define GHOST_ACTION_H

#include "ghost_proofs.h"

#define GHOST_ACTION_STATEMENT_BYTES 228
#define GHOST_ACTION_PROOF_BYTES 948224

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Verifies a KNOW_ACTION_v1 proof against the statement and the chain
 * parameters. Each non-null pointer must point to at least its length of
 * readable bytes. A null pointer, or parameters or a statement of the wrong
 * length, returns GHOST_PROOFS_BAD_ARGUMENT; an empty or oversized proof, or
 * one that is not a serialized proof followed only by zero bytes, returns
 * GHOST_PROOFS_MALFORMED_INPUT.
 */
int32_t ghost_verify_know_action(const uint8_t *params, size_t params_len,
                                 const uint8_t *statement, size_t statement_len,
                                 const uint8_t *proof, size_t proof_len);

#ifdef __cplusplus
}
#endif

#endif /* GHOST_ACTION_H */
