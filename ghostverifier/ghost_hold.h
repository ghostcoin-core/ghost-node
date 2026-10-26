/*
 * C interface to the proof of holding verifier of ghost-proofs, verify_hold,
 * added by the ghostverifier crate (src/lib.rs) beside ghost_data.h. Like
 * ghost_data.h this header is not a copy of the ghost repository's:
 * ghost-proofs has no C interface for the proof of holding.
 *
 * Written by hand; every constant here must equal its namesake in src/lib.rs
 * or ghost_proofs.h, and tests/hold.rs checks the Rust side.
 *
 * ABI: as ghost_proofs.h. The function is thread-safe, keeps no state between
 * calls, reads its buffers only during the call and never unwinds into the
 * caller: a caught panic returns GHOST_PROOFS_PANICKED. Only
 * GHOST_PROOFS_ACCEPTED accepts; every other status rejects.
 *
 * A proof of holding never goes on chain and the node checks none. The
 * function checks the proof only: issuing each challenge once, and taking the
 * roots from headers it accepts as current, are the caller's.
 *
 * Chain parameters, GHOST_PROOFS_CHAIN_PARAMS_BYTES bytes: as ghost_proofs.h.
 *
 * Context, GHOST_HOLD_CONTEXT_BYTES bytes:
 *   type 2 (GHOST_HOLD_TYPE_DATA_V2_0 then GHOST_HOLD_TYPE_DATA_V2_1), root
 *   32, marker-set root 32, verifier 32, challenge 32, cf 32, in that order.
 *   The root is the data tree root, the marker-set root the data spent-marker
 *   set root, both from headers, the verifier the verifier's own identity,
 *   the challenge its fresh challenge and cf the content fingerprint it asks
 *   about.
 *
 * Proof: as ghost_proofs.h, 1 to GHOST_PROOFS_PROOF_MAX_BYTES bytes, one
 * serialized proof optionally followed by zero bytes.
 */
#ifndef GHOST_HOLD_H
#define GHOST_HOLD_H

#include "ghost_proofs.h"

#define GHOST_HOLD_TYPE_DATA_V2_0 0x02
#define GHOST_HOLD_TYPE_DATA_V2_1 0x02

#define GHOST_HOLD_CONTEXT_BYTES 162

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Verifies a proof of holding against the context and the chain parameters.
 * Each non-null pointer must point to at least its length of readable bytes.
 * A null pointer, parameters or a context of the wrong length, or a type
 * other than DATA_V2 returns GHOST_PROOFS_BAD_ARGUMENT; an empty or oversized
 * proof, or one that is not a serialized proof followed only by zero bytes,
 * returns GHOST_PROOFS_MALFORMED_INPUT. Any other proof that does not verify
 * returns GHOST_PROOFS_REJECTED.
 */
int32_t ghost_verify_hold(const uint8_t *params, size_t params_len,
                          const uint8_t *context, size_t context_len,
                          const uint8_t *proof, size_t proof_len);

#ifdef __cplusplus
}
#endif

#endif /* GHOST_HOLD_H */
