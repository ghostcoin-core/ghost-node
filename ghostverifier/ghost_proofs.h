/*
 * C interface to the coin reveal verifier of ghost-proofs (src/ffi.rs).
 *
 * Written by hand; every constant here must equal its namesake in src/ffi.rs,
 * and tests/ffi.rs checks the Rust side.
 *
 * ABI: link the static library libghost_proofs.a built from this crate with
 * the default panic = "unwind". The function is thread-safe, keeps no state
 * between calls, reads its buffers only during the call and never unwinds
 * into the caller: a caught panic returns GHOST_PROOFS_PANICKED. Only
 * GHOST_PROOFS_ACCEPTED accepts; every other status rejects.
 *
 * Chain parameters, GHOST_PROOFS_CHAIN_PARAMS_BYTES bytes:
 *   chain_id 8, version 2, domain 32, in that order.
 *
 * Statement, GHOST_PROOFS_COIN_REVEAL_BYTES bytes:
 *   root 32, marker 32, remainder 32, remainder_note 156, recipient 20,
 *   out 32, fee 32, rule 32, in that order.
 *
 * Proof, 1 to GHOST_PROOFS_PROOF_MAX_BYTES bytes: one serialized proof,
 * optionally followed by zero bytes, so a zero-padded proof field can be
 * passed as it is. A non-zero byte after the serialization is malformed. The
 * maximum, 2 MiB, leaves room above a coin reveal proof (about 1.19 MB).
 */
#ifndef GHOST_PROOFS_H
#define GHOST_PROOFS_H

#include <stddef.h>
#include <stdint.h>

#define GHOST_PROOFS_ACCEPTED 0
#define GHOST_PROOFS_REJECTED 1
#define GHOST_PROOFS_MALFORMED_INPUT 2
#define GHOST_PROOFS_BAD_ARGUMENT 3
#define GHOST_PROOFS_PANICKED 4

#define GHOST_PROOFS_CHAIN_PARAMS_BYTES 42
#define GHOST_PROOFS_COIN_REVEAL_BYTES 368
#define GHOST_PROOFS_PROOF_MAX_BYTES 2097152

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Verifies a coin reveal proof against the statement and the chain
 * parameters. Each non-null pointer must point to at least its length of
 * readable bytes. A null pointer, or parameters or a statement of the wrong
 * length, returns GHOST_PROOFS_BAD_ARGUMENT without reading the buffers; an
 * empty or oversized proof returns GHOST_PROOFS_MALFORMED_INPUT.
 */
int32_t ghost_verify_coin_reveal(const uint8_t *params, size_t params_len,
                                 const uint8_t *statement, size_t statement_len,
                                 const uint8_t *proof, size_t proof_len);

#ifdef __cplusplus
}
#endif

#endif /* GHOST_PROOFS_H */
