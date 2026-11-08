/*
 * C interface to the coin reveal verifiers and the root proof verifiers of
 * ghost-proofs (src/ffi.rs).
 *
 * Written by hand; every constant here must equal its namesake in src/ffi.rs,
 * and tests/ffi.rs checks the Rust side.
 *
 * ABI: link the static library libghost_proofs.a built from this crate with
 * the default panic = "unwind". Each function is thread-safe, keeps no state
 * between calls, reads its buffers only during the call and never unwinds
 * into the caller: a caught panic returns GHOST_PROOFS_PANICKED. Only
 * GHOST_PROOFS_ACCEPTED accepts; every other status rejects.
 *
 * Chain parameters, GHOST_PROOFS_CHAIN_PARAMS_BYTES bytes:
 *   chain_id 8, version 2, domain 32, in that order.
 *
 * Statement of ghost_verify_coin_reveal, GHOST_PROOFS_COIN_REVEAL_BYTES bytes:
 *   root 32, marker 32, remainder 32, remainder_note 156, recipient 20,
 *   out 32, fee 32, rule 32, in that order.
 *
 * Statement of ghost_verify_coin_reveal_v2 (statement S1 version 2, the
 * ordinary class), GHOST_PROOFS_COIN_REVEAL_V2_BYTES bytes:
 *   root 32, marker 32, remainder 32, remainder_note 380, recipient 20,
 *   out 32, fee 32, in that order. There is no rule.
 *
 * Proof, 1 to GHOST_PROOFS_PROOF_MAX_BYTES bytes: one serialized proof,
 * optionally followed by zero bytes, so a zero-padded proof field can be
 * passed as it is. A non-zero byte after the serialization is malformed. The
 * maximum, 2 MiB, leaves room above a coin reveal proof (about 1.19 MB).
 *
 * Root proofs. ghost_verify_bundle_root verifies the proof a block carries
 * for a bundle of private reveals, the shrink of the bundle's root;
 * ghost_verify_public_root verifies the public root proof, the shrink over
 * the ML-DSA-44 chunk proofs of the public transactions. Each accepts only a
 * shrink proof at index 0 made under the key for exactly the root inputs.
 *
 * Root key, GHOST_PROOFS_ROOT_KEY_BYTES bytes, 31 words of 4 bytes little
 * endian: the path (GHOST_PROOFS_ROOT_KEY_BUNDLE or GHOST_PROOFS_ROOT_KEY_PUBLIC),
 *   the shrink's log_blowup and num_queries, the lanes and height of each of
 *   its five tables (wires, arithmetic, permutation, bits, packing), the nine
 *   elements of its preprocessed commitment, the nine of its children's key
 *   digest. The node pins the key of spec 07's shapes, written once by
 *   root_key_to_bytes in src/ffi.rs; a key of the other path, or one outside
 *   the bounds of src/ffi.rs, is a bad argument.
 *
 * Root inputs, GHOST_PROOFS_ROOT_BINDING_BYTES bytes and one or more items:
 *   chain_id 8, protocol_version 2, statement_version 1, then the items in
 *   block order, one byte a public value. A bundle's item is a version 2
 *   coin reveal's public values, GHOST_PROOFS_REVEAL_PUBLIC_BYTES bytes (its
 *   607 binding field bytes, then its 32-byte binding digest); a public
 *   transaction's is its account 20, key identity 32 and transaction hash 32,
 *   GHOST_PROOFS_PUBLIC_TX_BYTES bytes.
 *
 * Root proof field, exactly GHOST_PROOFS_PROOF_FIELD_BYTES bytes: one
 * serialized shrink proof followed by zero bytes. Any other length, a field
 * that does not decode, or a non-zero byte after the proof is malformed.
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
#define GHOST_PROOFS_COIN_REVEAL_V2_BYTES 560
#define GHOST_PROOFS_PROOF_MAX_BYTES 2097152

#define GHOST_PROOFS_ROOT_KEY_BUNDLE 1
#define GHOST_PROOFS_ROOT_KEY_PUBLIC 2
#define GHOST_PROOFS_ROOT_KEY_BYTES 124
#define GHOST_PROOFS_ROOT_BINDING_BYTES 11
#define GHOST_PROOFS_REVEAL_PUBLIC_BYTES 639
#define GHOST_PROOFS_PUBLIC_TX_BYTES 84
#define GHOST_PROOFS_PROOF_FIELD_BYTES 1310720

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

/*
 * Verifies a version 2 coin reveal proof (statement S1 version 2) against
 * the statement and the chain parameters, with the same rules for null
 * pointers, lengths and the proof as ghost_verify_coin_reveal. The statement
 * is GHOST_PROOFS_COIN_REVEAL_V2_BYTES long.
 */
int32_t ghost_verify_coin_reveal_v2(const uint8_t *params, size_t params_len,
                                    const uint8_t *statement, size_t statement_len,
                                    const uint8_t *proof, size_t proof_len);

/*
 * Verifies a bundle's root proof field against the bundle root key and the
 * root inputs (the binding, then the ordered coin reveals' public values).
 * Each non-null pointer must point to at least its length of readable bytes.
 * A null pointer, a key that is not GHOST_PROOFS_ROOT_KEY_BYTES long or not a
 * bundle key, or inputs that are not the binding and a whole number of one or
 * more items, returns GHOST_PROOFS_BAD_ARGUMENT; a proof field that is not
 * GHOST_PROOFS_PROOF_FIELD_BYTES long returns GHOST_PROOFS_MALFORMED_INPUT.
 */
int32_t ghost_verify_bundle_root(const uint8_t *key, size_t key_len,
                                 const uint8_t *inputs, size_t inputs_len,
                                 const uint8_t *proof, size_t proof_len);

/*
 * Verifies the public root proof field against the public root key and the
 * root inputs (the binding, then the ordered public transactions' account,
 * key identity and transaction hash), with the same rules as
 * ghost_verify_bundle_root.
 */
int32_t ghost_verify_public_root(const uint8_t *key, size_t key_len,
                                 const uint8_t *inputs, size_t inputs_len,
                                 const uint8_t *proof, size_t proof_len);

#ifdef __cplusplus
}
#endif

#endif /* GHOST_PROOFS_H */
