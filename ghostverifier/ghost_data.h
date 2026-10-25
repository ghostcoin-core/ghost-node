/*
 * C interface to the data reveal verifier of ghost-proofs, added by the
 * ghostverifier crate (src/lib.rs) beside the coin reveal verifier of
 * ghost_proofs.h. Unlike ghost_proofs.h this header is not a copy of the ghost
 * repository's: ghost-proofs has no C interface for data reveals.
 *
 * Written by hand; every constant here must equal its namesake in src/lib.rs
 * or ghost_proofs.h, and tests/data_reveal.rs checks the Rust side.
 *
 * ABI: as ghost_proofs.h. The function is thread-safe, keeps no state between
 * calls, reads its buffers only during the call and never unwinds into the
 * caller: a caught panic returns GHOST_PROOFS_PANICKED. Only
 * GHOST_PROOFS_ACCEPTED accepts; every other status rejects.
 *
 * One function verifies both purposes, as ghost-proofs has one verifier for
 * both: a data reveal and a data revoke differ only in the purpose byte.
 *
 * Chain parameters, GHOST_PROOFS_CHAIN_PARAMS_BYTES bytes: as ghost_proofs.h.
 *
 * Statement, GHOST_DATA_REVEAL_BYTES bytes:
 *   purpose 1 (GHOST_DATA_PURPOSE_REVEAL or GHOST_DATA_PURPOSE_REVOKE), root
 *   32, marker 32, party 32, fee 32, rule 32, cf 32, in that order, so cf
 *   is at bytes 161 to 193. The party is the verifier-or-recipient address
 *   left-padded with zeros to 32 bytes, the fee a 32-byte amount word and cf
 *   the content fingerprint the data reveal carries, which the proof binds.
 *
 * Proof: as ghost_proofs.h, 1 to GHOST_PROOFS_PROOF_MAX_BYTES bytes, one
 * serialized proof optionally followed by zero bytes.
 *
 * The data reveal fee is not settled, and the verifier of the pinned
 * ghost-proofs rejects every data reveal for it, whatever the proof: a
 * well-formed call returns GHOST_DATA_FEE_UNSETTLED.
 */
#ifndef GHOST_DATA_H
#define GHOST_DATA_H

#include "ghost_proofs.h"

#define GHOST_DATA_FEE_UNSETTLED 5

#define GHOST_DATA_PURPOSE_REVEAL 0x02
#define GHOST_DATA_PURPOSE_REVOKE 0x03

#define GHOST_DATA_REVEAL_BYTES 193

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Verifies a data reveal or revoke proof against the statement and the chain
 * parameters. Each non-null pointer must point to at least its length of
 * readable bytes. A null pointer, parameters or a statement of the wrong
 * length, or an unknown purpose returns GHOST_PROOFS_BAD_ARGUMENT; an empty
 * or oversized proof, or one that is not a serialized proof followed only by
 * zero bytes, returns GHOST_PROOFS_MALFORMED_INPUT.
 */
int32_t ghost_verify_data_reveal(const uint8_t *params, size_t params_len,
                                 const uint8_t *statement, size_t statement_len,
                                 const uint8_t *proof, size_t proof_len);

#ifdef __cplusplus
}
#endif

#endif /* GHOST_DATA_H */
