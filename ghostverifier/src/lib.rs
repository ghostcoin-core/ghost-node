//! The reveal verifiers of ghost-proofs as a static library for the node.
//!
//! The node links `libghostverifier.a` through cgo and calls
//! [`ghost_verify_coin_reveal`], declared in `ghost_proofs.h` beside this
//! crate, a copy of the header at the pinned revision of ghost-proofs, and
//! [`ghost_verify_data_reveal`], declared in `ghost_data.h`. The coin
//! function is the one the ghost repository's prover is checked against.
//!
//! ghost-proofs has no C interface for data reveals, so this crate adds one
//! around its one data verifier, `verify_salted_data_reveal`, which checks a
//! reveal and a revoke of a salted data commitment alike: the purpose is the
//! first byte of the statement. The commitment binds the fee reserve with
//! F_d. The verifier accepts a real proof of a data reveal or revoke whose fee
//! is at most the reserve `DATA_RESERVE` and whose rule is empty; a fee above
//! the reserve (`FeeAboveReserve`) or a non-empty rule (`RuleNotEmpty`) is a
//! plain rejection, `GHOST_PROOFS_REJECTED`, like any other proof that does
//! not verify. The library needs no cargo feature: neither `build/ci.go` nor
//! the release build enables one.
//!
//! It also adds a C interface around the shipped verifier of the proof of
//! holding, `verify_hold`: [`ghost_verify_hold`], declared in `ghost_hold.h`.
//! A proof of holding never goes on chain; the node checks none. The function
//! is for a verifier that holds the node's headers, and for the node's tests.
//! Only the prover of a proof of holding is test-only, behind the
//! `unsettled-points-test` feature ([`prove_salted_hold`]).

use std::panic::{AssertUnwindSafe, catch_unwind};

use ghost_proofs::ffi::{
    CHAIN_PARAMS_BYTES, COIN_REVEAL_BYTES, GHOST_PROOFS_ACCEPTED, GHOST_PROOFS_BAD_ARGUMENT,
    GHOST_PROOFS_MALFORMED_INPUT, GHOST_PROOFS_PANICKED, GHOST_PROOFS_REJECTED, PROOF_MAX_BYTES,
    chain_params_from_bytes, verify_coin_reveal_bytes,
};
use ghost_proofs::{DataPurpose, DataReveal, HoldContext, Proof, ProofError, verify_hold, verify_salted_data_reveal};

pub use ghost_proofs::ffi::ghost_verify_coin_reveal;
pub use ghost_proofs::{PURPOSE_REVEAL, PURPOSE_REVOKE};

/// The test-only prover of a proof of holding and the absence witness of a
/// marker in a marker set built from the genesis set, for tests and the
/// fixture generators only. The release library never has them.
#[cfg(feature = "unsettled-points-test")]
pub use ghost_proofs::{prove_salted_hold, prove_salted_hold_claiming, test_absence_witness};

/// Length of a data reveal statement: the purpose (1), then the root, marker,
/// party, fee, rule and content fingerprint `cf` (32 each), in that order, so
/// `cf` sits at 161..193.
pub const DATA_REVEAL_BYTES: usize = 1 + 6 * 32;

/// Decodes a data reveal statement. A purpose other than `PURPOSE_REVEAL` or
/// `PURPOSE_REVOKE` is `ProofError::UnknownPurpose`.
pub fn data_reveal_from_bytes(bytes: &[u8; DATA_REVEAL_BYTES]) -> Result<DataReveal, ProofError> {
    let word = |i: usize| -> [u8; 32] { bytes[1 + 32 * i..1 + 32 * (i + 1)].try_into().expect("32 bytes") };
    Ok(DataReveal {
        purpose: DataPurpose::from_code(bytes[0])?,
        root: word(0),
        marker: word(1),
        party: word(2),
        fee: word(3),
        rule: word(4),
        cf: word(5),
    })
}

/// Encodes a data reveal statement in the layout of ghost_data.h.
pub fn data_reveal_to_bytes(tx: &DataReveal) -> [u8; DATA_REVEAL_BYTES] {
    let mut b = [0u8; DATA_REVEAL_BYTES];
    b[0] = tx.purpose.code();
    for (i, w) in [&tx.root, &tx.marker, &tx.party, &tx.fee, &tx.rule, &tx.cf].into_iter().enumerate() {
        b[1 + 32 * i..1 + 32 * (i + 1)].copy_from_slice(w);
    }
    b
}

/// A coin reveal statement with a non-empty rule. ghost-proofs rejects it
/// with `RuleNotEmpty` before any proof work, so verifying a proof against it
/// only frames the proof: see [`framed`].
const FRAMING_STATEMENT: [u8; COIN_REVEAL_BYTES] = {
    let mut s = [0u8; COIN_REVEAL_BYTES];
    s[COIN_REVEAL_BYTES - 1] = 1;
    s
};

/// Reports whether bytes are one serialized proof followed by zero bytes or
/// nothing. ghost-proofs keeps its framing to itself, so this asks the coin
/// byte verifier, which answers `GHOST_PROOFS_MALFORMED_INPUT` for anything
/// else and `GHOST_PROOFS_REJECTED` for a framed proof against
/// [`FRAMING_STATEMENT`]. Any other answer is not framed.
fn framed(bytes: &[u8]) -> bool {
    verify_coin_reveal_bytes(&[0; CHAIN_PARAMS_BYTES], &FRAMING_STATEMENT, bytes) == GHOST_PROOFS_REJECTED
}

/// Returns the length of the serialized proof at the start of a proof field,
/// or `None` unless the field is one serialized proof followed only by zero
/// bytes. A prefix shorter than the serialization never parses and every
/// longer one does, so the length is found by bisection between the last
/// non-zero byte and the end.
fn serialized_len(proof: &[u8]) -> Option<usize> {
    if !framed(proof) {
        return None;
    }
    let mut lo = proof.iter().rposition(|&b| b != 0).map_or(1, |i| i + 1);
    let mut hi = proof.len();
    // Most proofs end in a non-zero byte: one probe settles it.
    if lo < hi && framed(&proof[..lo]) {
        hi = lo;
    }
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if framed(&proof[..mid]) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    Some(hi)
}

fn verify_data_unguarded(params: &[u8], statement: &[u8], proof: &[u8]) -> i32 {
    let (Ok(params), Ok(statement)) = (
        <&[u8; CHAIN_PARAMS_BYTES]>::try_from(params),
        <&[u8; DATA_REVEAL_BYTES]>::try_from(statement),
    ) else {
        return GHOST_PROOFS_BAD_ARGUMENT;
    };
    if proof.is_empty() || proof.len() > PROOF_MAX_BYTES {
        return GHOST_PROOFS_MALFORMED_INPUT;
    }
    let Ok(tx) = data_reveal_from_bytes(statement) else {
        return GHOST_PROOFS_BAD_ARGUMENT;
    };
    let Some(len) = serialized_len(proof) else {
        return GHOST_PROOFS_MALFORMED_INPUT;
    };
    let params = chain_params_from_bytes(params);
    // A fee above the reserve, a non-empty rule and every other failure but
    // a malformed proof are plain rejections.
    match verify_salted_data_reveal(&params, &tx, &Proof::from_bytes(proof[..len].to_vec())) {
        Ok(()) => GHOST_PROOFS_ACCEPTED,
        Err(ProofError::MalformedProof) => GHOST_PROOFS_MALFORMED_INPUT,
        Err(_) => GHOST_PROOFS_REJECTED,
    }
}

/// Verifies a data reveal or revoke proof given as bytes in the layout of
/// ghost_data.h with the shipped verifier of ghost-proofs. Never panics.
pub fn verify_data_reveal_bytes(params: &[u8], statement: &[u8], proof: &[u8]) -> i32 {
    catch_unwind(AssertUnwindSafe(|| verify_data_unguarded(params, statement, proof))).unwrap_or(GHOST_PROOFS_PANICKED)
}

/// Verifies a data reveal or revoke proof against the statement and the
/// chain parameters, as declared in ghost_data.h.
///
/// # Safety
///
/// Each non-null pointer must point to at least its length of readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ghost_verify_data_reveal(
    params: *const u8,
    params_len: usize,
    statement: *const u8,
    statement_len: usize,
    proof: *const u8,
    proof_len: usize,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        if params.is_null() || statement.is_null() || proof.is_null() {
            return GHOST_PROOFS_BAD_ARGUMENT;
        }
        if params_len != CHAIN_PARAMS_BYTES || statement_len != DATA_REVEAL_BYTES {
            return GHOST_PROOFS_BAD_ARGUMENT;
        }
        if proof_len == 0 || proof_len > PROOF_MAX_BYTES {
            return GHOST_PROOFS_MALFORMED_INPUT;
        }
        // SAFETY: the pointers are not null and the caller guarantees each
        // points to at least its length of readable bytes.
        let (params, statement, proof) = unsafe {
            (
                std::slice::from_raw_parts(params, params_len),
                std::slice::from_raw_parts(statement, statement_len),
                std::slice::from_raw_parts(proof, proof_len),
            )
        };
        verify_data_reveal_bytes(params, statement, proof)
    }))
    .unwrap_or(GHOST_PROOFS_PANICKED)
}

/// Length of a proof of holding context: the type (2), then the root, the
/// marker-set root, the verifier, the challenge and the content fingerprint
/// `cf` (32 each), in that order.
pub const HOLD_CONTEXT_BYTES: usize = 2 + 5 * 32;

/// Decodes a proof of holding context in the layout of ghost_hold.h. Any type
/// decodes; the verifier refuses every type but `DATA_V2`.
pub fn hold_context_from_bytes(bytes: &[u8; HOLD_CONTEXT_BYTES]) -> HoldContext {
    let word = |i: usize| -> [u8; 32] { bytes[2 + 32 * i..2 + 32 * (i + 1)].try_into().expect("32 bytes") };
    HoldContext {
        type_tag: [bytes[0], bytes[1]],
        root: word(0),
        marker_set_root: word(1),
        verifier: word(2),
        challenge: word(3),
        cf: word(4),
    }
}

/// Encodes a proof of holding context in the layout of ghost_hold.h.
pub fn hold_context_to_bytes(ctx: &HoldContext) -> [u8; HOLD_CONTEXT_BYTES] {
    let mut b = [0u8; HOLD_CONTEXT_BYTES];
    b[..2].copy_from_slice(&ctx.type_tag);
    for (i, w) in [&ctx.root, &ctx.marker_set_root, &ctx.verifier, &ctx.challenge, &ctx.cf].into_iter().enumerate() {
        b[2 + 32 * i..2 + 32 * (i + 1)].copy_from_slice(w);
    }
    b
}

fn verify_hold_unguarded(params: &[u8], context: &[u8], proof: &[u8]) -> i32 {
    let (Ok(params), Ok(context)) = (
        <&[u8; CHAIN_PARAMS_BYTES]>::try_from(params),
        <&[u8; HOLD_CONTEXT_BYTES]>::try_from(context),
    ) else {
        return GHOST_PROOFS_BAD_ARGUMENT;
    };
    if proof.is_empty() || proof.len() > PROOF_MAX_BYTES {
        return GHOST_PROOFS_MALFORMED_INPUT;
    }
    let ctx = hold_context_from_bytes(context);
    if ctx.check().is_err() {
        return GHOST_PROOFS_BAD_ARGUMENT;
    }
    let Some(len) = serialized_len(proof) else {
        return GHOST_PROOFS_MALFORMED_INPUT;
    };
    let params = chain_params_from_bytes(params);
    match verify_hold(&params, &ctx, &Proof::from_bytes(proof[..len].to_vec())) {
        Ok(()) => GHOST_PROOFS_ACCEPTED,
        Err(ProofError::MalformedProof) => GHOST_PROOFS_MALFORMED_INPUT,
        Err(_) => GHOST_PROOFS_REJECTED,
    }
}

/// Verifies a proof of holding given as bytes in the layout of ghost_hold.h
/// with the shipped verifier of ghost-proofs. Never panics.
pub fn verify_hold_bytes(params: &[u8], context: &[u8], proof: &[u8]) -> i32 {
    catch_unwind(AssertUnwindSafe(|| verify_hold_unguarded(params, context, proof))).unwrap_or(GHOST_PROOFS_PANICKED)
}

/// Verifies a proof of holding against the context and the chain parameters,
/// as declared in ghost_hold.h. The challenge book is the caller's: this
/// checks the proof only.
///
/// # Safety
///
/// Each non-null pointer must point to at least its length of readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ghost_verify_hold(
    params: *const u8,
    params_len: usize,
    context: *const u8,
    context_len: usize,
    proof: *const u8,
    proof_len: usize,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        if params.is_null() || context.is_null() || proof.is_null() {
            return GHOST_PROOFS_BAD_ARGUMENT;
        }
        if params_len != CHAIN_PARAMS_BYTES || context_len != HOLD_CONTEXT_BYTES {
            return GHOST_PROOFS_BAD_ARGUMENT;
        }
        if proof_len == 0 || proof_len > PROOF_MAX_BYTES {
            return GHOST_PROOFS_MALFORMED_INPUT;
        }
        // SAFETY: the pointers are not null and the caller guarantees each
        // points to at least its length of readable bytes.
        let (params, context, proof) = unsafe {
            (
                std::slice::from_raw_parts(params, params_len),
                std::slice::from_raw_parts(context, context_len),
                std::slice::from_raw_parts(proof, proof_len),
            )
        };
        verify_hold_bytes(params, context, proof)
    }))
    .unwrap_or(GHOST_PROOFS_PANICKED)
}
