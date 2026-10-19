//! The reveal verifiers of ghost-proofs as a static library for the node.
//!
//! The node links `libghostverifier.a` through cgo and calls
//! [`ghost_verify_coin_reveal`], declared in `ghost_proofs.h` beside this
//! crate, a copy of the header at the pinned revision of ghost-proofs, and
//! [`ghost_verify_data_reveal`], declared in `ghost_data.h`. The coin
//! function is the one the ghost repository's prover is checked against.
//!
//! ghost-proofs has no C interface for data reveals, so this crate adds one
//! around its one data verifier, `verify_data_reveal`, which checks a reveal
//! and a revoke alike: the purpose is the first byte of the statement. At the
//! pinned revision that verifier rejects every data reveal with
//! `DataFeeUnsettled`, whatever the proof, until the data reveal fee is
//! settled; [`ghost_verify_data_reveal`] answers [`GHOST_DATA_FEE_UNSETTLED`]
//! for it. The accept path, [`ghost_verify_data_reveal_unsettled`], exists
//! only with the test-only feature `unsettled-points-test`, which neither
//! `build/ci.go` nor the release build enables.

use std::panic::{AssertUnwindSafe, catch_unwind};

use ghost_proofs::ffi::{
    CHAIN_PARAMS_BYTES, COIN_REVEAL_BYTES, GHOST_PROOFS_ACCEPTED, GHOST_PROOFS_BAD_ARGUMENT,
    GHOST_PROOFS_MALFORMED_INPUT, GHOST_PROOFS_PANICKED, GHOST_PROOFS_REJECTED, PROOF_MAX_BYTES,
    chain_params_from_bytes, verify_coin_reveal_bytes,
};
use ghost_proofs::{ChainParams, DataPurpose, DataReveal, Proof, ProofError, verify_data_reveal};

pub use ghost_proofs::ffi::ghost_verify_coin_reveal;
pub use ghost_proofs::{PURPOSE_REVEAL, PURPOSE_REVOKE};

/// Length of a data reveal statement: the purpose (1), then the root, marker,
/// party, fee and rule (32 each), in that order.
pub const DATA_REVEAL_BYTES: usize = 1 + 5 * 32;

/// The status of a data reveal the verifier rejects because the data reveal
/// fee is not settled. It rejects, like every status but
/// `GHOST_PROOFS_ACCEPTED`.
pub const GHOST_DATA_FEE_UNSETTLED: i32 = 5;

/// Signature of the ghost-proofs data verifiers.
type DataVerify = fn(&ChainParams, &DataReveal, &Proof) -> Result<(), ProofError>;

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
    })
}

/// Encodes a data reveal statement in the layout of ghost_data.h.
pub fn data_reveal_to_bytes(tx: &DataReveal) -> [u8; DATA_REVEAL_BYTES] {
    let mut b = [0u8; DATA_REVEAL_BYTES];
    b[0] = tx.purpose.code();
    for (i, w) in [&tx.root, &tx.marker, &tx.party, &tx.fee, &tx.rule].into_iter().enumerate() {
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

fn verify_data_unguarded(params: &[u8], statement: &[u8], proof: &[u8], verify: DataVerify) -> i32 {
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
    match verify(&params, &tx, &Proof::from_bytes(proof[..len].to_vec())) {
        Ok(()) => GHOST_PROOFS_ACCEPTED,
        Err(ProofError::MalformedProof) => GHOST_PROOFS_MALFORMED_INPUT,
        Err(ProofError::DataFeeUnsettled) => GHOST_DATA_FEE_UNSETTLED,
        Err(_) => GHOST_PROOFS_REJECTED,
    }
}

fn verify_data_guarded(params: &[u8], statement: &[u8], proof: &[u8], verify: DataVerify) -> i32 {
    catch_unwind(AssertUnwindSafe(|| verify_data_unguarded(params, statement, proof, verify)))
        .unwrap_or(GHOST_PROOFS_PANICKED)
}

/// The checks of the C functions, then the verifier on the buffers.
///
/// # Safety
///
/// Each non-null pointer must point to at least its length of readable bytes.
unsafe fn verify_data_raw(
    params: *const u8,
    params_len: usize,
    statement: *const u8,
    statement_len: usize,
    proof: *const u8,
    proof_len: usize,
    verify: DataVerify,
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
        verify_data_guarded(params, statement, proof, verify)
    }))
    .unwrap_or(GHOST_PROOFS_PANICKED)
}

/// Verifies a data reveal or revoke proof given as bytes in the layout of
/// ghost_data.h with the shipped verifier of ghost-proofs. Never panics.
pub fn verify_data_reveal_bytes(params: &[u8], statement: &[u8], proof: &[u8]) -> i32 {
    verify_data_guarded(params, statement, proof, verify_data_reveal)
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
    // SAFETY: the caller's guarantee, passed on.
    unsafe { verify_data_raw(params, params_len, statement, statement_len, proof, proof_len, verify_data_reveal) }
}

/// [`verify_data_reveal_bytes`] with the test-only verifier that skips the
/// unsettled fee. Not in the release library.
#[cfg(feature = "unsettled-points-test")]
pub fn verify_data_reveal_unsettled_bytes(params: &[u8], statement: &[u8], proof: &[u8]) -> i32 {
    verify_data_guarded(params, statement, proof, ghost_proofs::verify_data_reveal_unsettled)
}

/// [`ghost_verify_data_reveal`] with the test-only verifier of ghost-proofs
/// that skips the unsettled fee, so a test can see a real data proof
/// accepted. Not in the release library: it exists only with the feature
/// `unsettled-points-test`.
///
/// # Safety
///
/// Each non-null pointer must point to at least its length of readable bytes.
#[cfg(feature = "unsettled-points-test")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ghost_verify_data_reveal_unsettled(
    params: *const u8,
    params_len: usize,
    statement: *const u8,
    statement_len: usize,
    proof: *const u8,
    proof_len: usize,
) -> i32 {
    // SAFETY: the caller's guarantee, passed on.
    unsafe {
        verify_data_raw(
            params,
            params_len,
            statement,
            statement_len,
            proof,
            proof_len,
            ghost_proofs::verify_data_reveal_unsettled,
        )
    }
}
