//! Checks the proof of holding C interface of this crate. The argument checks
//! and the header run with no feature; the real proofs need the test-only
//! prover:
//!
//!     cargo test --release --locked
//!     cargo test --release --locked --features unsettled-points-test
//!
//! The chain constants, secrets and zero-knowledge randomness are fixed test
//! values, never a network's.

use ghost_proofs::ffi::{
    CHAIN_PARAMS_BYTES, GHOST_PROOFS_BAD_ARGUMENT, GHOST_PROOFS_MALFORMED_INPUT, PROOF_MAX_BYTES,
    chain_params_to_bytes,
};
use ghost_proofs::{COIN_V2, ChainParams, DATA_V2, HoldContext, PROTOCOL_VERSION_1};
use ghostverifier::{HOLD_CONTEXT_BYTES, ghost_verify_hold, hold_context_from_bytes, hold_context_to_bytes};

/// Example chain constants: chain id 1234, version 1 and a domain of 0x47
/// bytes, as in tests/data_reveal.rs.
fn params() -> ChainParams {
    ChainParams {
        chain_id: 1234u64.to_be_bytes(),
        version: PROTOCOL_VERSION_1,
        domain: [0x47; 32],
    }
}

fn context(type_tag: [u8; 2]) -> HoldContext {
    HoldContext {
        type_tag,
        root: [1; 32],
        marker_set_root: [2; 32],
        verifier: [3; 32],
        challenge: [4; 32],
        cf: [5; 32],
    }
}

/// The shipped verifier through its C function.
fn shipped_c(params: &[u8], context: &[u8], proof: &[u8]) -> i32 {
    // SAFETY: each pointer points to its slice's length of bytes.
    unsafe {
        ghost_verify_hold(
            params.as_ptr(),
            params.len(),
            context.as_ptr(),
            context.len(),
            proof.as_ptr(),
            proof.len(),
        )
    }
}

/// The value of a #define in ghost_hold.h or ghost_proofs.h.
fn header_define(name: &str) -> i64 {
    let headers = [include_str!("../ghost_hold.h"), include_str!("../ghost_proofs.h")];
    for line in headers.iter().flat_map(|h| h.lines()) {
        let mut words = line.split_whitespace();
        if words.next() == Some("#define") && words.next() == Some(name) {
            let value = words.next().expect("a value");
            return match value.strip_prefix("0x") {
                Some(hex) => i64::from_str_radix(hex, 16).expect("hex"),
                None => value.parse().expect("decimal"),
            };
        }
    }
    panic!("no #define {name}");
}

#[test]
fn header_matches() {
    assert_eq!(header_define("GHOST_HOLD_CONTEXT_BYTES"), HOLD_CONTEXT_BYTES as i64);
    assert_eq!(header_define("GHOST_HOLD_TYPE_DATA_V2_0"), DATA_V2[0] as i64);
    assert_eq!(header_define("GHOST_HOLD_TYPE_DATA_V2_1"), DATA_V2[1] as i64);
    assert_eq!(header_define("GHOST_PROOFS_CHAIN_PARAMS_BYTES"), CHAIN_PARAMS_BYTES as i64);
}

#[test]
fn context_round_trips() {
    let ctx = context(DATA_V2);
    let bytes = hold_context_to_bytes(&ctx);
    assert_eq!(&bytes[..2], &DATA_V2);
    assert_eq!(&bytes[130..], &[5; 32]);
    assert_eq!(hold_context_from_bytes(&bytes), ctx);
}

#[test]
fn bad_arguments() {
    let p = chain_params_to_bytes(&params());
    let ctx = hold_context_to_bytes(&context(DATA_V2));
    let proof = [1u8; 64];
    assert_eq!(shipped_c(&p[1..], &ctx, &proof), GHOST_PROOFS_BAD_ARGUMENT);
    assert_eq!(shipped_c(&p, &ctx[1..], &proof), GHOST_PROOFS_BAD_ARGUMENT);
    assert_eq!(shipped_c(&p, &hold_context_to_bytes(&context(COIN_V2)), &proof), GHOST_PROOFS_BAD_ARGUMENT);
    assert_eq!(shipped_c(&p, &hold_context_to_bytes(&context([1, 2])), &proof), GHOST_PROOFS_BAD_ARGUMENT);
    // SAFETY: null pointers are refused before any read.
    let null = unsafe { ghost_verify_hold(std::ptr::null(), 0, ctx.as_ptr(), ctx.len(), proof.as_ptr(), 1) };
    assert_eq!(null, GHOST_PROOFS_BAD_ARGUMENT);
    assert_eq!(shipped_c(&p, &ctx, &[]), GHOST_PROOFS_MALFORMED_INPUT);
    assert_eq!(shipped_c(&p, &ctx, &vec![1u8; PROOF_MAX_BYTES + 1]), GHOST_PROOFS_MALFORMED_INPUT);
    assert_eq!(shipped_c(&p, &ctx, &proof), GHOST_PROOFS_MALFORMED_INPUT);
}

#[cfg(feature = "unsettled-points-test")]
mod real {
    use super::*;
    use ghost_proofs::ffi::{GHOST_PROOFS_ACCEPTED, GHOST_PROOFS_REJECTED};
    use ghost_proofs::{
        EMPTY_RULE, ProofError, SaltedHoldOpening, TREE_DEPTH, Tree, data_commitment_v2, data_fingerprint_v2,
        data_marker_v2, empty_leaf, merkle_root, tree_node,
    };
    use ghostverifier::{prove_salted_hold, test_absence_witness};

    /// A real proof of holding of one data commitment at position 2 against
    /// a marker set holding two other markers, its context, and the opening.
    fn prove() -> (HoldContext, Vec<u8>, SaltedHoldOpening) {
        let (s, r, b, salt, cf) = ([1; 32], [2; 32], [3; 32], [0x5a; 16], [4; 32]);
        let mut path = [[0u8; 32]; TREE_DEPTH];
        let mut empty = empty_leaf();
        for (level, sibling) in path.iter_mut().enumerate() {
            *sibling = empty;
            empty = tree_node(Tree::Data, level as u8, &empty, &empty);
        }
        path[0] = [9; 32];
        let leaf = data_commitment_v2(&data_fingerprint_v2(&s, &r, &b, &salt, &cf, &EMPTY_RULE));
        let (absence, marker_set_root) = test_absence_witness(&[[0x11; 32], [0xee; 32]], &data_marker_v2(&r, &b, &salt));
        let opening = SaltedHoldOpening {
            s,
            r,
            b,
            salt,
            cf,
            rule: EMPTY_RULE,
            position: 2,
            path,
            absence,
        };
        let ctx = HoldContext {
            type_tag: DATA_V2,
            root: merkle_root(Tree::Data, &leaf, 2, &path),
            marker_set_root,
            verifier: [0x33; 32],
            challenge: [0x44; 32],
            cf,
        };
        let proof = prove_salted_hold(&params(), &opening, &ctx, [0x5d; 32]).expect("honest proof");
        (ctx, proof.into_bytes(), opening)
    }

    #[test]
    fn real_proof() {
        let p = chain_params_to_bytes(&params());
        let (ctx, proof, opening) = prove();
        let bytes = hold_context_to_bytes(&ctx);
        assert_eq!(shipped_c(&p, &bytes, &proof), GHOST_PROOFS_ACCEPTED);
        let mut padded = proof.clone();
        padded.resize(proof.len() + 100, 0);
        assert_eq!(shipped_c(&p, &bytes, &padded), GHOST_PROOFS_ACCEPTED);

        // Each context field changed by one byte is rejected.
        for at in [2, 34, 66, 98, 130, HOLD_CONTEXT_BYTES - 1] {
            let mut bad = bytes;
            bad[at] ^= 1;
            assert_eq!(shipped_c(&p, &bad, &proof), GHOST_PROOFS_REJECTED, "context byte {at}");
        }
        let mut other = params();
        other.chain_id = 1235u64.to_be_bytes();
        assert_eq!(shipped_c(&chain_params_to_bytes(&other), &bytes, &proof), GHOST_PROOFS_REJECTED);
        let mut flipped = proof.clone();
        let mid = flipped.len() / 2;
        flipped[mid] ^= 1;
        assert_ne!(shipped_c(&p, &bytes, &flipped), GHOST_PROOFS_ACCEPTED);

        // Once the marker is in the set, the honest prover has no witness.
        let mut after = ctx.clone();
        after.marker_set_root = [0x77; 32];
        assert_eq!(
            prove_salted_hold(&params(), &opening, &after, [0x5d; 32]).err(),
            Some(ProofError::NotInMarkerSet)
        );
    }
}
