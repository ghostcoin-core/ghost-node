//! Checks the policy action C interface of this crate (ghost_action.h)
//! against a real KNOW_ACTION_v1 proof of the pinned prover, with the shipped
//! verifier:
//!
//!     cargo test --release --locked
//!
//! The chain constants, action key and zero-knowledge randomness are fixed
//! test values, never a network's.

use std::sync::OnceLock;

use ghost_proofs::ffi::{
    CHAIN_PARAMS_BYTES, GHOST_PROOFS_ACCEPTED, GHOST_PROOFS_BAD_ARGUMENT, GHOST_PROOFS_MALFORMED_INPUT,
    GHOST_PROOFS_REJECTED, chain_params_to_bytes,
};
use ghost_proofs::*;
use ghostverifier::{
    ACTION_STATEMENT_BYTES, ghost_verify_know_action, know_action_from_bytes, know_action_to_bytes,
    verify_know_action_bytes,
};

struct Fixture {
    params: Vec<u8>,
    statement: Vec<u8>,
    proof: Vec<u8>,
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let params = ChainParams {
            chain_id: 1234u64.to_be_bytes(),
            version: PROTOCOL_VERSION_1,
            domain: [0x47; 32],
        };
        let root = [0x61; 32];
        let salt = [0x62; 32];
        let s = KnowAction {
            policy_address: [0x50; POLICY_ADDRESS_BYTES],
            marker: [0x63; 32],
            action_nonce: 3,
            action_tag: policy_action_tag(&root, &salt),
            action_salt: salt,
            expected_remaining: amount_word(1_000_000),
            debit: amount_word(4_321),
            expiry: 77,
            calldata_hash: action_calldata_hash(b"calldata").expect("short calldata"),
        };
        let proof = prove_know_action(&params, &s, &root, [0x5b; 32]).expect("honest action proof");
        assert_eq!(verify_know_action(&params, &s, &proof), Ok(()));
        Fixture {
            params: chain_params_to_bytes(&params).to_vec(),
            statement: know_action_to_bytes(&s).to_vec(),
            proof: proof.as_bytes().to_vec(),
        }
    })
}

fn call(params: &[u8], statement: &[u8], proof: &[u8]) -> i32 {
    // SAFETY: each pointer is a live slice of its length.
    unsafe {
        ghost_verify_know_action(
            params.as_ptr(),
            params.len(),
            statement.as_ptr(),
            statement.len(),
            proof.as_ptr(),
            proof.len(),
        )
    }
}

#[test]
fn layout_round_trips() {
    let f = fixture();
    assert_eq!(ACTION_STATEMENT_BYTES, 228);
    assert_eq!(ACTION_PROOF_BYTES, 948_224);
    let s = know_action_from_bytes(f.statement.as_slice().try_into().unwrap());
    assert_eq!(know_action_to_bytes(&s).as_slice(), f.statement.as_slice());
}

#[test]
fn accepts_the_honest_proof_padded_or_not() {
    let f = fixture();
    assert!(f.proof.len() <= ACTION_PROOF_BYTES, "proof of {} bytes", f.proof.len());
    assert_eq!(call(&f.params, &f.statement, &f.proof), GHOST_PROOFS_ACCEPTED);
    let mut padded = f.proof.clone();
    padded.resize(ACTION_PROOF_BYTES, 0);
    assert_eq!(call(&f.params, &f.statement, &padded), GHOST_PROOFS_ACCEPTED);
    assert_eq!(verify_know_action_bytes(&f.params, &f.statement, &padded), GHOST_PROOFS_ACCEPTED);
}

#[test]
fn rejects_every_changed_input() {
    let f = fixture();
    for at in 0..ACTION_STATEMENT_BYTES {
        if at % 7 != 0 && at != ACTION_STATEMENT_BYTES - 1 {
            continue;
        }
        let mut s = f.statement.clone();
        s[at] ^= 1;
        assert_eq!(call(&f.params, &s, &f.proof), GHOST_PROOFS_REJECTED, "statement byte {at}");
    }
    for at in [0, 8, 9, 10, CHAIN_PARAMS_BYTES - 1] {
        let mut p = f.params.clone();
        p[at] ^= 1;
        assert_eq!(call(&p, &f.statement, &f.proof), GHOST_PROOFS_REJECTED, "params byte {at}");
    }
    let mut q = f.proof.clone();
    let mid = q.len() / 2;
    q[mid] ^= 1;
    assert_ne!(call(&f.params, &f.statement, &q), GHOST_PROOFS_ACCEPTED);
}

#[test]
fn refuses_bad_arguments() {
    let f = fixture();
    assert_eq!(call(&f.params[1..], &f.statement, &f.proof), GHOST_PROOFS_BAD_ARGUMENT);
    assert_eq!(call(&f.params, &f.statement[1..], &f.proof), GHOST_PROOFS_BAD_ARGUMENT);
    assert_eq!(call(&f.params, &f.statement, &[]), GHOST_PROOFS_MALFORMED_INPUT);
    let mut long = f.proof.clone();
    long.resize(ACTION_PROOF_BYTES + 1, 0);
    assert_eq!(call(&f.params, &f.statement, &long), GHOST_PROOFS_MALFORMED_INPUT);
    let mut trailing = f.proof.clone();
    trailing.push(1);
    assert_eq!(call(&f.params, &f.statement, &trailing), GHOST_PROOFS_MALFORMED_INPUT);
    // SAFETY: null pointers are refused before any read.
    let st = unsafe { ghost_verify_know_action(std::ptr::null(), 42, f.statement.as_ptr(), 228, f.proof.as_ptr(), 1) };
    assert_eq!(st, GHOST_PROOFS_BAD_ARGUMENT);
}
