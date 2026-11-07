//! Checks the statement checker's C interface of this crate
//! (ghost_preimage.h) against a real KNOW_PREIMAGE_v1 proof of the pinned
//! prover, with the shipped verifier:
//!
//!     cargo test --release --locked --test know_preimage
//!
//! The chain constants, the preimage x and the zero-knowledge randomness are
//! fixed test values, never a network's.

use std::sync::OnceLock;

use ghost_proofs::ffi::{
    CHAIN_PARAMS_BYTES, GHOST_PROOFS_ACCEPTED, GHOST_PROOFS_BAD_ARGUMENT, GHOST_PROOFS_MALFORMED_INPUT,
    GHOST_PROOFS_REJECTED, chain_params_to_bytes,
};
use ghost_proofs::*;
use ghostverifier::{
    ACTION_STATEMENT_BYTES, PREIMAGE_STATEMENT_BYTES, ghost_verify_know_action, ghost_verify_know_preimage,
    know_preimage_from_bytes, know_preimage_to_bytes, verify_know_preimage_bytes,
};

struct Fixture {
    params: Vec<u8>,
    statement: Vec<u8>,
    proof: Vec<u8>,
}

/// The test chain's parameters: id 1234, version 1 and a genesis hash of
/// 0x47 bytes, as the node's fixtures.
fn test_params() -> ChainParams {
    ChainParams {
        chain_id: 1234u64.to_be_bytes(),
        version: PROTOCOL_VERSION_1,
        domain: [0x47; 32],
    }
}

/// A fixed test-only preimage.
const TEST_X: [u8; 32] = [0x71; 32];

/// Fixed test-only zero-knowledge randomness, so the proof is deterministic.
const TEST_ZK_RANDOMNESS: [u8; 32] = [0x5c; 32];

/// The calling policy, 0x00...00c0ffee61.
const TEST_POLICY: [u8; POLICY_ADDRESS_BYTES] = {
    let mut a = [0u8; POLICY_ADDRESS_BYTES];
    a[16] = 0xc0;
    a[17] = 0xff;
    a[18] = 0xee;
    a[19] = 0x61;
    a
};

/// The node's known-answer statement (examples/preimagefixture.rs and
/// core/ghostpriv/verifier_cgo_test.go): the policy, y of TEST_X and the
/// context whose byte i is i ^ 0xc5.
fn test_statement() -> KnowPreimage {
    let mut context = [0u8; PREIMAGE_CONTEXT_BYTES];
    for (i, b) in context.iter_mut().enumerate() {
        *b = (i as u8) ^ 0xc5;
    }
    KnowPreimage {
        policy_address: TEST_POLICY,
        y: policy_preimage_hash(&TEST_X),
        context,
    }
}

/// The node's fixture of this statement, which the node's verifier tests
/// read.
fn node_fixture_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../core/ghostpriv/testdata/know_preimage.bin")
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let params = test_params();
        let s = test_statement();
        let proof = prove_know_preimage(&params, &s, &TEST_X, TEST_ZK_RANDOMNESS).expect("honest preimage proof");
        assert_eq!(verify_know_preimage(&params, &s, &proof), Ok(()));
        Fixture {
            params: chain_params_to_bytes(&params).to_vec(),
            statement: know_preimage_to_bytes(&s).to_vec(),
            proof: proof.as_bytes().to_vec(),
        }
    })
}

fn call(params: &[u8], statement: &[u8], proof: &[u8]) -> i32 {
    // SAFETY: each pointer is a live slice of its length.
    unsafe {
        ghost_verify_know_preimage(
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
    assert_eq!(PREIMAGE_STATEMENT_BYTES, 116);
    assert_eq!(PREIMAGE_CONTEXT_BYTES, 64);
    assert_eq!(ACTION_PROOF_BYTES, 948_224);
    let s = know_preimage_from_bytes(f.statement.as_slice().try_into().unwrap());
    assert_eq!(s, test_statement());
    assert_eq!(know_preimage_to_bytes(&s).as_slice(), f.statement.as_slice());
    // The fields sit where ghost_preimage.h puts them.
    assert_eq!(&f.statement[..20], &TEST_POLICY);
    assert_eq!(&f.statement[20..52], &policy_preimage_hash(&TEST_X));
    assert_eq!(&f.statement[52..], &test_statement().context);
}

#[test]
fn prover_refuses_a_wrong_preimage() {
    let mut x = TEST_X;
    x[0] ^= 1;
    assert!(prove_know_preimage(&test_params(), &test_statement(), &x, TEST_ZK_RANDOMNESS).is_err());
}

#[test]
fn node_fixture_is_this_proof() {
    // The node's fixture is exactly the chain parameters, the statement and
    // the proof the pinned prover makes here, and the library accepts it.
    let f = fixture();
    let raw = std::fs::read(node_fixture_path()).expect("the node's fixture; see examples/preimagefixture.rs");
    let (head, proof) = raw.split_at(CHAIN_PARAMS_BYTES + PREIMAGE_STATEMENT_BYTES);
    assert_eq!(&head[..CHAIN_PARAMS_BYTES], f.params.as_slice(), "fixture chain parameters");
    assert_eq!(&head[CHAIN_PARAMS_BYTES..], f.statement.as_slice(), "fixture statement");
    assert_eq!(proof, f.proof.as_slice(), "fixture proof");
    assert_eq!(call(&head[..CHAIN_PARAMS_BYTES], &head[CHAIN_PARAMS_BYTES..], proof), GHOST_PROOFS_ACCEPTED);
}

#[test]
fn accepts_the_honest_proof_padded_or_not() {
    let f = fixture();
    assert!(f.proof.len() <= ACTION_PROOF_BYTES, "proof of {} bytes", f.proof.len());
    assert_eq!(call(&f.params, &f.statement, &f.proof), GHOST_PROOFS_ACCEPTED);
    let mut padded = f.proof.clone();
    padded.resize(ACTION_PROOF_BYTES, 0);
    assert_eq!(call(&f.params, &f.statement, &padded), GHOST_PROOFS_ACCEPTED);
    assert_eq!(verify_know_preimage_bytes(&f.params, &f.statement, &padded), GHOST_PROOFS_ACCEPTED);
}

#[test]
fn rejects_every_changed_input() {
    let f = fixture();
    for at in 0..PREIMAGE_STATEMENT_BYTES {
        if at % 5 != 0 && at != PREIMAGE_STATEMENT_BYTES - 1 {
            continue;
        }
        let mut s = f.statement.clone();
        s[at] ^= 1;
        assert_eq!(call(&f.params, &s, &f.proof), GHOST_PROOFS_REJECTED, "statement byte {at}");
    }
    for at in [0, 7, 8, 9, 10, CHAIN_PARAMS_BYTES - 1] {
        let mut p = f.params.clone();
        p[at] ^= 1;
        assert_eq!(call(&p, &f.statement, &f.proof), GHOST_PROOFS_REJECTED, "params byte {at}");
    }
    for at in [0, f.proof.len() / 2, f.proof.len() - 1] {
        let mut q = f.proof.clone();
        q[at] ^= 1;
        assert_ne!(call(&f.params, &f.statement, &q), GHOST_PROOFS_ACCEPTED, "proof byte {at}");
    }
}

#[test]
fn proof_is_not_a_policy_action_proof() {
    // The same proof bytes against a policy action statement of the same
    // chain never verify: the statements bind different tags and codes.
    let f = fixture();
    let statement = [0u8; ACTION_STATEMENT_BYTES];
    // SAFETY: each pointer is a live slice of its length.
    let st = unsafe {
        ghost_verify_know_action(
            f.params.as_ptr(),
            f.params.len(),
            statement.as_ptr(),
            statement.len(),
            f.proof.as_ptr(),
            f.proof.len(),
        )
    };
    assert_ne!(st, GHOST_PROOFS_ACCEPTED);
}

#[test]
fn refuses_bad_arguments() {
    let f = fixture();
    assert_eq!(call(&f.params[1..], &f.statement, &f.proof), GHOST_PROOFS_BAD_ARGUMENT);
    assert_eq!(call(&f.params, &f.statement[1..], &f.proof), GHOST_PROOFS_BAD_ARGUMENT);
    let mut long_statement = f.statement.clone();
    long_statement.push(0);
    assert_eq!(call(&f.params, &long_statement, &f.proof), GHOST_PROOFS_BAD_ARGUMENT);
    assert_eq!(call(&f.params, &f.statement, &[]), GHOST_PROOFS_MALFORMED_INPUT);
    let mut long = f.proof.clone();
    long.resize(ACTION_PROOF_BYTES + 1, 0);
    assert_eq!(call(&f.params, &f.statement, &long), GHOST_PROOFS_MALFORMED_INPUT);
    assert_eq!(verify_know_preimage_bytes(&f.params, &f.statement, &long), GHOST_PROOFS_MALFORMED_INPUT);
    let mut trailing = f.proof.clone();
    trailing.push(1);
    assert_eq!(call(&f.params, &f.statement, &trailing), GHOST_PROOFS_MALFORMED_INPUT);
    // SAFETY: null pointers are refused before any read.
    let st = unsafe {
        ghost_verify_know_preimage(std::ptr::null(), 42, f.statement.as_ptr(), 116, f.proof.as_ptr(), 1)
    };
    assert_eq!(st, GHOST_PROOFS_BAD_ARGUMENT);
    // SAFETY: null pointers are refused before any read.
    let st = unsafe { ghost_verify_know_preimage(f.params.as_ptr(), 42, std::ptr::null(), 116, f.proof.as_ptr(), 1) };
    assert_eq!(st, GHOST_PROOFS_BAD_ARGUMENT);
}
