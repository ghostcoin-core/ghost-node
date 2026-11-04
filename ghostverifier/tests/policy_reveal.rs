//! Checks the policy reveal C interface of this crate (ghost_policy.h) and
//! the version 2 coin reveal entry point it re-exports from ghost-proofs
//! against real proofs of the pinned prover, with the shipped verifier:
//!
//!     cargo test --release --locked
//!
//! The chain constants, secrets and zero-knowledge randomness are fixed test
//! values, never a network's.

use std::sync::OnceLock;

use ghost_proofs::ffi::{
    CHAIN_PARAMS_BYTES, COIN_REVEAL_V2_BYTES, GHOST_PROOFS_ACCEPTED, GHOST_PROOFS_BAD_ARGUMENT,
    GHOST_PROOFS_MALFORMED_INPUT, GHOST_PROOFS_REJECTED, chain_params_to_bytes,
};
use ghost_proofs::*;
use ghostverifier::{
    POLICY_REVEAL_BYTES, ghost_verify_coin_reveal_v2, ghost_verify_policy_reveal, policy_reveal_from_bytes,
    policy_reveal_to_bytes, verify_policy_reveal_bytes,
};

fn params() -> ChainParams {
    ChainParams {
        chain_id: 1234u64.to_be_bytes(),
        version: PROTOCOL_VERSION_1,
        domain: [0x47; 32],
    }
}

fn path() -> [[u8; 32]; TREE_DEPTH] {
    let mut path = [[0u8; 32]; TREE_DEPTH];
    let mut empty = empty_leaf();
    for (level, sibling) in path.iter_mut().enumerate() {
        *sibling = empty;
        empty = tree_node(Tree::Coin, level as u8, &empty, &empty);
    }
    path[0] = [9; 32];
    path
}

struct Fixture {
    params: Vec<u8>,
    statement: Vec<u8>,
    proof: Vec<u8>,
}

fn policy() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let rule = PolicyRule {
            policy_address: [0x50; POLICY_ADDRESS_BYTES],
            policy_codehash: [0x51; 32],
            params_hash: [0x52; 32],
            override_hash: policy_override_hash(&[0x53; 32]),
            action_tag: [0x54; 32],
            action_salt: [0x55; 32],
        };
        let opening = SaltedCoinOpening {
            s: [1; 32],
            r: [2; 32],
            b: [3; 32],
            salt: [0x6e; SALT_BYTES],
            v: amount_word(1_000),
            position: 5,
            path: path(),
        };
        let leaf = coin_commitment_v2(
            &coin_fingerprint_v2(&opening.s, &opening.r, &opening.b, &opening.salt, &rule.rule()),
            &opening.v,
        );
        let remainder = SaltedCoinRemainder {
            s: [1; 32],
            r: [2; 32],
            b: [5; 32],
            salt: [0x7f; SALT_BYTES],
            v: amount_word(0),
        };
        let request = PolicyRevealRequest {
            root: merkle_root(Tree::Coin, &leaf, opening.position, &opening.path),
            out: amount_word(990),
            fee: amount_word(10),
            instr: [0x56; 32],
            remainder_note: [0x34; NOTE_V3_BYTES],
        };
        let (tx, proof) =
            prove_policy_reveal(&params(), &opening, &rule, &remainder, &request, [0x5c; 32]).expect("honest proof");
        Fixture {
            params: chain_params_to_bytes(&params()).to_vec(),
            statement: policy_reveal_to_bytes(&tx).to_vec(),
            proof: proof.as_bytes().to_vec(),
        }
    })
}

fn policy_c(params: &[u8], statement: &[u8], proof: &[u8]) -> i32 {
    // SAFETY: each pointer points to its slice's length of bytes.
    unsafe {
        ghost_verify_policy_reveal(
            params.as_ptr(),
            params.len(),
            statement.as_ptr(),
            statement.len(),
            proof.as_ptr(),
            proof.len(),
        )
    }
}

fn header_define(name: &str) -> i64 {
    for line in include_str!("../ghost_policy.h")
        .lines()
        .chain(include_str!("../ghost_proofs.h").lines())
    {
        let mut words = line.split_whitespace();
        if words.next() == Some("#define") && words.next() == Some(name) {
            return words.next().expect("a value").parse().expect("decimal");
        }
    }
    panic!("no #define {name}");
}

#[test]
fn header_matches() {
    assert_eq!(header_define("GHOST_POLICY_REVEAL_BYTES"), POLICY_REVEAL_BYTES as i64);
    assert_eq!(
        header_define("GHOST_PROOFS_COIN_REVEAL_V2_BYTES"),
        COIN_REVEAL_V2_BYTES as i64
    );
    assert_eq!(
        header_define("GHOST_PROOFS_CHAIN_PARAMS_BYTES"),
        CHAIN_PARAMS_BYTES as i64
    );
    assert_eq!(POLICY_REVEAL_BYTES, 720);
}

#[test]
fn statement_round_trips_and_binds_the_layout() {
    let f = policy();
    let bytes: [u8; POLICY_REVEAL_BYTES] = f.statement.clone().try_into().unwrap();
    let tx = policy_reveal_from_bytes(&bytes);
    assert_eq!(policy_reveal_to_bytes(&tx), bytes);
    // The statement's fields, after the five header bytes, are the binding's.
    let public = policy_reveal_public_values(&params(), &tx);
    assert_eq!(&public[767 - POLICY_REVEAL_BYTES..767], &bytes[..]);
}

#[test]
fn shipped_verifier_accepts_real_policy_reveal() {
    let f = policy();
    assert_eq!(policy_c(&f.params, &f.statement, &f.proof), GHOST_PROOFS_ACCEPTED);
    let mut padded = f.proof.clone();
    padded.resize(f.proof.len() + 4096, 0);
    assert_eq!(policy_c(&f.params, &f.statement, &padded), GHOST_PROOFS_ACCEPTED);
    *padded.last_mut().unwrap() = 1;
    assert_eq!(policy_c(&f.params, &f.statement, &padded), GHOST_PROOFS_MALFORMED_INPUT);
}

#[test]
fn changed_field_or_proof_rejected() {
    let f = policy();
    for at in [0, 96, 160, 180, 276, 308, 340, POLICY_REVEAL_BYTES - 1] {
        let mut s = f.statement.clone();
        s[at] ^= 1;
        assert_eq!(
            verify_policy_reveal_bytes(&f.params, &s, &f.proof),
            GHOST_PROOFS_REJECTED,
            "byte {at}"
        );
    }
    let mut p = f.params.clone();
    p[9] = 2;
    assert_eq!(policy_c(&p, &f.statement, &f.proof), GHOST_PROOFS_REJECTED);
    for at in [0, f.proof.len() / 2, f.proof.len() - 1] {
        let mut q = f.proof.clone();
        q[at] ^= 1;
        let status = policy_c(&f.params, &f.statement, &q);
        assert!(
            [GHOST_PROOFS_REJECTED, GHOST_PROOFS_MALFORMED_INPUT].contains(&status),
            "proof byte {at}: {status}"
        );
    }
    // The policy proof is no version 2 ordinary reveal.
    let stmt = [0u8; COIN_REVEAL_V2_BYTES];
    // SAFETY: each pointer points to its slice's length of bytes.
    let status = unsafe {
        ghost_verify_coin_reveal_v2(
            f.params.as_ptr(),
            f.params.len(),
            stmt.as_ptr(),
            stmt.len(),
            f.proof.as_ptr(),
            f.proof.len(),
        )
    };
    assert_ne!(status, GHOST_PROOFS_ACCEPTED);
}

#[test]
fn bad_arguments_rejected() {
    let f = policy();
    assert_eq!(
        policy_c(&f.params[1..], &f.statement, &f.proof),
        GHOST_PROOFS_BAD_ARGUMENT
    );
    assert_eq!(
        policy_c(&f.params, &f.statement[1..], &f.proof),
        GHOST_PROOFS_BAD_ARGUMENT
    );
    assert_eq!(policy_c(&f.params, &f.statement, &[]), GHOST_PROOFS_MALFORMED_INPUT);
    // SAFETY: null pointers are refused before any read.
    let status = unsafe { ghost_verify_policy_reveal(std::ptr::null(), 0, std::ptr::null(), 0, std::ptr::null(), 0) };
    assert_eq!(status, GHOST_PROOFS_BAD_ARGUMENT);
}
