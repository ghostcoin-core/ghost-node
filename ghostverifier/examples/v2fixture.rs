//! Writes the known-answer fixtures of the node's verifier tests for the
//! version 2 statements, core/ghostpriv/testdata/coin_reveal_v2.bin.gz (an
//! ordinary reveal, statement S1 version 2) and
//! core/ghostpriv/testdata/policy_reveal.bin.gz (a policy reveal, statement
//! S4), uncompressed:
//!
//!     cargo run --release --locked --example v2fixture -- coin_reveal_v2.bin policy_reveal.bin
//!     gzip -n -9 coin_reveal_v2.bin policy_reveal.bin
//!
//! Each file is the chain parameters (42 bytes), the statement (560 bytes in
//! the layout of ghost_proofs.h, or 720 in that of ghost_policy.h) and then
//! the proof, as the pinned prover makes it. The chain parameters carry the
//! reveal's version, as the node's binding does: 2 for the ordinary reveal,
//! 1 for the policy reveal. The secrets, salts and zero-knowledge randomness
//! are fixed, so the output is the same on every run; it is for tests only
//! and must never be used for a real reveal.

use std::{env, fs, process};

use ghost_proofs::ffi::{chain_params_to_bytes, coin_reveal_v2_to_bytes};
use ghost_proofs::*;
use ghostverifier::policy_reveal_to_bytes;

/// Example chain constants, not a network's: chain id 1234 and a domain of
/// 0x47 bytes, the genesis hash the node passes, with the given version.
fn params(version: [u8; 2]) -> ChainParams {
    ChainParams {
        chain_id: 1234u64.to_be_bytes(),
        version,
        domain: [0x47; 32],
    }
}

/// Fixed test-only zero-knowledge randomness, so the proofs are deterministic.
const TEST_ZK_RANDOMNESS: [u8; 32] = [0x5b; 32];

/// The fixed test-only rule of the policy coin.
fn rule() -> PolicyRule {
    PolicyRule {
        policy_address: [0x50; POLICY_ADDRESS_BYTES],
        policy_codehash: [0x51; 32],
        params_hash: [0x52; 32],
        override_hash: policy_override_hash(&[0x53; 32]),
        action_tag: [0x54; 32],
        action_salt: [0x55; 32],
    }
}

/// A salted coin of 1,000,000 with the given rule at position 5 of a coin
/// tree whose leaves are empty but one, and its root.
fn opening(input_rule: &[u8; 32], salt: u8) -> (SaltedCoinOpening, [u8; 32]) {
    let mut path = [[0u8; 32]; TREE_DEPTH];
    let mut empty = empty_leaf();
    for (level, sibling) in path.iter_mut().enumerate() {
        *sibling = empty;
        empty = tree_node(Tree::Coin, level as u8, &empty, &empty);
    }
    path[0] = [9; 32];
    let opening = SaltedCoinOpening {
        s: [1; 32],
        r: [2; 32],
        b: [3; 32],
        salt: [salt; SALT_BYTES],
        v: amount_word(1_000_000),
        position: 5,
        path,
    };
    let leaf = coin_commitment_v2(
        &coin_fingerprint_v2(&opening.s, &opening.r, &opening.b, &opening.salt, input_rule),
        &opening.v,
    );
    let root = merkle_root(Tree::Coin, &leaf, opening.position, &opening.path);
    (opening, root)
}

fn write(out: &str, params: &ChainParams, statement: &[u8], proof: &Proof) {
    let mut file = Vec::new();
    file.extend_from_slice(&chain_params_to_bytes(params));
    file.extend_from_slice(statement);
    file.extend_from_slice(proof.as_bytes());
    if let Err(err) = fs::write(out, &file) {
        eprintln!("write {out}: {err}");
        process::exit(1);
    }
    println!(
        "wrote {out}: {} bytes, proof of {} bytes",
        file.len(),
        proof.as_bytes().len()
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: v2fixture <ordinary reveal file> <policy reveal file>");
        process::exit(2);
    }

    // An ordinary reveal of a plain coin for 600,000 and a fee of 21, with
    // a plain remainder.
    let p2 = params(PROTOCOL_VERSION_2);
    let (coin, root) = opening(&EMPTY_RULE, 0x6d);
    let remainder = SaltedCoinRemainder {
        s: [1; 32],
        r: [2; 32],
        b: [4; 32],
        salt: [0x7e; SALT_BYTES],
        v: amount_word(1_000_000 - 600_000 - 21),
    };
    let request = CoinRevealV2Request {
        root,
        recipient: [0x11; 20],
        out: amount_word(600_000),
        fee: amount_word(21),
        remainder_note: [0x33; NOTE_V3_BYTES],
    };
    let (tx, proof) = prove_coin_reveal_v2(
        &p2,
        &coin,
        &InputRule::plain(),
        &remainder,
        &EMPTY_RULE,
        &request,
        TEST_ZK_RANDOMNESS,
    )
    .expect("honest version 2 proof");
    assert_eq!(verify_coin_reveal_v2(&p2, &tx, &proof), Ok(()));
    write(&args[1], &p2, &coin_reveal_v2_to_bytes(&tx), &proof);

    // A policy reveal of a coin with rule() into its escrow slot: 999,979
    // out and a fee of 21, a zero-value remainder.
    let p1 = params(PROTOCOL_VERSION_1);
    let rule = rule();
    let (coin, root) = opening(&rule.rule(), 0x6e);
    let remainder = SaltedCoinRemainder {
        s: [1; 32],
        r: [2; 32],
        b: [5; 32],
        salt: [0x7f; SALT_BYTES],
        v: amount_word(0),
    };
    let request = PolicyRevealRequest {
        root,
        out: amount_word(1_000_000 - 21),
        fee: amount_word(21),
        instr: [0x56; 32],
        remainder_note: [0x34; NOTE_V3_BYTES],
    };
    let (tx, proof) =
        prove_policy_reveal(&p1, &coin, &rule, &remainder, &request, TEST_ZK_RANDOMNESS).expect("honest policy proof");
    assert_eq!(verify_policy_reveal(&p1, &tx, &proof), Ok(()));
    write(&args[2], &p1, &policy_reveal_to_bytes(&tx), &proof);
}
