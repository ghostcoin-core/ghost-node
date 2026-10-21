//! Writes the known-answer fixtures of the node's verifier tests,
//! core/ghostpriv/testdata/coin_reveal.bin.gz (a version 1 coin) and
//! core/ghostpriv/testdata/salted_coin_reveal.bin.gz (a salted, version 2
//! coin), uncompressed:
//!
//!     cargo run --release --locked --example knownanswer -- coin_reveal.bin salted_coin_reveal.bin
//!     gzip -n -9 coin_reveal.bin salted_coin_reveal.bin
//!
//! Each file is the chain parameters (42 bytes), the coin reveal statement
//! (368 bytes), both in the layout of ghost_proofs.h, and then the proof, as
//! the pinned prover makes it. The statement layout is the same for both
//! formats. The salts and the zero-knowledge randomness are fixed, so the
//! output is the same on every run; it is for tests only and must never be
//! used for a real reveal.

use std::{env, fs, process};

use ghost_proofs::ffi::{chain_params_to_bytes, coin_reveal_to_bytes};
use ghost_proofs::*;

/// Example chain constants, not a network's: chain id 1234, version 1 and a
/// domain of 0x47 bytes, the genesis hash the node passes.
fn params() -> ChainParams {
    ChainParams {
        chain_id: 1234u64.to_be_bytes(),
        version: PROTOCOL_VERSION_1,
        domain: [0x47; 32],
    }
}

/// Fixed test-only zero-knowledge randomness, so the proof is deterministic.
const TEST_ZK_RANDOMNESS: [u8; 32] = [0x5a; 32];

/// Fixed test-only salts of the salted coin and of its remainder; a wallet
/// draws every salt fresh.
const TEST_INPUT_SALT: [u8; SALT_BYTES] = [0x6d; SALT_BYTES];
const TEST_REMAINDER_SALT: [u8; SALT_BYTES] = [0x7e; SALT_BYTES];

/// Writes the chain parameters, the statement and the proof to out.
fn write(out: &str, tx: &CoinReveal, proof: &Proof) {
    let mut file = Vec::new();
    file.extend_from_slice(&chain_params_to_bytes(&params()));
    file.extend_from_slice(&coin_reveal_to_bytes(tx));
    file.extend_from_slice(proof.as_bytes());
    if let Err(err) = fs::write(out, &file) {
        eprintln!("write {out}: {err}");
        process::exit(1);
    }
    println!("wrote {out}: {} bytes, proof of {} bytes", file.len(), proof.as_bytes().len());
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: knownanswer <version 1 output file> <salted output file>");
        process::exit(2);
    }
    let (out, salted_out) = (&args[1], &args[2]);

    // A coin of 1,000,000 at position 5 of a coin tree whose leaves are empty
    // but one, revealed for 600,000 and a fee of 21.
    let mut path = [[0u8; 32]; TREE_DEPTH];
    let mut empty = empty_leaf();
    for (level, sibling) in path.iter_mut().enumerate() {
        *sibling = empty;
        empty = tree_node(Tree::Coin, level as u8, &empty, &empty);
    }
    path[0] = [9; 32];
    let opening = CoinOpening {
        s: [1; 32],
        r: [2; 32],
        b: [3; 32],
        v: amount_word(1_000_000),
        position: 5,
        path,
    };
    let leaf = coin_commitment(&coin_fingerprint(&opening.s, &opening.r, &opening.b, &EMPTY_RULE), &opening.v);
    let request = RevealRequest {
        root: merkle_root(Tree::Coin, &leaf, opening.position, &opening.path),
        recipient: [0x11; 20],
        out: amount_word(600_000),
        fee: amount_word(21),
        rule: EMPTY_RULE,
        remainder_note: [0x33; NOTE_BYTES],
    };
    let remainder = CoinRemainder {
        s: [1; 32],
        r: [2; 32],
        b: [4; 32],
        v: amount_word(1_000_000 - 600_000 - 21),
    };
    let (tx, proof) =
        prove_coin_reveal(&params(), &opening, &remainder, &request, TEST_ZK_RANDOMNESS).expect("honest proof");
    assert_eq!(verify_coin_reveal(&params(), &tx, &proof), Ok(()));
    assert!(verify_salted_coin_reveal(&params(), &tx, &proof).is_err());
    write(out, &tx, &proof);

    // The same coin, salted: the salt is a private witness, so the statement
    // has the same layout and only the proof tells the formats apart.
    let opening = SaltedCoinOpening {
        s: opening.s,
        r: opening.r,
        b: opening.b,
        salt: TEST_INPUT_SALT,
        v: opening.v,
        position: opening.position,
        path: opening.path,
    };
    let leaf = coin_commitment_v2(
        &coin_fingerprint_v2(&opening.s, &opening.r, &opening.b, &opening.salt, &EMPTY_RULE),
        &opening.v,
    );
    let request = RevealRequest {
        root: merkle_root(Tree::Coin, &leaf, opening.position, &opening.path),
        ..request
    };
    let remainder = SaltedCoinRemainder {
        s: remainder.s,
        r: remainder.r,
        b: remainder.b,
        salt: TEST_REMAINDER_SALT,
        v: remainder.v,
    };
    let (tx, proof) = prove_salted_coin_reveal(&params(), &opening, &remainder, &request, TEST_ZK_RANDOMNESS)
        .expect("honest salted proof");
    assert_eq!(verify_salted_coin_reveal(&params(), &tx, &proof), Ok(()));
    assert!(verify_coin_reveal(&params(), &tx, &proof).is_err());
    write(salted_out, &tx, &proof);
}
