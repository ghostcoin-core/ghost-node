//! Writes the known-answer fixture of the node's verifier tests,
//! core/ghostpriv/testdata/coin_reveal.bin.gz, uncompressed:
//!
//!     cargo run --release --locked --example knownanswer -- coin_reveal.bin
//!     gzip -n -9 coin_reveal.bin
//!
//! The file is the chain parameters (42 bytes), the coin reveal statement (368
//! bytes), both in the layout of ghost_proofs.h, and then the proof, as the
//! pinned prover makes it. The zero-knowledge randomness is fixed, so the
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

fn main() {
    let Some(out) = env::args().nth(1) else {
        eprintln!("usage: knownanswer <output file>");
        process::exit(2);
    };

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

    let mut file = Vec::new();
    file.extend_from_slice(&chain_params_to_bytes(&params()));
    file.extend_from_slice(&coin_reveal_to_bytes(&tx));
    file.extend_from_slice(proof.as_bytes());
    if let Err(err) = fs::write(&out, &file) {
        eprintln!("write {out}: {err}");
        process::exit(1);
    }
    println!("wrote {out}: {} bytes, proof of {} bytes", file.len(), proof.as_bytes().len());
}
