//! Writes the real-proof fixture of the reveal pool's end-to-end tests,
//! core/txpool/ghostpool/testdata/real_reveal.bin.gz, uncompressed, from a
//! request file those tests write for their own chain:
//!
//!     GHOST_REAL_PROOF_REQUEST=/tmp/real_reveal.req CGO_ENABLED=1 \
//!         go test -tags ghostproofs -run '^TestRealProofRevealPoolAndBlock$' ./core/txpool/ghostpool/
//!     cargo run --release --locked --manifest-path ghostverifier/Cargo.toml \
//!         --example revealfixture -- /tmp/real_reveal.req real_reveal.bin
//!     gzip -n -9 real_reveal.bin
//!
//! The request is the chain parameters (42 bytes) in the layout of
//! ghost_proofs.h, the coin's position in the coin tree (4 bytes, big
//! endian) and its 32 sibling hashes (32 bytes each), the coin's value, the
//! recipient (20 bytes), out and fee, the amounts as 32-byte amount words:
//! 1,186 bytes.
//!
//! The file is the request, the fingerprint F and the salt (16 bytes) the
//! tests commit with salted, version 2 commit data, the coin reveal statement (368 bytes) in the layout of ghost_proofs.h and then the
//! proof, as the pinned prover makes it. The coin's secrets and the
//! zero-knowledge randomness are fixed, so the output is the same on every
//! run for one request; it is for tests only and must never be used for a
//! real reveal.

use std::{env, fs, process};

use ghost_proofs::ffi::{CHAIN_PARAMS_BYTES, chain_params_from_bytes, coin_reveal_to_bytes};
use ghost_proofs::*;

/// Length of the request file.
const REQUEST_BYTES: usize = CHAIN_PARAMS_BYTES + 4 + 32 * TREE_DEPTH + 32 + 20 + 32 + 32;

/// Fixed test-only salts of the committed coin and of its remainder; a
/// wallet draws every salt fresh.
const TEST_SALT: [u8; SALT_BYTES] = [0x25; SALT_BYTES];
const TEST_REMAINDER_SALT: [u8; SALT_BYTES] = [0x26; SALT_BYTES];

/// Fixed test-only secrets of the committed coin and of its remainder.
const TEST_S: [u8; 32] = [0x21; 32];
const TEST_R: [u8; 32] = [0x22; 32];
const TEST_B: [u8; 32] = [0x23; 32];
const TEST_REMAINDER_B: [u8; 32] = [0x24; 32];

/// The note stored with the remainder, a fixed test pattern.
const TEST_REMAINDER_NOTE: [u8; NOTE_BYTES] = [0x5c; NOTE_BYTES];

/// Fixed test-only zero-knowledge randomness, so the proof is deterministic.
const TEST_ZK_RANDOMNESS: [u8; 32] = [0x6b; 32];

/// Reads the next n bytes of the request.
fn take<'a>(rest: &mut &'a [u8], n: usize) -> &'a [u8] {
    let (head, tail) = rest.split_at(n);
    *rest = tail;
    head
}

fn word(bytes: &[u8]) -> [u8; 32] {
    bytes.try_into().expect("32 bytes")
}

fn amount(name: &str, word: &[u8; 32]) -> u128 {
    amount_value(word).unwrap_or_else(|| {
        eprintln!("{name} is not an amount word");
        process::exit(1);
    })
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: revealfixture <request file> <output file>");
        process::exit(2);
    }
    let (input, out) = (&args[1], &args[2]);
    let request = fs::read(input).unwrap_or_else(|err| {
        eprintln!("read {input}: {err}");
        process::exit(1);
    });
    if request.len() != REQUEST_BYTES {
        eprintln!("request of {} bytes, want {REQUEST_BYTES}", request.len());
        process::exit(1);
    }

    let mut rest = &request[..];
    let params = chain_params_from_bytes(take(&mut rest, CHAIN_PARAMS_BYTES).try_into().expect("chain parameters"));
    let position = u32::from_be_bytes(take(&mut rest, 4).try_into().expect("position"));
    let mut path = [[0u8; 32]; TREE_DEPTH];
    for sibling in path.iter_mut() {
        *sibling = word(take(&mut rest, 32));
    }
    let value = word(take(&mut rest, 32));
    let recipient: [u8; 20] = take(&mut rest, 20).try_into().expect("recipient");
    let out_word = word(take(&mut rest, 32));
    let fee = word(take(&mut rest, 32));

    let (v, o, f) = (amount("value", &value), amount("out", &out_word), amount("fee", &fee));
    let Some(left) = v.checked_sub(o).and_then(|left| left.checked_sub(f)) else {
        eprintln!("out {o} and fee {f} take more than the value {v}");
        process::exit(1);
    };

    let fingerprint = coin_fingerprint_v2(&TEST_S, &TEST_R, &TEST_B, &TEST_SALT, &EMPTY_RULE);
    let opening = SaltedCoinOpening {
        s: TEST_S,
        r: TEST_R,
        b: TEST_B,
        salt: TEST_SALT,
        v: value,
        position,
        path,
    };
    let leaf = coin_commitment_v2(&fingerprint, &opening.v);
    let reveal = RevealRequest {
        root: merkle_root(Tree::Coin, &leaf, opening.position, &opening.path),
        recipient,
        out: out_word,
        fee,
        rule: EMPTY_RULE,
        remainder_note: TEST_REMAINDER_NOTE,
    };
    let remainder = SaltedCoinRemainder {
        s: TEST_S,
        r: TEST_R,
        b: TEST_REMAINDER_B,
        salt: TEST_REMAINDER_SALT,
        v: amount_word(left),
    };
    let (tx, proof) = prove_salted_coin_reveal(&params, &opening, &remainder, &reveal, TEST_ZK_RANDOMNESS)
        .expect("honest salted proof");
    assert_eq!(verify_salted_coin_reveal(&params, &tx, &proof), Ok(()));
    assert!(verify_coin_reveal(&params, &tx, &proof).is_err());

    let mut file = Vec::new();
    file.extend_from_slice(&request);
    file.extend_from_slice(&fingerprint);
    file.extend_from_slice(&TEST_SALT);
    file.extend_from_slice(&coin_reveal_to_bytes(&tx));
    file.extend_from_slice(proof.as_bytes());
    if let Err(err) = fs::write(out, &file) {
        eprintln!("write {out}: {err}");
        process::exit(1);
    }
    println!("wrote {out}: {} bytes, proof of {} bytes", file.len(), proof.as_bytes().len());
}
