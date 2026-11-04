//! Writes the known-answer fixture of the node's policy action tests,
//! core/ghostpriv/testdata/know_action.bin.gz and
//! core/txpool/ghostpool/testdata/pool_action.bin.gz (statement KNOW_ACTION_v1),
//! uncompressed, from the inputs file the node's tests write
//! (GHOST_REAL_PROOF_REQUEST, see core/ghostpriv/realproof_action_test.go
//! and core/txpool/ghostpool/realproof_action_test.go):
//!
//!     cargo run --release --locked --example actionfixture -- inputs.bin know_action.bin
//!     gzip -n -9 know_action.bin
//!
//! The inputs file is the chain parameters (42 bytes), the statement (228
//! bytes in the layout of ghost_action.h) and the action root (32 bytes), the
//! private key behind the statement's action tag under its salt. The output
//! is the chain parameters, the statement and then the proof, as the pinned
//! prover makes it. The zero-knowledge randomness is fixed, so the output is
//! the same on every run; it is for tests only and must never be used for a
//! real action.

use std::{env, fs, process};

use ghost_proofs::ffi::{CHAIN_PARAMS_BYTES, chain_params_from_bytes};
use ghost_proofs::*;
use ghostverifier::{ACTION_STATEMENT_BYTES, know_action_from_bytes};

/// Fixed test-only zero-knowledge randomness, so the proof is deterministic.
const TEST_ZK_RANDOMNESS: [u8; 32] = [0x5b; 32];

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: actionfixture <inputs file> <output file>");
        process::exit(2);
    }
    let raw = fs::read(&args[1]).unwrap_or_else(|err| {
        eprintln!("read {}: {err}", args[1]);
        process::exit(1);
    });
    if raw.len() != CHAIN_PARAMS_BYTES + ACTION_STATEMENT_BYTES + 32 {
        eprintln!("inputs of {} bytes", raw.len());
        process::exit(1);
    }
    let (p, rest) = raw.split_at(CHAIN_PARAMS_BYTES);
    let (s, root) = rest.split_at(ACTION_STATEMENT_BYTES);
    let params = chain_params_from_bytes(p.try_into().expect("params"));
    let statement = know_action_from_bytes(s.try_into().expect("statement"));
    let root: [u8; 32] = root.try_into().expect("root");
    let proof = prove_know_action(&params, &statement, &root, TEST_ZK_RANDOMNESS).expect("honest action proof");
    assert_eq!(verify_know_action(&params, &statement, &proof), Ok(()));
    let mut file = Vec::new();
    file.extend_from_slice(p);
    file.extend_from_slice(s);
    file.extend_from_slice(proof.as_bytes());
    if let Err(err) = fs::write(&args[2], &file) {
        eprintln!("write {}: {err}", args[2]);
        process::exit(1);
    }
    println!("wrote {}: {} bytes, proof of {} bytes", args[2], file.len(), proof.as_bytes().len());
}
