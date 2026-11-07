//! Writes the known-answer fixture of the node's statement checker tests,
//! core/ghostpriv/testdata/know_preimage.bin (statement KNOW_PREIMAGE_v1):
//!
//!     cargo run --release --locked --manifest-path ghostverifier/Cargo.toml \
//!         --example preimagefixture -- core/ghostpriv/testdata/know_preimage.bin
//!
//! With one argument it proves the fixed known-answer statement below, the
//! one TestGhostVerifierKnownAnswerPreimage (core/ghostpriv/verifier_cgo_test.go)
//! builds. With two, like the policy action's generator (actionfixture.rs),
//! it proves the statement of the inputs file that test writes when
//! GHOST_REAL_PROOF_REQUEST names it:
//!
//!     cargo run --release --locked --manifest-path ghostverifier/Cargo.toml \
//!         --example preimagefixture -- inputs.bin core/ghostpriv/testdata/know_preimage.bin
//!
//! The inputs file is the chain parameters (42 bytes), the statement (116
//! bytes in the layout of ghost_preimage.h) and the preimage x (32 bytes),
//! with y = K("ghost/policy-preimage/v1", x). The output is the chain
//! parameters, the statement and then the proof, as the pinned prover makes
//! it. It is not compressed: the proof does not compress, so gzip would save
//! almost nothing. The preimage and the zero-knowledge randomness are fixed,
//! so the output is the same on every run; it is for tests only and must
//! never be used for a real statement.

use std::{env, fs, process};

use ghost_proofs::ffi::{CHAIN_PARAMS_BYTES, chain_params_from_bytes, chain_params_to_bytes};
use ghost_proofs::*;
use ghostverifier::{PREIMAGE_STATEMENT_BYTES, know_preimage_from_bytes, know_preimage_to_bytes};

/// Fixed test-only zero-knowledge randomness, so the proof is deterministic.
const TEST_ZK_RANDOMNESS: [u8; 32] = [0x5c; 32];

/// The known-answer statement's fixed test-only preimage.
const TEST_X: [u8; 32] = [0x71; 32];

/// The known-answer statement's calling policy, 0x00...00c0ffee61.
const TEST_POLICY: [u8; POLICY_ADDRESS_BYTES] = {
    let mut a = [0u8; POLICY_ADDRESS_BYTES];
    a[16] = 0xc0;
    a[17] = 0xff;
    a[18] = 0xee;
    a[19] = 0x61;
    a
};

/// The known-answer inputs: the example chain (id 1234, version 1, a
/// genesis hash of 0x47 bytes), the policy, y of TEST_X and the context
/// whose byte i is i ^ 0xc5, and TEST_X.
fn known_answer() -> (ChainParams, KnowPreimage, [u8; 32]) {
    let params = ChainParams {
        chain_id: 1234u64.to_be_bytes(),
        version: PROTOCOL_VERSION_1,
        domain: [0x47; 32],
    };
    let mut context = [0u8; PREIMAGE_CONTEXT_BYTES];
    for (i, b) in context.iter_mut().enumerate() {
        *b = (i as u8) ^ 0xc5;
    }
    let statement = KnowPreimage {
        policy_address: TEST_POLICY,
        y: policy_preimage_hash(&TEST_X),
        context,
    };
    (params, statement, TEST_X)
}

/// Reads the inputs file the node's test writes.
fn read_inputs(path: &str) -> (ChainParams, KnowPreimage, [u8; 32]) {
    let raw = fs::read(path).unwrap_or_else(|err| {
        eprintln!("read {path}: {err}");
        process::exit(1);
    });
    if raw.len() != CHAIN_PARAMS_BYTES + PREIMAGE_STATEMENT_BYTES + 32 {
        eprintln!("inputs of {} bytes", raw.len());
        process::exit(1);
    }
    let (p, rest) = raw.split_at(CHAIN_PARAMS_BYTES);
    let (s, x) = rest.split_at(PREIMAGE_STATEMENT_BYTES);
    (
        chain_params_from_bytes(p.try_into().expect("params")),
        know_preimage_from_bytes(s.try_into().expect("statement")),
        x.try_into().expect("x"),
    )
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let (params, statement, x, out) = match args.len() {
        2 => {
            let (p, s, x) = known_answer();
            (p, s, x, &args[1])
        }
        3 => {
            let (p, s, x) = read_inputs(&args[1]);
            (p, s, x, &args[2])
        }
        _ => {
            eprintln!("usage: preimagefixture [<inputs file>] <output file>");
            process::exit(2);
        }
    };
    if policy_preimage_hash(&x) != statement.y {
        eprintln!("x does not hash to the statement's y");
        process::exit(1);
    }
    let proof = prove_know_preimage(&params, &statement, &x, TEST_ZK_RANDOMNESS).expect("honest preimage proof");
    assert_eq!(verify_know_preimage(&params, &statement, &proof), Ok(()));
    let mut file = Vec::new();
    file.extend_from_slice(&chain_params_to_bytes(&params));
    file.extend_from_slice(&know_preimage_to_bytes(&statement));
    file.extend_from_slice(proof.as_bytes());
    if let Err(err) = fs::write(out, &file) {
        eprintln!("write {out}: {err}");
        process::exit(1);
    }
    println!("wrote {out}: {} bytes, proof of {} bytes", file.len(), proof.as_bytes().len());
}
