//! Checks the data reveal C interface of this crate against real proofs of
//! the pinned ghost-proofs prover, a data reveal and a data revoke:
//!
//!     cargo test --release --locked --features unsettled-points-test
//!
//! The prover and the accepting verifier exist only with the test-only
//! feature, so without it this file is empty. The chain constants, secrets
//! and zero-knowledge randomness are fixed test values, never a network's.

#![cfg(feature = "unsettled-points-test")]

use std::sync::OnceLock;

use ghost_proofs::ffi::{
    CHAIN_PARAMS_BYTES, GHOST_PROOFS_ACCEPTED, GHOST_PROOFS_BAD_ARGUMENT, GHOST_PROOFS_MALFORMED_INPUT,
    GHOST_PROOFS_PANICKED, GHOST_PROOFS_REJECTED, PROOF_MAX_BYTES, chain_params_to_bytes,
};
use ghost_proofs::{
    ChainParams, DataOpening, DataPurpose, DataRevealRequest, EMPTY_RULE, PROTOCOL_VERSION_1, TREE_DEPTH, Tree,
    amount_word, data_commitment, data_fingerprint, empty_leaf, merkle_root, prove_data_reveal, tree_node,
    verify_data_reveal_unsettled,
};
use ghostverifier::{
    DATA_REVEAL_BYTES, GHOST_DATA_FEE_UNSETTLED, PURPOSE_REVEAL, PURPOSE_REVOKE, data_reveal_from_bytes,
    data_reveal_to_bytes, ghost_verify_data_reveal, ghost_verify_data_reveal_unsettled, verify_data_reveal_bytes,
    verify_data_reveal_unsettled_bytes,
};

/// Example chain constants: chain id 1234, version 1 and a domain of 0x47
/// bytes, as in examples/knownanswer.rs.
fn params() -> ChainParams {
    ChainParams {
        chain_id: 1234u64.to_be_bytes(),
        version: PROTOCOL_VERSION_1,
        domain: [0x47; 32],
    }
}

/// Fixed test-only zero-knowledge randomness, so the proofs are deterministic.
const TEST_ZK_RANDOMNESS: [u8; 32] = [0x5d; 32];

/// The party: a 20-byte address left-padded with zeros, as the node passes it.
fn party() -> [u8; 32] {
    let mut p = [0u8; 32];
    p[12..].copy_from_slice(&[0x11; 20]);
    p
}

/// One real proof: the chain parameters and statement in the layout of
/// ghost_data.h, and the proof.
struct Fixture {
    params: Vec<u8>,
    statement: [u8; DATA_REVEAL_BYTES],
    proof: Vec<u8>,
}

/// Proves the purpose for one data commitment at position 3 of a data tree
/// whose other leaves are empty but one, with a zero fee and the empty rule.
fn prove(purpose: DataPurpose) -> Fixture {
    let mut path = [[0u8; 32]; TREE_DEPTH];
    let mut empty = empty_leaf();
    for (level, sibling) in path.iter_mut().enumerate() {
        *sibling = empty;
        empty = tree_node(Tree::Data, level as u8, &empty, &empty);
    }
    path[0] = [9; 32];
    let opening = DataOpening {
        s: [1; 32],
        r: [2; 32],
        b: [3; 32],
        cf: TEST_CF,
        position: 3,
        path,
    };
    let leaf = data_commitment(&data_fingerprint(&opening.s, &opening.r, &opening.b, &opening.cf, &EMPTY_RULE));
    let request = DataRevealRequest {
        purpose,
        root: merkle_root(Tree::Data, &leaf, opening.position, &opening.path),
        party: party(),
        fee: amount_word(0),
        rule: EMPTY_RULE,
    };
    let (tx, proof) = prove_data_reveal(&params(), &opening, &request, TEST_ZK_RANDOMNESS).expect("honest proof");
    assert_eq!(verify_data_reveal_unsettled(&params(), &tx, &proof), Ok(()));
    let statement = data_reveal_to_bytes(&tx);
    assert_eq!(data_reveal_from_bytes(&statement), Ok(tx));
    Fixture {
        params: chain_params_to_bytes(&params()).to_vec(),
        statement,
        proof: proof.into_bytes(),
    }
}

fn reveal() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| prove(DataPurpose::Reveal))
}

fn revoke() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| prove(DataPurpose::Revoke))
}

/// The test-only accepting verifier through its C function.
fn unsettled_c(params: &[u8], statement: &[u8], proof: &[u8]) -> i32 {
    // SAFETY: each pointer points to its slice's length of bytes.
    unsafe {
        ghost_verify_data_reveal_unsettled(
            params.as_ptr(),
            params.len(),
            statement.as_ptr(),
            statement.len(),
            proof.as_ptr(),
            proof.len(),
        )
    }
}

/// The shipped verifier through its C function.
fn shipped_c(params: &[u8], statement: &[u8], proof: &[u8]) -> i32 {
    // SAFETY: each pointer points to its slice's length of bytes.
    unsafe {
        ghost_verify_data_reveal(
            params.as_ptr(),
            params.len(),
            statement.as_ptr(),
            statement.len(),
            proof.as_ptr(),
            proof.len(),
        )
    }
}

/// Asserts a status is a proof rejection: never an acceptance, never an
/// unknown status, and not an argument or fee answer.
fn assert_rejects(name: &str, status: i32) {
    assert!(
        [GHOST_PROOFS_REJECTED, GHOST_PROOFS_MALFORMED_INPUT, GHOST_PROOFS_PANICKED].contains(&status),
        "{name}: status {status}"
    );
}

/// The value of a #define in ghost_data.h or ghost_proofs.h.
fn header_define(name: &str) -> i64 {
    let headers = [include_str!("../ghost_data.h"), include_str!("../ghost_proofs.h")];
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
    assert_eq!(header_define("GHOST_DATA_REVEAL_BYTES"), DATA_REVEAL_BYTES as i64);
    assert_eq!(header_define("GHOST_DATA_FEE_UNSETTLED"), GHOST_DATA_FEE_UNSETTLED as i64);
    assert_eq!(header_define("GHOST_DATA_PURPOSE_REVEAL"), PURPOSE_REVEAL as i64);
    assert_eq!(header_define("GHOST_DATA_PURPOSE_REVOKE"), PURPOSE_REVOKE as i64);
    assert_eq!(header_define("GHOST_PROOFS_CHAIN_PARAMS_BYTES"), CHAIN_PARAMS_BYTES as i64);
    assert_eq!(header_define("GHOST_PROOFS_PROOF_MAX_BYTES"), PROOF_MAX_BYTES as i64);
    assert_eq!((PURPOSE_REVEAL, PURPOSE_REVOKE), (0x02, 0x03));
    assert_eq!(DATA_REVEAL_BYTES, 193);
    for status in [
        GHOST_PROOFS_ACCEPTED,
        GHOST_PROOFS_REJECTED,
        GHOST_PROOFS_MALFORMED_INPUT,
        GHOST_PROOFS_BAD_ARGUMENT,
        GHOST_PROOFS_PANICKED,
    ] {
        assert_ne!(status, GHOST_DATA_FEE_UNSETTLED);
    }
}

/// The content fingerprint the fixture's opening carries.
const TEST_CF: [u8; 32] = [4; 32];

#[test]
fn data_reveal_statement_carries_cf() {
    for (name, f) in [("reveal", reveal()), ("revoke", revoke())] {
        assert_eq!(f.statement.len(), 193, "{name}");
        assert_eq!(f.statement[161..193], TEST_CF, "{name}: cf at 161..193");
        let tx = data_reveal_from_bytes(&f.statement).expect("statement");
        assert_eq!(tx.cf, TEST_CF, "{name}: decoded cf");
        assert_eq!(data_reveal_to_bytes(&tx), f.statement, "{name}: round trip");
        // Another cf is written at 161..193 and nowhere else.
        let mut other = data_reveal_from_bytes(&f.statement).expect("statement");
        other.cf = [0xcf; 32];
        let bytes = data_reveal_to_bytes(&other);
        assert_eq!(bytes[..161], f.statement[..161], "{name}: before cf");
        assert_eq!(bytes[161..], [0xcf; 32], "{name}: other cf");
        assert_eq!(data_reveal_from_bytes(&bytes), Ok(other), "{name}: other cf round trip");
        // The real proof, accepted by the unsettled verifier through C.
        assert_eq!(unsettled_c(&f.params, &f.statement, &f.proof), GHOST_PROOFS_ACCEPTED, "{name} through C");
    }
}

#[test]
fn data_reveal_rejects_other_cf() {
    for (name, f) in [("reveal", reveal()), ("revoke", revoke())] {
        for at in [161, 175, 192] {
            let mut statement = f.statement;
            statement[at] ^= 1;
            let what = format!("{name} cf byte {at}");
            assert_rejects(&what, unsettled_c(&f.params, &statement, &f.proof));
            assert_rejects(&what, verify_data_reveal_unsettled_bytes(&f.params, &statement, &f.proof));
        }
        let mut zero = f.statement;
        zero[161..].fill(0);
        assert_rejects(&format!("{name} zero cf"), unsettled_c(&f.params, &zero, &f.proof));
    }
}

#[test]
fn real_reveal_and_revoke_accepted() {
    for (name, f, purpose) in [("reveal", reveal(), PURPOSE_REVEAL), ("revoke", revoke(), PURPOSE_REVOKE)] {
        assert_eq!(f.statement[0], purpose, "{name} purpose byte");
        assert_eq!(verify_data_reveal_unsettled_bytes(&f.params, &f.statement, &f.proof), GHOST_PROOFS_ACCEPTED, "{name}");
        assert_eq!(unsettled_c(&f.params, &f.statement, &f.proof), GHOST_PROOFS_ACCEPTED, "{name} through C");
        // The proof field of a data reveal: the proof followed by zeros.
        let mut padded = f.proof.clone();
        padded.resize(f.proof.len() + 4096, 0);
        assert_eq!(unsettled_c(&f.params, &f.statement, &padded), GHOST_PROOFS_ACCEPTED, "{name} padded");
    }
}

#[test]
fn shipped_verifier_names_the_unsettled_fee() {
    for (name, f) in [("reveal", reveal()), ("revoke", revoke())] {
        assert_eq!(verify_data_reveal_bytes(&f.params, &f.statement, &f.proof), GHOST_DATA_FEE_UNSETTLED, "{name}");
        assert_eq!(shipped_c(&f.params, &f.statement, &f.proof), GHOST_DATA_FEE_UNSETTLED, "{name} through C");
        let mut padded = f.proof.clone();
        padded.resize(f.proof.len() + 64, 0);
        assert_eq!(shipped_c(&f.params, &f.statement, &padded), GHOST_DATA_FEE_UNSETTLED, "{name} padded");
        // A broken proof is still malformed, not a fee question.
        let mut garbage = padded.clone();
        garbage[f.proof.len() + 10] = 1;
        assert_eq!(shipped_c(&f.params, &f.statement, &garbage), GHOST_PROOFS_MALFORMED_INPUT, "{name} bad padding");
    }
}

#[test]
fn changed_statement_field_rejected() {
    for (name, f) in [("reveal", reveal()), ("revoke", revoke())] {
        // Each 32-byte field: root, marker, party, fee, rule, cf.
        for (field, at) in
            [("root", 1), ("marker", 33), ("party", 65 + 31), ("fee", 97 + 31), ("rule", 129 + 31), ("cf", 161)]
        {
            let mut statement = f.statement;
            statement[at] ^= 1;
            assert_rejects(&format!("{name} {field}"), unsettled_c(&f.params, &statement, &f.proof));
        }
        for at in [0, 9, CHAIN_PARAMS_BYTES - 1] {
            let mut params = f.params.clone();
            params[at] ^= 1;
            assert_rejects(&format!("{name} chain parameter byte {at}"), unsettled_c(&params, &f.statement, &f.proof));
        }
    }
}

#[test]
fn changed_proof_byte_rejected() {
    for (name, f) in [("reveal", reveal()), ("revoke", revoke())] {
        let n = f.proof.len();
        for at in [0, 1, n / 3, n / 2, 2 * n / 3, n - 40, n - 1] {
            let mut proof = f.proof.clone();
            proof[at] ^= 1;
            assert_rejects(&format!("{name} proof byte {at}"), unsettled_c(&f.params, &f.statement, &proof));
        }
        let mut padded = f.proof.clone();
        padded.resize(n + 64, 0);
        padded[n + 10] = 1;
        assert_eq!(unsettled_c(&f.params, &f.statement, &padded), GHOST_PROOFS_MALFORMED_INPUT, "{name} padding");
        assert_eq!(unsettled_c(&f.params, &f.statement, &f.proof[..n - 1]), GHOST_PROOFS_MALFORMED_INPUT, "{name} truncated");
    }
}

#[test]
fn proof_for_one_purpose_rejected_for_the_other() {
    let (rv, rk) = (reveal(), revoke());
    assert_eq!(rv.statement[1..], rk.statement[1..], "one commitment, two purposes");
    let mut as_revoke = rv.statement;
    as_revoke[0] = PURPOSE_REVOKE;
    assert_rejects("reveal proof as a revoke", unsettled_c(&rv.params, &as_revoke, &rv.proof));
    let mut as_reveal = rk.statement;
    as_reveal[0] = PURPOSE_REVEAL;
    assert_rejects("revoke proof as a reveal", unsettled_c(&rk.params, &as_reveal, &rk.proof));
}

#[test]
fn bad_arguments_rejected() {
    let f = reveal();
    for purpose in [0x00, 0x01, 0x04, 0xff] {
        let mut statement = f.statement;
        statement[0] = purpose;
        assert_eq!(unsettled_c(&f.params, &statement, &f.proof), GHOST_PROOFS_BAD_ARGUMENT, "purpose {purpose:#x}");
        assert_eq!(shipped_c(&f.params, &statement, &f.proof), GHOST_PROOFS_BAD_ARGUMENT, "purpose {purpose:#x}");
    }
    assert_eq!(unsettled_c(&f.params[1..], &f.statement, &f.proof), GHOST_PROOFS_BAD_ARGUMENT);
    assert_eq!(unsettled_c(&f.params, &f.statement[1..], &f.proof), GHOST_PROOFS_BAD_ARGUMENT);
    assert_eq!(unsettled_c(&f.params, &f.statement, &[]), GHOST_PROOFS_MALFORMED_INPUT);
    assert_eq!(unsettled_c(&f.params, &f.statement, &vec![0; PROOF_MAX_BYTES + 1]), GHOST_PROOFS_MALFORMED_INPUT);
    assert_rejects("zero proof", unsettled_c(&f.params, &f.statement, &[0; 4096]));
    // SAFETY: null pointers are checked before anything is read.
    let null = unsafe {
        [
            ghost_verify_data_reveal(
                std::ptr::null(),
                CHAIN_PARAMS_BYTES,
                f.statement.as_ptr(),
                DATA_REVEAL_BYTES,
                f.proof.as_ptr(),
                f.proof.len(),
            ),
            ghost_verify_data_reveal(
                f.params.as_ptr(),
                CHAIN_PARAMS_BYTES,
                std::ptr::null(),
                DATA_REVEAL_BYTES,
                f.proof.as_ptr(),
                f.proof.len(),
            ),
            ghost_verify_data_reveal_unsettled(
                f.params.as_ptr(),
                CHAIN_PARAMS_BYTES,
                f.statement.as_ptr(),
                DATA_REVEAL_BYTES,
                std::ptr::null(),
                f.proof.len(),
            ),
        ]
    };
    assert_eq!(null, [GHOST_PROOFS_BAD_ARGUMENT; 3]);
}
