//! Checks the data reveal C interface of this crate against real proofs of
//! the pinned ghost-proofs prover, a data reveal and a data revoke, with the
//! shipped verifier, the one the release library links:
//!
//!     cargo test --release --locked
//!
//! No cargo feature is needed. The chain constants, secrets and
//! zero-knowledge randomness are fixed test values, never a network's.

use std::sync::OnceLock;

use ghost_proofs::ffi::{
    CHAIN_PARAMS_BYTES, GHOST_PROOFS_ACCEPTED, GHOST_PROOFS_BAD_ARGUMENT, GHOST_PROOFS_MALFORMED_INPUT,
    GHOST_PROOFS_PANICKED, GHOST_PROOFS_REJECTED, PROOF_MAX_BYTES, chain_params_to_bytes,
};
use ghost_proofs::{
    ChainParams, DATA_RESERVE, DataPurpose, DataRevealRequest, EMPTY_RULE, PROTOCOL_VERSION_1, Proof, ProofError,
    SaltedDataOpening, TREE_DEPTH, Tree, amount_word, data_commitment_v2, data_fingerprint_v2, empty_leaf,
    merkle_root, prove_salted_data_reveal, tree_node, verify_salted_data_reveal,
};
use ghostverifier::{
    DATA_REVEAL_BYTES, PURPOSE_REVEAL, PURPOSE_REVOKE, data_reveal_from_bytes, data_reveal_to_bytes,
    ghost_verify_data_reveal, verify_data_reveal_bytes,
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

/// The content fingerprint the fixture's opening carries.
const TEST_CF: [u8; 32] = [4; 32];

/// A rule other than the empty rule.
const OTHER_RULE: [u8; 32] = [1; 32];

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

/// The opening of one salted data commitment at position 3 of a data tree
/// whose other leaves are empty but one, and the request for the purpose with
/// the fee and rule. The leaf binds the fee reserve with F_d and the empty
/// rule.
fn request(purpose: DataPurpose, fee: u128, rule: [u8; 32]) -> (SaltedDataOpening, DataRevealRequest) {
    let mut path = [[0u8; 32]; TREE_DEPTH];
    let mut empty = empty_leaf();
    for (level, sibling) in path.iter_mut().enumerate() {
        *sibling = empty;
        empty = tree_node(Tree::Data, level as u8, &empty, &empty);
    }
    path[0] = [9; 32];
    let opening = SaltedDataOpening {
        s: [1; 32],
        r: [2; 32],
        b: [3; 32],
        salt: [0x5a; 16],
        cf: TEST_CF,
        position: 3,
        path,
    };
    let leaf = data_commitment_v2(&data_fingerprint_v2(
        &opening.s,
        &opening.r,
        &opening.b,
        &opening.salt,
        &opening.cf,
        &EMPTY_RULE,
    ));
    let request = DataRevealRequest {
        purpose,
        root: merkle_root(Tree::Data, &leaf, opening.position, &opening.path),
        party: party(),
        fee: amount_word(fee),
        rule,
    };
    (opening, request)
}

/// Proves the purpose with the fee and the empty rule.
fn prove(purpose: DataPurpose, fee: u128) -> Fixture {
    let (opening, request) = request(purpose, fee, EMPTY_RULE);
    let (tx, proof) =
        prove_salted_data_reveal(&params(), &opening, &request, TEST_ZK_RANDOMNESS).expect("honest proof");
    let statement = data_reveal_to_bytes(&tx);
    assert_eq!(data_reveal_from_bytes(&statement), Ok(tx));
    Fixture {
        params: chain_params_to_bytes(&params()).to_vec(),
        statement,
        proof: proof.into_bytes(),
    }
}

impl Fixture {
    /// The shipped verifier of ghost-proofs on the fixture, without this
    /// crate's interface.
    fn verify(&self) -> Result<(), ProofError> {
        let tx = data_reveal_from_bytes(&self.statement).expect("statement");
        verify_salted_data_reveal(&params(), &tx, &Proof::from_bytes(self.proof.clone()))
    }

    /// The proof field of a data reveal: the proof followed by zeros.
    fn padded(&self, zeros: usize) -> Vec<u8> {
        let mut p = self.proof.clone();
        p.resize(self.proof.len() + zeros, 0);
        p
    }
}

fn reveal() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| prove(DataPurpose::Reveal, 0))
}

fn revoke() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| prove(DataPurpose::Revoke, 0))
}

fn reveal_at_reserve() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| prove(DataPurpose::Reveal, DATA_RESERVE))
}

fn revoke_at_reserve() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| prove(DataPurpose::Revoke, DATA_RESERVE))
}

fn reveal_above_reserve() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| prove(DataPurpose::Reveal, DATA_RESERVE + 1))
}

fn revoke_above_reserve() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| prove(DataPurpose::Revoke, DATA_RESERVE + 1))
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
/// unknown status, and not an argument answer.
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
    assert_eq!(header_define("GHOST_DATA_PURPOSE_REVEAL"), PURPOSE_REVEAL as i64);
    assert_eq!(header_define("GHOST_DATA_PURPOSE_REVOKE"), PURPOSE_REVOKE as i64);
    assert_eq!(header_define("GHOST_PROOFS_CHAIN_PARAMS_BYTES"), CHAIN_PARAMS_BYTES as i64);
    assert_eq!(header_define("GHOST_PROOFS_PROOF_MAX_BYTES"), PROOF_MAX_BYTES as i64);
    assert_eq!((PURPOSE_REVEAL, PURPOSE_REVOKE), (0x02, 0x03));
    assert_eq!(DATA_REVEAL_BYTES, 193);
    // ghost_data.h adds no status of its own: every answer is one of
    // ghost_proofs.h's.
    let data_defines: Vec<&str> = include_str!("../ghost_data.h")
        .lines()
        .filter_map(|l| l.strip_prefix("#define "))
        .filter(|l| *l != "GHOST_DATA_H")
        .collect();
    assert_eq!(
        data_defines,
        ["GHOST_DATA_PURPOSE_REVEAL 0x02", "GHOST_DATA_PURPOSE_REVOKE 0x03", "GHOST_DATA_REVEAL_BYTES 193"]
    );
}

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
        // The real proof, accepted by the shipped verifier through C.
        assert_eq!(shipped_c(&f.params, &f.statement, &f.proof), GHOST_PROOFS_ACCEPTED, "{name} through C");
    }
}

#[test]
fn data_reveal_rejects_other_cf() {
    for (name, f) in [("reveal", reveal()), ("revoke", revoke())] {
        for at in [161, 175, 192] {
            let mut statement = f.statement;
            statement[at] ^= 1;
            let what = format!("{name} cf byte {at}");
            assert_rejects(&what, shipped_c(&f.params, &statement, &f.proof));
            assert_rejects(&what, verify_data_reveal_bytes(&f.params, &statement, &f.proof));
        }
        let mut zero = f.statement;
        zero[161..].fill(0);
        assert_rejects(&format!("{name} zero cf"), shipped_c(&f.params, &zero, &f.proof));
    }
}

#[test]
fn shipped_verifier_accepts_real_reveal_and_revoke() {
    for (name, f, purpose) in [("reveal", reveal(), PURPOSE_REVEAL), ("revoke", revoke(), PURPOSE_REVOKE)] {
        assert_eq!(f.statement[0], purpose, "{name} purpose byte");
        assert_eq!(f.statement[97..129], amount_word(0), "{name} zero fee");
        assert_eq!(f.verify(), Ok(()), "{name} by ghost-proofs");
        assert_eq!(verify_data_reveal_bytes(&f.params, &f.statement, &f.proof), GHOST_PROOFS_ACCEPTED, "{name}");
        assert_eq!(shipped_c(&f.params, &f.statement, &f.proof), GHOST_PROOFS_ACCEPTED, "{name} through C");
        for zeros in [1, 64, 4096] {
            let padded = f.padded(zeros);
            assert_eq!(
                verify_data_reveal_bytes(&f.params, &f.statement, &padded),
                GHOST_PROOFS_ACCEPTED,
                "{name} and {zeros} zeros"
            );
            assert_eq!(
                shipped_c(&f.params, &f.statement, &padded),
                GHOST_PROOFS_ACCEPTED,
                "{name} and {zeros} zeros through C"
            );
        }
    }
}

#[test]
fn fee_at_the_reserve_accepted() {
    for (name, f, purpose) in [
        ("reveal", reveal_at_reserve(), PURPOSE_REVEAL),
        ("revoke", revoke_at_reserve(), PURPOSE_REVOKE),
    ] {
        assert_eq!(f.statement[0], purpose, "{name} purpose byte");
        assert_eq!(f.statement[97..129], amount_word(DATA_RESERVE), "{name} fee is the reserve");
        assert_eq!(f.verify(), Ok(()), "{name} by ghost-proofs");
        assert_eq!(verify_data_reveal_bytes(&f.params, &f.statement, &f.proof), GHOST_PROOFS_ACCEPTED, "{name}");
        assert_eq!(shipped_c(&f.params, &f.statement, &f.proof), GHOST_PROOFS_ACCEPTED, "{name} through C");
        assert_eq!(shipped_c(&f.params, &f.statement, &f.padded(4096)), GHOST_PROOFS_ACCEPTED, "{name} padded");
        // The proof binds the fee: one wei less is rejected.
        let mut less = f.statement;
        less[97..129].copy_from_slice(&amount_word(DATA_RESERVE - 1));
        assert_eq!(shipped_c(&f.params, &less, &f.proof), GHOST_PROOFS_REJECTED, "{name} with a lower fee");
    }
}

#[test]
fn fee_above_reserve_is_a_plain_rejection() {
    for (name, f) in [("reveal", reveal_above_reserve()), ("revoke", revoke_above_reserve())] {
        assert_eq!(f.statement[97..129], amount_word(DATA_RESERVE + 1), "{name} fee above the reserve");
        assert_eq!(f.verify(), Err(ProofError::FeeAboveReserve), "{name} by ghost-proofs");
        assert_eq!(verify_data_reveal_bytes(&f.params, &f.statement, &f.proof), GHOST_PROOFS_REJECTED, "{name}");
        assert_eq!(shipped_c(&f.params, &f.statement, &f.proof), GHOST_PROOFS_REJECTED, "{name} through C");
        assert_eq!(shipped_c(&f.params, &f.statement, &f.padded(64)), GHOST_PROOFS_REJECTED, "{name} padded");
    }
    // An accepted proof with its fee raised above the reserve is rejected
    // for the fee too.
    for (name, f) in [("reveal", reveal()), ("revoke", revoke())] {
        for fee in [DATA_RESERVE + 1, u128::from(u64::MAX)] {
            let mut tx = data_reveal_from_bytes(&f.statement).expect("statement");
            tx.fee = amount_word(fee);
            let proof = Proof::from_bytes(f.proof.clone());
            assert_eq!(
                verify_salted_data_reveal(&params(), &tx, &proof),
                Err(ProofError::FeeAboveReserve),
                "{name} fee {fee}"
            );
            let statement = data_reveal_to_bytes(&tx);
            assert_eq!(verify_data_reveal_bytes(&f.params, &statement, &f.proof), GHOST_PROOFS_REJECTED, "{name} fee {fee}");
            assert_eq!(shipped_c(&f.params, &statement, &f.proof), GHOST_PROOFS_REJECTED, "{name} fee {fee} through C");
        }
    }
}

#[test]
fn non_empty_rule_is_rejected_before_the_proof() {
    for purpose in [DataPurpose::Reveal, DataPurpose::Revoke] {
        let (opening, request) = request(purpose, 0, OTHER_RULE);
        assert!(
            matches!(
                prove_salted_data_reveal(&params(), &opening, &request, TEST_ZK_RANDOMNESS),
                Err(ProofError::RuleNotEmpty)
            ),
            "{purpose:?}: the prover refuses a non-empty rule"
        );
    }
    for (name, f) in [("reveal", reveal()), ("revoke", revoke())] {
        let mut tx = data_reveal_from_bytes(&f.statement).expect("statement");
        tx.rule = OTHER_RULE;
        // Whatever the proof: the real one, or bytes that are no proof.
        for (what, proof) in [("real proof", f.proof.clone()), ("no proof", vec![0xab; 16])] {
            assert_eq!(
                verify_salted_data_reveal(&params(), &tx, &Proof::from_bytes(proof)),
                Err(ProofError::RuleNotEmpty),
                "{name}, {what}"
            );
        }
        let statement = data_reveal_to_bytes(&tx);
        assert_eq!(verify_data_reveal_bytes(&f.params, &statement, &f.proof), GHOST_PROOFS_REJECTED, "{name}");
        assert_eq!(shipped_c(&f.params, &statement, &f.proof), GHOST_PROOFS_REJECTED, "{name} through C");
        assert_eq!(shipped_c(&f.params, &statement, &f.padded(64)), GHOST_PROOFS_REJECTED, "{name} padded");
    }
}

#[test]
fn shipped_verifier_malformed_padding_is_not_a_fee_question() {
    for (name, f) in [
        ("reveal", reveal()),
        ("revoke", revoke()),
        ("reveal at the reserve", reveal_at_reserve()),
        ("reveal above the reserve", reveal_above_reserve()),
        ("revoke above the reserve", revoke_above_reserve()),
    ] {
        // A broken proof field is malformed, whatever the fee.
        let mut garbage = f.padded(64);
        garbage[f.proof.len() + 10] = 1;
        assert_eq!(shipped_c(&f.params, &f.statement, &garbage), GHOST_PROOFS_MALFORMED_INPUT, "{name} bad padding");
        assert_eq!(
            verify_data_reveal_bytes(&f.params, &f.statement, &garbage),
            GHOST_PROOFS_MALFORMED_INPUT,
            "{name} bad padding"
        );
        let n = f.proof.len();
        assert_eq!(shipped_c(&f.params, &f.statement, &f.proof[..n - 1]), GHOST_PROOFS_MALFORMED_INPUT, "{name} truncated");
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
            assert_rejects(&format!("{name} {field}"), shipped_c(&f.params, &statement, &f.proof));
        }
        for at in [0, 9, CHAIN_PARAMS_BYTES - 1] {
            let mut params = f.params.clone();
            params[at] ^= 1;
            assert_rejects(&format!("{name} chain parameter byte {at}"), shipped_c(&params, &f.statement, &f.proof));
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
            assert_rejects(&format!("{name} proof byte {at}"), shipped_c(&f.params, &f.statement, &proof));
        }
        let mut padded = f.padded(64);
        padded[n + 10] = 1;
        assert_eq!(shipped_c(&f.params, &f.statement, &padded), GHOST_PROOFS_MALFORMED_INPUT, "{name} padding");
        assert_eq!(shipped_c(&f.params, &f.statement, &f.proof[..n - 1]), GHOST_PROOFS_MALFORMED_INPUT, "{name} truncated");
    }
}

#[test]
fn proof_for_one_purpose_rejected_for_the_other() {
    let (rv, rk) = (reveal(), revoke());
    assert_eq!(rv.statement[1..], rk.statement[1..], "one commitment, two purposes");
    let mut as_revoke = rv.statement;
    as_revoke[0] = PURPOSE_REVOKE;
    assert_rejects("reveal proof as a revoke", shipped_c(&rv.params, &as_revoke, &rv.proof));
    let mut as_reveal = rk.statement;
    as_reveal[0] = PURPOSE_REVEAL;
    assert_rejects("revoke proof as a reveal", shipped_c(&rk.params, &as_reveal, &rk.proof));
}

#[test]
fn bad_arguments_rejected() {
    let f = reveal();
    for purpose in [0x00, 0x01, 0x04, 0xff] {
        let mut statement = f.statement;
        statement[0] = purpose;
        assert_eq!(shipped_c(&f.params, &statement, &f.proof), GHOST_PROOFS_BAD_ARGUMENT, "purpose {purpose:#x}");
        assert_eq!(
            verify_data_reveal_bytes(&f.params, &statement, &f.proof),
            GHOST_PROOFS_BAD_ARGUMENT,
            "purpose {purpose:#x}"
        );
    }
    assert_eq!(shipped_c(&f.params[1..], &f.statement, &f.proof), GHOST_PROOFS_BAD_ARGUMENT);
    assert_eq!(shipped_c(&f.params, &f.statement[1..], &f.proof), GHOST_PROOFS_BAD_ARGUMENT);
    assert_eq!(shipped_c(&f.params, &f.statement, &[]), GHOST_PROOFS_MALFORMED_INPUT);
    assert_eq!(shipped_c(&f.params, &f.statement, &vec![0; PROOF_MAX_BYTES + 1]), GHOST_PROOFS_MALFORMED_INPUT);
    assert_rejects("zero proof", shipped_c(&f.params, &f.statement, &[0; 4096]));
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
            ghost_verify_data_reveal(
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
