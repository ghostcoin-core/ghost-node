//! Writes the real-proof fixture of the node's Guard lifecycle test,
//! core/ghostpriv/lifecycle/testdata/real_guard_lifecycle.bin.gz,
//! uncompressed, from the request file that test writes for its own chains:
//!
//!     GHOST_REAL_PROOF_REQUEST=/tmp/real_guard.req CGO_ENABLED=1 \
//!         go test -tags ghostproofs -run '^TestRealProofGuardLifecycle$' ./core/ghostpriv/lifecycle/
//!     cargo run --release --locked --manifest-path ghostverifier/Cargo.toml \
//!         --example guardfixture -- /tmp/real_guard.req real_guard_lifecycle.bin
//!     gzip -n -9 real_guard_lifecycle.bin
//!
//! The test runs the Guard lifecycle on the stub verifier to write the
//! request, then on the default verifier with the proofs of the fixture. Each
//! proof it needs is one job of the request, in the order the lifecycle makes
//! them: the ordinary reveals (statement S1 version 2), the words-only sweeps
//! into Guard (policy reveals, statement S4) and the stop card's cancels
//! (policy actions, KNOW_ACTION_v1).
//!
//! The request is the number of jobs (4, big endian) and then the jobs. Every
//! job is its kind (1), the chain parameters (42) in the layout of
//! ghost_proofs.h, carrying the statement's own version as the node's
//! binding does, and then:
//!
//! - kind 1, an ordinary reveal: the opening of the coin (1,172: s, r and b
//!   of 32 bytes each, the salt of 16, the value as an amount word, the
//!   position in the coin tree, 4 bytes big endian, and the 32 sibling
//!   hashes), the override switch (1, 0 or 1), the coin's rule (180: the
//!   policy address of 20 bytes, then its code hash, the parameters hash, the
//!   override hash, the action tag and the action salt), the override secret
//!   (32), the remainder (144: s, r, b, the salt and the value), the
//!   remainder's rule (32) and the statement (560) in the layout of
//!   ghost_proofs.h;
//! - kind 2, a policy reveal: the opening (1,172), the rule's override hash
//!   (32), the remainder (144) and the statement (720) in the layout of
//!   ghost_policy.h, whose policy fields are the rest of the coin's rule;
//! - kind 3, a policy action: the statement (228) in the layout of
//!   ghost_action.h and the action root behind its action tag (32).
//!
//! The root, recipient, out, fee, instruction and note of a reveal are the
//! statement's. The generator proves every job with the pinned prover,
//! checks that the statement it proved is the request's byte for byte, so
//! the node's hashes of the coins, markers, remainders and rules are the
//! prover's, and verifies the proof.
//!
//! The file is the request and then, for every job in order, the proof's
//! length (4, big endian) and the proof. The secrets are the test's own
//! synthetic ones and the zero-knowledge randomness of each job is fixed, so
//! the output is the same on every run for one request; it is for tests only
//! and must never be used for a real coin.

use std::{env, fmt::Display, fs, process};

use ghost_proofs::ffi::{CHAIN_PARAMS_BYTES, COIN_REVEAL_V2_BYTES, chain_params_from_bytes, coin_reveal_v2_to_bytes};
use ghost_proofs::*;
use ghostverifier::{
    ACTION_STATEMENT_BYTES, POLICY_REVEAL_BYTES, know_action_from_bytes, policy_reveal_from_bytes,
    policy_reveal_to_bytes,
};

/// The kinds of job.
const KIND_REVEAL: u8 = 1;
const KIND_POLICY: u8 = 2;
const KIND_ACTION: u8 = 3;

/// Lengths of the parts of a job.
const OPENING_BYTES: usize = 3 * 32 + SALT_BYTES + 32 + 4 + 32 * TREE_DEPTH;
const REMAINDER_BYTES: usize = 3 * 32 + SALT_BYTES + 32;
const RULE_BYTES: usize = POLICY_ADDRESS_BYTES + 5 * 32;

/// The tag of the fixed test-only zero-knowledge randomness of each job.
const TAG_TEST_ZK_RANDOMNESS: &str = "ghost/test-guard-lifecycle/zk-randomness/v1";

fn fail(msg: impl Display) -> ! {
    eprintln!("{msg}");
    process::exit(1);
}

fn word(bytes: &[u8]) -> [u8; 32] {
    bytes.try_into().expect("32 bytes")
}

/// The request, read from the front.
struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> &'a [u8] {
        let rest = self.rest;
        if rest.len() < n {
            fail(format!("the request ends {} bytes into a part of {n}", rest.len()));
        }
        let (head, tail) = rest.split_at(n);
        self.rest = tail;
        head
    }

    fn word(&mut self) -> [u8; 32] {
        word(self.take(32))
    }

    fn salt(&mut self) -> [u8; SALT_BYTES] {
        self.take(SALT_BYTES).try_into().expect("salt")
    }

    fn opening(&mut self) -> SaltedCoinOpening {
        let start = self.rest.len();
        let (s, r, b, salt, v) = (self.word(), self.word(), self.word(), self.salt(), self.word());
        let position = u32::from_be_bytes(self.take(4).try_into().expect("position"));
        let mut path = [[0u8; 32]; TREE_DEPTH];
        for sibling in path.iter_mut() {
            *sibling = self.word();
        }
        debug_assert_eq!(start - self.rest.len(), OPENING_BYTES);
        SaltedCoinOpening {
            s,
            r,
            b,
            salt,
            v,
            position,
            path,
        }
    }

    fn remainder(&mut self) -> SaltedCoinRemainder {
        let start = self.rest.len();
        let (s, r, b, salt, v) = (self.word(), self.word(), self.word(), self.salt(), self.word());
        debug_assert_eq!(start - self.rest.len(), REMAINDER_BYTES);
        SaltedCoinRemainder { s, r, b, salt, v }
    }

    fn rule(&mut self) -> PolicyRule {
        let start = self.rest.len();
        let rule = PolicyRule {
            policy_address: self.take(POLICY_ADDRESS_BYTES).try_into().expect("policy address"),
            policy_codehash: self.word(),
            params_hash: self.word(),
            override_hash: self.word(),
            action_tag: self.word(),
            action_salt: self.word(),
        };
        debug_assert_eq!(start - self.rest.len(), RULE_BYTES);
        rule
    }
}

/// An ordinary reveal, statement S1 version 2.
fn reveal_job(r: &mut Reader, params: &ChainParams, job: u32, zk: [u8; 32]) -> Proof {
    let opening = r.opening();
    let switch = r.take(1)[0];
    let rule = r.rule();
    let override_secret = r.word();
    let remainder = r.remainder();
    let remainder_rule = r.word();
    let statement: [u8; COIN_REVEAL_V2_BYTES] = r.take(COIN_REVEAL_V2_BYTES).try_into().expect("statement");
    let input = match switch {
        0 => InputRule::plain(),
        1 => InputRule::with_override(rule, override_secret),
        other => fail(format!("job {job}: override switch {other}")),
    };
    let note_end = 96 + NOTE_V3_BYTES;
    let request = CoinRevealV2Request {
        root: word(&statement[0..32]),
        recipient: statement[note_end..note_end + 20].try_into().expect("recipient"),
        out: word(&statement[note_end + 20..note_end + 52]),
        fee: word(&statement[note_end + 52..note_end + 84]),
        remainder_note: statement[96..note_end].try_into().expect("note"),
    };
    let (tx, proof) = prove_coin_reveal_v2(params, &opening, &input, &remainder, &remainder_rule, &request, zk)
        .unwrap_or_else(|err| fail(format!("job {job}: ordinary reveal not proved: {err:?}")));
    let proved = coin_reveal_v2_to_bytes(&tx);
    if proved != statement {
        fail(format!(
            "job {job}: the ordinary reveal proved has marker {} and remainder {}, the request's {} and {}",
            hex(&proved[32..64]),
            hex(&proved[64..96]),
            hex(&statement[32..64]),
            hex(&statement[64..96])
        ));
    }
    if let Err(err) = verify_coin_reveal_v2(params, &tx, &proof) {
        fail(format!("job {job}: the ordinary reveal does not verify: {err:?}"));
    }
    proof
}

/// A policy reveal, statement S4.
fn policy_job(r: &mut Reader, params: &ChainParams, job: u32, zk: [u8; 32]) -> Proof {
    let opening = r.opening();
    let override_hash = r.word();
    let remainder = r.remainder();
    let statement: [u8; POLICY_REVEAL_BYTES] = r.take(POLICY_REVEAL_BYTES).try_into().expect("statement");
    let want = policy_reveal_from_bytes(&statement);
    let rule = PolicyRule {
        policy_address: want.policy_address,
        policy_codehash: want.policy_codehash,
        params_hash: want.params_hash,
        override_hash,
        action_tag: want.action_tag,
        action_salt: want.action_salt,
    };
    let request = PolicyRevealRequest {
        root: want.root,
        out: want.out,
        fee: want.fee,
        instr: want.instr,
        remainder_note: want.remainder_note,
    };
    let (tx, proof) = prove_policy_reveal(params, &opening, &rule, &remainder, &request, zk)
        .unwrap_or_else(|err| fail(format!("job {job}: policy reveal not proved: {err:?}")));
    if policy_reveal_to_bytes(&tx) != statement {
        fail(format!(
            "job {job}: the policy reveal proved has marker {} and remainder {}, the request's {} and {}",
            hex(&tx.marker),
            hex(&tx.remainder),
            hex(&want.marker),
            hex(&want.remainder)
        ));
    }
    if let Err(err) = verify_policy_reveal(params, &tx, &proof) {
        fail(format!("job {job}: the policy reveal does not verify: {err:?}"));
    }
    proof
}

/// A policy action, KNOW_ACTION_v1.
fn action_job(r: &mut Reader, params: &ChainParams, job: u32, zk: [u8; 32]) -> Proof {
    let statement: [u8; ACTION_STATEMENT_BYTES] = r.take(ACTION_STATEMENT_BYTES).try_into().expect("statement");
    let root = r.word();
    let statement = know_action_from_bytes(&statement);
    let proof = prove_know_action(params, &statement, &root, zk)
        .unwrap_or_else(|err| fail(format!("job {job}: policy action not proved: {err:?}")));
    if let Err(err) = verify_know_action(params, &statement, &proof) {
        fail(format!("job {job}: the policy action does not verify: {err:?}"));
    }
    proof
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: guardfixture <request file> <output file>");
        process::exit(2);
    }
    let (input, out) = (&args[1], &args[2]);
    let request = fs::read(input).unwrap_or_else(|err| fail(format!("read {input}: {err}")));

    let mut r = Reader { rest: &request };
    let count = u32::from_be_bytes(r.take(4).try_into().expect("job count"));
    if count == 0 {
        fail("a request of no jobs");
    }
    let mut proofs = Vec::new();
    for job in 0..count {
        let kind = r.take(1)[0];
        let params = chain_params_from_bytes(r.take(CHAIN_PARAMS_BYTES).try_into().expect("chain parameters"));
        let zk = tagged(TAG_TEST_ZK_RANDOMNESS, &[&job.to_be_bytes()]);
        let proof = match kind {
            KIND_REVEAL => reveal_job(&mut r, &params, job, zk),
            KIND_POLICY => policy_job(&mut r, &params, job, zk),
            KIND_ACTION => action_job(&mut r, &params, job, zk),
            other => fail(format!("job {job}: unknown kind {other}")),
        };
        println!("job {job} of kind {kind}: proof of {} bytes", proof.as_bytes().len());
        proofs.push(proof);
    }
    if !r.rest.is_empty() {
        fail(format!("{} bytes after the last job", r.rest.len()));
    }

    let mut file = request.clone();
    for proof in &proofs {
        let len = u32::try_from(proof.as_bytes().len()).expect("a proof below 4 GiB");
        file.extend_from_slice(&len.to_be_bytes());
        file.extend_from_slice(proof.as_bytes());
    }
    if let Err(err) = fs::write(out, &file) {
        fail(format!("write {out}: {err}"));
    }
    println!("wrote {out}: {} bytes, {count} proofs", file.len());
}
