//! Writes the real-proof fixture of the reveal pool's data lifecycle test,
//! core/txpool/ghostpool/testdata/real_data_lifecycle.bin.gz, uncompressed,
//! from a request file that test writes for its own chain:
//!
//!     GHOST_REAL_PROOF_REQUEST=/tmp/real_data.req CGO_ENABLED=1 \
//!         go test -tags ghostproofs -run '^TestRealProofDataLifecycle$' ./core/txpool/ghostpool/
//!     cargo run --release --locked --features unsettled-points-test \
//!         --manifest-path ghostverifier/Cargo.toml \
//!         --example datalifecyclefixture -- /tmp/real_data.req real_data_lifecycle.bin
//!     gzip -n -9 real_data_lifecycle.bin
//!
//! It needs the test-only prover of the proof of holding, so it runs only
//! with the unsettled-points-test feature. The node verifies every proof in
//! it with the shipped verifiers, which need no feature.
//!
//! The chain the test builds: block 1 makes two salted data commitments, A
//! at position 0 and B at position 1 of the empty data tree; block 2 reveals
//! A to the reveal verifier; block 3 revokes B. The proof of holding of B is
//! made after block 2, against block 1's data root and block 2's marker-set
//! root, which holds A's marker.
//!
//! The request is the chain parameters (42 bytes) in the layout of
//! ghost_proofs.h and the fee of the reveal and the revoke as a 32-byte
//! amount word: 74 bytes.
//!
//! The file is, in order:
//!
//! - the request (74);
//! - for A and then B, F_d (32) and the salt (16) the test commits with;
//! - the data reveal statement of A and the data revoke statement of B (193
//!   each), in the layout of ghost_data.h;
//! - the proof of holding context of B (162), in the layout of ghost_hold.h;
//! - the marker-set root after block 3, with both markers (32);
//! - the reveal, revoke and hold proofs, each as its length (4, big endian)
//!   then the proof.
//!
//! The content fingerprint of each commitment is
//! K("ghost/test-data-lifecycle/content-fingerprint/v1", length, content)
//! over the fixed content of [`CONTENT_A`] and [`CONTENT_B`], so the test
//! checks it against the content. The secrets, salts and zero-knowledge
//! randomness are fixed, so the output is the same on every run for one
//! request; it is for tests only and must never be used for real data.

use std::{env, fs, process};

use ghost_proofs::ffi::{CHAIN_PARAMS_BYTES, chain_params_from_bytes};
use ghost_proofs::*;
use ghostverifier::{
    data_reveal_to_bytes, hold_context_to_bytes, prove_salted_hold, test_absence_witness, verify_hold_bytes,
};

/// Length of the request file.
const REQUEST_BYTES: usize = CHAIN_PARAMS_BYTES + 32;

/// The fixed test content of A and B.
const CONTENT_A: &[u8] = b"synthetic data lifecycle content A, example only";
const CONTENT_B: &[u8] = b"synthetic data lifecycle content B, example only";

/// The reveal verifier of A, a 20-byte address left-padded with zeros.
const REVEAL_PARTY: [u8; 20] = [0x9d; 20];

/// The holding verifier's identity and its challenge, fixed test values.
const HOLD_VERIFIER: [u8; 32] = [0x7a; 32];
const HOLD_CHALLENGE: [u8; 32] = [0x7c; 32];

/// Fixed test-only zero-knowledge randomness, so the proofs are deterministic.
const TEST_ZK_RANDOMNESS: [u8; 32] = [0x6c; 32];

/// One commitment's fixed test-only secrets.
struct Secrets {
    s: [u8; 32],
    r: [u8; 32],
    b: [u8; 32],
    salt: [u8; SALT_BYTES],
    cf: [u8; 32],
}

impl Secrets {
    fn new(seed: u8, content: &[u8]) -> Self {
        Secrets {
            s: [seed; 32],
            r: [seed + 1; 32],
            b: [seed + 2; 32],
            salt: [seed + 3; SALT_BYTES],
            cf: tagged(
                "ghost/test-data-lifecycle/content-fingerprint/v1",
                &[&(content.len() as u64).to_be_bytes(), content],
            ),
        }
    }

    fn fingerprint(&self) -> [u8; 32] {
        data_fingerprint_v2(&self.s, &self.r, &self.b, &self.salt, &self.cf, &EMPTY_RULE)
    }

    fn leaf(&self) -> [u8; 32] {
        data_commitment_v2(&self.fingerprint())
    }

    fn marker(&self) -> [u8; 32] {
        data_marker_v2(&self.r, &self.b, &self.salt)
    }

    fn opening(&self, position: u32, path: [[u8; 32]; TREE_DEPTH]) -> SaltedDataOpening {
        SaltedDataOpening {
            s: self.s,
            r: self.r,
            b: self.b,
            salt: self.salt,
            cf: self.cf,
            position,
            path,
        }
    }
}

/// The path of position 0 or 1 of a data tree whose only other used leaf is
/// the sibling.
fn path(sibling: [u8; 32]) -> [[u8; 32]; TREE_DEPTH] {
    let mut path = [[0u8; 32]; TREE_DEPTH];
    let mut empty = empty_leaf();
    for (level, s) in path.iter_mut().enumerate() {
        *s = empty;
        empty = tree_node(Tree::Data, level as u8, &empty, &empty);
    }
    path[0] = sibling;
    path
}

fn append_proof(file: &mut Vec<u8>, proof: &[u8]) {
    file.extend_from_slice(&u32::try_from(proof.len()).expect("a proof below 4 GiB").to_be_bytes());
    file.extend_from_slice(proof);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: datalifecyclefixture <request file> <output file>");
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
    let params_bytes: [u8; CHAIN_PARAMS_BYTES] = request[..CHAIN_PARAMS_BYTES].try_into().expect("chain parameters");
    let params = chain_params_from_bytes(&params_bytes);
    let fee: [u8; 32] = request[CHAIN_PARAMS_BYTES..].try_into().expect("fee");
    if amount_value(&fee).is_none_or(|f| f > DATA_RESERVE) {
        eprintln!("the fee is no amount word or above the data reserve");
        process::exit(1);
    }

    let (a, b) = (Secrets::new(0x31, CONTENT_A), Secrets::new(0x41, CONTENT_B));
    let (path_a, path_b) = (path(b.leaf()), path(a.leaf()));
    let root = merkle_root(Tree::Data, &a.leaf(), 0, &path_a);
    assert_eq!(merkle_root(Tree::Data, &b.leaf(), 1, &path_b), root);

    // Block 2: A revealed to the reveal verifier.
    let mut party = [0u8; 32];
    party[12..].copy_from_slice(&REVEAL_PARTY);
    let reveal_request = DataRevealRequest {
        purpose: DataPurpose::Reveal,
        root,
        party,
        fee,
        rule: EMPTY_RULE,
    };
    let (reveal, reveal_proof) =
        prove_salted_data_reveal(&params, &a.opening(0, path_a), &reveal_request, TEST_ZK_RANDOMNESS)
            .expect("honest reveal proof");
    assert_eq!(reveal.marker, a.marker());
    assert_eq!(verify_salted_data_reveal(&params, &reveal, &reveal_proof), Ok(()));

    // After block 2: B held, against the marker set holding A's marker.
    let (absence, marker_set_root) = test_absence_witness(&[a.marker()], &b.marker());
    let ctx = HoldContext {
        type_tag: DATA_V2,
        root,
        marker_set_root,
        verifier: HOLD_VERIFIER,
        challenge: HOLD_CHALLENGE,
        cf: b.cf,
    };
    let hold_opening = SaltedHoldOpening {
        s: b.s,
        r: b.r,
        b: b.b,
        salt: b.salt,
        cf: b.cf,
        rule: EMPTY_RULE,
        position: 1,
        path: path_b,
        absence,
    };
    let hold_proof = prove_salted_hold(&params, &hold_opening, &ctx, TEST_ZK_RANDOMNESS).expect("honest hold proof");
    let ctx_bytes = hold_context_to_bytes(&ctx);
    assert_eq!(verify_hold_bytes(&params_bytes, &ctx_bytes, hold_proof.as_bytes()), 0);

    // Block 3: B revoked.
    let revoke_request = DataRevealRequest {
        purpose: DataPurpose::Revoke,
        root,
        party: [0; 32],
        fee,
        rule: EMPTY_RULE,
    };
    let (revoke, revoke_proof) =
        prove_salted_data_reveal(&params, &b.opening(1, path_b), &revoke_request, TEST_ZK_RANDOMNESS)
            .expect("honest revoke proof");
    assert_eq!(revoke.marker, b.marker());
    assert_eq!(verify_salted_data_reveal(&params, &revoke, &revoke_proof), Ok(()));

    // After block 3 the marker-set root holds both markers. The proof of
    // holding made before is refused against it, and the honest prover has
    // no absence witness for B any more.
    let (_, after) = test_absence_witness(&[a.marker(), b.marker()], &[0xff; 32]);
    let mut ctx_after = ctx.clone();
    ctx_after.marker_set_root = after;
    assert_ne!(verify_hold_bytes(&params_bytes, &hold_context_to_bytes(&ctx_after), hold_proof.as_bytes()), 0);
    assert_eq!(
        prove_salted_hold(&params, &hold_opening, &ctx_after, TEST_ZK_RANDOMNESS).err(),
        Some(ProofError::NotInMarkerSet)
    );

    let mut file = Vec::new();
    file.extend_from_slice(&request);
    for c in [&a, &b] {
        file.extend_from_slice(&c.fingerprint());
        file.extend_from_slice(&c.salt);
    }
    file.extend_from_slice(&data_reveal_to_bytes(&reveal));
    file.extend_from_slice(&data_reveal_to_bytes(&revoke));
    file.extend_from_slice(&ctx_bytes);
    file.extend_from_slice(&after);
    append_proof(&mut file, reveal_proof.as_bytes());
    append_proof(&mut file, revoke_proof.as_bytes());
    append_proof(&mut file, hold_proof.as_bytes());
    if let Err(err) = fs::write(out, &file) {
        eprintln!("write {out}: {err}");
        process::exit(1);
    }
    println!(
        "wrote {out}: {} bytes, proofs of {}, {} and {} bytes",
        file.len(),
        reveal_proof.as_bytes().len(),
        revoke_proof.as_bytes().len(),
        hold_proof.as_bytes().len()
    );
}
