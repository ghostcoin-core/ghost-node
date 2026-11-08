//! The root verifiers through the C interface the node links: a real
//! test-shape bundle root and a real test-shape public root, made by the
//! fixture generator (examples/rootfixture.rs), each verify under the key it
//! wrote, in the root inputs the node builds; a changed proof byte, a changed
//! input, another chain id and a changed key are refused, as is one path's
//! proof or key on the other.

#[allow(dead_code)]
#[path = "../examples/rootfixture.rs"]
mod rootfixture;

use ghost_proofs::ffi::{
    GHOST_PROOFS_ACCEPTED, GHOST_PROOFS_BAD_ARGUMENT, GHOST_PROOFS_MALFORMED_INPUT, GHOST_PROOFS_PANICKED,
    GHOST_PROOFS_REJECTED, PUBLIC_TX_BYTES, REVEAL_PUBLIC_BYTES, ROOT_BINDING_BYTES, ROOT_KEY_BYTES,
    root_inputs_to_bytes,
};
use ghost_proofs::layers::{self, PROOF_FIELD_BYTES};
use ghost_proofs::*;
use ghostverifier::{ghost_verify_bundle_root, ghost_verify_public_root};
use rootfixture::{BundleRoot, CHAIN_ID, PublicRoot, prove_bundle, prove_public};

type RootFn = unsafe extern "C" fn(*const u8, usize, *const u8, usize, *const u8, usize) -> i32;

fn call(f: RootFn, key: &[u8], inputs: &[u8], field: &[u8]) -> i32 {
    // SAFETY: each pointer points to its slice's length of readable bytes.
    let status = unsafe { f(key.as_ptr(), key.len(), inputs.as_ptr(), inputs.len(), field.as_ptr(), field.len()) };
    assert_ne!(status, GHOST_PROOFS_PANICKED, "the verifier panicked");
    status
}

fn bundle(key: &[u8], inputs: &[u8], field: &[u8]) -> i32 {
    call(ghost_verify_bundle_root, key, inputs, field)
}

fn public(key: &[u8], inputs: &[u8], field: &[u8]) -> i32 {
    call(ghost_verify_public_root, key, inputs, field)
}

fn refused(status: i32) -> bool {
    status == GHOST_PROOFS_REJECTED || status == GHOST_PROOFS_MALFORMED_INPUT
}

/// A proof in the root proof field: its bytes, then zeros.
fn field_of(proof: &[u8]) -> Vec<u8> {
    assert!(proof.len() <= PROOF_FIELD_BYTES, "a proof of {} bytes", proof.len());
    let mut field = proof.to_vec();
    field.resize(PROOF_FIELD_BYTES, 0);
    field
}

/// The root inputs as the node builds them (core/ghostpriv): the chain id (8,
/// big endian), the protocol version (2) and the statement version (1), then
/// the items in order.
fn node_inputs(chain_id: u64, items: &[Vec<u8>]) -> Vec<u8> {
    let mut b = chain_id.to_be_bytes().to_vec();
    b.extend_from_slice(&PROTOCOL_VERSION_2);
    b.push(STATEMENT_VERSION_2);
    for item in items {
        b.extend_from_slice(item);
    }
    b
}

/// Proofs with a byte changed at several places, a non-zero padding byte and
/// fields one byte short or long: none is accepted.
fn assert_changed_proof_refused(f: RootFn, key: &[u8], inputs: &[u8], proof_len: usize, field: &[u8]) {
    for at in [0, proof_len / 3, proof_len / 2, proof_len - 1] {
        let mut changed = field.to_vec();
        changed[at] ^= 1;
        let status = call(f, key, inputs, &changed);
        assert!(refused(status), "a proof changed at byte {at} of {proof_len}: status {status}");
    }
    let mut padded = field.to_vec();
    padded[proof_len] = 1;
    assert_eq!(call(f, key, inputs, &padded), GHOST_PROOFS_MALFORMED_INPUT);
    assert_eq!(call(f, key, inputs, &field[..PROOF_FIELD_BYTES - 1]), GHOST_PROOFS_MALFORMED_INPUT);
    let mut longer = field.to_vec();
    longer.push(0);
    assert_eq!(call(f, key, inputs, &longer), GHOST_PROOFS_MALFORMED_INPUT);
}

/// Keys with one word changed (the preprocessed commitment, the children's
/// key digest): neither is accepted.
fn assert_changed_key_refused(f: RootFn, key: &[u8], inputs: &[u8], field: &[u8]) {
    assert_eq!(key.len(), ROOT_KEY_BYTES);
    for word in [13, 22] {
        let mut changed = key.to_vec();
        changed[4 * word] ^= 2;
        assert_ne!(call(f, &changed, inputs, field), GHOST_PROOFS_ACCEPTED, "key word {word} changed");
    }
}

fn check_bundle(b: &BundleRoot) -> Vec<u8> {
    // The item is the node's: the 607-byte binding input of the reveal on the
    // chain, then its binding digest.
    let item = &b.item;
    assert_eq!(item.len(), REVEAL_PUBLIC_BYTES);
    assert_eq!(item[..8], CHAIN_ID.to_be_bytes());
    assert_eq!(item[8..10], PROTOCOL_VERSION_2);
    assert_eq!(item[10..42], b.params.domain);
    assert_eq!(item[42..44], [STATEMENT_COIN_REVEAL, STATEMENT_VERSION_2]);
    assert_eq!(item[44..46], COIN_V2);
    assert_eq!(item[47..79], b.tx.root);
    assert_eq!(item[79..111], b.tx.marker);
    assert_eq!(item[111..143], b.tx.remainder);
    assert_eq!(item[143..163], b.tx.recipient);
    assert_eq!(item[163..195], b.tx.out);
    assert_eq!(item[195..227], b.tx.fee);
    assert_eq!(item[227..607], b.tx.remainder_note);
    assert_eq!(item[607..], coin_reveal_v2_binding(&b.params, &b.tx));

    let key = &b.key[..];
    let inputs = node_inputs(CHAIN_ID, std::slice::from_ref(item));
    assert_eq!(inputs, root_inputs_to_bytes(&b.binding, std::slice::from_ref(item)));
    assert_eq!(inputs.len(), ROOT_BINDING_BYTES + REVEAL_PUBLIC_BYTES);
    let field = field_of(&b.shrink);
    assert_eq!(bundle(key, &inputs, &field), GHOST_PROOFS_ACCEPTED);

    // A changed input: a field of the reveal, its digest, the versions, the
    // reveal twice.
    for at in [79, 143, 226, 400, REVEAL_PUBLIC_BYTES - 1] {
        let mut changed = item.clone();
        changed[at] ^= 1;
        let changed = node_inputs(CHAIN_ID, &[changed]);
        assert_eq!(bundle(key, &changed, &field), GHOST_PROOFS_REJECTED, "item byte {at} changed");
    }
    for at in [9, 10] {
        let mut changed = inputs.clone();
        changed[at] ^= 1;
        assert_eq!(bundle(key, &changed, &field), GHOST_PROOFS_REJECTED, "binding byte {at} changed");
    }
    let twice = node_inputs(CHAIN_ID, &[item.clone(), item.clone()]);
    assert_eq!(bundle(key, &twice, &field), GHOST_PROOFS_REJECTED);

    // Another chain id: in the binding alone, and with the reveal's public
    // values on that chain; and a shrink proven for that chain over this
    // root, which the honest prover refuses to make.
    let other = CHAIN_ID + 1;
    assert_eq!(bundle(key, &node_inputs(other, std::slice::from_ref(item)), &field), GHOST_PROOFS_REJECTED);
    let elsewhere = ChainParams {
        chain_id: other.to_be_bytes(),
        ..b.params.clone()
    };
    let item_elsewhere = coin_reveal_v2_public_values(&elsewhere, &b.tx);
    let inputs_elsewhere = node_inputs(other, std::slice::from_ref(&item_elsewhere));
    assert_eq!(bundle(key, &inputs_elsewhere, &field), GHOST_PROOFS_REJECTED);
    let binding_elsewhere = layers::Binding::of(&elsewhere);
    let tag = b.shrink_key.tag(&binding_elsewhere, 0);
    let forged = layers::prove_layer_unchecked(&b.shrink_key, &b.root_key, &tag, &[(b.root.clone(), b.claim)], [0x65; 32])
        .expect("an unchecked shrink proves");
    let forged = field_of(&forged);
    for inputs in [&inputs, &inputs_elsewhere] {
        assert_eq!(bundle(key, inputs, &forged), GHOST_PROOFS_REJECTED);
    }

    assert_changed_proof_refused(ghost_verify_bundle_root, key, &inputs, b.shrink.len(), &field);
    assert_changed_key_refused(ghost_verify_bundle_root, key, &inputs, &field);

    // The root's proof, or the reveal's, in the root proof field.
    assert!(refused(bundle(key, &inputs, &field_of(&b.root))));
    let reveal = b.reveal.as_bytes();
    assert!(refused(bundle(key, &inputs, &field_of(&reveal[..reveal.len().min(PROOF_FIELD_BYTES)]))));

    // The bundle key is no public root key.
    let public_inputs = node_inputs(CHAIN_ID, &[vec![0; PUBLIC_TX_BYTES]]);
    assert_eq!(public(key, &public_inputs, &field), GHOST_PROOFS_BAD_ARGUMENT);
    field
}

fn check_public(p: &PublicRoot, bundle_field: &[u8]) {
    let item = &p.item;
    assert_eq!(item.len(), PUBLIC_TX_BYTES);
    let key = &p.key[..];
    let inputs = node_inputs(CHAIN_ID, std::slice::from_ref(item));
    assert_eq!(inputs, root_inputs_to_bytes(&p.binding, std::slice::from_ref(item)));
    let field = field_of(&p.shrink);
    assert_eq!(public(key, &inputs, &field), GHOST_PROOFS_ACCEPTED);

    // A changed account, key identity or transaction hash, the transaction
    // twice, the versions.
    for at in [0, 20, 51, 83] {
        let mut changed = item.clone();
        changed[at] ^= 1;
        let changed = node_inputs(CHAIN_ID, &[changed]);
        assert_eq!(public(key, &changed, &field), GHOST_PROOFS_REJECTED, "transaction byte {at} changed");
    }
    let twice = node_inputs(CHAIN_ID, &[item.clone(), item.clone()]);
    assert_eq!(public(key, &twice, &field), GHOST_PROOFS_REJECTED);
    for at in [9, 10] {
        let mut changed = inputs.clone();
        changed[at] ^= 1;
        assert_eq!(public(key, &changed, &field), GHOST_PROOFS_REJECTED, "binding byte {at} changed");
    }

    // Another chain id.
    let other = node_inputs(CHAIN_ID + 1, std::slice::from_ref(item));
    assert_eq!(public(key, &other, &field), GHOST_PROOFS_REJECTED);

    assert_changed_proof_refused(ghost_verify_public_root, key, &inputs, p.shrink.len(), &field);
    assert_changed_key_refused(ghost_verify_public_root, key, &inputs, &field);

    // The root's proof, or a bundle's shrink, in the field.
    assert!(refused(public(key, &inputs, &field_of(&p.root))));
    assert!(refused(public(key, &inputs, bundle_field)));

    // The public root key is no bundle key.
    let bundle_inputs = node_inputs(CHAIN_ID, &[vec![0; REVEAL_PUBLIC_BYTES]]);
    assert_eq!(bundle(key, &bundle_inputs, &field), GHOST_PROOFS_BAD_ARGUMENT);
}

/// A real test-shape bundle root and public root each verify through the C
/// functions of the linked library, and nothing else does.
#[test]
fn real_test_shape_roots_verify_through_the_c_interface() {
    let b = prove_bundle();
    let bundle_field = check_bundle(&b);
    drop(b);
    let p = prove_public();
    check_public(&p, &bundle_field);
}

/// Bad arguments are refused before any verification: null pointers, a key
/// of the wrong length, inputs with no item or a partial one.
#[test]
fn bad_root_arguments_are_refused() {
    let key = [0u8; ROOT_KEY_BYTES];
    let field = vec![0u8; PROOF_FIELD_BYTES];
    let one = node_inputs(CHAIN_ID, &[vec![0; REVEAL_PUBLIC_BYTES]]);
    for f in [ghost_verify_bundle_root as RootFn, ghost_verify_public_root] {
        // SAFETY: null pointers are refused without being read.
        let status = unsafe { f(std::ptr::null(), ROOT_KEY_BYTES, one.as_ptr(), one.len(), field.as_ptr(), field.len()) };
        assert_eq!(status, GHOST_PROOFS_BAD_ARGUMENT);
        assert_eq!(call(f, &key[..ROOT_KEY_BYTES - 1], &one, &field), GHOST_PROOFS_BAD_ARGUMENT);
        assert_eq!(call(f, &key, &one[..ROOT_BINDING_BYTES], &field), GHOST_PROOFS_BAD_ARGUMENT);
        assert_eq!(call(f, &key, &one[..one.len() - 1], &field), GHOST_PROOFS_BAD_ARGUMENT);
        assert_ne!(call(f, &key, &one, &field), GHOST_PROOFS_ACCEPTED);
    }
}
