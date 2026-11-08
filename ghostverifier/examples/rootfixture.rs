//! Writes the real test-shape root proofs of the node's root verifier tests
//! (core/ghostpriv/verifier_cgo_root_test.go) into a folder, made fresh at
//! test time and never committed:
//!
//!     cargo run --release --locked --manifest-path ghostverifier/Cargo.toml --example rootfixture -- /tmp/ghost-root-fixture
//!
//! `bundle_root.bin` is a bundle of one version 2 ordinary reveal: the bundle
//! root key (124 bytes), the chain parameters (42), the spent coin's
//! fingerprint F (32) and value (32, an amount word), the reveal's statement
//! (560, in the layout of ghost_proofs.h) and then the shrink proof, unpadded.
//! The coin is the only leaf of the coin tree, at position 0, so a node test
//! chain that commits F and the value in its block 1 has the reveal's root as
//! its block 1 coin root, and the reveal applies in a bundle of its block 2.
//!
//! `public_root.bin` is a public root over one public transaction: the public
//! root key (124 bytes), the chain id (8), the transaction's account, key
//! identity and hash (84) and then the shrink proof, unpadded. The signature
//! is the first ML-DSA-44 known-answer vector of ghost-proofs'
//! tests/data/ml_dsa_44_vectors.txt, made under the context "ghost/tx/v1".
//!
//! Both are proven at the test shapes of ghost-proofs' own root tests
//! (blowup 2^2 to 2^3, one or two queries), far below spec 07's shapes: the
//! keys are test keys, for tests only, and never a node's production key.
//! The secrets, salts and zero-knowledge randomness are fixed.
//!
//! The chain constants are those of the node's test chain: the internal
//! network's chain id, the genesis hash of `newFixture(t, 5*GasPriv, nil)` in
//! core/ghostpriv and the window fee of an ordinary reveal in its block 2. The
//! Go test names the values it expects when they differ.
//!
//! tests/root_verify.rs includes this file as a module.

use std::{env, fs, path::Path, process};

use ghost_proofs::ffi::{
    REVEAL_PUBLIC_BYTES, ROOT_KEY_BYTES, RootPath, chain_params_to_bytes, coin_reveal_v2_to_bytes, root_key_to_bytes,
};
use ghost_proofs::layers::{self, Claim, LayerKey, LayerShape};
use ghost_proofs::mldsa::{self, SignedTx};
use ghost_proofs::*;

/// The internal network's chain id, the node test chain's.
pub const CHAIN_ID: u64 = 6_777_971;

/// The genesis hash of the node test chain, the reveal's domain.
pub const GENESIS_HEX: &str = "c36a650b5cd43a737f37d8d187dfc0ee36198a4d6e94c7c1b8a2a3f06c322022";

/// The value of the spent coin, one GHOST in wei.
pub const COIN_VALUE: u128 = 1_000_000_000_000_000_000;

/// What the reveal pays out, half a GHOST.
pub const OUT: u128 = 500_000_000_000_000_000;

/// The window fee of an ordinary reveal in block 2 of the node test chain.
pub const FEE: u128 = 26_448_599_764_588_822;

/// The recipient of the reveal.
pub const RECIPIENT: [u8; 20] = [0x11; 20];

/// The account of the public transaction.
pub const PUBLIC_ACCOUNT: [u8; 20] = [0x01; 20];

/// The reveal proofs' shape: blowup 2^3 and two queries.
pub const TEST: LayerShape = LayerShape {
    log_blowup: 3,
    num_queries: 2,
};

/// The layers' shape: blowup 2^2 and two queries.
pub const LEAN: LayerShape = LayerShape {
    log_blowup: 2,
    num_queries: 2,
};

/// The chunk's shape: blowup 2^2 and one query.
pub const SMALL: LayerShape = LayerShape {
    log_blowup: 2,
    num_queries: 1,
};

/// The first ML-DSA-44 known-answer vector of ghost-proofs, lines 6 to 8 of
/// tests/data/ml_dsa_44_vectors.txt at the pinned revision.
const VECTOR: &str = r"
pk c50ff582ada80e526fd932662d5d24b31648d11a7b4e4310ba09b0371cf6d0a1fdd9832ee13818f95531893d2e4b294560551d52c1aeb9407908f1b61fbbb722f8d9e71a11358da366d535311690c3d8f4e74b5c76d85d3387382bbb9a8218bad30ae4c04a13726f6aa1893bec1799e3883561c31981c2d6e34d736cc1e4b4d32cbaa3adec329ef16d8205e9b959d99c81d97aca455459e81c8c7990bf38dee35e765524e55053197632649b1bd601f216cd7521a4e0b8f8812d0a7185c94300c11f49d65fcc2d6b762aef3bedd185355b44210577c6f3ef6e04c5311cb9b118ff1f1eee4cecd44e17f919f0f0605783337c03d35aa1939ddcca3c203f38677fd47a867283763b8249a2367e346384bb21d085c0b728849416cebb7f9cb293c6d25487b4dbc325088665e3a982647110f933e5b165b1bea07e579b8ed75581d34667c3ab92490b3e4ad37de4728371c7c22140994aee16e6b03c3727a180a002bb8aee12a5b6ff823a5858abac9d562c8c645c0d2af74a5a77af8cf4fbb5b066d59a42c358fdd834916211bb2a6b9c179a71ac3f18c7c8d8078a2057027bab696025a963b2140b6faabd58352fe61bc0488e228a93438eba31ba7db4938159fae8ddd54dbb68f723011aee905409eaad645c155a242a44a436c27a65b53b0415a106c8e33125356fb76bd13987ed9dcaeca0c1eade6d5877c50df5404536dc75f0b35810715ad0c7ec87559cb98cb7df775243ed0fff145f4a815a6cd84927b28f247787b85192f9f1d3bf6555b22d88892f0d4e677ff10e83892c40d6cdf0729e28459cf9a80ea8d2bc978f6c978fe7fae3139ff8eaa115b98bb04c701966c1c272d9bf771dd801327650fc1b3ab2d31f178c246dd3f34d6fc81775a602a5efb8d9540ef2b7102b4e6acd59f127e5cf681d9c6350eea562edcaa9d408453df946b5a0e76cd475422e2095042342673d61a9f72ab35a8659e75f83cda2e5210a127d21de649180b08cbbf6c6c251e7cbda7b1885f165b8fa1933967fa1057af8a04b9979ab98fe29081bd6e8e44c9082e81d4474f1ccc026c5f512889afc198a858fc251d472f7cac6f2520eaaf251b3d5949a791ee5b82e58d6d129a870c60fc6e991418addc511d230f10aa84b45382e5e7a7ba21a722946f6ab2a41cb176bde3cade3e071c4f72c69afc9d76d6032889228f0d3275e30bed37418741ee6a1b59559fada2d98421c4eb45f7d716fea7f546b02c1e615e855a4c89066eb3eb5eac6af66be0ce015411bfd4f50b45436cb5d3524bf37fe258f3177bba4b7fe5663da8c766e237ce1c1caadaf3444b8f908d7e71e4a3f90cf133c51ce0189be295167a32a5dad870e3331d6e6174105e9b1ee2b1111dab3cd592ddc050a08a2ee5c7213b0e209bb706db2f375617e55685910fd1c4a02a66fe105cebd125a7d6d61279cdb6258792962a8186f2444d572721ed68b063ffb38b4492c37bc9ce7b33aa440c50a930a6dacb019ce9147533b57c64040a8f917189ffc5ee4e103c5424f421f6e67da1c0067b91fca33e33801d654abe709fc125c69e5c6976bee785b5a42b422b84877c741f888794ebb72c86c20d1b94c8c214749eeec13b6407e5891542838886007d42ac5a6604b42062479743e564700959449c999f60b4d6bb102ae9c13c577a643a0828b4ffd4e94280adf2e7f093adfa2d0247de82db3318d5a1b7eb950b4974fd410fcfdeed37a20836cb4d5c528a25cf719eb360f49e1c2fd21ef1e25069f9dd74905c4f4a82fb6d7ba31d340d4aa9f9cf3a563608a3522df15c0142875e02d1fac45b88d12ecb77bf498850d2188bdfcb0f2e359a19120
msg 112e4b6885a2bfdcf91633506d8aa7c4e1fe1b3855728facc9e603203d5a7794
sig 28352af44fa4d598af04bfe328d4e3182097b10545e9864c2edbca097f10a225b53f2a6b545f52e9495875f6fd9f21ef548e699e4c96589d72851b172e5b11cff273cbb31335e7e6fb260a3e1f6939649cef10d0701c0ca05e18f72ba14b33e6464d23817dce5b121c4cad6409a76ca7cf8c08c0f8f65131fcfbfa9e970df7db9b1a7d34e7a964802373575197ed89e6f9bbde7ca0f2d4d7af78b18d1356c5a2d92f86872ed0477762b4ce830f0bbda56cffe4defb00bbbc2d014f897ab383e897bd601b886dfec6e08d0609e4222f8bc165c39f8774aee23feb4ccacc36eeb1c1a5a4271173dd2ef449baa8207a775a73d9e785ec5100c3c20050ddfed903748f31de97086cd179cd46ef935597c211bdad580a8fcd0926aee96f75d65047d39917f8df6994d94c21a3dc31b761ccf36de1f7e1ff8ceadb9c03b9cad8ab36db3fa2ec6fbab67d844eb722e2bd414dc730278bc51e14f597be87fb829f37d0dde93cd336d2efd6a2ee6645bf9776c455f296ac4d2aced27e93cb937abd0ca09af551353f143aa57d3626ae9a052038ce779f3f0c1881836c28651c5a70f353055e9b76a93a8eeb7b6d582b4069e23fa7c9bfe6d5f4a237a2288be723775cb53f9a4939c77b9b74087728743e845a7407a5e7555d90194145623fa090a6bdabadc0d69fe1cedb234a6df9ab93b304fc573f2ef04489d48d185d116e71449b37352a9faf725e7d37d8776a2ede592e89e4057916295b48b297257b2683faaf7f90d7ef9b22438ba1574308dd3a3cb93cd2ebfb411c2f85f490c74f0d8b6f05ca6bc0390c7ff002e97558ea411a2c5dcdd7d90da0a8af65608466ef4aad53f601ec770a748bf98d83b21a9f658ca34493af002821991c37f9e3d01f38fbe2b997ac6852695c6765a8d9175b82eff965fcfe2e62102df80a2353e0fbd1052d815e69ea50d633825b1165c70bda005aa1cbbca4d4ecff73a2a054a6e9276b88d10c983959f7850503125c633d826946ef2d71549c0ecf79c02d01d245b553ff5ed47c5ff4c186c8313312351fb20d19cf581a235435ea6e8997ad2ceff91530f308d72ef2adb53837f9b6323609301d322f919eb39f288b0b861ac2e0537680199f43dfec1506cccbb8510cfbe5d77fc21a25a147b4aea603aba42e514f48fa46822bc4b5185ce97e2b6ded461b87e644a7de16731f8b2e13c1ac10ef30b0dccf0b6e4e27d64e2f1263ea210592bb1047de9d59d3624f4705072d2ad24b2c2c2195e43fd4a39f01bd23e35c6b45e1b29bb93e196ef660b104acf62c4ef49b534db3a8802409994e558f36fa3bf1750d25b935cfaa11cb4af76d93bb9a3fe136d254f70df30c9b8ce92ca89b8ff2539163f989979c30e1037ac9ab54e6cc5b3006d2b55b7b3cf301ceb94108ca2b76288dbc49f07ec04b05ae04cc57015608cc899f3800bfbb4abd2ab3dc3a323a576e4ea21f56d5ede17a97e91c285cc410a4e7a601214c597ca14d3d3610d96c3e8fa7a7d4c6c05de8b81ba8e663da8d2db900b08a2d627c34a87f2cd5216cea2aaba62d1e402e61a34df23251ca220a6616234324d492abed4ab81fc8beeef0f4ffa43184098ff433831a729762c2a371dc7656ae1cb3a20a2b7674791b5a7586f2ed21e7fdcd55780620b24a5815550ac17d226c092e15289e7477e926491a049e8d07769777ba460a52e708b14c18ae5345db96a74cb6c9bfd4ab66c07c166cc254aec0430bcadf4a84cdcf48ef7cec6b7e46dfed13f630e844956d7271dd9475416a85bd503f3f0b94479a11c64eecf4d0a6dba594e00c3f61584db3f898514975be1a2c4b91d1ea1c8ddab1653aa589052ceefed5ad5e37eb4491382c021c7a3432e3a3d6b5ee2a3facf7aec40f157b9ad542b3246994423da76fa4dabef96aea2922df3272ac568c6dd4861b3834a288ba61e46ac1f0588c9368ca7a3a79c17fe82bf251beb6790d5a95f0802db457c5338a01c93458ccc5379636bfdaefc7cbbfcd3e485fea2e8fe2bcec5286dd9b8ff41d8748ad9015c403e6f29868abfbc898b2f936c794b70a3d7baea56215e7239c89618ac0ddc685009a6a6cf7e08289b535160468a7d95a6d63f812b3328af1538767dd714ae295a523fc2b4f975cbe342fcd25cf73718a613541a720688bba9927bcdba958f37ce4bf47d9939bc5939469fa871dcdb483637fbf9c647376c658835af95ba03cd7293b00e2a664adef244173a9e588dcc9c031576f0fbd7459570fbb7821beb14e707bbf29bae4b6a264283234ec86041ef2f1d0ec6f69427f21e3d4676f2e46d6268141e7ba039e449e146db7b21c3738c130d3616bdf6778027b6bf9d01dde98165d43a9672bfe5fe9b4383d28c09044d151db8157d0820ba0d61c53cbca73d1173f34301d731063dd9520c07cb6c3539249912641a34b914eb84bc5234cad4fe495f65524f35e19a735045f0f734afc145dc5c803d6e178f809fa4540df28980169b63a593a9761a3c6bfb1209c716fb685713305b49673590427c7e020985d22c2aeb48aeb8b1f0f8f0a91c417528dee9843c7e62ec65599d675147061327aca73dcd34e2ac12fc66b3bb328ef5d5492cdde53740047f12947deec6dc79fd42599f5951ee405b5ef56cdcbecc358993d8e845e41f5af202f800e1b8d7f885e99b03cfe3426c6c9fa2c124a26e811954d2fcab277f07373224f6439d0c05e60e229ef5de46d68c859029680057b5956fd1f788d77994f15007d9724e1b371e2276e9e418679112668c9f408f31c27faa3c8e99f9a3865fff817d843873ad6d02a34d2d1abee5352e07021c356da0e49e6500259d47c9bee0397e86cd571f8581fbc321512ab33d9da27a9de1aa3016d3a62690f804ab796619d83b09e87af929b7e3d16fc82234c18ae9621913aaaf5c7da6240ef5f6624611000ae3308e38f190b14328bb205d6b1d2b1989a454093ae16bcc3cefffce45ed0b333be07accb23b3635deb06dc7f18830c20e0b223134f7d462f3c15e630800d3769ff93a31e87b1f182580ec1d2a79e473db1a581a5f79e988348840e4ebe5285e06dad0afda64480c8958b4a44b0c03d627021f1bdd480e425e09942bc770a1eba0ddbb137b5a69852f6f8e3540f8fa4bf46663dc445ab0a79897b1b68eccc60c5dff40c2d34949833712788e98dce7e0b7f3aeb3c00c912d4193ba7d0701becee7489e43d1c2e26a5ad356f1fded7f0b74f5e60cd9e428841764bd220a130a5e54cf8c0965700f901fffd403f584288df1b4cec1e74997f796bf9c681a4212c373f4c565c6b8486878a98b4c4ebedff1018212324272a535766779ca1b7e0e4f40b12252b2e69a5b9d3d7e1ee393e5b60828699ccdee600000000000000000000000000000000000000000000000011222e38
";

/// Decodes lower-case hex.
pub fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "odd hex");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

/// The chain parameters of the node test chain for a version 2 reveal.
pub fn chain_params() -> ChainParams {
    ChainParams {
        chain_id: CHAIN_ID.to_be_bytes(),
        version: PROTOCOL_VERSION_2,
        domain: unhex(GENESIS_HEX).try_into().expect("32-byte genesis hash"),
    }
}

/// The binding of the public root: the chain, the protocol version 2 and the
/// statement version 2, as the node builds it.
pub fn public_binding() -> layers::Binding {
    layers::Binding {
        chain_id: CHAIN_ID.to_be_bytes(),
        protocol_version: PROTOCOL_VERSION_2,
        statement_version: STATEMENT_VERSION_2,
    }
}

/// The authentication path of position 0 of a coin tree whose other leaves
/// are empty.
fn empty_path() -> [[u8; 32]; TREE_DEPTH] {
    let mut path = [[0u8; 32]; TREE_DEPTH];
    let mut empty = empty_leaf();
    for (level, sibling) in path.iter_mut().enumerate() {
        *sibling = empty;
        empty = tree_node(Tree::Coin, level as u8, &empty, &empty);
    }
    path
}

/// A real test-shape bundle of one reveal: the reveal, its proof, the root
/// inputs' binding and item, the root and shrink keys and proofs, and the
/// shrink's key bytes.
pub struct BundleRoot {
    pub params: ChainParams,
    pub fingerprint: [u8; 32],
    pub value: [u8; 32],
    pub tx: CoinRevealV2,
    pub reveal: Proof,
    pub binding: layers::Binding,
    pub claim: Claim,
    pub item: Vec<u8>,
    pub root_key: LayerKey,
    pub shrink_key: LayerKey,
    pub root: Vec<u8>,
    pub shrink: Vec<u8>,
    pub key: [u8; ROOT_KEY_BYTES],
}

/// Proves the bundle of one version 2 reveal of a plain salted coin of
/// COIN_VALUE at position 0, paying OUT to RECIPIENT and FEE, through a batch,
/// a root and a shrink.
pub fn prove_bundle() -> BundleRoot {
    let params = chain_params();
    let shape = ScaleShape {
        num_queries: TEST.num_queries,
        digest_elems: 9,
    };
    let opening = SaltedCoinOpening {
        s: [0x21; 32],
        r: [0x22; 32],
        b: [0x23; 32],
        salt: [0x24; SALT_BYTES],
        v: amount_word(COIN_VALUE),
        position: 0,
        path: empty_path(),
    };
    let fingerprint = coin_fingerprint_v2(&opening.s, &opening.r, &opening.b, &opening.salt, &EMPTY_RULE);
    let leaf = coin_commitment_v2(&fingerprint, &opening.v);
    let remainder = SaltedCoinRemainder {
        s: [0x25; 32],
        r: [0x26; 32],
        b: [0x27; 32],
        salt: [0x28; SALT_BYTES],
        v: amount_word(COIN_VALUE - OUT - FEE),
    };
    let request = CoinRevealV2Request {
        root: merkle_root(Tree::Coin, &leaf, opening.position, &opening.path),
        recipient: RECIPIENT,
        out: amount_word(OUT),
        fee: amount_word(FEE),
        remainder_note: [0x33; NOTE_V3_BYTES],
    };
    let (tx, reveal) = prove_coin_reveal_v2_scale_shaped(
        &params,
        &opening,
        &InputRule::plain(),
        &remainder,
        &EMPTY_RULE,
        &request,
        [0x61; 32],
        shape,
    )
    .expect("an honest reveal proves");
    verify_coin_reveal_v2_scale_shaped(&params, &tx, &reveal, shape).expect("the reveal verifies");

    let child = layers::RevealChild::new(TEST.num_queries);
    let binding = layers::Binding::of(&params);
    let start = layers::START_DIGEST;
    let item = coin_reveal_v2_public_values(&params, &tx);
    assert_eq!(item.len(), REVEAL_PUBLIC_BYTES);
    let publics = layers::RevealChild::public_values(&params, &tx);
    let claim = Claim::of(&start, std::slice::from_ref(&publics));

    let batch_key = layers::batch_key(&child, TEST, child.log_height(), 1, LEAN).expect("batch key");
    let children = vec![(reveal.as_bytes().to_vec(), publics)];
    let batch = layers::prove_batch(&batch_key, &child, &binding, 0, &start, &children, [0x62; 32]).expect("batch");
    let root_key = layers::root_key(&batch_key, 1, LEAN).expect("root key");
    let root = layers::prove_layer(&root_key, &batch_key, &binding, 0, &[(batch, claim)], [0x63; 32]).expect("root");
    drop(batch_key);
    let shrink_key = layers::shrink_key(&root_key, LEAN).expect("shrink key");
    let shrink = layers::prove_layer(&shrink_key, &root_key, &binding, 0, &[(root.clone(), claim)], [0x64; 32])
        .expect("shrink");
    layers::verify_layer(&shrink_key, &binding, 0, &claim, &shrink).expect("the shrink verifies");
    let key = root_key_to_bytes(&shrink_key, RootPath::Bundle).expect("bundle root key bytes");
    BundleRoot {
        params,
        fingerprint,
        value: opening.v,
        tx,
        reveal,
        binding,
        claim,
        item,
        root_key,
        shrink_key,
        root,
        shrink,
        key,
    }
}

/// The public transaction of the known-answer vector, from PUBLIC_ACCOUNT.
pub fn signed_tx() -> SignedTx {
    let field = |name: &str| -> Vec<u8> {
        let line = VECTOR
            .lines()
            .find_map(|l| l.strip_prefix(name).and_then(|rest| rest.strip_prefix(' ')))
            .expect("vector field");
        unhex(line)
    };
    SignedTx::new(PUBLIC_ACCOUNT, field("pk"), field("msg"), field("sig"))
}

/// A real test-shape public root over one transaction: its root inputs'
/// binding and item, the root and shrink keys and proofs, and the shrink's key
/// bytes.
pub struct PublicRoot {
    pub binding: layers::Binding,
    pub claim: Claim,
    pub item: Vec<u8>,
    pub root_key: LayerKey,
    pub shrink_key: LayerKey,
    pub root: Vec<u8>,
    pub shrink: Vec<u8>,
    pub key: [u8; ROOT_KEY_BYTES],
}

/// Proves the public root of the known-answer transaction: a chunk of two
/// slots holding it, a batch over the chunk, a root over the batch and the
/// shrink.
pub fn prove_public() -> PublicRoot {
    let binding = public_binding();
    let start = layers::START_DIGEST;
    let tx = signed_tx();
    assert!(tx.verifies(), "the known-answer signature verifies");
    let item = [&tx.account[..], &tx.key_id[..], &tx.message[..]].concat();
    let claim = mldsa::claim_of(&start, &[tx.public_values()]);

    let chunk = mldsa::chunk_key(2, mldsa::TX_HASH_BYTES, SMALL).expect("chunk key");
    let chunk_proof =
        mldsa::prove_chunk(&chunk, &binding, 0, &start, std::slice::from_ref(&tx), [0x71; 32]).expect("chunk");
    let batch_key = mldsa::chunk_batch_key(&chunk, 1, SMALL).expect("batch key");
    let batch = layers::prove_layer(&batch_key, chunk.layer_key(), &binding, 0, &[(chunk_proof, claim)], [0x72; 32])
        .expect("batch");
    drop(chunk);
    let root_key = layers::root_key(&batch_key, 1, LEAN).expect("root key");
    let root = layers::prove_layer(&root_key, &batch_key, &binding, 0, &[(batch, claim)], [0x73; 32]).expect("root");
    drop(batch_key);
    let shrink_key = layers::shrink_key(&root_key, LEAN).expect("shrink key");
    let shrink = layers::prove_layer(&shrink_key, &root_key, &binding, 0, &[(root.clone(), claim)], [0x74; 32])
        .expect("shrink");
    layers::verify_layer(&shrink_key, &binding, 0, &claim, &shrink).expect("the shrink verifies");
    let key = root_key_to_bytes(&shrink_key, RootPath::Public).expect("public root key bytes");
    PublicRoot {
        binding,
        claim,
        item,
        root_key,
        shrink_key,
        root,
        shrink,
        key,
    }
}

/// The bundle fixture file: key, chain parameters, F, value, statement, proof.
pub fn bundle_file(b: &BundleRoot) -> Vec<u8> {
    let mut file = b.key.to_vec();
    file.extend_from_slice(&chain_params_to_bytes(&b.params));
    file.extend_from_slice(&b.fingerprint);
    file.extend_from_slice(&b.value);
    file.extend_from_slice(&coin_reveal_v2_to_bytes(&b.tx));
    file.extend_from_slice(&b.shrink);
    file
}

/// The public root fixture file: key, chain id, transaction, proof.
pub fn public_file(p: &PublicRoot) -> Vec<u8> {
    let mut file = p.key.to_vec();
    file.extend_from_slice(&p.binding.chain_id);
    file.extend_from_slice(&p.item);
    file.extend_from_slice(&p.shrink);
    file
}

fn write(dir: &Path, name: &str, bytes: &[u8]) {
    let path = dir.join(name);
    if let Err(err) = fs::write(&path, bytes) {
        eprintln!("write {}: {err}", path.display());
        process::exit(1);
    }
    println!("wrote {}: {} bytes", path.display(), bytes.len());
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: rootfixture <folder>");
        process::exit(2);
    }
    let dir = Path::new(&args[1]);
    if let Err(err) = fs::create_dir_all(dir) {
        eprintln!("create {}: {err}", dir.display());
        process::exit(1);
    }
    let bundle = prove_bundle();
    println!("bundle root: shrink proof of {} bytes", bundle.shrink.len());
    write(dir, "bundle_root.bin", &bundle_file(&bundle));
    let public = prove_public();
    println!("public root: shrink proof of {} bytes", public.shrink.len());
    write(dir, "public_root.bin", &public_file(&public));
}
