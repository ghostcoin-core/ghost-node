//! The coin reveal verifier of ghost-proofs as a static library for the node.
//!
//! The node links `libghostverifier.a` through cgo and calls
//! [`ghost_verify_coin_reveal`], declared in `ghost_proofs.h` beside this
//! crate, a copy of the header at the pinned revision of ghost-proofs. This
//! crate adds nothing of its own: the function is the one the ghost
//! repository's prover is checked against.

pub use ghost_proofs::ffi::ghost_verify_coin_reveal;
