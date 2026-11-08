// Copyright 2026 The Ghost Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

//go:build cgo && (ghostrelease || ghostproofs) && (linux || darwin)

package ghostpriv

// The root verifiers of ghost-proofs, ghost_verify_bundle_root and
// ghost_verify_public_root of ghost_proofs.h, in the library
// verifier_cgo.go links.

/*
#cgo CFLAGS: -I${SRCDIR}/../../ghostverifier
#include "ghost_proofs.h"
*/
import "C"

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"
)

// The node's lengths and paths are those of ghost_proofs.h: the root key,
// the root binding, a bundled reveal's public values, a public binding, the
// root proof field and the key paths.
var (
	_ = [1]struct{}{}[C.GHOST_PROOFS_ROOT_KEY_BYTES-RootKeySize]
	_ = [1]struct{}{}[C.GHOST_PROOFS_ROOT_BINDING_BYTES-RootBindingSize]
	_ = [1]struct{}{}[C.GHOST_PROOFS_REVEAL_PUBLIC_BYTES-BundleRevealPublicSize]
	_ = [1]struct{}{}[C.GHOST_PROOFS_PUBLIC_TX_BYTES-PublicBindingSize]
	_ = [1]struct{}{}[C.GHOST_PROOFS_PROOF_FIELD_BYTES-ProofSize]
	_ = [1]struct{}{}[C.GHOST_PROOFS_ROOT_KEY_BUNDLE-RootKeyBundle]
	_ = [1]struct{}{}[C.GHOST_PROOFS_ROOT_KEY_PUBLIC-RootKeyPublic]
)

// ErrRootKey is returned by NewRootVerifier for a key that is not a root
// key of its path: RootKeySize bytes whose first word, little endian, is
// RootKeyBundle or RootKeyPublic.
var ErrRootKey = errors.New("root verifier key is not a 124-byte key of its root's path")

// RootVerifier is the linked proof verifier with the verifier keys of the two
// root proofs: it verifies reveals as DefaultVerifier does, bundle roots
// (BundleVerifier) through ghost_verify_bundle_root and public roots
// (PublicRootVerifier) through ghost_verify_public_root, each under its
// key. The keys are its caller's: the node pins none yet, so the default
// verifier has neither interface and fails every root closed
// (ErrBundleUnsupported, ErrPublicRootUnsupported). Install one with
// SetVerifier.
type RootVerifier struct {
	ghostVerifier
	bundleKey []byte
	publicKey []byte
}

// The linked verifier with keys verifies both roots.
var (
	_ BundleVerifier     = (*RootVerifier)(nil)
	_ PublicRootVerifier = (*RootVerifier)(nil)
)

// NewRootVerifier returns the linked proof verifier with bundleKey as the
// bundle root's verifier key and publicKey as the public root's, each
// RootKeySize bytes in the layout of ghost_proofs.h. A key of the wrong
// length or path is ErrRootKey; its other words are checked by the library
// at each verification, which refuses a key out of its bounds. The keys are
// copied.
func NewRootVerifier(bundleKey, publicKey []byte) (*RootVerifier, error) {
	if err := checkRootKey(bundleKey, RootKeyBundle); err != nil {
		return nil, fmt.Errorf("bundle root key: %w", err)
	}
	if err := checkRootKey(publicKey, RootKeyPublic); err != nil {
		return nil, fmt.Errorf("public root key: %w", err)
	}
	return &RootVerifier{
		bundleKey: append([]byte(nil), bundleKey...),
		publicKey: append([]byte(nil), publicKey...),
	}, nil
}

func checkRootKey(key []byte, path uint32) error {
	if len(key) != RootKeySize {
		return fmt.Errorf("%w: %d bytes", ErrRootKey, len(key))
	}
	if have := binary.LittleEndian.Uint32(key); have != path {
		return fmt.Errorf("%w: path %d, want %d", ErrRootKey, have, path)
	}
	return nil
}

// VerifyBundle implements BundleVerifier: it verifies the root proof field
// against the bundle key and in.RootInputs(). A proof shorter than the field
// is padded with zeros, as the field is; a longer one, inputs with no reveal
// or whose count is not their reveals', and every answer of the library but
// acceptance are ErrProofRejected.
func (v *RootVerifier) VerifyBundle(in *BundleInputs, proof []byte) error {
	if in == nil || len(in.Reveals) == 0 || len(in.Reveals)%BundleRevealPublicSize != 0 || in.RevealCount() != int(in.Count) {
		return fmt.Errorf("%w: no bundle root inputs", ErrProofRejected)
	}
	return verifyRoot(v.bundleKey, in.RootInputs(), proof, func(k, i, p *C.uint8_t, kl, il, pl C.size_t) C.int32_t {
		return C.ghost_verify_bundle_root(k, kl, i, il, p, pl)
	})
}

// VerifyPublicRoot implements PublicRootVerifier: it verifies the root proof
// field against the public root key and in.RootInputs(), with the rules of
// VerifyBundle.
func (v *RootVerifier) VerifyPublicRoot(in *PublicRootInputs, proof []byte) error {
	if in == nil || len(in.Bindings) == 0 || len(in.Bindings) != int(in.Count) {
		return fmt.Errorf("%w: no public root inputs", ErrProofRejected)
	}
	return verifyRoot(v.publicKey, in.RootInputs(), proof, func(k, i, p *C.uint8_t, kl, il, pl C.size_t) C.int32_t {
		return C.ghost_verify_public_root(k, kl, i, il, p, pl)
	})
}

func verifyRoot(key, inputs, proof []byte, verify func(k, i, p *C.uint8_t, kl, il, pl C.size_t) C.int32_t) error {
	if len(key) != RootKeySize {
		return fmt.Errorf("%w: no root key", ErrProofRejected)
	}
	if len(proof) > ProofSize {
		return fmt.Errorf("%w: root proof of %d bytes", ErrProofRejected, len(proof))
	}
	field := make([]byte, ProofSize)
	copy(field, proof)
	status := verify(
		(*C.uint8_t)(unsafe.Pointer(&key[0])),
		(*C.uint8_t)(unsafe.Pointer(&inputs[0])),
		(*C.uint8_t)(unsafe.Pointer(&field[0])),
		C.size_t(len(key)), C.size_t(len(inputs)), C.size_t(len(field)),
	)
	if status == C.GHOST_PROOFS_ACCEPTED {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrProofRejected, ghostStatusName(status))
}
