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

//go:build cgo && ghostrelease && (linux || darwin)

package ghostpriv

// The production root verifier keys of a release build. The linked verifier
// a release build uses by default carries the two keys compiled in, so it
// verifies bundle roots and public roots without anything installing another
// verifier. Builds with the ghostproofs tag carry no key: their default
// verifier fails every root closed, and their tests use NewRootVerifier with
// test-shape keys.

/*
#cgo CFLAGS: -I${SRCDIR}/../../ghostverifier
#include "ghost_proofs.h"
*/
import "C"

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"unsafe"
)

// The production root keys, 124 bytes each as lower-case hex, exactly as the
// pinned ghost revision commits them in proofs/keys/bundle-root-key.hex and
// proofs/keys/public-root-key.hex, and the SHA-256 of each key as pinned in
// proofs/keys/bundle-root-key.sha256 and proofs/keys/public-root-key.sha256.
// The keys are derived once in the ghost repository; a node never derives
// them.
const (
	productionBundleRootKeyHex = "010000000500000038000000080000000000040002000000000004000100000000000200" +
		"010000000001000001000000004000007080b1563d3fbd62925f7f530962342e65519e5c" +
		"3b054f3efa406658f39c9274c9930e0731224c42256cc74cd1a9786963fecb1765640b45" +
		"bbaae22ad5aa0c0e58454b4114175970"
	productionBundleRootKeySHA256 = "5a230c8f019c3f9b707ebea174149cef74488bd17aee21214ef77c0b689ddec0"

	productionPublicRootKeyHex = "020000000500000038000000080000000000040002000000000004000100000000000200" +
		"01000000000100000100000000400000981a51520e341c68ac751d3ef3572a761a3b382c" +
		"d52c013370e5b0388b72601725fd560fc8f46565113ce3645cd3765db0d3ec6187f15f4f" +
		"9241c26d6787154bec2eba20234f744c"
	productionPublicRootKeySHA256 = "d00492b05e4513aed78b20a4291d2696bc8e112792490c3f423f398f2a5a93f5"
)

// productionBundleRootKey and productionPublicRootKey are the keys the
// release build verifies roots under, set at package init, or nil for a key
// that failed its checks: that root kind then fails closed.
var (
	productionBundleRootKey = loadProductionRootKey(productionBundleRootKeyHex, productionBundleRootKeySHA256, RootKeyBundle)
	productionPublicRootKey = loadProductionRootKey(productionPublicRootKeyHex, productionPublicRootKeySHA256, RootKeyPublic)
)

// The default verifier of a release build verifies both roots.
var (
	_ BundleVerifier     = ghostVerifier{}
	_ PublicRootVerifier = ghostVerifier{}
)

// loadProductionRootKey decodes a production root key and returns it only if
// it is a root key of path (checkRootKey), its SHA-256 is digest and the
// linked library takes it for the production key of path
// (ghost_root_key_is_production). Anything else is nil.
func loadProductionRootKey(keyHex, digest string, path uint32) []byte {
	key, err := hex.DecodeString(keyHex)
	if err != nil || checkRootKey(key, path) != nil {
		return nil
	}
	sum := sha256.Sum256(key)
	if hex.EncodeToString(sum[:]) != digest {
		return nil
	}
	if !rootKeyIsProduction(path, key) {
		return nil
	}
	return key
}

// rootKeyIsProduction reports whether the linked library accepts key as the
// production root key of path.
func rootKeyIsProduction(path uint32, key []byte) bool {
	if len(key) == 0 {
		return false
	}
	status := C.ghost_root_key_is_production(C.uint32_t(path), (*C.uint8_t)(unsafe.Pointer(&key[0])), C.size_t(len(key)))
	return status == C.GHOST_PROOFS_ACCEPTED
}

// VerifyBundle implements BundleVerifier for the default verifier of a
// release build: it verifies the root proof under the production bundle root
// key, as RootVerifier.VerifyBundle does. Without that key it fails closed
// with ErrBundleUnsupported.
func (ghostVerifier) VerifyBundle(in *BundleInputs, proof []byte) error {
	key := productionBundleRootKey
	if key == nil {
		return fmt.Errorf("%w: the release build carries no valid production bundle root key", ErrBundleUnsupported)
	}
	return (&RootVerifier{bundleKey: key}).VerifyBundle(in, proof)
}

// VerifyPublicRoot implements PublicRootVerifier for the default verifier of
// a release build: it verifies the root proof under the production public
// root key, as RootVerifier.VerifyPublicRoot does. Without that key it fails
// closed with ErrPublicRootUnsupported.
func (ghostVerifier) VerifyPublicRoot(in *PublicRootInputs, proof []byte) error {
	key := productionPublicRootKey
	if key == nil {
		return fmt.Errorf("%w: the release build carries no valid production public root key", ErrPublicRootUnsupported)
	}
	return (&RootVerifier{publicKey: key}).VerifyPublicRoot(in, proof)
}
