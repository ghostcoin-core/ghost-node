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

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/holiman/uint256"
)

// The digests ghost commits in proofs/keys/bundle-root-key.sha256 and
// proofs/keys/public-root-key.sha256 at the pinned revision, written here
// apart from the release build's own constants.
const (
	committedBundleRootKeyDigest = "5a230c8f019c3f9b707ebea174149cef74488bd17aee21214ef77c0b689ddec0"
	committedPublicRootKeyDigest = "d00492b05e4513aed78b20a4291d2696bc8e112792490c3f423f398f2a5a93f5"
)

// stubRootProof is the stub verifier's root proof of binding
// (ghostprivtest.BundleProof, ghostprivtest.PublicRootProof): the whole root
// proof field, K("ghost/test-proof/v1", binding) and then zeros.
func stubRootProof(binding common.Hash) []byte {
	proof := make([]byte, ProofSize)
	tag := ghosttree.K("ghost/test-proof/v1", binding[:])
	copy(proof, tag[:])
	return proof
}

// flipLastHexDigit returns keyHex with its last digit changed, still hex.
func flipLastHexDigit(keyHex string) string {
	b := []byte(keyHex)
	b[len(b)-1] ^= 1
	return string(b)
}

// TestProductionRootVerifier checks the root verifier a release build uses
// by default: it carries the production bundle root and public root keys,
// whose SHA-256 are the digests ghost commits and which the linked library
// takes for the production keys; it is the active verifier with nothing
// installed, verifies both roots and refuses the stub's root proofs. A key
// that fails its checks is not loaded, and without it that root kind fails
// closed, never falling back to the stub.
func TestProductionRootVerifier(t *testing.T) {
	keys := []struct {
		name, keyHex, pinned, committed string
		path, other                     uint32
		loaded                          []byte
	}{
		{"bundle", productionBundleRootKeyHex, productionBundleRootKeySHA256, committedBundleRootKeyDigest, RootKeyBundle, RootKeyPublic, productionBundleRootKey},
		{"public", productionPublicRootKeyHex, productionPublicRootKeySHA256, committedPublicRootKeyDigest, RootKeyPublic, RootKeyBundle, productionPublicRootKey},
	}
	for _, k := range keys {
		if len(k.loaded) != RootKeySize {
			t.Fatalf("%s root: the release build loaded a key of %d bytes, want %d", k.name, len(k.loaded), RootKeySize)
		}
		if sum := sha256.Sum256(k.loaded); hex.EncodeToString(sum[:]) != k.committed {
			t.Fatalf("%s root: loaded key's SHA-256 %x, ghost commits %s", k.name, sum, k.committed)
		}
		if err := checkRootKey(k.loaded, k.path); err != nil {
			t.Fatalf("%s root: %v", k.name, err)
		}
		if !rootKeyIsProduction(k.path, k.loaded) {
			t.Fatalf("%s root: the linked library does not take the loaded key for the production key", k.name)
		}
		if rootKeyIsProduction(k.other, k.loaded) {
			t.Fatalf("%s root: the linked library takes the key for the production key of the other path", k.name)
		}
		flipped, _ := hex.DecodeString(flipLastHexDigit(k.keyHex))
		if rootKeyIsProduction(k.path, flipped) {
			t.Fatalf("%s root: the linked library takes a changed key for the production key", k.name)
		}

		// The loader refuses a changed key, a changed digest and the
		// other path.
		if loadProductionRootKey(k.keyHex, k.pinned, k.path) == nil {
			t.Fatalf("%s root: the loader refuses the production key", k.name)
		}
		for _, c := range []struct {
			name, keyHex, digest string
			path                 uint32
		}{
			{"changed key", flipLastHexDigit(k.keyHex), k.pinned, k.path},
			{"changed key with its own digest", flipLastHexDigit(k.keyHex), digestOfHex(t, flipLastHexDigit(k.keyHex)), k.path},
			{"changed digest", k.keyHex, flipLastHexDigit(k.pinned), k.path},
			{"other path", k.keyHex, k.pinned, k.other},
			{"no key", "", k.pinned, k.path},
		} {
			if key := loadProductionRootKey(c.keyHex, c.digest, c.path); key != nil {
				t.Fatalf("%s root, %s: the loader returned a key", k.name, c.name)
			}
		}
	}

	// Nothing installs a verifier: the active one is the default, and it
	// verifies both roots.
	def := DefaultVerifier()
	if ActiveVerifier() != def {
		t.Fatalf("the active verifier is %T, not the default", ActiveVerifier())
	}
	if _, ok := def.(BundleVerifier); !ok {
		t.Fatal("the release build's default verifier verifies no bundle root")
	}
	if _, ok := def.(PublicRootVerifier); !ok {
		t.Fatal("the release build's default verifier verifies no public root")
	}

	genesis := common.Hash{0x0d}
	reveal := &Reveal{
		Version:   RevealVersion,
		ChainID:   1337,
		Root:      common.Hash{0x01},
		Marker:    common.Hash{0x02},
		Remainder: common.Hash{0x03},
		Recipient: common.Address{0x04},
		Out:       uint256.NewInt(5),
		Fee:       uint256.NewInt(1),
	}
	bundle := NewBundleInputs(reveal.ChainID, genesis, []*Reveal{reveal})
	public := NewPublicRootInputs(reveal.ChainID, genesis, []types.GhostBinding{{0x05}})
	bundleStub, publicStub := stubRootProof(bundle.Binding), stubRootProof(public.Binding)

	// Under the production keys the stub's root proofs are rejected proofs.
	for _, v := range []Verifier{nil, def} {
		err := VerifyBundleRoot(v, bundle, bundleStub)
		if !errors.Is(err, ErrBundleProof) || !errors.Is(err, ErrProofRejected) || errors.Is(err, ErrBundleUnsupported) {
			t.Fatalf("stub bundle root proof: %v, want %v and %v", err, ErrBundleProof, ErrProofRejected)
		}
		err = VerifyPublicRoot(v, public, publicStub)
		if !errors.Is(err, ErrPublicRootProof) || !errors.Is(err, ErrProofRejected) || errors.Is(err, ErrPublicRootUnsupported) {
			t.Fatalf("stub public root proof: %v, want %v and %v", err, ErrPublicRootProof, ErrProofRejected)
		}
	}

	// A node whose keys failed their checks fails both roots closed and
	// still refuses the stub's proofs.
	savedBundle, savedPublic := productionBundleRootKey, productionPublicRootKey
	t.Cleanup(func() { productionBundleRootKey, productionPublicRootKey = savedBundle, savedPublic })
	productionBundleRootKey, productionPublicRootKey = nil, nil
	if err := VerifyBundleRoot(nil, bundle, bundleStub); !errors.Is(err, ErrBundleUnsupported) {
		t.Fatalf("no bundle root key, stub proof: %v, want %v", err, ErrBundleUnsupported)
	}
	if err := VerifyPublicRoot(nil, public, publicStub); !errors.Is(err, ErrPublicRootUnsupported) {
		t.Fatalf("no public root key, stub proof: %v, want %v", err, ErrPublicRootUnsupported)
	}
}

// digestOfHex returns the SHA-256, as hex, of the bytes keyHex encodes.
func digestOfHex(t *testing.T, keyHex string) string {
	t.Helper()
	b, err := hex.DecodeString(keyHex)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
