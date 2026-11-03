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

// Package ghostprivtest holds the stub reveal verifier, for tests only. It
// must only ever be imported from _test.go files: a node with it would mint
// for anyone who knows the stub proof format.
//
// The one exception is the test-depth build. With the ghosttreetest14 tag,
// install.go installs the stub as the active verifier when the package is
// initialised, and cmd/geth/ghostprivtest_install.go, under the same tag,
// imports the package, so a test-depth geth accepts stub reveal proofs. A
// build without the tag installs nothing, and the release tag together with
// ghosttreetest14 does not build (core/ghosttree/depth_refuse.go), so a
// release node never carries the stub.
//
// A stub proof is the proof field of a reveal whose first 32 bytes are
// K("ghost/test-proof/v1", binding digest) and whose other bytes are zero.
// The binding digest is the node's: the version 2 ordinary reveal's, of type
// COIN version 2, the version 1 ordinary reveal's, the policy reveal's or the
// data reveal's. A version 1 ordinary reveal has two binding digests, as the
// real verifier accepts one of an unsalted or a salted coin: the node's
// BindingDigest, of type COIN version 1, and SaltedBindingDigest, the same
// input with type COIN version 2; the stub of either verifies. The stub
// checks nothing else: membership, the marker's derivation and conservation
// are the real proof's job. Ordinary reveals of each version, policy and data
// reveals have binding digests of their own, with their own tags, so the stub
// proof of one never verifies another, nor a reveal's a revoke.
//
// A policy action's stub proof is the same over the action's binding digest,
// in its own, shorter proof field of ghostpriv.ActionProofSize bytes
// (ActionProof): the inputs are Kind ghosttree.Coin with purpose
// ghostpriv.PurposeAction. A proof field of the reveal size never verifies
// an action, nor an action's a reveal.
package ghostprivtest

import (
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghosttree"
)

// TagTestProof is the hash tag of a stub proof.
const TagTestProof = "ghost/test-proof/v1"

// ErrStubProof is returned for a proof that is not the stub proof of the
// binding digest.
var ErrStubProof = errors.New("not the stub proof of the binding digest")

// Proof returns the stub proof of a binding digest: the whole proof field,
// ghostpriv.ProofSize bytes.
func Proof(binding common.Hash) []byte {
	proof := make([]byte, ghostpriv.ProofSize)
	tag := ghosttree.K(TagTestProof, binding[:])
	copy(proof, tag[:])
	return proof
}

// ActionProof returns the stub proof of a policy action's binding digest:
// the whole proof field of an action, ghostpriv.ActionProofSize bytes.
func ActionProof(binding common.Hash) []byte {
	proof := make([]byte, ghostpriv.ActionProofSize)
	tag := ghosttree.K(TagTestProof, binding[:])
	copy(proof, tag[:])
	return proof
}

// Verifier is the stub verifier: it accepts exactly the stub proof of the
// binding digest the node computed, for a coin, policy or data reveal and
// for a policy action.
type Verifier struct{}

// VerifyReveal implements ghostpriv.Verifier.
func (Verifier) VerifyReveal(in *ghostpriv.VerifyInputs, proof []byte) error {
	if in == nil {
		return ErrStubProof
	}
	// An action's proof field has its own length, and only an action's.
	size := ghostpriv.ProofSize
	if in.Kind == ghosttree.Coin && in.Purpose == ghostpriv.PurposeAction {
		size = ghostpriv.ActionProofSize
	}
	if len(proof) != size {
		return ErrStubProof
	}
	if in.Kind != ghosttree.Coin && in.Kind != ghosttree.Data {
		return ErrStubProof
	}
	have := common.BytesToHash(proof[:32])
	if have != ghosttree.K(TagTestProof, in.Binding[:]) {
		salted, ok := saltedBinding(in)
		if !ok || have != ghosttree.K(TagTestProof, salted[:]) {
			return ErrStubProof
		}
	}
	for _, b := range proof[32:] {
		if b != 0 {
			return ErrStubProof
		}
	}
	return nil
}

// saltedBinding returns the binding digest of a version 1 coin reveal over a
// salted coin, type CoinV2, rebuilt from the inputs. It reports false for
// any other statement, which has one binding only, and for inputs whose
// unsalted digest is not the node's binding, so the salted digest always
// covers the very fields the node bound.
func saltedBinding(in *ghostpriv.VerifyInputs) (common.Hash, bool) {
	if in.Kind != ghosttree.Coin || in.Purpose != ghostpriv.PurposeReveal || in.Version != ghostpriv.RevealVersionV1 || in.Out == nil || in.Fee == nil {
		return common.Hash{}, false
	}
	r := &ghostpriv.Reveal{
		Version:   ghostpriv.RevealVersionV1,
		ChainID:   in.ChainID,
		Marker:    in.Marker,
		Root:      in.Root,
		Remainder: in.Remainder,
		Recipient: in.Recipient,
		Out:       in.Out,
		Fee:       in.Fee,
		Note:      in.Note,
	}
	if in.Rule != (common.Hash{}) || r.BindingDigest(in.ChainID, in.Domain) != in.Binding {
		return common.Hash{}, false
	}
	return r.SaltedBindingDigest(in.ChainID, in.Domain), true
}
