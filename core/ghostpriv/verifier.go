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

package ghostpriv

import (
	"errors"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/holiman/uint256"
)

// ErrNoVerifier is the answer of the reject-all verifier to every reveal: the
// node was built without the proof verifier, so it cannot confirm any proof.
var ErrNoVerifier = errors.New("no reveal proof verifier in this node")

// ErrStatementUnsupported is the answer of the linked proof verifier, given
// without calling it, to a statement it has no proof system for: a version 2
// ordinary reveal and a policy reveal. Their statements are not those of the
// linked library's C interface, so they are refused, fail-closed, before any
// state change, until a verifier that supports them is linked.
var ErrStatementUnsupported = errors.New("linked proof verifier does not verify this statement version")

// VerifyInputs are the public inputs of a reveal's proof, as the node
// computes them: never taken from the proof.
//
// Kind and Purpose name the statement: an ordinary coin reveal is Kind
// ghosttree.Coin with PurposeReveal; a policy reveal is Kind ghosttree.Coin
// with PurposePolicySpend; a data reveal is Kind ghosttree.Data with
// PurposeReveal or PurposeRevoke. For a data reveal Recipient is the
// verifier-or-recipient field, which credits nothing, Cf is the content
// fingerprint the reveal carries, and Remainder, Out, Rule and Note are zero.
// For a coin reveal Cf is zero and Version is the reveal's version: Note is
// the version 2 reveal's 380-byte remainder note, or the version 1 reveal's
// RevealNoteSize note in its first RevealNoteSize bytes with the rest zero,
// which the proof binds as it is. The policy fields, from Policy to Instr,
// are set for a policy reveal only; a policy reveal's Recipient is zero.
//
// A policy action is Kind ghosttree.Coin with PurposeAction: its proof shows
// knowledge of the action key behind the slot's ActionTag and ActionSalt and
// binds the action. Marker is the slot's marker, Policy to Instr are the
// slot's, and the action fields, from ActionNonce to CalldataHash, are set;
// Root, Remainder, Recipient, Rule, Note and Cf are zero and Out and Fee are
// zero amounts. The action fields are zero for every other statement.
//
// A KNOW_PREIMAGE_v1 statement, which the statement checker at 0x61
// verifies, is Kind ghosttree.Coin with PurposePreimage (preimage.go):
// Policy is the calling policy, Y and Context are the statement's, and
// Version, Binding, ChainID and Domain are set; every other field is zero.
// Y and Context are zero for every other statement.
type VerifyInputs struct {
	Kind      ghosttree.Kind
	Purpose   byte
	Version   uint16      // the reveal payload's version
	Binding   common.Hash // the binding digest
	ChainID   uint64
	Domain    common.Hash // the genesis block hash
	Root      common.Hash
	Marker    common.Hash
	Remainder common.Hash
	Recipient common.Address
	Out       *uint256.Int
	Fee       *uint256.Int
	Rule      common.Hash // 32 zero bytes, the empty rule
	Note      [NoteSize]byte
	Cf        common.Hash // the content fingerprint, data reveals only

	Policy         common.Address // the policy address
	PolicyCodeHash common.Hash    // the policy's code hash
	ParamsHash     common.Hash
	ActionTag      common.Hash
	ActionSalt     common.Hash
	Instr          common.Hash

	ActionNonce       uint64       // the slot's action nonce the action spends
	ExpectedRemaining *uint256.Int // the slot's remaining before the action
	Debit             *uint256.Int // the exact amount the action takes
	Expiry            uint64       // the last block height the action is valid in
	CalldataHash      common.Hash  // ActionCalldataHash of the policy call's calldata

	Y       common.Hash               // y = K("ghost/policy-preimage/v1", x)
	Context [PreimageContextSize]byte // the context the policy supplies
}

// HoldInputs are the public inputs of a proof of holding of a data
// commitment, as its verifier chooses them: the data tree root and the data
// marker-set root from headers it accepts, its own identity, its fresh
// challenge and the content fingerprint it asks about. The chain id and
// genesis hash are the chain's. A proof of holding never goes on chain and
// block processing checks none.
type HoldInputs struct {
	ChainID       uint64
	Domain        common.Hash // the genesis block hash
	Root          common.Hash // a data tree root
	MarkerSetRoot common.Hash // a data marker-set root, a header's DataMarkerRoot
	Verifier      common.Hash // the holding verifier's own identity
	Challenge     common.Hash // the holding verifier's fresh challenge
	Cf            common.Hash // the content fingerprint
}

// Verifier checks the proof of a reveal against the inputs the node computed.
// It returns nil only for a proof it positively accepts; any doubt is an
// error.
type Verifier interface {
	VerifyReveal(in *VerifyInputs, proof []byte) error
}

// DefaultVerifier, the verifier the node uses until another is set, is in
// verifier_cgo.go for builds that link the proof verifier of the ghost
// repository (release builds on Linux and macOS, and builds with the
// ghostproofs tag) and in verifier_nocgo.go, which rejects every reveal, for
// all others, as is VerifyHold.

type verifierBox struct{ v Verifier }

var active atomic.Pointer[verifierBox]

// ActiveVerifier returns the verifier block processing uses.
func ActiveVerifier() Verifier {
	if b := active.Load(); b != nil && b.v != nil {
		return b.v
	}
	return DefaultVerifier()
}

// SetVerifier makes v the verifier block processing uses, nil for the
// default, and returns a function that restores the one before. It is for
// linking the proof system's verifier in at startup and for tests; nothing
// else calls it.
func SetVerifier(v Verifier) (restore func()) {
	prev := active.Swap(&verifierBox{v: v})
	return func() { active.Store(prev) }
}
