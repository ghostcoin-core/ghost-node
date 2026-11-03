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
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/params/ghost"
)

// The statement KNOW_PREIMAGE_v1 (spec 10, section 9.3), which the
// statement checker at 0x61 verifies for the frozen policy that calls it. Its
// proof shows knowledge of a 32-byte x with y = K("ghost/policy-preimage/v1",
// x). The public inputs are the chain id, the version, the domain (the
// genesis hash), the calling policy's address, y and a 64-byte context the
// policy supplies; the binding digest covers all of them, under a tag,
// statement code and purpose of its own, so a digest made for a policy
// action never verifies here, nor this one for an action.
const (
	TagPolicyPreimage  = "ghost/policy-preimage/v1"
	TagPreimageBinding = "ghost/preimage-binding/v1"

	// PreimageVersion is the version the binding carries.
	PreimageVersion uint16 = 0x0001

	// StatementPreimage is the statement code of KNOW_PREIMAGE_v1, the first
	// byte of the statement checker's input. The checker takes no other.
	StatementPreimage byte = 0x06

	// PurposePreimage is the purpose of the statement.
	PurposePreimage byte = 0x07

	// PreimageContextSize is the length of the context.
	PreimageContextSize = 64

	// PreimageBindingSize is the length of the binding digest input.
	PreimageBindingSize = 161

	// PreimageInputSize is the length of the statement checker's input: the
	// statement code (1), y (32), the context (64) and the proof field, which
	// is the policy action's, ActionProofSize bytes: 917,601 bytes.
	PreimageInputSize = 1 + 32 + PreimageContextSize + ActionProofSize
)

// A proof-carrying transaction holds the whole checker input.
var _ = [1]struct{}{}[ghost.ProofTxMaxBytes/PreimageInputSize-1]

var (
	// ErrPreimageInput is returned for a statement checker input that is not
	// PreimageInputSize bytes or does not start with StatementPreimage.
	ErrPreimageInput = errors.New("statement checker input is not a KNOW_PREIMAGE_v1 statement of 917,601 bytes")

	// ErrPreimageDomain is returned when the chain id or the genesis hash
	// the binding needs is missing: the check fails closed.
	ErrPreimageDomain = errors.New("statement check without the chain id or the genesis hash")

	// ErrPreimageProof is returned, wrapping the verifier's answer, for a
	// proof the verifier checked and did not accept.
	ErrPreimageProof = errors.New("statement proof rejected")
)

// Preimage is a decoded statement checker input: the KNOW_PREIMAGE_v1
// statement over Y and Context, and its proof field.
type Preimage struct {
	Y       common.Hash
	Context [PreimageContextSize]byte
	Proof   []byte // ActionProofSize bytes
}

// PreimageY returns y = K("ghost/policy-preimage/v1", x), the value a proof
// of knowledge of x is about.
func PreimageY(x common.Hash) common.Hash {
	return ghosttree.K(TagPolicyPreimage, x[:])
}

// DecodePreimageInput decodes the statement checker's input: exactly
// PreimageInputSize bytes, the statement code StatementPreimage, y, the
// context and the proof field. Anything else is ErrPreimageInput.
func DecodePreimageInput(input []byte) (*Preimage, error) {
	if len(input) != PreimageInputSize {
		return nil, fmt.Errorf("%w: %d bytes", ErrPreimageInput, len(input))
	}
	if input[0] != StatementPreimage {
		return nil, fmt.Errorf("%w: statement %#x", ErrPreimageInput, input[0])
	}
	p := &Preimage{
		Y:     common.BytesToHash(input[1:33]),
		Proof: common.CopyBytes(input[33+PreimageContextSize:]),
	}
	copy(p.Context[:], input[33:33+PreimageContextSize])
	return p, nil
}

// MarshalBinary returns the statement checker's input for the statement: a
// shorter proof is padded with zeros, a longer one is an error.
func (p *Preimage) MarshalBinary() ([]byte, error) {
	if len(p.Proof) > ActionProofSize {
		return nil, fmt.Errorf("proof of %d bytes, the field holds %d", len(p.Proof), ActionProofSize)
	}
	out := make([]byte, PreimageInputSize)
	out[0] = StatementPreimage
	copy(out[1:33], p.Y[:])
	copy(out[33:33+PreimageContextSize], p.Context[:])
	copy(out[33+PreimageContextSize:], p.Proof)
	return out, nil
}

// BindingInput returns the 161 bytes the binding digest hashes: the chain id
// (8), the version 1 (2), the domain, which is the genesis hash (32), the
// statement 0x06, its version 0x01 and the purpose 0x07 (1 each), the
// calling policy's address (20), y (32) and the context (64). The node
// supplies all but y and the context; the proof is not covered.
func (p *Preimage) BindingInput(chainID uint64, genesis common.Hash, policy common.Address) []byte {
	b := make([]byte, 0, PreimageBindingSize)
	b = binary.BigEndian.AppendUint64(b, chainID)
	b = binary.BigEndian.AppendUint16(b, PreimageVersion)
	b = append(b, genesis[:]...)
	b = append(b, StatementPreimage, statementVersion, PurposePreimage)
	b = append(b, policy[:]...)
	b = append(b, p.Y[:]...)
	b = append(b, p.Context[:]...)
	return b
}

// BindingDigest returns K("ghost/preimage-binding/v1", BindingInput).
func (p *Preimage) BindingDigest(chainID uint64, genesis common.Hash, policy common.Address) common.Hash {
	return ghosttree.K(TagPreimageBinding, p.BindingInput(chainID, genesis, policy))
}

// VerifyInputs returns the inputs the verifier receives for the statement
// made for policy on the chain of chainID and genesis: Kind ghosttree.Coin
// with PurposePreimage, the policy, y and the context. Every other field is
// zero.
func (p *Preimage) VerifyInputs(chainID uint64, genesis common.Hash, policy common.Address) *VerifyInputs {
	return &VerifyInputs{
		Kind:    ghosttree.Coin,
		Purpose: PurposePreimage,
		Version: PreimageVersion,
		Binding: p.BindingDigest(chainID, genesis, policy),
		ChainID: chainID,
		Domain:  genesis,
		Policy:  policy,
		Y:       p.Y,
		Context: p.Context,
	}
}

// PreimageVerifier is a Verifier that says which statements it has a proof
// system for. A verifier that does not implement it, or reports false, is
// not asked about KNOW_PREIMAGE_v1: the statement is refused with
// ErrStatementUnsupported without calling it. The linked proof verifier has
// no such proof system yet.
type PreimageVerifier interface {
	Verifier
	VerifiesPreimage() bool
}

// VerifyPreimage verifies the statement checker's input for the calling
// policy on the chain of chainID and genesis through v, the active verifier
// when nil. It returns nil only for a proof the verifier accepts:
// ErrPreimageInput for an input of the wrong length or statement,
// ErrPreimageDomain without a chain id or genesis hash, ErrStatementUnsupported
// (or ErrNoVerifier) when the node cannot verify the statement, and an error
// wrapping ErrPreimageProof for a proof the verifier rejects. The caller
// charges the gas or the check before calling it.
func VerifyPreimage(v Verifier, chainID uint64, genesis common.Hash, policy common.Address, input []byte) error {
	p, err := DecodePreimageInput(input)
	if err != nil {
		return err
	}
	if chainID == 0 || genesis == (common.Hash{}) {
		return ErrPreimageDomain
	}
	if v == nil {
		v = ActiveVerifier()
	}
	if pv, ok := v.(PreimageVerifier); !ok || !pv.VerifiesPreimage() {
		return fmt.Errorf("%w: KNOW_PREIMAGE_v1", ErrStatementUnsupported)
	}
	if err := v.VerifyReveal(p.VerifyInputs(chainID, genesis, policy), p.Proof); err != nil {
		if errors.Is(err, ErrNoVerifier) || errors.Is(err, ErrStatementUnsupported) {
			return err
		}
		return fmt.Errorf("%w: %w", ErrPreimageProof, err)
	}
	return nil
}
