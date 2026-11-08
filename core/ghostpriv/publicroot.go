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
	"github.com/ethereum/go-ethereum/core/types"
)

// The public root (type 0x56): one root proof stands in for the signatures
// of the binding transactions (type 0x57) of its block. The node verifies the
// root against public inputs it builds itself, for every binding transaction
// of the block in block order: the 20-byte account, the 32-byte key identity
// read from state at this block (types.GhostRecordedKeyIdentity) and the
// 32-byte transaction hash (types.GhostBindingTx.TxHash), with the chain id
// and the genesis hash as the domain. A binding is those 84 bytes. The root
// proves the signatures only: every state-dependent check of a binding
// transaction (nonce, balance, code, gas) still runs at its execution.
//
// The payload, after the type byte:
//
//	version (2, 0x0001) | chain id (8) | count (2) | root proof (1,310,720) | count bindings of 84 bytes
const (
	// PublicRootVersion is the only version of the public root payload.
	PublicRootVersion uint16 = 0x0001

	// PublicBindingSize is the length of one binding.
	PublicBindingSize = types.GhostBindingSize

	// PublicRootBindingSize is the length of the public root binding
	// digest's input.
	PublicRootBindingSize = 8 + 2 + 32 + 1 + 2 + 32

	// PurposePublicRoot is the purpose of the public root statement.
	PurposePublicRoot byte = 0x09

	// PublicRootProtocolVersion and PublicRootStatementVersion are the
	// versions the binding of a public root's proof names after the chain
	// id (PublicRootInputs.RootInputs): protocol version 2 and statement
	// version 2, as ghost-proofs makes a public root.
	PublicRootProtocolVersion  uint16 = 0x0002
	PublicRootStatementVersion byte   = 0x02

	// Offsets of the public root payload.
	offRootVersion  = 0
	offRootChainID  = 2
	offRootCount    = 10
	offRootProof    = types.GhostPublicRootHeaderSize
	offRootBindings = offRootProof + ProofSize
)

// The hash tags of the public root: the digest of its ordered bindings and
// its binding digest. Neither is a reveal's or a bundle's tag, so no other
// statement's digest or proof stands in for a public root.
const (
	TagPublicRootContents = "ghost/public-root-contents/v1"
	TagPublicRootBinding  = "ghost/public-root-binding/v1"
)

// The errors of a public root. Each makes the block that includes the root
// or its binding transactions invalid.
var (
	ErrPublicRootLength      = errors.New("public root is not a 0x56 envelope of 1,310,733 + 84 * count bytes")
	ErrPublicRootCount       = errors.New("public root count is not the count of its block's binding transactions")
	ErrPublicRootVersion     = errors.New("public root version is not 1")
	ErrPublicRootChainID     = errors.New("public root chain id is not this chain's")
	ErrPublicRootBinding     = errors.New("public root binding is not the one the node builds")
	ErrPublicRootProof       = errors.New("public root proof rejected")
	ErrPublicRootUnsupported = errors.New("proof verifier does not verify public roots")
	ErrPublicRootRepeated    = errors.New("block holds more than one public root")
	ErrPublicRootMissing     = errors.New("binding transaction without a public root before it in its block")
	ErrPublicKeyIdentity     = errors.New("binding key identity is not the one recorded in state")
)

// PublicRootInputs are the public inputs of a public root's proof, as the
// node computes them from the binding transactions of the block: never taken
// from the proof nor from the root. Bindings are the 84-byte bindings in
// block order; Contents is K(TagPublicRootContents, b_1 || ... || b_n) over
// them; Binding is K(TagPublicRootBinding, BindingInput()).
type PublicRootInputs struct {
	ChainID  uint64
	Domain   common.Hash // the genesis block hash
	Version  uint16      // the public root version, PublicRootVersion
	Count    uint16
	Bindings []types.GhostBinding
	Contents common.Hash
	Binding  common.Hash
}

// BindingInput returns the 77 bytes the public root binding digest hashes:
// the chain id (8), the root version (2), the domain (32), the purpose 0x09
// (1), the count (2) and the contents digest (32).
func (in *PublicRootInputs) BindingInput() []byte {
	b := make([]byte, 0, PublicRootBindingSize)
	b = binary.BigEndian.AppendUint64(b, in.ChainID)
	b = binary.BigEndian.AppendUint16(b, in.Version)
	b = append(b, in.Domain[:]...)
	b = append(b, PurposePublicRoot)
	b = binary.BigEndian.AppendUint16(b, in.Count)
	b = append(b, in.Contents[:]...)
	return b
}

// RootInputs returns the inputs of the public root's proof in the layout of
// ghost_proofs.h: the binding, which is the chain id (8, big endian),
// PublicRootProtocolVersion (2) and PublicRootStatementVersion (1), then
// the 84-byte Bindings in block order, the ordered items of the root. The
// root binding of ghost_proofs.h has no domain, so Domain is not among them.
func (in *PublicRootInputs) RootInputs() []byte {
	b := make([]byte, 0, RootBindingSize+PublicBindingSize*len(in.Bindings))
	b = binary.BigEndian.AppendUint64(b, in.ChainID)
	b = binary.BigEndian.AppendUint16(b, PublicRootProtocolVersion)
	b = append(b, PublicRootStatementVersion)
	for _, binding := range in.Bindings {
		b = append(b, binding[:]...)
	}
	return b
}

// PublicRootVerifier checks the proof of a public root against the inputs
// the node computed. It returns nil only for a proof it positively accepts.
// A verifier offers it beside Verifier; the node finds it by a type
// assertion on the active verifier, and a verifier without it fails every
// public root closed with ErrPublicRootUnsupported.
type PublicRootVerifier interface {
	VerifyPublicRoot(in *PublicRootInputs, proof []byte) error
}

// NewPublicRootInputs builds the public inputs of a public root over the
// bindings, in block order, on the chain of chainID and genesis.
func NewPublicRootInputs(chainID uint64, genesis common.Hash, bindings []types.GhostBinding) *PublicRootInputs {
	contents := make([]byte, 0, PublicBindingSize*len(bindings))
	for _, b := range bindings {
		contents = append(contents, b[:]...)
	}
	in := &PublicRootInputs{
		ChainID:  chainID,
		Domain:   genesis,
		Version:  PublicRootVersion,
		Count:    uint16(len(bindings)),
		Bindings: append([]types.GhostBinding(nil), bindings...),
		Contents: ghosttree.K(TagPublicRootContents, contents),
	}
	in.Binding = ghosttree.K(TagPublicRootBinding, in.BindingInput())
	return in
}

// NodeBinding is the binding the node builds for a binding transaction of
// account whose transaction hash is txHash: the account, the key identity
// read from st, the state at this point of the block, and the hash.
func NodeBinding(st types.GhostKeyIdentityReader, account common.Address, txHash common.Hash) types.GhostBinding {
	return types.NewGhostBinding(account, types.GhostRecordedKeyIdentity(st, account), txHash)
}

// CheckBinding checks the binding a binding transaction carries against the
// one the node builds for it on st: the account must have a key identity
// recorded, the carried key identity must be it (ErrPublicKeyIdentity) and
// the carried transaction hash must be txHash (ErrPublicRootBinding). It
// returns the node's binding.
func CheckBinding(st types.GhostKeyIdentityReader, carried types.GhostBinding, txHash common.Hash) (types.GhostBinding, error) {
	node := NodeBinding(st, carried.Account(), txHash)
	if recorded := node.KeyIdentity(); recorded == (common.Hash{}) || recorded != carried.KeyIdentity() {
		return node, fmt.Errorf("%w: account %v, key identity %v, recorded %v", ErrPublicKeyIdentity,
			carried.Account().Hex(), carried.KeyIdentity(), recorded)
	}
	if carried.TxHash() != txHash {
		return node, fmt.Errorf("%w: account %v, transaction hash %v, want %v", ErrPublicRootBinding,
			carried.Account().Hex(), carried.TxHash(), txHash)
	}
	return node, nil
}

// PublicRoot is a decoded public root payload: its proof and the bindings it
// lists, in order.
type PublicRoot struct {
	Version  uint16
	ChainID  uint64
	Proof    []byte // ProofSize bytes, or fewer to be padded with zeros
	Bindings []types.GhostBinding
}

// Inputs returns the public inputs of the root over the bindings it lists on
// the chain of chainID and genesis. The node checks a root against the
// inputs it builds from its block (CheckPublicRoot), not these.
func (r *PublicRoot) Inputs(chainID uint64, genesis common.Hash) *PublicRootInputs {
	return NewPublicRootInputs(chainID, genesis, r.Bindings)
}

// MarshalBinary returns the root's envelope: the type byte 0x56 and the
// payload. A count of 0 or above 65,535, or a proof longer than the field,
// is an error.
func (r *PublicRoot) MarshalBinary() ([]byte, error) {
	if len(r.Proof) > ProofSize {
		return nil, fmt.Errorf("root proof of %d bytes, the field holds %d", len(r.Proof), ProofSize)
	}
	n := len(r.Bindings)
	if n < 1 || n > 0xffff {
		return nil, fmt.Errorf("%w: %d bindings", ErrPublicRootLength, n)
	}
	env := make([]byte, 1+types.GhostPublicRootPayloadSize(n))
	env[0] = types.GhostPublicRootTxType
	p := env[1:]
	binary.BigEndian.PutUint16(p[offRootVersion:], r.Version)
	binary.BigEndian.PutUint64(p[offRootChainID:], r.ChainID)
	binary.BigEndian.PutUint16(p[offRootCount:], uint16(n))
	copy(p[offRootProof:offRootBindings], r.Proof)
	for i, b := range r.Bindings {
		copy(p[offRootBindings+i*PublicBindingSize:], b[:])
	}
	return env, nil
}

// DecodePublicRoot decodes a public root envelope and runs its shape checks:
// the type byte, a payload of at least the fixed fields, a count of at least
// 1 and the exact length of that count (ErrPublicRootLength) and version 1
// (ErrPublicRootVersion). The chain id is checked by CheckPublicRoot.
func DecodePublicRoot(envelope []byte) (*PublicRoot, error) {
	if len(envelope) < 1+types.GhostPublicRootFixedSize || envelope[0] != types.GhostPublicRootTxType {
		return nil, fmt.Errorf("%w: %d bytes", ErrPublicRootLength, len(envelope))
	}
	p := envelope[1:]
	n := int(binary.BigEndian.Uint16(p[offRootCount:]))
	if n < 1 {
		return nil, fmt.Errorf("%w: count %d", ErrPublicRootLength, n)
	}
	if want := types.GhostPublicRootPayloadSize(n); len(p) != want {
		return nil, fmt.Errorf("%w: %d bytes for count %d, want %d", ErrPublicRootLength, len(envelope), n, want+1)
	}
	r := &PublicRoot{
		Version:  binary.BigEndian.Uint16(p[offRootVersion:]),
		ChainID:  binary.BigEndian.Uint64(p[offRootChainID:]),
		Proof:    common.CopyBytes(p[offRootProof:offRootBindings]),
		Bindings: make([]types.GhostBinding, n),
	}
	if r.Version != PublicRootVersion {
		return nil, fmt.Errorf("%w: %d", ErrPublicRootVersion, r.Version)
	}
	for i := range n {
		copy(r.Bindings[i][:], p[offRootBindings+i*PublicBindingSize:])
	}
	return r, nil
}

// VerifyPublicRoot verifies a public root's proof against in with verifier,
// the default verifier when nil. A verifier that is no PublicRootVerifier
// fails closed with ErrPublicRootUnsupported; a proof it refuses is
// ErrPublicRootProof.
func VerifyPublicRoot(verifier Verifier, in *PublicRootInputs, proof []byte) error {
	if verifier == nil {
		verifier = DefaultVerifier()
	}
	rv, ok := verifier.(PublicRootVerifier)
	if !ok {
		return fmt.Errorf("%w: %T", ErrPublicRootUnsupported, verifier)
	}
	if err := rv.VerifyPublicRoot(in, common.CopyBytes(proof)); err != nil {
		return fmt.Errorf("%w: %w", ErrPublicRootProof, err)
	}
	return nil
}

// CheckPublicRoot runs every check of a public root, none of which changes
// the state: the shape checks of DecodePublicRoot, the root's chain id
// (ErrPublicRootChainID), the bindings it lists against the node's
// bindings of the block's binding transactions, in block order, built on
// the state at the root (ErrPublicRootCount, ErrPublicRootBinding), and the
// proof against the inputs built from the node's bindings
// (ErrPublicRootUnsupported, ErrPublicRootProof). It returns the decoded
// root.
func CheckPublicRoot(env *BlockEnv, verifier Verifier, envelope []byte, bindings []types.GhostBinding) (*PublicRoot, error) {
	r, err := DecodePublicRoot(envelope)
	if err != nil {
		return nil, err
	}
	if env == nil || env.ChainID == nil || !env.ChainID.IsUint64() {
		return nil, fmt.Errorf("%w: no chain id", ErrPublicRootChainID)
	}
	chainID := env.ChainID.Uint64()
	if r.ChainID != chainID {
		return nil, fmt.Errorf("%w: have %d, chain %d", ErrPublicRootChainID, r.ChainID, chainID)
	}
	if len(r.Bindings) != len(bindings) {
		return nil, fmt.Errorf("%w: root of %d, block of %d", ErrPublicRootCount, len(r.Bindings), len(bindings))
	}
	for i := range bindings {
		if r.Bindings[i] != bindings[i] {
			return nil, fmt.Errorf("%w: binding %d of the root is not the block's", ErrPublicRootBinding, i)
		}
	}
	if err := VerifyPublicRoot(verifier, NewPublicRootInputs(chainID, env.Genesis, bindings), r.Proof); err != nil {
		return nil, err
	}
	return r, nil
}
