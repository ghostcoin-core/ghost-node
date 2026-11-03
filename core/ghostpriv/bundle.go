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

// The private bundle (type 0x55): one root proof stands in for the proofs of
// all the version 2 ordinary reveals of the bundle. The node verifies the
// root against public inputs it builds itself from the bundle's ordered
// bodies, its count, the chain and the versions; the root proves the
// validity of the reveals' proofs only. Every state-dependent check runs at
// execution, reveal by reveal, and a reveal that fails one is skipped while
// the rest of the bundle runs.
//
// The payload, after the type byte:
//
//	version (2, 0x0001) | chain id (8) | count (2) | root proof (1,310,720) | count bodies of 570 bytes
//
// A body is a version 2 reveal payload without its proof field: the payload's
// bytes 0 to 190 (version, chain id, marker, root, remainder, recipient, out
// and fee) followed by its 380-byte note.
const (
	// BundleVersion is the only version of the bundle payload.
	BundleVersion uint16 = 0x0001

	// BundleMaxReveals is the largest count of a bundle, 44 batches of 32
	// reveals.
	BundleMaxReveals = types.GhostBundleMaxReveals

	// BundleBodySize is the length of one bundled reveal, 190 + 380 bytes.
	BundleBodySize = types.GhostBundleBodySize

	// BundleBindingSize is the length of the bundle binding digest's input.
	BundleBindingSize = 79

	// PurposeBundle is the purpose of the bundle statement.
	PurposeBundle byte = 0x08

	// Offsets of the bundle payload.
	offBundleVersion = 0
	offBundleChainID = 2
	offBundleCount   = 10
	offBundleProof   = types.GhostBundleHeaderSize
	offBundleBodies  = offBundleProof + ProofSize
)

// The hash tags of the bundle: the digest of its ordered contents and its
// binding digest. Neither is a reveal's tag, so no reveal's digest or proof
// stands in for a root.
const (
	TagBundleContents = "ghost/bundle-contents/v1"
	TagBundleBinding  = "ghost/bundle-binding/v1"
)

// The errors of a bundle. Each makes the block that includes the bundle
// invalid, before any change of the bundle's; a reveal of the bundle that
// fails a state-dependent check is skipped instead (BundleSkip).
var (
	ErrBundleLength      = errors.New("bundle is not a 0x55 envelope of 1,310,733 + 570 * count bytes")
	ErrBundleCount       = errors.New("bundle count is not 1 to 1,408")
	ErrBundleVersion     = errors.New("bundle version is not 1")
	ErrBundleChainID     = errors.New("bundle chain id is not this chain's")
	ErrBundleBody        = errors.New("bundle body is not a version 2 reveal")
	ErrBundleProof       = errors.New("bundle root proof rejected")
	ErrBundleUnsupported = errors.New("proof verifier does not verify bundle roots")
)

// BundleInputs are the public inputs of a bundle's root proof, as the node
// computes them from the bundle: never taken from the proof. Contents is
// K(TagBundleContents, b_1 || ... || b_n) over the binding digests of the
// bundled reveals in order, each the Binding of Reveal.VerifyInputs of that
// reveal on this chain; Binding is K(TagBundleBinding, BindingInput()).
type BundleInputs struct {
	ChainID       uint64
	Domain        common.Hash // the genesis block hash
	Version       uint16      // the bundle version, BundleVersion
	RevealVersion uint16      // the version of every bundled reveal, RevealVersion
	Count         uint16
	Contents      common.Hash
	Binding       common.Hash
}

// BindingInput returns the 79 bytes the bundle binding digest hashes: the
// chain id (8), the bundle version (2), the domain (32), the statement 0x01
// and its version, the reveal version 0x02 (1 each), the purpose 0x08 (1),
// the count (2) and the contents digest (32).
func (in *BundleInputs) BindingInput() []byte {
	b := make([]byte, 0, BundleBindingSize)
	b = binary.BigEndian.AppendUint64(b, in.ChainID)
	b = binary.BigEndian.AppendUint16(b, in.Version)
	b = append(b, in.Domain[:]...)
	b = append(b, statementCoinReveal, byte(in.RevealVersion))
	b = append(b, PurposeBundle)
	b = binary.BigEndian.AppendUint16(b, in.Count)
	b = append(b, in.Contents[:]...)
	return b
}

// BundleVerifier checks the root proof of a bundle against the inputs the
// node computed. It returns nil only for a proof it positively accepts. A
// verifier offers it beside Verifier; the node finds it by a type assertion
// on the active verifier, and a verifier without it fails every bundle
// closed with ErrBundleUnsupported.
type BundleVerifier interface {
	VerifyBundle(in *BundleInputs, proof []byte) error
}

// NewBundleInputs builds the public inputs of a bundle of reveals, in order,
// on the chain of chainID and genesis.
func NewBundleInputs(chainID uint64, genesis common.Hash, reveals []*Reveal) *BundleInputs {
	digests := make([]byte, 0, 32*len(reveals))
	for _, r := range reveals {
		b := r.BindingDigest(chainID, genesis)
		digests = append(digests, b[:]...)
	}
	in := &BundleInputs{
		ChainID:       chainID,
		Domain:        genesis,
		Version:       BundleVersion,
		RevealVersion: RevealVersion,
		Count:         uint16(len(reveals)),
		Contents:      ghosttree.K(TagBundleContents, digests),
	}
	in.Binding = ghosttree.K(TagBundleBinding, in.BindingInput())
	return in
}

// Bundle is a decoded bundle payload: its root proof and its reveals, in
// order, each without a proof.
type Bundle struct {
	Version uint16
	ChainID uint64
	Proof   []byte // ProofSize bytes, or fewer to be padded with zeros
	Reveals []*Reveal
}

// Inputs returns the public inputs of the bundle's root on the chain of
// chainID and genesis.
func (b *Bundle) Inputs(chainID uint64, genesis common.Hash) *BundleInputs {
	return NewBundleInputs(chainID, genesis, b.Reveals)
}

// MarshalBinary returns the bundle's envelope: the type byte 0x55 and the
// payload. Every reveal must be a version 2 reveal; its proof is not
// carried. A count outside 1 to BundleMaxReveals, or a root proof longer
// than the field, is an error.
func (b *Bundle) MarshalBinary() ([]byte, error) {
	if len(b.Proof) > ProofSize {
		return nil, fmt.Errorf("root proof of %d bytes, the field holds %d", len(b.Proof), ProofSize)
	}
	n := len(b.Reveals)
	if n < 1 || n > BundleMaxReveals {
		return nil, fmt.Errorf("%w: %d", ErrBundleCount, n)
	}
	env := make([]byte, 1+types.GhostBundlePayloadSize(n))
	env[0] = types.GhostBundleTxType
	p := env[1:]
	binary.BigEndian.PutUint16(p[offBundleVersion:], b.Version)
	binary.BigEndian.PutUint64(p[offBundleChainID:], b.ChainID)
	binary.BigEndian.PutUint16(p[offBundleCount:], uint16(n))
	copy(p[offBundleProof:offBundleBodies], b.Proof)
	for i, r := range b.Reveals {
		body, err := BundleBody(r)
		if err != nil {
			return nil, fmt.Errorf("reveal %d: %w", i, err)
		}
		copy(p[offBundleBodies+i*BundleBodySize:], body)
	}
	return env, nil
}

// BundleBody returns the body of a version 2 reveal in a bundle: its payload
// without the proof field, the payload's first 190 bytes and its 380-byte
// note.
func BundleBody(r *Reveal) ([]byte, error) {
	if r.Version != RevealVersion {
		return nil, fmt.Errorf("%w: version %d", ErrBundleBody, r.Version)
	}
	body := make([]byte, BundleBodySize)
	binary.BigEndian.PutUint16(body[offVersion:], r.Version)
	binary.BigEndian.PutUint64(body[offChainID:], r.ChainID)
	copy(body[offMarker:], r.Marker[:])
	copy(body[offRoot:], r.Root[:])
	copy(body[offRemainder:], r.Remainder[:])
	copy(body[offRecipient:], r.Recipient[:])
	if r.Out != nil {
		copy(body[offOut:offFee], amountWord(r.Out))
	}
	if r.Fee != nil {
		copy(body[offFee:offProof], amountWord(r.Fee))
	}
	copy(body[offProof:], r.Note[:])
	return body, nil
}

// DecodeBundleBody decodes one bundled reveal as a version 2 reveal whose
// proof field is zero, left nil (Reveal.MarshalBinary pads it with zeros): a
// body of BundleBodySize bytes, version 2, with out and fee below 2^96.
// Anything else is ErrBundleBody.
func DecodeBundleBody(body []byte) (*Reveal, error) {
	if len(body) != BundleBodySize {
		return nil, fmt.Errorf("%w: %d bytes", ErrBundleBody, len(body))
	}
	r := &Reveal{
		Version:   binary.BigEndian.Uint16(body[offVersion:]),
		ChainID:   binary.BigEndian.Uint64(body[offChainID:]),
		Marker:    common.BytesToHash(body[offMarker:offRoot]),
		Root:      common.BytesToHash(body[offRoot:offRemainder]),
		Remainder: common.BytesToHash(body[offRemainder:offRecipient]),
		Recipient: common.BytesToAddress(body[offRecipient:offOut]),
	}
	copy(r.Note[:], body[offProof:])
	if r.Version != RevealVersion {
		return nil, fmt.Errorf("%w: %w: %d", ErrBundleBody, ErrRevealVersion, r.Version)
	}
	var err error
	if r.Out, err = readAmount(body[offOut:offFee]); err != nil {
		return nil, fmt.Errorf("%w: %w: out", ErrBundleBody, ErrRevealAmount)
	}
	if r.Fee, err = readAmount(body[offFee:offProof]); err != nil {
		return nil, fmt.Errorf("%w: %w: fee", ErrBundleBody, ErrRevealAmount)
	}
	return r, nil
}

// DecodeBundle decodes a bundle envelope and runs its shape checks: the type
// byte and a payload of at least the fixed fields (ErrBundleLength), a count
// of 1 to BundleMaxReveals (ErrBundleCount), the exact length of that count
// (ErrBundleLength), version 1 (ErrBundleVersion) and every body a version 2
// reveal (ErrBundleBody). The chain ids are checked by CheckBundle.
func DecodeBundle(envelope []byte) (*Bundle, error) {
	if len(envelope) < 1+types.GhostBundleFixedSize || envelope[0] != types.GhostBundleTxType {
		return nil, fmt.Errorf("%w: %d bytes", ErrBundleLength, len(envelope))
	}
	p := envelope[1:]
	n := int(binary.BigEndian.Uint16(p[offBundleCount:]))
	if n < 1 || n > BundleMaxReveals {
		return nil, fmt.Errorf("%w: %d", ErrBundleCount, n)
	}
	if want := types.GhostBundlePayloadSize(n); len(p) != want {
		return nil, fmt.Errorf("%w: %d bytes for count %d, want %d", ErrBundleLength, len(envelope), n, want+1)
	}
	b := &Bundle{
		Version: binary.BigEndian.Uint16(p[offBundleVersion:]),
		ChainID: binary.BigEndian.Uint64(p[offBundleChainID:]),
		Proof:   common.CopyBytes(p[offBundleProof:offBundleBodies]),
		Reveals: make([]*Reveal, n),
	}
	if b.Version != BundleVersion {
		return nil, fmt.Errorf("%w: %d", ErrBundleVersion, b.Version)
	}
	for i := range n {
		off := offBundleBodies + i*BundleBodySize
		r, err := DecodeBundleBody(p[off : off+BundleBodySize])
		if err != nil {
			return nil, fmt.Errorf("body %d: %w", i, err)
		}
		b.Reveals[i] = r
	}
	return b, nil
}

// VerifyBundleRoot verifies a bundle's root proof against in with verifier,
// the default verifier when nil. A verifier that is no BundleVerifier fails
// closed with ErrBundleUnsupported; a proof it refuses is ErrBundleProof.
func VerifyBundleRoot(verifier Verifier, in *BundleInputs, proof []byte) error {
	if verifier == nil {
		verifier = DefaultVerifier()
	}
	bv, ok := verifier.(BundleVerifier)
	if !ok {
		return fmt.Errorf("%w: %T", ErrBundleUnsupported, verifier)
	}
	if err := bv.VerifyBundle(in, common.CopyBytes(proof)); err != nil {
		return fmt.Errorf("%w: %w", ErrBundleProof, err)
	}
	return nil
}

// CheckBundle runs every structural check of a bundle, none of which reads
// the state: the shape checks of DecodeBundle, the bundle's chain id and
// every body's (ErrBundleChainID), and the root proof against the inputs the
// node builds from the bundle (ErrBundleUnsupported, ErrBundleProof). It
// returns the decoded bundle. It changes nothing.
func CheckBundle(env *BlockEnv, verifier Verifier, envelope []byte) (*Bundle, error) {
	b, err := DecodeBundle(envelope)
	if err != nil {
		return nil, err
	}
	if env == nil || env.Header == nil || env.Header.Number == nil {
		return nil, fmt.Errorf("%w: no including block", ErrRevealChainInfo)
	}
	if env.ChainID == nil || !env.ChainID.IsUint64() {
		return nil, fmt.Errorf("%w: chain %v", ErrBundleChainID, env.ChainID)
	}
	chainID := env.ChainID.Uint64()
	if b.ChainID != chainID {
		return nil, fmt.Errorf("%w: have %d, chain %d", ErrBundleChainID, b.ChainID, chainID)
	}
	for i, r := range b.Reveals {
		if r.ChainID != chainID {
			return nil, fmt.Errorf("%w: body %d has %d, chain %d", ErrBundleChainID, i, r.ChainID, chainID)
		}
	}
	if err := VerifyBundleRoot(verifier, b.Inputs(chainID, env.Genesis), b.Proof); err != nil {
		return nil, err
	}
	return b, nil
}

// BundleSkip is a reveal of a bundle that was skipped: its index in the
// bundle and the state-dependent check it failed.
type BundleSkip struct {
	Index int
	Err   error
}

// ApplyBundle checks a bundle and applies its reveals in order. The
// structural checks (CheckBundle) run first, before any change; a failure of
// one is returned and makes the block invalid. Then each reveal runs checks
// 4 to 9 of a lone reveal on the state the reveals before it left, and the
// coin tree check, and makes the very change a lone reveal makes, through a
// snapshot: a reveal that fails a state-dependent check (the window fee, a
// registered policy as recipient, a root that is not eligible, a spent
// marker, a repeat of a marker of the bundle included, the backstop, a coin
// tree that cannot take the remainder) is skipped with no change at all: it
// pays nothing and writes no log and no total. The skipped reveals are
// returned, in order. The gas is the caller's: it is the bundle's whole,
// skipped reveals included. On an error nothing is changed.
func ApplyBundle(st StateDB, env *BlockEnv, verifier Verifier, envelope []byte) ([]BundleSkip, error) {
	b, err := CheckBundle(env, verifier, envelope)
	if err != nil {
		return nil, err
	}
	start := st.Snapshot()
	var skipped []BundleSkip
	for i, r := range b.Reveals {
		snap := st.Snapshot()
		fee, kind, err := checkRevealFields(st, env, r)
		if err == nil {
			err = applyCheckedReveal(st, env, r, fee)
			kind = RevealState
		}
		if err == nil {
			continue
		}
		if kind == RevealStructural {
			st.RevertToSnapshot(start)
			return nil, fmt.Errorf("reveal %d: %w", i, err)
		}
		st.RevertToSnapshot(snap)
		skipped = append(skipped, BundleSkip{Index: i, Err: err})
	}
	return skipped, nil
}
