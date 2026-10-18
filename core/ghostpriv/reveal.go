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
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/holiman/uint256"
)

// Offsets and lengths of the reveal payload, which is a fixed layout and not
// RLP.
const (
	offVersion   = 0
	offChainID   = 2
	offMarker    = 10
	offRoot      = 42
	offRemainder = 74
	offRecipient = 106
	offOut       = 126
	offFee       = 158
	offProof     = 190
	offNote      = offProof + ProofSize

	// ProofSize is the length of the proof field: the serialized proof
	// followed by zeros.
	ProofSize = 1_028_144

	// PayloadSize is the length of the payload, EnvelopeSize of the type
	// byte and the payload.
	PayloadSize  = types.GhostRevealPayloadSize
	EnvelopeSize = types.GhostRevealEnvelopeSize

	// BindingSize is the length of the binding digest's input.
	BindingSize = 415
)

// Fixed fields of the binding digest.
const (
	statementCoinReveal = 0x01
	statementVersion    = 0x01
	purposeReveal       = 0x01
)

// The errors of the reveal checks, one per check, in the order they run.
// Check 6 computes the binding digest and check 11 has nothing to read, so
// neither can fail; ErrRevealChainInfo wraps a missing ancestor under the
// check that needed it.
var (
	ErrRevealLength    = errors.New("reveal is not a 0x50 envelope of 1,028,491 bytes")
	ErrRevealVersion   = errors.New("reveal version is not 1")
	ErrRevealAmount    = errors.New("reveal out or fee not below 2^96")
	ErrRevealChainID   = errors.New("reveal chain id is not this chain's")
	ErrRevealFee       = errors.New("reveal fee is not the window fee")
	ErrRevealRoot      = errors.New("reveal root is not an ancestor's coin tree root")
	ErrRevealMarker    = errors.New("reveal marker already used")
	ErrRevealBackstop  = errors.New("reveal takes more than the hidden set holds")
	ErrRevealProof     = errors.New("reveal proof rejected")
	ErrRevealTree      = errors.New("coin tree cannot take the remainder")
	ErrRevealChainInfo = errors.New("chain information for the reveal unavailable")
)

// Reveal is a decoded reveal payload.
type Reveal struct {
	Version   uint16
	ChainID   uint64
	Marker    common.Hash
	Root      common.Hash
	Remainder common.Hash
	Recipient common.Address
	Out       *uint256.Int
	Fee       *uint256.Int
	Proof     []byte // ProofSize bytes, or fewer to be padded with zeros
	Note      [NoteSize]byte
}

// MarshalBinary returns the reveal's envelope: the type byte 0x50 and the
// payload of EnvelopeSize - 1 bytes. A shorter proof is padded with zeros;
// a longer one is an error.
func (r *Reveal) MarshalBinary() ([]byte, error) {
	if len(r.Proof) > ProofSize {
		return nil, fmt.Errorf("proof of %d bytes, the field holds %d", len(r.Proof), ProofSize)
	}
	env := make([]byte, EnvelopeSize)
	env[0] = types.GhostRevealTxType
	p := env[1:]
	binary.BigEndian.PutUint16(p[offVersion:], r.Version)
	binary.BigEndian.PutUint64(p[offChainID:], r.ChainID)
	copy(p[offMarker:], r.Marker[:])
	copy(p[offRoot:], r.Root[:])
	copy(p[offRemainder:], r.Remainder[:])
	copy(p[offRecipient:], r.Recipient[:])
	if r.Out != nil {
		copy(p[offOut:offFee], amountWord(r.Out))
	}
	if r.Fee != nil {
		copy(p[offFee:offProof], amountWord(r.Fee))
	}
	copy(p[offProof:offNote], r.Proof)
	copy(p[offNote:], r.Note[:])
	return env, nil
}

// DecodeReveal decodes a reveal envelope and runs the first three checks:
// the type byte and exact length (ErrRevealLength), version 1
// (ErrRevealVersion), and out and fee below 2^96 (ErrRevealAmount).
func DecodeReveal(envelope []byte) (*Reveal, error) {
	if len(envelope) != EnvelopeSize || envelope[0] != types.GhostRevealTxType {
		return nil, fmt.Errorf("%w: %d bytes", ErrRevealLength, len(envelope))
	}
	p := envelope[1:]
	r := &Reveal{
		Version:   binary.BigEndian.Uint16(p[offVersion:]),
		ChainID:   binary.BigEndian.Uint64(p[offChainID:]),
		Marker:    common.BytesToHash(p[offMarker:offRoot]),
		Root:      common.BytesToHash(p[offRoot:offRemainder]),
		Remainder: common.BytesToHash(p[offRemainder:offRecipient]),
		Recipient: common.BytesToAddress(p[offRecipient:offOut]),
		Proof:     common.CopyBytes(p[offProof:offNote]),
	}
	copy(r.Note[:], p[offNote:])
	if r.Version != Version {
		return nil, fmt.Errorf("%w: %d", ErrRevealVersion, r.Version)
	}
	var err error
	if r.Out, err = readAmount(p[offOut:offFee]); err != nil {
		return nil, fmt.Errorf("%w: out", ErrRevealAmount)
	}
	if r.Fee, err = readAmount(p[offFee:offProof]); err != nil {
		return nil, fmt.Errorf("%w: fee", ErrRevealAmount)
	}
	return r, nil
}

// BindingDigest returns the binding digest the proof must commit to,
// K("ghost/coin-reveal-binding/v1", fields) over the 415 bytes of
// BindingInput.
func (r *Reveal) BindingDigest(chainID uint64, genesis common.Hash) common.Hash {
	return ghosttree.K(TagRevealBinding, r.BindingInput(chainID, genesis))
}

// BindingInput returns the 415 bytes the binding digest hashes: the chain
// id (8), the version (2), the domain, which is the genesis hash (32), the
// statement and its version (1 each), the type COIN (2), the purpose (1),
// the root, marker and remainder (32 each), the recipient (20), out and fee
// (32 each), the rule, 32 zero bytes for the empty rule, and the note (156).
// The version is always 1 and the rule always empty: the node supplies them.
func (r *Reveal) BindingInput(chainID uint64, genesis common.Hash) []byte {
	out, fee := r.Out, r.Fee
	if out == nil {
		out = new(uint256.Int)
	}
	if fee == nil {
		fee = new(uint256.Int)
	}
	b := make([]byte, 0, BindingSize)
	b = binary.BigEndian.AppendUint64(b, chainID)
	b = binary.BigEndian.AppendUint16(b, Version)
	b = append(b, genesis[:]...)
	b = append(b, statementCoinReveal, statementVersion)
	b = append(b, Coin[:]...)
	b = append(b, purposeReveal)
	b = append(b, r.Root[:]...)
	b = append(b, r.Marker[:]...)
	b = append(b, r.Remainder[:]...)
	b = append(b, r.Recipient[:]...)
	b = append(b, amountWord(out)...)
	b = append(b, amountWord(fee)...)
	b = append(b, make([]byte, 32)...) // the empty rule
	b = append(b, r.Note[:]...)
	return b
}

// ChainReader gives the headers of the including block's ancestry by hash
// and number. *core.BlockChain satisfies it.
type ChainReader interface {
	GetHeader(hash common.Hash, number uint64) *types.Header
}

// BlockEnv is what a reveal is checked against: the including block's
// header (its number, parent hash, base fee and coinbase), the chain that
// holds its ancestors, the chain id and the genesis hash.
type BlockEnv struct {
	Header  *types.Header
	Chain   ChainReader
	ChainID *big.Int
	Genesis common.Hash
}

// parent returns the parent of h from the chain, checking that it is the
// block h names; nil if it is not available.
func (env *BlockEnv) parent(h *types.Header) *types.Header {
	if h.Number == nil || h.Number.Sign() <= 0 || env.Chain == nil {
		return nil
	}
	n := h.Number.Uint64() - 1
	p := env.Chain.GetHeader(h.ParentHash, n)
	if p == nil || p.Number == nil || p.Number.Uint64() != n || p.Hash() != h.ParentHash {
		return nil
	}
	return p
}

// windowBaseFee returns the base fee of the first block of the including
// block's fee window, found by walking its parent links; the including block
// itself when it starts the window.
func (env *BlockEnv) windowBaseFee() (*big.Int, error) {
	h := env.Header
	start := WindowStart(h.Number.Uint64())
	for h.Number.Uint64() > start {
		if h = env.parent(h); h == nil {
			return nil, fmt.Errorf("%w: ancestor at height %d", ErrRevealChainInfo, start)
		}
	}
	if h.BaseFee == nil {
		return nil, fmt.Errorf("%w: block %d has no base fee", ErrRevealChainInfo, start)
	}
	return h.BaseFee, nil
}

// rootEligible reports whether root is the coin tree root in the header of
// a block of the including block's ancestry, strictly below it, found by
// walking parent links. A missing ancestor ends the walk with false.
func (env *BlockEnv) rootEligible(root common.Hash) bool {
	for h := env.parent(env.Header); h != nil; h = env.parent(h) {
		if h.CoinTreeRoot != nil && *h.CoinTreeRoot == root {
			return true
		}
	}
	return false
}

// CheckReveal runs checks 1 to 11 of a reveal against the state before it
// and returns the decoded reveal and its window fee. It changes nothing.
func CheckReveal(st StateDB, env *BlockEnv, verifier Verifier, envelope []byte) (*Reveal, Fee, error) {
	// Checks 1 to 3: type, length, version and amount words.
	r, err := DecodeReveal(envelope)
	if err != nil {
		return nil, Fee{}, err
	}
	if env == nil || env.Header == nil || env.Header.Number == nil {
		return nil, Fee{}, fmt.Errorf("%w: no including block", ErrRevealChainInfo)
	}
	// Check 4: the chain id.
	if env.ChainID == nil || !env.ChainID.IsUint64() || env.ChainID.Uint64() != r.ChainID {
		return nil, Fee{}, fmt.Errorf("%w: have %d, chain %v", ErrRevealChainID, r.ChainID, env.ChainID)
	}
	chainID := env.ChainID.Uint64()
	// Check 5: the fee of the window.
	bRef, err := env.windowBaseFee()
	if err != nil {
		return nil, Fee{}, fmt.Errorf("%w: %w", ErrRevealFee, err)
	}
	fee, err := WindowFee(bRef)
	if err != nil {
		return nil, Fee{}, fmt.Errorf("%w: %w", ErrRevealFee, err)
	}
	if !fee.Total.Eq(r.Fee) {
		return nil, Fee{}, fmt.Errorf("%w: have %v, want %v", ErrRevealFee, r.Fee, fee.Total)
	}
	// Check 6: the node's own binding digest.
	binding := r.BindingDigest(chainID, env.Genesis)
	// Check 7: the root.
	if !env.rootEligible(r.Root) {
		return nil, Fee{}, fmt.Errorf("%w: %x", ErrRevealRoot, r.Root)
	}
	// Check 8: the marker, against the spent set, which holds the markers of
	// earlier reveals of this block too.
	if ghosttree.IsSpent(st, ghosttree.Coin, r.Marker) {
		return nil, Fee{}, fmt.Errorf("%w: %x", ErrRevealMarker, r.Marker)
	}
	// Check 9: the backstop.
	hidden, err := Hidden(st)
	if err != nil {
		return nil, Fee{}, fmt.Errorf("%w: %w", ErrRevealBackstop, err)
	}
	if need := new(uint256.Int).Add(r.Out, r.Fee); need.Gt(hidden) {
		return nil, Fee{}, fmt.Errorf("%w: out plus fee %v, hidden %v", ErrRevealBackstop, need, hidden)
	}
	// Check 10: the proof, for the inputs the node computed. Check 11, the
	// rule, is the empty rule, which the inputs carry as 32 zero bytes.
	if verifier == nil {
		verifier = DefaultVerifier()
	}
	in := &VerifyInputs{
		Binding:   binding,
		ChainID:   chainID,
		Domain:    env.Genesis,
		Root:      r.Root,
		Marker:    r.Marker,
		Remainder: r.Remainder,
		Recipient: r.Recipient,
		Out:       new(uint256.Int).Set(r.Out),
		Fee:       new(uint256.Int).Set(r.Fee),
		Note:      r.Note,
	}
	if err := verifier.VerifyReveal(in, common.CopyBytes(r.Proof)); err != nil {
		return nil, Fee{}, fmt.Errorf("%w: %w", ErrRevealProof, err)
	}
	return r, fee, nil
}

// ApplyReveal checks a reveal and makes its one atomic change: it marks the
// marker spent, credits out to the recipient as a plain balance credit,
// burns the base part of the fee, pays the tip to the coinbase, appends the
// remainder with the receipt log and adds out plus fee to the total out. The
// gas is the caller's. On an error nothing is changed.
func ApplyReveal(st StateDB, env *BlockEnv, verifier Verifier, envelope []byte) error {
	r, fee, err := CheckReveal(st, env, verifier, envelope)
	if err != nil {
		return err
	}
	height := env.Header.Number.Uint64()
	snap := st.Snapshot()
	fail := func(err error) error {
		st.RevertToSnapshot(snap)
		return err
	}
	// Check 12: the coin tree takes the remainder, or nothing is written.
	res, err := ghosttree.Append(st, ghosttree.Coin, height, r.Remainder)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrRevealTree, err)
	}
	loc, err := receiptLocation(res)
	if err != nil {
		return fail(fmt.Errorf("%w: %w", ErrRevealTree, err))
	}
	// Check 13: the change.
	if err := ghosttree.MarkSpent(st, ghosttree.Coin, r.Marker); err != nil {
		return fail(fmt.Errorf("%w: %w", ErrRevealMarker, err))
	}
	if err := addTotal(st, SlotTotalOut, new(uint256.Int).Add(r.Out, r.Fee)); err != nil {
		return fail(err)
	}
	st.AddBalance(r.Recipient, r.Out)
	st.AddBalance(env.Header.Coinbase, fee.Tip)

	data := make([]byte, 0, 8+32+NoteSize+20+32)
	data = append(data, loc...)
	data = append(data, r.Remainder[:]...)
	data = append(data, r.Note[:]...)
	data = append(data, r.Recipient[:]...)
	data = append(data, amountWord(r.Out)...)
	st.AddLog(&types.Log{
		Address:     ghosttree.TreeAccount(ghosttree.Coin),
		Topics:      []common.Hash{ghosttree.K(TagRevealReceipt), r.Marker},
		Data:        data,
		BlockNumber: height,
	})
	return nil
}
