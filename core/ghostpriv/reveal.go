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
	ProofSize = 1_310_720

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
	statementDataReveal = 0x02
	statementVersion    = 0x01
	purposeReveal       = PurposeReveal
)

// The purposes of a data reveal. The coin reveal has only PurposeReveal.
const (
	PurposeReveal byte = 0x01 // a one-time reveal of the data
	PurposeRevoke byte = 0x02 // a revoke, which spends the marker for good
)

// The errors of the reveal checks, one per check, in the order they run.
// Check 6 computes the binding digest and check 11 has nothing to read, so
// neither can fail; ErrRevealChainInfo wraps a missing ancestor under the
// check that needed it.
var (
	ErrRevealLength    = errors.New("reveal is not a 0x50 envelope of 1,311,067 bytes")
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

// SaltedBindingDigest returns the binding digest of the same reveal over a
// salted coin: BindingDigest with the type CoinV2 in place of Coin. The
// proof system accepts a coin reveal whose proof commits to either; the node
// passes its verifier only BindingDigest, and a verifier that checks the
// binding itself, such as the test stub, computes this one from the inputs.
func (r *Reveal) SaltedBindingDigest(chainID uint64, genesis common.Hash) common.Hash {
	return ghosttree.K(TagRevealBinding, r.bindingInput(chainID, genesis, CoinV2))
}

// BindingInput returns the 415 bytes the binding digest hashes: the chain
// id (8), the version (2), the domain, which is the genesis hash (32), the
// statement and its version (1 each), the type COIN (2), the purpose (1),
// the root, marker and remainder (32 each), the recipient (20), out and fee
// (32 each), the rule, 32 zero bytes for the empty rule, and the note (156).
// The version is always 1 and the rule always empty: the node supplies them.
func (r *Reveal) BindingInput(chainID uint64, genesis common.Hash) []byte {
	return r.bindingInput(chainID, genesis, Coin)
}

// bindingInput returns BindingInput with typ as the coin type.
func (r *Reveal) bindingInput(chainID uint64, genesis common.Hash, typ [2]byte) []byte {
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
	b = append(b, typ[:]...)
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
// and number. *core.BlockChain satisfies it, and is also a
// ghosttree.HeaderLookup and ghosttree.RootIndex: the root check then asks
// its tree-root index instead of walking the ancestry.
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

// windowFeeOf returns the fee of the window that starts at the header of the
// first block of h's fee window, found by walking the parent links from h; h
// itself when it starts the window. It also returns that first header.
func (env *BlockEnv) windowFeeOf(h *types.Header) (Fee, *types.Header, error) {
	start := WindowStart(h.Number.Uint64())
	for h.Number.Uint64() > start {
		if h = env.parent(h); h == nil {
			return Fee{}, nil, fmt.Errorf("%w: ancestor at height %d", ErrRevealChainInfo, start)
		}
	}
	if h.BaseFee == nil {
		return Fee{}, nil, fmt.Errorf("%w: block %d has no base fee", ErrRevealChainInfo, start)
	}
	fee, err := WindowFee(h.BaseFee)
	if err != nil {
		return Fee{}, nil, err
	}
	return fee, h, nil
}

// windowFee returns the window fee that paid equals, the fee of the
// including block's window, else that of the window before it, split by the
// cover rule for the including block's base fee. The first window has none
// before it. The previous window is read only when the current fee does not
// match, so the walk reads at most the headers of the two windows. Any other
// fee, or one that fails the cover rule, is ErrRevealFee.
func (env *BlockEnv) windowFee(paid *uint256.Int) (Fee, error) {
	fee, err := env.matchFee(paid)
	if err != nil {
		return Fee{}, err
	}
	if env.Header.BaseFee == nil {
		return Fee{}, fmt.Errorf("%w: %w: including block has no base fee", ErrRevealFee, ErrRevealChainInfo)
	}
	split, err := fee.Cover(env.Header.BaseFee)
	if err != nil {
		return Fee{}, fmt.Errorf("%w: %w", ErrRevealFee, err)
	}
	return split, nil
}

// matchFee returns the window fee that paid equals, by the rule of windowFee.
func (env *BlockEnv) matchFee(paid *uint256.Int) (Fee, error) {
	cur, start, err := env.windowFeeOf(env.Header)
	if err != nil {
		return Fee{}, fmt.Errorf("%w: %w", ErrRevealFee, err)
	}
	if cur.Total.Eq(paid) {
		return cur, nil
	}
	if start.Number.Sign() == 0 {
		return Fee{}, fmt.Errorf("%w: have %v, want %v", ErrRevealFee, paid, cur.Total)
	}
	last := env.parent(start)
	if last == nil {
		return Fee{}, fmt.Errorf("%w: have %v, want %v: %w: ancestor at height %d", ErrRevealFee, paid, cur.Total, ErrRevealChainInfo, start.Number.Uint64()-1)
	}
	prev, _, err := env.windowFeeOf(last)
	if err != nil {
		return Fee{}, fmt.Errorf("%w: have %v, want %v: %w", ErrRevealFee, paid, cur.Total, err)
	}
	if prev.Total.Eq(paid) {
		return prev, nil
	}
	return Fee{}, fmt.Errorf("%w: have %v, want %v or %v", ErrRevealFee, paid, cur.Total, prev.Total)
}

// rootEligible reports whether root is the tree root of the kind in the
// header of a block of the including block's ancestry, strictly below it
// (spec 05, section 5). When the chain keeps a tree-root index, as
// *core.BlockChain does, the index answers: ghosttree.EligibleRoot walks a
// side branch only down to its fork point, so the reads are bounded
// whatever the age of the root. When the chain keeps no index, or the index
// is not ready, the parent links are walked down to the genesis, so that a
// valid block is never refused because the index lags. Any other failed
// lookup, and a missing ancestor, is false.
func (env *BlockEnv) rootEligible(kind ghosttree.Kind, root common.Hash) bool {
	parent := env.parent(env.Header)
	if parent == nil {
		return false
	}
	if chain, ok := env.Chain.(ghosttree.HeaderLookup); ok {
		eligible, err := ghosttree.EligibleRoot(chain, parent, kind, root)
		if !errors.Is(err, ghosttree.ErrIndexNotReady) {
			return err == nil && eligible
		}
	}
	for h := parent; h != nil; h = env.parent(h) {
		if r := ghosttree.HeaderRoot(h, kind); r != nil && *r == root {
			return true
		}
	}
	return false
}

// CheckReveal runs checks 1 to 11 of a reveal against the state before it
// and returns the decoded reveal and the window fee it pays: that of the
// including block's window or of the window before it. It changes nothing.
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
	// Check 5: the fee of the including block's window or of the window
	// before it, which must cover G_PRIV times the including block's base
	// fee. The fee returned is the one that matched, split by the cover rule
	// into the burn and the tip, never above that window's nominal tip.
	fee, err := env.windowFee(r.Fee)
	if err != nil {
		return nil, Fee{}, err
	}
	// Check 6: the node's own binding digest.
	binding := r.BindingDigest(chainID, env.Genesis)
	// Check 7: the root.
	if !env.rootEligible(ghosttree.Coin, r.Root) {
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
		Kind:      ghosttree.Coin,
		Purpose:   purposeReveal,
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
// burns G_PRIV times the larger of the window price and the block's base fee,
// pays the rest of the fee to the coinbase as the tip, appends the
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
	// Check 12: the coin tree takes the remainder, or nothing is written. The
	// remainder is the commitment the proof opens: a remainder is always
	// version 2 (spec 03), K(TagCommitment, CoinV2, F, v), and the node
	// appends it as given.
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

// DataBindingSize is the length of a data reveal's binding digest input.
const DataBindingSize = 196

// The errors of the data reveal checks, one per check, in the order they
// run. Check 8 computes the binding digest and cannot fail.
var (
	ErrDataRevealLength   = errors.New("data reveal is not a 0x51 envelope of 1,311,067 bytes")
	ErrDataRevealVersion  = errors.New("data reveal version is not 1")
	ErrDataRevealAmount   = errors.New("data reveal out or fee not below 2^96")
	ErrDataRevealChainID  = errors.New("data reveal chain id is not this chain's")
	ErrDataRevealFee      = errors.New("data reveal fee rejected")
	ErrDataRevealPurpose  = errors.New("data reveal purpose is neither reveal nor revoke")
	ErrDataRevealShape    = errors.New("data reveal carries a value or a remainder")
	ErrDataRevealRoot     = errors.New("data reveal root is not an ancestor's data tree root")
	ErrDataRevealMarker   = errors.New("data reveal marker already used")
	ErrDataRevealBackstop = errors.New("data reveal reserve is more than the hidden set holds")
	ErrDataRevealProof    = errors.New("data reveal proof rejected")

	// ErrDataRevealFeeAboveReserve is wrapped by ErrDataRevealFee for a
	// window fee above DataReserve, which the reserve cannot pay.
	ErrDataRevealFeeAboveReserve = errors.New("data reveal fee above the data reserve")
)

// PurposeField returns the 32-byte purpose field of a data reveal, 31 zero
// bytes then the purpose.
func PurposeField(purpose byte) common.Hash { return common.Hash{31: purpose} }

// DataReveal is a decoded data reveal payload. It has the coin reveal's
// layout: the remainder field holds the purpose, the recipient field is the
// verifier-or-recipient field, and out must be zero. The remainder's note
// slot, which a data reveal has no use for, carries the content fingerprint
// cf in its first 32 bytes; the other NoteSize - 32 bytes, Note, must be
// zero. Any 32 bytes are a valid cf: the proof binds it.
type DataReveal struct {
	Version  uint16
	ChainID  uint64
	Marker   common.Hash
	Root     common.Hash
	Purpose  common.Hash    // the purpose field, see PurposeField
	Verifier common.Address // the verifier-or-recipient field; credits nothing
	Out      *uint256.Int
	Fee      *uint256.Int
	Proof    []byte      // ProofSize bytes, or fewer to be padded with zeros
	Cf       common.Hash // the content fingerprint, bytes 0..32 of the note slot
	Note     [NoteSize - 32]byte
}

// MarshalBinary returns the data reveal's envelope: the type byte 0x51 and
// the payload of EnvelopeSize - 1 bytes. A shorter proof is padded with
// zeros; a longer one is an error.
func (r *DataReveal) MarshalBinary() ([]byte, error) {
	if len(r.Proof) > ProofSize {
		return nil, fmt.Errorf("proof of %d bytes, the field holds %d", len(r.Proof), ProofSize)
	}
	env := make([]byte, types.GhostDataRevealEnvelopeSize)
	env[0] = types.GhostDataRevealTxType
	p := env[1:]
	binary.BigEndian.PutUint16(p[offVersion:], r.Version)
	binary.BigEndian.PutUint64(p[offChainID:], r.ChainID)
	copy(p[offMarker:], r.Marker[:])
	copy(p[offRoot:], r.Root[:])
	copy(p[offRemainder:], r.Purpose[:])
	copy(p[offRecipient:], r.Verifier[:])
	if r.Out != nil {
		copy(p[offOut:offFee], amountWord(r.Out))
	}
	if r.Fee != nil {
		copy(p[offFee:offProof], amountWord(r.Fee))
	}
	copy(p[offProof:offNote], r.Proof)
	copy(p[offNote:], r.Cf[:])
	copy(p[offNote+32:], r.Note[:])
	return env, nil
}

// DecodeDataReveal decodes a data reveal envelope and runs the first three
// checks: the type byte 0x51 and exact length (ErrDataRevealLength), version
// 1 (ErrDataRevealVersion), and out and fee below 2^96
// (ErrDataRevealAmount). A coin reveal envelope, type 0x50, fails the first.
func DecodeDataReveal(envelope []byte) (*DataReveal, error) {
	if len(envelope) != types.GhostDataRevealEnvelopeSize || envelope[0] != types.GhostDataRevealTxType {
		return nil, fmt.Errorf("%w: %d bytes", ErrDataRevealLength, len(envelope))
	}
	p := envelope[1:]
	r := &DataReveal{
		Version:  binary.BigEndian.Uint16(p[offVersion:]),
		ChainID:  binary.BigEndian.Uint64(p[offChainID:]),
		Marker:   common.BytesToHash(p[offMarker:offRoot]),
		Root:     common.BytesToHash(p[offRoot:offRemainder]),
		Purpose:  common.BytesToHash(p[offRemainder:offRecipient]),
		Verifier: common.BytesToAddress(p[offRecipient:offOut]),
		Proof:    common.CopyBytes(p[offProof:offNote]),
		Cf:       common.BytesToHash(p[offNote : offNote+32]),
	}
	copy(r.Note[:], p[offNote+32:])
	if r.Version != Version {
		return nil, fmt.Errorf("%w: %d", ErrDataRevealVersion, r.Version)
	}
	var err error
	if r.Out, err = readAmount(p[offOut:offFee]); err != nil {
		return nil, fmt.Errorf("%w: out", ErrDataRevealAmount)
	}
	if r.Fee, err = readAmount(p[offFee:offProof]); err != nil {
		return nil, fmt.Errorf("%w: fee", ErrDataRevealAmount)
	}
	return r, nil
}

// purpose returns the purpose of the purpose field: PurposeReveal or
// PurposeRevoke after 31 zero bytes. Anything else is ErrDataRevealPurpose.
func (r *DataReveal) purpose() (byte, error) {
	for _, b := range r.Purpose[:31] {
		if b != 0 {
			return 0, fmt.Errorf("%w: %x", ErrDataRevealPurpose, r.Purpose)
		}
	}
	switch p := r.Purpose[31]; p {
	case PurposeReveal, PurposeRevoke:
		return p, nil
	default:
		return 0, fmt.Errorf("%w: %#x", ErrDataRevealPurpose, p)
	}
}

// dataBindingType is the type field of a data reveal's binding input. It is
// part of the binding layout the data reveal statement fixes, not a leaf
// type: it stays the two bytes the binding has always carried and does not
// follow Data, the type of a version 1 data leaf.
var dataBindingType = [2]byte{0x02, 0x01}

// BindingDigest returns the binding digest a data reveal's proof must commit
// to, K("ghost/data-reveal-binding/v1", fields) over the 196 bytes of
// BindingInput. Its tag, statement and type differ from the coin reveal's,
// so it never equals a coin reveal's digest.
func (r *DataReveal) BindingDigest(chainID uint64, genesis common.Hash) common.Hash {
	return ghosttree.K(TagDataRevealBinding, r.BindingInput(chainID, genesis))
}

// BindingInput returns the 196 bytes the data binding digest hashes: the
// chain id (8), the version (2), the domain, which is the genesis hash (32),
// the transaction type 0x51 (1), the statement 0x02 and its version (1
// each), the type field (2, dataBindingType), the purpose (1, the last byte of the purpose
// field), the verifier-or-recipient field (20), the root and marker (32
// each), the fee (32) and the content fingerprint cf (32). The node supplies the chain id, version, domain,
// transaction type, statement and type; the proof is not covered.
func (r *DataReveal) BindingInput(chainID uint64, genesis common.Hash) []byte {
	fee := r.Fee
	if fee == nil {
		fee = new(uint256.Int)
	}
	b := make([]byte, 0, DataBindingSize)
	b = binary.BigEndian.AppendUint64(b, chainID)
	b = binary.BigEndian.AppendUint16(b, Version)
	b = append(b, genesis[:]...)
	b = append(b, types.GhostDataRevealTxType, statementDataReveal, statementVersion)
	b = append(b, dataBindingType[:]...)
	b = append(b, r.Purpose[31])
	b = append(b, r.Verifier[:]...)
	b = append(b, r.Root[:]...)
	b = append(b, r.Marker[:]...)
	b = append(b, amountWord(fee)...)
	b = append(b, r.Cf[:]...)
	return b
}

// VerifyInputs returns the inputs the verifier receives for the data reveal's
// proof with the given purpose, chain id and genesis hash. Both a block's
// checks and the pool build them here, so they never disagree.
func (r *DataReveal) VerifyInputs(purpose byte, chainID uint64, genesis common.Hash) *VerifyInputs {
	fee := new(uint256.Int)
	if r.Fee != nil {
		fee.Set(r.Fee)
	}
	return &VerifyInputs{
		Kind:      ghosttree.Data,
		Purpose:   purpose,
		Binding:   r.BindingDigest(chainID, genesis),
		ChainID:   chainID,
		Domain:    genesis,
		Root:      r.Root,
		Marker:    r.Marker,
		Recipient: r.Verifier,
		Out:       new(uint256.Int),
		Fee:       fee,
		Cf:        r.Cf,
	}
}

// CheckDataReveal runs checks 1 to 11 of a data reveal against the state
// before it and returns the decoded data reveal and its purpose. It changes
// nothing.
func CheckDataReveal(st StateDB, env *BlockEnv, verifier Verifier, envelope []byte) (*DataReveal, byte, error) {
	r, purpose, _, err := checkDataReveal(st, env, verifier, envelope)
	return r, purpose, err
}

// checkDataReveal is CheckDataReveal that also returns the window fee the
// data reveal pays, split by the cover rule.
func checkDataReveal(st StateDB, env *BlockEnv, verifier Verifier, envelope []byte) (*DataReveal, byte, Fee, error) {
	// Checks 1 to 3: type, length, version and amount words.
	r, err := DecodeDataReveal(envelope)
	if err != nil {
		return nil, 0, Fee{}, err
	}
	if env == nil || env.Header == nil || env.Header.Number == nil {
		return nil, 0, Fee{}, fmt.Errorf("%w: no including block", ErrRevealChainInfo)
	}
	// Check 4: the chain id.
	if env.ChainID == nil || !env.ChainID.IsUint64() || env.ChainID.Uint64() != r.ChainID {
		return nil, 0, Fee{}, fmt.Errorf("%w: have %d, chain %v", ErrDataRevealChainID, r.ChainID, env.ChainID)
	}
	chainID := env.ChainID.Uint64()
	// Check 5: the fee, as a coin reveal's: the fee of the including block's
	// window or of the window before it, which must cover G_PRIV times the
	// including block's base fee. The reserve the data commit burned pays
	// it, so it can be no more than DataReserve.
	fee, err := env.windowFee(r.Fee)
	if err != nil {
		return nil, 0, Fee{}, fmt.Errorf("%w: %w", ErrDataRevealFee, err)
	}
	if fee.Total.Gt(DataReserve) {
		return nil, 0, Fee{}, fmt.Errorf("%w: %w: fee %v, reserve %v", ErrDataRevealFee, ErrDataRevealFeeAboveReserve, fee.Total, DataReserve)
	}
	// Check 6: the purpose.
	purpose, err := r.purpose()
	if err != nil {
		return nil, 0, Fee{}, err
	}
	// Check 7: no value and no remainder: out and the note slot after cf
	// are zero.
	if !r.Out.IsZero() {
		return nil, 0, Fee{}, fmt.Errorf("%w: out %v", ErrDataRevealShape, r.Out)
	}
	if r.Note != ([NoteSize - 32]byte{}) {
		return nil, 0, Fee{}, fmt.Errorf("%w: a note", ErrDataRevealShape)
	}
	// Check 8: the node's own binding digest, in the verifier's inputs.
	in := r.VerifyInputs(purpose, chainID, env.Genesis)
	// Check 9: the root, a data tree root of the ancestry.
	if !env.rootEligible(ghosttree.Data, r.Root) {
		return nil, 0, Fee{}, fmt.Errorf("%w: %x", ErrDataRevealRoot, r.Root)
	}
	// Check 10: the marker, against the data marker set, which holds the
	// markers of earlier data reveals and revokes of this block too.
	if ghosttree.IsSpent(st, ghosttree.Data, r.Marker) {
		return nil, 0, Fee{}, fmt.Errorf("%w: %x", ErrDataRevealMarker, r.Marker)
	}
	// The backstop: the reserve leaves the hidden set, so it must hold it.
	hidden, err := Hidden(st)
	if err != nil {
		return nil, 0, Fee{}, fmt.Errorf("%w: %w", ErrDataRevealBackstop, err)
	}
	if DataReserve.Gt(hidden) {
		return nil, 0, Fee{}, fmt.Errorf("%w: reserve %v, hidden %v", ErrDataRevealBackstop, DataReserve, hidden)
	}
	// Check 11: the proof, for the inputs the node computed.
	if verifier == nil {
		verifier = DefaultVerifier()
	}
	if err := verifier.VerifyReveal(in, common.CopyBytes(r.Proof)); err != nil {
		return nil, 0, Fee{}, fmt.Errorf("%w: %w", ErrDataRevealProof, err)
	}
	return r, purpose, fee, nil
}

// ApplyDataReveal checks a data reveal or revoke and makes its one atomic
// change: it adds the marker to the data marker set, adds DataReserve to the
// total out, settles the fee from the reserve as a coin reveal's (the burn
// credited to nobody, the tip to the coinbase), forfeits the rest of the
// reserve, credited to nobody, and writes the receipt log. It appends to
// neither tree and credits nothing else. The gas is the caller's. On an
// error nothing is changed.
func ApplyDataReveal(st StateDB, env *BlockEnv, verifier Verifier, envelope []byte) error {
	r, purpose, fee, err := checkDataReveal(st, env, verifier, envelope)
	if err != nil {
		return err
	}
	snap := st.Snapshot()
	if err := ghosttree.MarkSpent(st, ghosttree.Data, r.Marker); err != nil {
		st.RevertToSnapshot(snap)
		return fmt.Errorf("%w: %w", ErrDataRevealMarker, err)
	}
	if err := addTotal(st, SlotTotalOut, DataReserve); err != nil {
		st.RevertToSnapshot(snap)
		return err
	}
	st.AddBalance(env.Header.Coinbase, fee.Tip)
	data := make([]byte, 0, 1+20)
	data = append(data, purpose)
	data = append(data, r.Verifier[:]...)
	st.AddLog(&types.Log{
		Address:     ghosttree.TreeAccount(ghosttree.Data),
		Topics:      []common.Hash{ghosttree.K(TagDataRevealReceipt), r.Marker},
		Data:        data,
		BlockNumber: env.Header.Number.Uint64(),
	})
	return nil
}
