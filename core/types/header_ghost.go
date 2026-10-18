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

package types

import (
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

// A header has one of two layouts (docs/trees-and-headers.md):
//
//   - the base layout, with both tree roots nil: fields 0 to 14 and the
//     optional fields BaseFee, WithdrawalsHash, BlobGasUsed, ExcessBlobGas and
//     ParentBeaconRoot, exactly as the base client encodes them;
//   - the Ghost layout of spec 05, section 10, with both tree roots set: the
//     18-item list of fields 0 to 14, BaseFee, CoinTreeRoot and DataTreeRoot,
//     and none of the other optional fields.
//
// Any other combination cannot be encoded. The decoder tells the layouts
// apart by shape: 18 items with a 32-byte string at index 17. In the base
// layout index 17 is BlobGasUsed, an integer of at most 8 bytes.

const ghostHeaderItems = 18

var (
	errPartialTreeRoots = errors.New("header sets one tree root without the other")
	errTreeRootsNoFee   = errors.New("header with tree roots has no base fee")
	errTreeRootsField   = errors.New("header with tree roots sets a field the Ghost layout forbids")
)

// ghostLayout reports whether the header takes the Ghost layout, and an error
// for a combination of fields neither layout encodes.
func (obj *Header) ghostLayout() (bool, error) {
	coin, data := obj.CoinTreeRoot != nil, obj.DataTreeRoot != nil
	switch {
	case !coin && !data:
		return false, nil
	case coin != data:
		return false, errPartialTreeRoots
	case obj.BaseFee == nil:
		return false, errTreeRootsNoFee
	case obj.WithdrawalsHash != nil:
		return false, fmt.Errorf("%w: withdrawalsHash", errTreeRootsField)
	case obj.BlobGasUsed != nil:
		return false, fmt.Errorf("%w: blobGasUsed", errTreeRootsField)
	case obj.ExcessBlobGas != nil:
		return false, fmt.Errorf("%w: excessBlobGas", errTreeRootsField)
	case obj.ParentBeaconRoot != nil:
		return false, fmt.Errorf("%w: parentBeaconRoot", errTreeRootsField)
	}
	return true, nil
}

// EncodeRLP implements rlp.Encoder. The base layout is written byte for byte
// as the generated encoder did.
func (obj *Header) EncodeRLP(_w io.Writer) error {
	ghost, err := obj.ghostLayout()
	if err != nil {
		return err
	}
	w := rlp.NewEncoderBuffer(_w)
	_tmp0 := w.List()
	w.WriteBytes(obj.ParentHash[:])
	w.WriteBytes(obj.UncleHash[:])
	w.WriteBytes(obj.Coinbase[:])
	w.WriteBytes(obj.Root[:])
	w.WriteBytes(obj.TxHash[:])
	w.WriteBytes(obj.ReceiptHash[:])
	w.WriteBytes(obj.Bloom[:])
	if obj.Difficulty == nil {
		w.Write(rlp.EmptyString)
	} else {
		if obj.Difficulty.Sign() == -1 {
			return rlp.ErrNegativeBigInt
		}
		w.WriteBigInt(obj.Difficulty)
	}
	if obj.Number == nil {
		w.Write(rlp.EmptyString)
	} else {
		if obj.Number.Sign() == -1 {
			return rlp.ErrNegativeBigInt
		}
		w.WriteBigInt(obj.Number)
	}
	w.WriteUint64(obj.GasLimit)
	w.WriteUint64(obj.GasUsed)
	w.WriteUint64(obj.Time)
	w.WriteBytes(obj.Extra)
	w.WriteBytes(obj.MixDigest[:])
	w.WriteBytes(obj.Nonce[:])
	if ghost {
		if obj.BaseFee.Sign() == -1 {
			return rlp.ErrNegativeBigInt
		}
		w.WriteBigInt(obj.BaseFee)
		w.WriteBytes(obj.CoinTreeRoot[:])
		w.WriteBytes(obj.DataTreeRoot[:])
		w.ListEnd(_tmp0)
		return w.Flush()
	}
	_tmp1 := obj.BaseFee != nil
	_tmp2 := obj.WithdrawalsHash != nil
	_tmp3 := obj.BlobGasUsed != nil
	_tmp4 := obj.ExcessBlobGas != nil
	_tmp5 := obj.ParentBeaconRoot != nil
	if _tmp1 || _tmp2 || _tmp3 || _tmp4 || _tmp5 {
		if obj.BaseFee == nil {
			w.Write(rlp.EmptyString)
		} else {
			if obj.BaseFee.Sign() == -1 {
				return rlp.ErrNegativeBigInt
			}
			w.WriteBigInt(obj.BaseFee)
		}
	}
	if _tmp2 || _tmp3 || _tmp4 || _tmp5 {
		if obj.WithdrawalsHash == nil {
			w.Write([]byte{0x80})
		} else {
			w.WriteBytes(obj.WithdrawalsHash[:])
		}
	}
	if _tmp3 || _tmp4 || _tmp5 {
		if obj.BlobGasUsed == nil {
			w.Write([]byte{0x80})
		} else {
			w.WriteUint64((*obj.BlobGasUsed))
		}
	}
	if _tmp4 || _tmp5 {
		if obj.ExcessBlobGas == nil {
			w.Write([]byte{0x80})
		} else {
			w.WriteUint64((*obj.ExcessBlobGas))
		}
	}
	if _tmp5 {
		if obj.ParentBeaconRoot == nil {
			w.Write([]byte{0x80})
		} else {
			w.WriteBytes(obj.ParentBeaconRoot[:])
		}
	}
	w.ListEnd(_tmp0)
	return w.Flush()
}

// baseHeader has the fields and tags of Header but none of its methods, so
// the rlp package decodes it by reflection, as it decoded Header before the
// Ghost layout; the tree roots are tagged rlp:"-" and stay nil.
type baseHeader Header

// ghostHeaderRLP is the Ghost layout: every field required.
type ghostHeaderRLP struct {
	ParentHash   common.Hash
	UncleHash    common.Hash
	Coinbase     common.Address
	Root         common.Hash
	TxHash       common.Hash
	ReceiptHash  common.Hash
	Bloom        Bloom
	Difficulty   *big.Int
	Number       *big.Int
	GasLimit     uint64
	GasUsed      uint64
	Time         uint64
	Extra        []byte
	MixDigest    common.Hash
	Nonce        BlockNonce
	BaseFee      *big.Int
	CoinTreeRoot common.Hash
	DataTreeRoot common.Hash
}

func (g *ghostHeaderRLP) header() *Header {
	coin, data := g.CoinTreeRoot, g.DataTreeRoot
	return &Header{
		ParentHash:   g.ParentHash,
		UncleHash:    g.UncleHash,
		Coinbase:     g.Coinbase,
		Root:         g.Root,
		TxHash:       g.TxHash,
		ReceiptHash:  g.ReceiptHash,
		Bloom:        g.Bloom,
		Difficulty:   g.Difficulty,
		Number:       g.Number,
		GasLimit:     g.GasLimit,
		GasUsed:      g.GasUsed,
		Time:         g.Time,
		Extra:        g.Extra,
		MixDigest:    g.MixDigest,
		Nonce:        g.Nonce,
		BaseFee:      g.BaseFee,
		CoinTreeRoot: &coin,
		DataTreeRoot: &data,
	}
}

// isGhostLayout reports whether raw is a list of exactly 18 items whose item
// at index 17 is a 32-byte string. Malformed input is not; the base decoder
// then reports what is wrong with it.
func isGhostLayout(raw []byte) bool {
	content, _, err := rlp.SplitList(raw)
	if err != nil {
		return false
	}
	if n, err := rlp.CountValues(content); err != nil || n != ghostHeaderItems {
		return false
	}
	for i := 0; i < ghostHeaderItems; i++ {
		kind, item, rest, err := rlp.Split(content)
		if err != nil {
			return false
		}
		if i == ghostHeaderItems-1 {
			return kind == rlp.String && len(item) == common.HashLength
		}
		content = rest
	}
	return false
}

// DecodeRLP implements rlp.Decoder. A header in the Ghost layout decodes
// with both roots set; any other input decodes exactly as before.
func (h *Header) DecodeRLP(s *rlp.Stream) error {
	raw, err := s.Raw()
	if err != nil {
		return err
	}
	if isGhostLayout(raw) {
		var g ghostHeaderRLP
		if err := rlp.DecodeBytes(raw, &g); err != nil {
			return err
		}
		*h = *g.header()
		return nil
	}
	var dec baseHeader
	if err := rlp.DecodeBytes(raw, &dec); err != nil {
		return err
	}
	*h = Header(dec)
	return nil
}

// The reasons DecodeGhostHeader rejects bytes with, in the order spec 05,
// section 10 checks them.
const (
	GhostReasonNonCanonicalRLP     = "non-canonical-rlp"
	GhostReasonTrailingBytes       = "trailing-bytes"
	GhostReasonItemCount           = "item-count"
	GhostReasonFieldSize           = "field-size"
	GhostReasonNonCanonicalInteger = "non-canonical-integer"
	GhostReasonIntegerRange        = "integer-range"
)

// GhostHeaderError is the rejection of DecodeGhostHeader, with the reason of
// the specification.
type GhostHeaderError struct {
	Reason string
	Detail string
}

func (e *GhostHeaderError) Error() string {
	return "ghost header: " + e.Reason + ": " + e.Detail
}

func ghostReject(reason, format string, args ...any) error {
	return &GhostHeaderError{Reason: reason, Detail: fmt.Sprintf(format, args...)}
}

// rlpItem is one canonical RLP item: a string (content) or a list (items).
type rlpItem struct {
	list    bool
	content []byte
	items   []rlpItem
}

// parseCanonical reads one canonical RLP item from the front of b.
func parseCanonical(b []byte) (rlpItem, []byte, error) {
	if len(b) == 0 {
		return rlpItem{}, nil, ghostReject(GhostReasonNonCanonicalRLP, "unexpected end of input")
	}
	prefix := b[0]
	var (
		list         bool
		header, size int
	)
	switch {
	case prefix < 0x80:
		return rlpItem{content: b[:1]}, b[1:], nil
	case prefix <= 0xb7:
		header, size = 1, int(prefix-0x80)
	case prefix <= 0xbf:
		n, err := longLength(b, int(prefix-0xb7))
		if err != nil {
			return rlpItem{}, nil, err
		}
		header, size = 1+int(prefix-0xb7), n
	case prefix <= 0xf7:
		list, header, size = true, 1, int(prefix-0xc0)
	default:
		n, err := longLength(b, int(prefix-0xf7))
		if err != nil {
			return rlpItem{}, nil, err
		}
		list, header, size = true, 1+int(prefix-0xf7), n
	}
	if size > len(b)-header {
		return rlpItem{}, nil, ghostReject(GhostReasonNonCanonicalRLP, "item of %d bytes overruns the input", size)
	}
	content, rest := b[header:header+size], b[header+size:]
	if !list {
		if size == 1 && content[0] < 0x80 {
			return rlpItem{}, nil, ghostReject(GhostReasonNonCanonicalRLP, "single byte %#x wrapped in a string", content[0])
		}
		return rlpItem{content: content}, rest, nil
	}
	item := rlpItem{list: true}
	for len(content) > 0 {
		child, more, err := parseCanonical(content)
		if err != nil {
			return rlpItem{}, nil, err
		}
		item.items = append(item.items, child)
		content = more
	}
	return item, rest, nil
}

// longLength reads the n-byte length of a long-form item at the front of b.
func longLength(b []byte, n int) (int, error) {
	if len(b) < 1+n {
		return 0, ghostReject(GhostReasonNonCanonicalRLP, "truncated length")
	}
	if b[1] == 0 {
		return 0, ghostReject(GhostReasonNonCanonicalRLP, "length with a leading zero byte")
	}
	if n > 4 {
		return 0, ghostReject(GhostReasonNonCanonicalRLP, "length of %d bytes", n)
	}
	size := 0
	for _, c := range b[1 : 1+n] {
		size = size<<8 | int(c)
	}
	if size < 56 {
		return 0, ghostReject(GhostReasonNonCanonicalRLP, "long form for a length of %d", size)
	}
	return size, nil
}

// Field sizes of the Ghost layout: exact sizes of the fixed fields, and the
// widths in bytes of the integers.
var (
	ghostFixedSizes = map[int]int{0: 32, 1: 32, 2: 20, 3: 32, 4: 32, 5: 32, 6: 256, 13: 32, 14: 8, 16: 32, 17: 32}
	ghostIntWidths  = []struct{ index, width int }{{7, 32}, {8, 8}, {9, 8}, {10, 8}, {11, 8}, {15, 32}}
)

const ghostMaxExtra = 32

// DecodeGhostHeader is the strict reference decoder of spec 05, section 10.
// It accepts only the Ghost layout and rejects anything else with a
// *GhostHeaderError carrying the first reason that applies.
func DecodeGhostHeader(b []byte) (*Header, error) {
	// 1. One canonical RLP list.
	top, rest, err := parseCanonical(b)
	if err != nil {
		return nil, err
	}
	if !top.list {
		return nil, ghostReject(GhostReasonNonCanonicalRLP, "not a list")
	}
	// 2. Nothing after it.
	if len(rest) > 0 {
		return nil, ghostReject(GhostReasonTrailingBytes, "%d bytes after the list", len(rest))
	}
	// 3. Exactly 18 items, none a list.
	if len(top.items) != ghostHeaderItems {
		return nil, ghostReject(GhostReasonItemCount, "%d items, want %d", len(top.items), ghostHeaderItems)
	}
	for i, item := range top.items {
		if item.list {
			return nil, ghostReject(GhostReasonItemCount, "item %d is a list", i)
		}
	}
	items := top.items
	// 4. Field sizes.
	for i := 0; i < ghostHeaderItems; i++ {
		if size, fixed := ghostFixedSizes[i]; fixed && len(items[i].content) != size {
			return nil, ghostReject(GhostReasonFieldSize, "item %d has %d bytes, want %d", i, len(items[i].content), size)
		}
	}
	if len(items[12].content) > ghostMaxExtra {
		return nil, ghostReject(GhostReasonFieldSize, "extraData has %d bytes, at most %d", len(items[12].content), ghostMaxExtra)
	}
	// 5. Canonical integers within their widths.
	for _, f := range ghostIntWidths {
		if c := items[f.index].content; len(c) > 0 && c[0] == 0 {
			return nil, ghostReject(GhostReasonNonCanonicalInteger, "item %d has a leading zero byte", f.index)
		}
	}
	for _, f := range ghostIntWidths {
		if c := items[f.index].content; len(c) > f.width {
			return nil, ghostReject(GhostReasonIntegerRange, "item %d has %d bytes, at most %d", f.index, len(c), f.width)
		}
	}
	uint64At := func(i int) uint64 { return new(big.Int).SetBytes(items[i].content).Uint64() }
	g := ghostHeaderRLP{
		Difficulty: new(big.Int).SetBytes(items[7].content),
		Number:     new(big.Int).SetBytes(items[8].content),
		GasLimit:   uint64At(9),
		GasUsed:    uint64At(10),
		Time:       uint64At(11),
		Extra:      common.CopyBytes(items[12].content),
		BaseFee:    new(big.Int).SetBytes(items[15].content),
	}
	copy(g.ParentHash[:], items[0].content)
	copy(g.UncleHash[:], items[1].content)
	copy(g.Coinbase[:], items[2].content)
	copy(g.Root[:], items[3].content)
	copy(g.TxHash[:], items[4].content)
	copy(g.ReceiptHash[:], items[5].content)
	copy(g.Bloom[:], items[6].content)
	copy(g.MixDigest[:], items[13].content)
	copy(g.Nonce[:], items[14].content)
	copy(g.CoinTreeRoot[:], items[16].content)
	copy(g.DataTreeRoot[:], items[17].content)
	return g.header(), nil
}
