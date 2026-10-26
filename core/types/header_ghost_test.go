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
	"bytes"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

// The header vectors of spec 05, section 11. Their logs bloom is 256 zero
// bytes, written out as zeroBloom; everything else is copied unchanged, and
// the stated hashes check the whole.
var zeroBloom = "b90100" + strings.Repeat("00", BloomByteLength)

// The items of header-block-one-example, which the negative vectors share.
const (
	blockOneHead       = "a0039d14f59db29e2e76c8ed76f90b70de42e48f8a67dba060b363501af50e3ba4a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479400000000000000000000000000000000000004d2a01111111111111111111111111111111111111111111111111111111111111111a02222222222222222222222222222222222222222222222222222222222222222a03333333333333333333333333333333333333333333333333333333333333333"
	blockOneDifficulty = "8401000000"
	blockOneNumber     = "01"
	blockOneRest       = "8401c9c3808301ec30846b37040e80a04444444444444444444444444444444444444444444444444444444444444444880102030405060708"
	blockOneFee        = "84342770c0"
	blockOneCoin       = "a0142c6bdf0882396330f9942ddd49df5d860b05a5218dad1ce6ef8e69238b6ec5"
	blockOneData       = "a0dfc2bf39581c30d2cf1f025586af2f821524daa2e496fea9f950731202f3237a"
	blockOneMarker     = "a0f121b372119409a7d6fda684a14ab815c7ef9a07ba48f50ff59ea5fc62d36e4f"
)

var (
	vectorGenesisRLP  = "f90281a00000000000000000000000000000000000000000000000000000000000000000a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347940000000000000000000000000000000000000000a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421" + zeroBloom + "8401000000808401c9c38080846b3703f0a0000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26fa00000000000000000000000000000000000000000000000000000000000000000880000000000000000843b9aca00a08e66512042388a7863d500c4f96861466ae48b9d64ea1e10ec382c31aa61b5a8a03d5cea4ec4750f6e39c05a6464043afed27b95090a4d93a304d88204e9a3fe03a00ef484d17824d5fefb2533c70af81a3267af1169dd091395ad7607762aeee0a3"
	vectorGenesisHash = "039d14f59db29e2e76c8ed76f90b70de42e48f8a67dba060b363501af50e3ba4"

	blockOneBody       = blockOneHead + zeroBloom + blockOneDifficulty + blockOneNumber + blockOneRest
	vectorBlockOneRLP  = "f90264" + blockOneBody + blockOneFee + blockOneCoin + blockOneData + blockOneMarker
	vectorBlockOneHash = "81ca961404b518ee3ded78ebee1c4e23eba18b7c86515b6471e970cfed8538f4"
)

// The negative vectors: header-block-one-example with one fault each.
var negativeHeaderVectors = []struct {
	name, reason, rlp string
}{
	// A withdrawals root after the base fee.
	{"header-forbidden-field", GhostReasonItemCount, "f90285" + blockOneBody + blockOneFee + "a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421" + blockOneCoin + blockOneData + blockOneMarker},
	// An empty string appended.
	{"header-extra-trailing-field", GhostReasonItemCount, "f90265" + blockOneBody + blockOneFee + blockOneCoin + blockOneData + blockOneMarker + "80"},
	// No base fee.
	{"header-missing-required-field", GhostReasonItemCount, "f9025f" + blockOneBody + blockOneCoin + blockOneData + blockOneMarker},
	// The block number with a leading zero byte.
	{"header-non-canonical-integer", GhostReasonNonCanonicalInteger, "f90266" + blockOneHead + zeroBloom + blockOneDifficulty + "820001" + blockOneRest + blockOneFee + blockOneCoin + blockOneData + blockOneMarker},
	// The coin tree root cut to 31 bytes.
	{"header-short-tree-root", GhostReasonFieldSize, "f90263" + blockOneBody + blockOneFee + "9f142c6bdf0882396330f9942ddd49df5d860b05a5218dad1ce6ef8e69238b6e" + blockOneData + blockOneMarker},
	// One byte after the list.
	{"header-trailing-bytes", GhostReasonTrailingBytes, vectorBlockOneRLP + "00"},
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hexutil.Decode("0x" + s)
	if err != nil {
		t.Fatalf("bad hex in test: %v", err)
	}
	return b
}

func hashPtr(s string) *common.Hash {
	h := common.HexToHash(s)
	return &h
}

// vectorGenesis and vectorBlockOne are the field values of the two positive
// vectors.
func vectorGenesis() *Header {
	return &Header{
		ParentHash:     common.Hash{},
		UncleHash:      common.HexToHash("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"),
		Coinbase:       common.Address{},
		Root:           common.HexToHash("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),
		TxHash:         common.HexToHash("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),
		ReceiptHash:    common.HexToHash("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),
		Difficulty:     big.NewInt(16777216),
		Number:         big.NewInt(0),
		GasLimit:       30000000,
		GasUsed:        0,
		Time:           1798767600,
		Extra:          common.FromHex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"),
		BaseFee:        big.NewInt(1000000000),
		CoinTreeRoot:   hashPtr("8e66512042388a7863d500c4f96861466ae48b9d64ea1e10ec382c31aa61b5a8"),
		DataTreeRoot:   hashPtr("3d5cea4ec4750f6e39c05a6464043afed27b95090a4d93a304d88204e9a3fe03"),
		DataMarkerRoot: hashPtr("0ef484d17824d5fefb2533c70af81a3267af1169dd091395ad7607762aeee0a3"),
	}
}

func vectorBlockOne() *Header {
	return &Header{
		ParentHash:     common.HexToHash("039d14f59db29e2e76c8ed76f90b70de42e48f8a67dba060b363501af50e3ba4"),
		UncleHash:      common.HexToHash("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"),
		Coinbase:       common.HexToAddress("00000000000000000000000000000000000004d2"),
		Root:           common.HexToHash("1111111111111111111111111111111111111111111111111111111111111111"),
		TxHash:         common.HexToHash("2222222222222222222222222222222222222222222222222222222222222222"),
		ReceiptHash:    common.HexToHash("3333333333333333333333333333333333333333333333333333333333333333"),
		Difficulty:     big.NewInt(16777216),
		Number:         big.NewInt(1),
		GasLimit:       30000000,
		GasUsed:        126000,
		Time:           1798767630,
		MixDigest:      common.HexToHash("4444444444444444444444444444444444444444444444444444444444444444"),
		Nonce:          BlockNonce{1, 2, 3, 4, 5, 6, 7, 8},
		BaseFee:        big.NewInt(875000000),
		CoinTreeRoot:   hashPtr("142c6bdf0882396330f9942ddd49df5d860b05a5218dad1ce6ef8e69238b6ec5"),
		DataTreeRoot:   hashPtr("dfc2bf39581c30d2cf1f025586af2f821524daa2e496fea9f950731202f3237a"),
		DataMarkerRoot: hashPtr("f121b372119409a7d6fda684a14ab815c7ef9a07ba48f50ff59ea5fc62d36e4f"),
	}
}

// TestGhostHeaderVectors checks the positive header vectors: the fields
// encode to the stated bytes and hash, and the bytes decode back to the same
// header with both decoders.
func TestGhostHeaderVectors(t *testing.T) {
	for _, v := range []struct {
		name   string
		header *Header
		rlp    string
		hash   string
	}{
		{"header-genesis-example", vectorGenesis(), vectorGenesisRLP, vectorGenesisHash},
		{"header-block-one-example", vectorBlockOne(), vectorBlockOneRLP, vectorBlockOneHash},
	} {
		want := mustHex(t, v.rlp)
		if h := crypto.Keccak256Hash(want); h != common.HexToHash(v.hash) {
			t.Fatalf("%s: the vector's bytes hash to %x, not the stated %s", v.name, h, v.hash)
		}
		got, err := rlp.EncodeToBytes(v.header)
		if err != nil {
			t.Fatalf("%s: encode: %v", v.name, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: encoding\n got %x\nwant %x", v.name, got, want)
		}
		if h := v.header.Hash(); h != common.HexToHash(v.hash) {
			t.Errorf("%s: hash %x, want %s", v.name, h, v.hash)
		}

		var dec Header
		if err := rlp.DecodeBytes(want, &dec); err != nil {
			t.Fatalf("%s: decode: %v", v.name, err)
		}
		if dec.CoinTreeRoot == nil || dec.DataTreeRoot == nil {
			t.Fatalf("%s: decoded without its tree roots", v.name)
		}
		if *dec.CoinTreeRoot != *v.header.CoinTreeRoot || *dec.DataTreeRoot != *v.header.DataTreeRoot {
			t.Errorf("%s: decoded roots %x %x", v.name, *dec.CoinTreeRoot, *dec.DataTreeRoot)
		}
		if dec.WithdrawalsHash != nil || dec.BlobGasUsed != nil || dec.ExcessBlobGas != nil || dec.ParentBeaconRoot != nil {
			t.Errorf("%s: decoded a forbidden field", v.name)
		}
		if re, _ := rlp.EncodeToBytes(&dec); !bytes.Equal(re, want) {
			t.Errorf("%s: decode and encode gives\n%x", v.name, re)
		}
		if dec.Hash() != common.HexToHash(v.hash) {
			t.Errorf("%s: decoded hash %x", v.name, dec.Hash())
		}

		strict, err := DecodeGhostHeader(want)
		if err != nil {
			t.Fatalf("%s: strict decoder rejects a positive vector: %v", v.name, err)
		}
		if re, _ := rlp.EncodeToBytes(strict); !bytes.Equal(re, want) {
			t.Errorf("%s: strict decode and encode gives\n%x", v.name, re)
		}
		if strict.Hash() != common.HexToHash(v.hash) {
			t.Errorf("%s: strict decoded hash %x", v.name, strict.Hash())
		}

		// The whole block round trips too.
		block := NewBlockWithHeader(v.header)
		enc, err := rlp.EncodeToBytes(block)
		if err != nil {
			t.Fatal(err)
		}
		var decBlock Block
		if err := rlp.DecodeBytes(enc, &decBlock); err != nil {
			t.Fatalf("%s: block decode: %v", v.name, err)
		}
		if decBlock.Hash() != common.HexToHash(v.hash) {
			t.Errorf("%s: block hash %x after a round trip", v.name, decBlock.Hash())
		}
	}
	// Block one's parent is the genesis vector.
	if vectorBlockOne().ParentHash != vectorGenesis().Hash() {
		t.Error("block one does not build on the genesis vector")
	}
}

// TestGhostHeaderNegativeVectors checks that the strict decoder rejects each
// negative vector with its stated reason, and that the ordinary decoder never
// reads one as a Ghost header with both roots.
func TestGhostHeaderNegativeVectors(t *testing.T) {
	for _, v := range negativeHeaderVectors {
		b := mustHex(t, v.rlp)
		h, err := DecodeGhostHeader(b)
		var reject *GhostHeaderError
		if !errors.As(err, &reject) {
			t.Errorf("%s: decoded %v, error %v; want rejection %s", v.name, h, err, v.reason)
			continue
		}
		if reject.Reason != v.reason {
			t.Errorf("%s: rejected for %s (%v), want %s", v.name, reject.Reason, err, v.reason)
		}
		var dec Header
		if err := rlp.DecodeBytes(b, &dec); err == nil && dec.CoinTreeRoot != nil && dec.DataTreeRoot != nil {
			t.Errorf("%s: the ordinary decoder reads it as a Ghost header", v.name)
		}
	}
	// The reasons the vectors do not reach.
	good := mustHex(t, vectorBlockOneRLP)
	for _, c := range []struct {
		name, reason string
		b            []byte
	}{
		{"empty input", GhostReasonNonCanonicalRLP, nil},
		{"a string, not a list", GhostReasonNonCanonicalRLP, []byte{0x83, 1, 2, 3}},
		{"truncated", GhostReasonNonCanonicalRLP, good[:len(good)-1]},
		{"wrapped single byte", GhostReasonNonCanonicalRLP, []byte{0xc2, 0x81, 0x01}},
		{"long form for a short list", GhostReasonNonCanonicalRLP, []byte{0xf8, 0x01, 0x80}},
		{"long length with a leading zero", GhostReasonNonCanonicalRLP, append([]byte{0xf9, 0x00, 0x38}, bytes.Repeat([]byte{0x80}, 0x38)...)},
		{"item that is a list", GhostReasonItemCount, append([]byte{0xd2, 0xc0}, bytes.Repeat([]byte{0x80}, 17)...)},
		{"too large an integer", GhostReasonIntegerRange, withItem(t, good, 8, []byte{0x89, 1, 2, 3, 4, 5, 6, 7, 8, 9})},
		{"extraData over 32 bytes", GhostReasonFieldSize, withItem(t, good, 12, append([]byte{0xa1}, bytes.Repeat([]byte{7}, 33)...))},
		{"short coinbase", GhostReasonFieldSize, withItem(t, good, 2, append([]byte{0x93}, bytes.Repeat([]byte{7}, 19)...))},
	} {
		_, err := DecodeGhostHeader(c.b)
		var reject *GhostHeaderError
		if !errors.As(err, &reject) || reject.Reason != c.reason {
			t.Errorf("%s: error %v, want reason %s", c.name, err, c.reason)
		}
	}
}

// withItem returns the list b with item i replaced by the encoded item.
func withItem(t *testing.T, b []byte, i int, item []byte) []byte {
	t.Helper()
	content, _, err := rlp.SplitList(b)
	if err != nil {
		t.Fatal(err)
	}
	var items [][]byte
	for len(content) > 0 {
		_, _, rest, err := rlp.Split(content)
		if err != nil {
			t.Fatal(err)
		}
		items = append(items, content[:len(content)-len(rest)])
		content = rest
	}
	items[i] = item
	body := bytes.Join(items, nil)
	return append(rlpListHeader(len(body)), body...)
}

func rlpListHeader(size int) []byte {
	if size < 56 {
		return []byte{0xc0 + byte(size)}
	}
	var n []byte
	for s := size; s > 0; s >>= 8 {
		n = append([]byte{byte(s)}, n...)
	}
	return append([]byte{0xf7 + byte(len(n))}, n...)
}

// The bytes the generated encoder wrote for the headers of baseHeaders, item
// by item: a 32-byte hash whose first byte is b, and the logs bloom whose
// first byte is 4.
func baseHash(b string) string { return "a0" + b + strings.Repeat("00", 31) }

var (
	baseFixed = baseHash("01") +
		"a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347" + // uncle hash
		"94" + "02" + strings.Repeat("00", 19) + // coinbase
		baseHash("03") +
		"a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421" + // transactions
		"a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421" + // receipts
		"b90100" + "04" + strings.Repeat("00", 255) + // logs bloom
		"83020000" + "8203e8" + "837a1200" + "825208" + "846553f100" + "8462617365" + // difficulty to extra
		baseHash("05") + "880000000000000006" // mix digest, nonce

	emptyWithdrawals = "a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"

	baseRLPNone        = "f901ff" + baseFixed
	baseRLPFee         = "f90204" + baseFixed + "843b9aca00"
	baseRLPWithdrawals = "f90221" + baseFixed + "07" + emptyWithdrawals
	baseRLPBlobGas     = "f90226" + baseFixed + "07" + emptyWithdrawals + "83020000" + "80"
	baseRLPAll         = "f90247" + baseFixed + "07" + emptyWithdrawals + "83020000" + "80" + baseHash("08")
	baseRLPBeaconOnly  = "f90224" + baseFixed + "80" + "80" + "80" + "80" + baseHash("09")
)

// baseHeaders are headers of the base layout with none, some or all of the
// old optional fields, and the bytes the generated encoder wrote for them.
func baseHeaders() []struct {
	name   string
	header *Header
	rlp    string
	decode bool
} {
	base := func() *Header {
		return &Header{
			ParentHash:  common.Hash{1},
			UncleHash:   EmptyUncleHash,
			Coinbase:    common.Address{2},
			Root:        common.Hash{3},
			TxHash:      EmptyTxsHash,
			ReceiptHash: EmptyReceiptsHash,
			Bloom:       Bloom{4},
			Difficulty:  big.NewInt(131072),
			Number:      big.NewInt(1000),
			GasLimit:    8_000_000,
			GasUsed:     21_000,
			Time:        1_700_000_000,
			Extra:       []byte("base"),
			MixDigest:   common.Hash{5},
			Nonce:       EncodeNonce(6),
		}
	}
	withdrawals := EmptyWithdrawalsHash
	blobGas, excess := uint64(131072), uint64(0)
	fee := base()
	fee.BaseFee = big.NewInt(1_000_000_000)
	withWithdrawals := base()
	withWithdrawals.BaseFee, withWithdrawals.WithdrawalsHash = big.NewInt(7), &withdrawals
	withBlobGas := base()
	withBlobGas.BaseFee, withBlobGas.WithdrawalsHash, withBlobGas.BlobGasUsed, withBlobGas.ExcessBlobGas = big.NewInt(7), &withdrawals, &blobGas, &excess
	all := CopyHeader(withBlobGas)
	all.ParentBeaconRoot = &common.Hash{8}
	beaconOnly := base()
	beaconOnly.ParentBeaconRoot = &common.Hash{9}
	return []struct {
		name   string
		header *Header
		rlp    string
		decode bool
	}{
		{"no optional fields", base(), baseRLPNone, true},
		{"base fee", fee, baseRLPFee, true},
		{"base fee and withdrawals", withWithdrawals, baseRLPWithdrawals, true},
		{"up to the blob gas fields", withBlobGas, baseRLPBlobGas, true},
		{"every optional field", all, baseRLPAll, true},
		// The base client writes the unset fields before it as empty
		// strings, which its decoder never read back; that stays so.
		{"beacon root only", beaconOnly, baseRLPBeaconOnly, false},
	}
}

// TestBaseHeaderEncodingUnchanged checks that headers without tree roots
// encode to exactly the bytes of the generated encoder and of the rlp
// package's reflection encoder, and decode back unchanged.
func TestBaseHeaderEncodingUnchanged(t *testing.T) {
	for _, c := range baseHeaders() {
		got, err := rlp.EncodeToBytes(c.header)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if want := mustHex(t, c.rlp); !bytes.Equal(got, want) {
			t.Errorf("%s: encoding\n got %x\nwant %x", c.name, got, want)
		}
		reflected, err := rlp.EncodeToBytes((*baseHeader)(c.header))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, reflected) {
			t.Errorf("%s: encoding differs from the reflection encoder\n got %x\nwant %x", c.name, got, reflected)
		}
		// The strict decoder takes only the Ghost layout.
		if _, err := DecodeGhostHeader(got); err == nil {
			t.Errorf("%s: the strict decoder accepts a base header", c.name)
		}
		var dec Header
		err = rlp.DecodeBytes(got, &dec)
		var old baseHeader
		if oldErr := rlp.DecodeBytes(got, &old); (oldErr == nil) != (err == nil) {
			t.Errorf("%s: decoding error %v, the reflection decoder's %v", c.name, err, oldErr)
		}
		if !c.decode {
			if err == nil {
				t.Errorf("%s: decodes", c.name)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: decode: %v", c.name, err)
		}
		if dec.CoinTreeRoot != nil || dec.DataTreeRoot != nil || dec.DataMarkerRoot != nil {
			t.Errorf("%s: decoded with tree roots", c.name)
		}
		if re, _ := rlp.EncodeToBytes(&dec); !bytes.Equal(re, got) {
			t.Errorf("%s: round trip gives\n%x", c.name, re)
		}
		if dec.Hash() != c.header.Hash() {
			t.Errorf("%s: hash changes in a round trip", c.name)
		}
	}
}

// TestGhostHeaderRejectsPartialOrMixedFields checks that a header with one
// root only, roots without a base fee, or roots with a forbidden field cannot
// be encoded, and that the size and copy count the roots.
func TestGhostHeaderRejectsPartialOrMixedFields(t *testing.T) {
	blobGas := uint64(1)
	withdrawals := EmptyWithdrawalsHash
	for name, mutate := range map[string]func(h *Header){
		"coin root only":                  func(h *Header) { h.DataTreeRoot, h.DataMarkerRoot = nil, nil },
		"data root only":                  func(h *Header) { h.CoinTreeRoot, h.DataMarkerRoot = nil, nil },
		"marker root only":                func(h *Header) { h.CoinTreeRoot, h.DataTreeRoot = nil, nil },
		"no marker root":                  func(h *Header) { h.DataMarkerRoot = nil },
		"no coin root":                    func(h *Header) { h.CoinTreeRoot = nil },
		"no data root":                    func(h *Header) { h.DataTreeRoot = nil },
		"roots without a base fee":        func(h *Header) { h.BaseFee = nil },
		"roots with a withdrawals hash":   func(h *Header) { h.WithdrawalsHash = &withdrawals },
		"roots with blob gas used":        func(h *Header) { h.BlobGasUsed = &blobGas },
		"roots with excess blob gas":      func(h *Header) { h.ExcessBlobGas = &blobGas },
		"roots with a parent beacon root": func(h *Header) { h.ParentBeaconRoot = &common.Hash{1} },
	} {
		h := vectorBlockOne()
		mutate(h)
		if b, err := rlp.EncodeToBytes(h); err == nil {
			t.Errorf("%s: encoded as %x", name, b)
		}
		if b, err := rlp.EncodeToBytes(NewBlockWithHeader(h)); err == nil {
			t.Errorf("%s: block encoded as %x", name, b)
		}
	}

	// A base header of 19 items has a short integer at index 18, its excess
	// blob gas, and decodes as a base header.
	h := vectorBlockOne()
	h.CoinTreeRoot, h.DataTreeRoot, h.DataMarkerRoot = nil, nil, nil
	h.WithdrawalsHash, h.BlobGasUsed, h.ExcessBlobGas = &withdrawals, &blobGas, &blobGas
	b, err := rlp.EncodeToBytes(h)
	if err != nil {
		t.Fatal(err)
	}
	if n := countItems(t, b); n != 19 {
		t.Fatalf("test header has %d items", n)
	}
	var dec Header
	if err := rlp.DecodeBytes(b, &dec); err != nil {
		t.Fatal(err)
	}
	if dec.CoinTreeRoot != nil || dec.DataMarkerRoot != nil || dec.ExcessBlobGas == nil || *dec.ExcessBlobGas != blobGas {
		t.Errorf("a 19-item base header decoded as %+v", dec)
	}
	// A forbidden field between the base fee and the roots decodes as
	// neither layout.
	if err := rlp.DecodeBytes(mustHex(t, negativeHeaderVectors[0].rlp), &dec); err == nil {
		t.Error("the forbidden-field vector decodes")
	}

	// Copy and size.
	g := vectorBlockOne()
	cpy := CopyHeader(g)
	if cpy.CoinTreeRoot == g.CoinTreeRoot || cpy.DataTreeRoot == g.DataTreeRoot || cpy.DataMarkerRoot == g.DataMarkerRoot {
		t.Error("CopyHeader shares the root pointers")
	}
	if *cpy.CoinTreeRoot != *g.CoinTreeRoot || *cpy.DataTreeRoot != *g.DataTreeRoot || *cpy.DataMarkerRoot != *g.DataMarkerRoot {
		t.Error("CopyHeader changes the roots")
	}
	cpy.CoinTreeRoot[0] ^= 1
	if cpy.Hash() == g.Hash() {
		t.Error("a changed coin root leaves the hash unchanged")
	}
	cpy = CopyHeader(g)
	cpy.DataTreeRoot[31] ^= 1
	if cpy.Hash() == g.Hash() {
		t.Error("a changed data root leaves the hash unchanged")
	}
	bare := CopyHeader(g)
	bare.CoinTreeRoot, bare.DataTreeRoot, bare.DataMarkerRoot = nil, nil, nil
	if diff := g.Size() - bare.Size(); diff != 3*common.HashLength {
		t.Errorf("the roots add %v to the size, want %d", diff, 3*common.HashLength)
	}
}

func countItems(t *testing.T, b []byte) int {
	t.Helper()
	content, _, err := rlp.SplitList(b)
	if err != nil {
		t.Fatal(err)
	}
	n, err := rlp.CountValues(content)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// vectorBlockOneEighteenItems is header-block-one-example without its data
// marker root: the 18-item layout before the marker root, negative vector
// header-eighteen-items.
var vectorBlockOneEighteenItems = "f90243" + blockOneBody + blockOneFee + blockOneCoin + blockOneData

// TestGhostHeaderDataMarkerRoot checks the data marker root at index 18 of
// the Ghost layout: the vectors, the rejection of the 18-item layout, the
// all-or-none rule of the three roots, the hash, copy and size, and that a
// 19-item base header still decodes as a base header.
func TestGhostHeaderDataMarkerRoot(t *testing.T) {
	// Both positive vectors encode to their bytes and hash.
	for _, v := range []struct {
		name   string
		header *Header
		rlp    string
		hash   string
	}{
		{"header-genesis-example", vectorGenesis(), vectorGenesisRLP, vectorGenesisHash},
		{"header-block-one-example", vectorBlockOne(), vectorBlockOneRLP, vectorBlockOneHash},
	} {
		got, err := rlp.EncodeToBytes(v.header)
		if err != nil {
			t.Fatalf("%s: encode: %v", v.name, err)
		}
		if want := mustHex(t, v.rlp); !bytes.Equal(got, want) {
			t.Errorf("%s: encoding\n got %x\nwant %x", v.name, got, want)
		}
		if n := countItems(t, got); n != 19 {
			t.Errorf("%s: %d items, want 19", v.name, n)
		}
		if h := v.header.Hash(); h != common.HexToHash(v.hash) {
			t.Errorf("%s: hash %x, want %s", v.name, h, v.hash)
		}
		dec, err := DecodeGhostHeader(got)
		if err != nil {
			t.Fatalf("%s: strict decode: %v", v.name, err)
		}
		if dec.DataMarkerRoot == nil || *dec.DataMarkerRoot != *v.header.DataMarkerRoot {
			t.Errorf("%s: decoded marker root %v", v.name, dec.DataMarkerRoot)
		}
	}

	// header-eighteen-items: block one without the marker root.
	eighteen := mustHex(t, vectorBlockOneEighteenItems)
	_, err := DecodeGhostHeader(eighteen)
	var reject *GhostHeaderError
	if !errors.As(err, &reject) || reject.Reason != GhostReasonItemCount {
		t.Errorf("header-eighteen-items: error %v, want reason %s", err, GhostReasonItemCount)
	}
	var dec Header
	if err := rlp.DecodeBytes(eighteen, &dec); err == nil && (dec.CoinTreeRoot != nil || dec.DataTreeRoot != nil || dec.DataMarkerRoot != nil) {
		t.Error("header-eighteen-items decodes as a Ghost header through rlp")
	}

	// Exactly one or two of the three roots set does not encode.
	for name, mutate := range map[string]func(h *Header){
		"coin root only":   func(h *Header) { h.DataTreeRoot, h.DataMarkerRoot = nil, nil },
		"data root only":   func(h *Header) { h.CoinTreeRoot, h.DataMarkerRoot = nil, nil },
		"marker root only": func(h *Header) { h.CoinTreeRoot, h.DataTreeRoot = nil, nil },
		"no marker root":   func(h *Header) { h.DataMarkerRoot = nil },
		"no data root":     func(h *Header) { h.DataTreeRoot = nil },
		"no coin root":     func(h *Header) { h.CoinTreeRoot = nil },
	} {
		h := vectorBlockOne()
		mutate(h)
		if b, err := rlp.EncodeToBytes(h); !errors.Is(err, errPartialTreeRoots) {
			t.Errorf("%s: encoded as %x, error %v", name, b, err)
		}
	}

	// The hash covers the marker root.
	g := vectorBlockOne()
	cpy := CopyHeader(g)
	cpy.DataMarkerRoot[0] ^= 1
	if cpy.Hash() == g.Hash() {
		t.Error("a changed marker root leaves the hash unchanged")
	}

	// CopyHeader copies it into a separate pointer, and Size counts it.
	cpy = CopyHeader(g)
	if cpy.DataMarkerRoot == g.DataMarkerRoot || *cpy.DataMarkerRoot != *g.DataMarkerRoot {
		t.Error("CopyHeader does not copy the marker root into a separate pointer")
	}
	noMarker := CopyHeader(g)
	noMarker.DataMarkerRoot = nil
	if diff := g.Size() - noMarker.Size(); diff != common.HashLength {
		t.Errorf("the marker root adds %v to the size, want %d", diff, common.HashLength)
	}

	// A 19-item base header (base fee, withdrawals root, blob gas used,
	// excess blob gas, no beacon root) decodes as a base header.
	withdrawals := EmptyWithdrawalsHash
	blobGas, excess := uint64(131072), uint64(7)
	base := vectorBlockOne()
	base.CoinTreeRoot, base.DataTreeRoot, base.DataMarkerRoot = nil, nil, nil
	base.WithdrawalsHash, base.BlobGasUsed, base.ExcessBlobGas = &withdrawals, &blobGas, &excess
	b, err := rlp.EncodeToBytes(base)
	if err != nil {
		t.Fatal(err)
	}
	if n := countItems(t, b); n != 19 {
		t.Fatalf("base header has %d items, want 19", n)
	}
	dec = Header{}
	if err := rlp.DecodeBytes(b, &dec); err != nil {
		t.Fatalf("19-item base header: %v", err)
	}
	if dec.DataMarkerRoot != nil || dec.CoinTreeRoot != nil || dec.DataTreeRoot != nil {
		t.Error("a 19-item base header decoded with roots")
	}
	if dec.ExcessBlobGas == nil || *dec.ExcessBlobGas != excess || dec.Hash() != base.Hash() {
		t.Errorf("a 19-item base header decoded as %+v", dec)
	}
}
