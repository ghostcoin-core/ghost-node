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

// The vectors above are the 19-item list before the header MMR root. The
// Ghost layout appends the root as item 19: the genesis vector carries the
// empty root, and block one, on that genesis, the root of the one-leaf MMR
// over it. Their bytes are the items above with the root item appended, so
// they do not come from the encoder under test.
var (
	mmrEmptyRootHex = "b1f684aabd11aa3966ac25d6ac9c50e10cc53cbfb48957f3f514fb4b08fd23ac" // decision 0005
	genesisMmrItem  = "a0" + mmrEmptyRootHex

	// vectorGenesisMmrBody is the content of the genesis vector's list with
	// the header MMR root.
	vectorGenesisMmrBody = strings.TrimPrefix(vectorGenesisRLP, "f90281") + genesisMmrItem
)

// mmrVectors returns the encodings and hashes of the genesis and block one
// vectors with the header MMR root, and block one's root.
func mmrVectors(t *testing.T) (genesis []byte, genesisHash common.Hash, blockOne []byte, blockOneHash common.Hash, blockOneRoot common.Hash) {
	t.Helper()
	body := mustHex(t, vectorGenesisMmrBody)
	genesis = append(rlpListHeader(len(body)), body...)
	genesisHash = crypto.Keccak256Hash(genesis)
	blockOneRoot = oneLeafRoot(t, genesisHash, big.NewInt(16777216))
	blockOne = mustHex(t, blockOneMmrRLPHex(t, genesisHash, blockOneRoot, blockOneDifficulty+blockOneNumber, blockOneFee, blockOneCoin, ""))
	return genesis, genesisHash, blockOne, crypto.Keccak256Hash(blockOne), blockOneRoot
}

// blockOneMmrRLPHex is block one on the genesis with the header MMR root, with
// the given pieces between the bloom and the rest, as the base fee and as the
// coin tree root, and extra appended after the root item.
func blockOneMmrRLPHex(t *testing.T, parent, root common.Hash, difficultyNumber, fee, coin, extra string) string {
	t.Helper()
	head := "a0" + common.Bytes2Hex(parent[:]) + blockOneHead[66:]
	body := head + zeroBloom + difficultyNumber + blockOneRest + fee + coin + blockOneData + blockOneMarker + "a0" + common.Bytes2Hex(root[:]) + extra
	return common.Bytes2Hex(rlpListHeader(len(body)/2)) + body
}

// oneLeafRoot is the header MMR root over one leaf, computed from decision
// 0005's formulas here rather than with core/ghostmmr.
func oneLeafRoot(t *testing.T, headerHash common.Hash, difficulty *big.Int) common.Hash {
	t.Helper()
	tagged := func(tag string, parts ...[]byte) []byte {
		return crypto.Keccak256(append([][]byte{{byte(len(tag))}, []byte(tag)}, parts...)...)
	}
	work := make([]byte, 16)
	difficulty.FillBytes(work)
	leaf := tagged("ghost/header-mmr-leaf/v1", headerHash[:], work)
	return common.BytesToHash(tagged("ghost/header-mmr-root/v1", []byte{0, 0, 0, 0, 0, 0, 0, 1}, leaf, work))
}

// The negative vectors: block one with the header MMR root and one fault
// each.
func negativeHeaderVectors(t *testing.T) []struct {
	name, reason string
	rlp          []byte
} {
	_, genesis, blockOne, _, root := mmrVectors(t)
	pieces := func(difficultyNumber, fee, coin, extra string) []byte {
		return mustHex(t, blockOneMmrRLPHex(t, genesis, root, difficultyNumber, fee, coin, extra))
	}
	plain := blockOneDifficulty + blockOneNumber
	return []struct {
		name, reason string
		rlp          []byte
	}{
		// A withdrawals root after the base fee.
		{"header-forbidden-field", GhostReasonItemCount, pieces(plain, blockOneFee+"a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421", blockOneCoin, "")},
		// An empty string appended.
		{"header-extra-trailing-field", GhostReasonItemCount, pieces(plain, blockOneFee, blockOneCoin, "80")},
		// No base fee.
		{"header-missing-required-field", GhostReasonItemCount, pieces(plain, "", blockOneCoin, "")},
		// The block number with a leading zero byte.
		{"header-non-canonical-integer", GhostReasonNonCanonicalInteger, pieces(blockOneDifficulty+"820001", blockOneFee, blockOneCoin, "")},
		// The coin tree root cut to 31 bytes.
		{"header-short-tree-root", GhostReasonFieldSize, pieces(plain, blockOneFee, "9f142c6bdf0882396330f9942ddd49df5d860b05a5218dad1ce6ef8e69238b6e", "")},
		// One byte after the list.
		{"header-trailing-bytes", GhostReasonTrailingBytes, append(append([]byte{}, blockOne...), 0)},
		// The 18-item layout, without the data marker root.
		{"header-eighteen-items", GhostReasonItemCount, mustHex(t, vectorBlockOneEighteenItems)},
		// The 19-item list, without the header MMR root.
		{"header-nineteen-items", GhostReasonItemCount, mustHex(t, vectorBlockOneRLP)},
	}
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

// vectorGenesisMmr and vectorBlockOneMmr are the field values of the vectors
// with the header MMR root.
func vectorGenesisMmr() *Header {
	h := vectorGenesis()
	h.HeaderMmrRoot = hashPtr(mmrEmptyRootHex)
	return h
}

func vectorBlockOneMmr(t *testing.T) *Header {
	_, genesis, _, _, root := mmrVectors(t)
	h := vectorBlockOne()
	h.ParentHash, h.HeaderMmrRoot = genesis, &root
	return h
}

// TestGhostHeaderVectors checks the positive header vectors: the fields
// encode to the stated bytes and hash, and the bytes decode back to the same
// header with both decoders. The vectors without the header MMR root still
// encode and decode through rlp, and the strict decoder refuses them.
func TestGhostHeaderVectors(t *testing.T) {
	genesisMmr, genesisMmrHash, blockOneMmr, blockOneMmrHash, _ := mmrVectors(t)
	for _, v := range []struct {
		name   string
		header *Header
		rlp    string
		hash   string
		strict bool
	}{
		{"header-genesis-example", vectorGenesis(), vectorGenesisRLP, vectorGenesisHash, false},
		{"header-block-one-example", vectorBlockOne(), vectorBlockOneRLP, vectorBlockOneHash, false},
		{"header-genesis-with-mmr", vectorGenesisMmr(), common.Bytes2Hex(genesisMmr), common.Bytes2Hex(genesisMmrHash[:]), true},
		{"header-block-one-with-mmr", vectorBlockOneMmr(t), common.Bytes2Hex(blockOneMmr), common.Bytes2Hex(blockOneMmrHash[:]), true},
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

		if (dec.HeaderMmrRoot != nil) != v.strict || (v.strict && *dec.HeaderMmrRoot != *v.header.HeaderMmrRoot) {
			t.Errorf("%s: decoded header MMR root %v", v.name, dec.HeaderMmrRoot)
		}

		strict, err := DecodeGhostHeader(want)
		if !v.strict {
			var reject *GhostHeaderError
			if !errors.As(err, &reject) || reject.Reason != GhostReasonItemCount {
				t.Errorf("%s: strict decoder without the header MMR root: %v, want %s", v.name, err, GhostReasonItemCount)
			}
		} else {
			if err != nil {
				t.Fatalf("%s: strict decoder rejects a positive vector: %v", v.name, err)
			}
			if re, _ := rlp.EncodeToBytes(strict); !bytes.Equal(re, want) {
				t.Errorf("%s: strict decode and encode gives\n%x", v.name, re)
			}
			if strict.Hash() != common.HexToHash(v.hash) {
				t.Errorf("%s: strict decoded hash %x", v.name, strict.Hash())
			}
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
	// Block one's parent is the genesis vector, and so with the root.
	if vectorBlockOne().ParentHash != vectorGenesis().Hash() {
		t.Error("block one does not build on the genesis vector")
	}
	if vectorBlockOneMmr(t).ParentHash != vectorGenesisMmr().Hash() {
		t.Error("block one with the header MMR root does not build on the genesis with it")
	}
	// The genesis with the root is 33 bytes longer than without it.
	if len(genesisMmr) != len(mustHex(t, vectorGenesisRLP))+33 || len(blockOneMmr) != len(mustHex(t, vectorBlockOneRLP))+33 {
		t.Errorf("vectors with the root are %d and %d bytes", len(genesisMmr), len(blockOneMmr))
	}
}

// TestGhostHeaderNegativeVectors checks that the strict decoder rejects each
// negative vector with its stated reason, and that the ordinary decoder never
// reads one as a Ghost header with the header MMR root.
func TestGhostHeaderNegativeVectors(t *testing.T) {
	for _, v := range negativeHeaderVectors(t) {
		b := v.rlp
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
		if err := rlp.DecodeBytes(b, &dec); err == nil && dec.HeaderMmrRoot != nil {
			t.Errorf("%s: the ordinary decoder reads it as a Ghost header", v.name)
		}
	}
	// The reasons the vectors do not reach.
	_, _, good, _, _ := mmrVectors(t)
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
		{"item that is a list", GhostReasonItemCount, append([]byte{0xd3, 0xc0}, bytes.Repeat([]byte{0x80}, 18)...)},
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
	if err := rlp.DecodeBytes(negativeHeaderVectors(t)[0].rlp, &dec); err == nil {
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
	genesisMmr, genesisMmrHash, blockOneMmr, blockOneMmrHash, _ := mmrVectors(t)
	for _, v := range []struct {
		name   string
		header *Header
		rlp    []byte
		hash   common.Hash
	}{
		{"header-genesis-with-mmr", vectorGenesisMmr(), genesisMmr, genesisMmrHash},
		{"header-block-one-with-mmr", vectorBlockOneMmr(t), blockOneMmr, blockOneMmrHash},
	} {
		got, err := rlp.EncodeToBytes(v.header)
		if err != nil {
			t.Fatalf("%s: encode: %v", v.name, err)
		}
		if !bytes.Equal(got, v.rlp) {
			t.Errorf("%s: encoding\n got %x\nwant %x", v.name, got, v.rlp)
		}
		if n := countItems(t, got); n != 20 {
			t.Errorf("%s: %d items, want 20", v.name, n)
		}
		if h := v.header.Hash(); h != v.hash {
			t.Errorf("%s: hash %x, want %x", v.name, h, v.hash)
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

// TestHeaderMMRRootField checks the header MMR root, the last item of the
// Ghost layout: its place and bytes, the round trip through both decoders,
// the hash, copy and size, and the combinations that do not encode.
func TestHeaderMMRRootField(t *testing.T) {
	_, genesis, blockOne, blockOneHash, root := mmrVectors(t)
	h := vectorBlockOneMmr(t)
	got, err := rlp.EncodeToBytes(h)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, blockOne) || h.Hash() != blockOneHash {
		t.Fatalf("block one with the root encodes to\n%x\nwant\n%x", got, blockOne)
	}
	// The root is the last of the 20 items, after the data marker root.
	content, _, _ := rlp.SplitList(got)
	var items [][]byte
	for len(content) > 0 {
		_, item, rest, err := rlp.Split(content)
		if err != nil {
			t.Fatal(err)
		}
		items, content = append(items, item), rest
	}
	if len(items) != 20 || !bytes.Equal(items[19], root[:]) || !bytes.Equal(items[18], h.DataMarkerRoot[:]) {
		t.Fatalf("%d items, the last %x", len(items), items[len(items)-1])
	}
	if h.ParentHash != genesis {
		t.Fatal("block one is not on the genesis with the root")
	}
	// Both decoders give the root back.
	var dec Header
	if err := rlp.DecodeBytes(got, &dec); err != nil || dec.HeaderMmrRoot == nil || *dec.HeaderMmrRoot != root {
		t.Fatalf("decoded root %v (%v)", dec.HeaderMmrRoot, err)
	}
	strict, err := DecodeGhostHeader(got)
	if err != nil || strict.HeaderMmrRoot == nil || *strict.HeaderMmrRoot != root || strict.Hash() != blockOneHash {
		t.Fatalf("strict decoded root %v (%v)", strict, err)
	}
	// A 31-byte root is a field-size; 21 items an item-count.
	short := withItem(t, got, 19, append([]byte{0x9f}, root[:31]...))
	var reject *GhostHeaderError
	if _, err := DecodeGhostHeader(short); !errors.As(err, &reject) || reject.Reason != GhostReasonFieldSize {
		t.Errorf("a 31-byte header MMR root: %v", err)
	}
	if err := rlp.DecodeBytes(short, &dec); err == nil && dec.HeaderMmrRoot != nil {
		t.Error("the ordinary decoder takes a 31-byte header MMR root")
	}
	// The hash covers the root, CopyHeader copies it, Size counts it.
	cpy := CopyHeader(h)
	if cpy.HeaderMmrRoot == h.HeaderMmrRoot || *cpy.HeaderMmrRoot != *h.HeaderMmrRoot {
		t.Error("CopyHeader shares or changes the header MMR root")
	}
	cpy.HeaderMmrRoot[31] ^= 1
	if cpy.Hash() == h.Hash() {
		t.Error("a changed header MMR root leaves the hash unchanged")
	}
	without := CopyHeader(h)
	without.HeaderMmrRoot = nil
	if diff := h.Size() - without.Size(); diff != common.HashLength {
		t.Errorf("the header MMR root adds %v to the size", diff)
	}
	// Without it the header is the 19-item list, which is not a Ghost header.
	pre, err := rlp.EncodeToBytes(without)
	if err != nil {
		t.Fatal(err)
	}
	if n := countItems(t, pre); n != 19 {
		t.Fatalf("a header without the root has %d items", n)
	}
	if _, err := DecodeGhostHeader(pre); !errors.As(err, &reject) || reject.Reason != GhostReasonItemCount {
		t.Errorf("19 items: %v, want %s", err, GhostReasonItemCount)
	}
	if err := rlp.DecodeBytes(pre, &dec); err != nil || dec.HeaderMmrRoot != nil || dec.Hash() != without.Hash() {
		t.Errorf("19 items decode as %v (%v)", dec.HeaderMmrRoot, err)
	}
	// The root without the tree roots does not encode, in a header or a block.
	bare := CopyHeader(h)
	bare.CoinTreeRoot, bare.DataTreeRoot, bare.DataMarkerRoot = nil, nil, nil
	if b, err := rlp.EncodeToBytes(bare); !errors.Is(err, errMmrRootNoRoots) {
		t.Errorf("the root without the tree roots encodes as %x (%v)", b, err)
	}
	if _, err := rlp.EncodeToBytes(NewBlockWithHeader(bare)); err == nil {
		t.Error("a block with the root and no tree roots encodes")
	}
	// The root with a partial set of tree roots is still a partial set.
	partial := CopyHeader(h)
	partial.DataMarkerRoot = nil
	if _, err := rlp.EncodeToBytes(partial); !errors.Is(err, errPartialTreeRoots) {
		t.Errorf("the root with two tree roots: %v", err)
	}
	// A base header of 20 items, every optional field, stays a base header.
	for _, c := range baseHeaders() {
		if c.name != "every optional field" {
			continue
		}
		b := mustHex(t, c.rlp)
		if n := countItems(t, b); n != 20 {
			t.Fatalf("base header with every optional field has %d items", n)
		}
		var base Header
		if err := rlp.DecodeBytes(b, &base); err != nil || base.HeaderMmrRoot != nil || base.CoinTreeRoot != nil || base.ParentBeaconRoot == nil {
			t.Errorf("a 20-item base header decoded as %+v (%v)", base, err)
		}
	}
	// The genesis vector carries the empty root.
	g := vectorGenesisMmr()
	if g.HeaderMmrRoot == nil || *g.HeaderMmrRoot != common.HexToHash(mmrEmptyRootHex) {
		t.Error("the genesis vector does not carry the empty root")
	}
}
