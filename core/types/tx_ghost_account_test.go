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
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"runtime"
	"sort"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/slhdsa"
	"github.com/cloudflare/circl/xof"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rlp"
)

var (
	ghostTestChainID = big.NewInt(1337)
	ghostTestGenesis = common.HexToHash("0x9a0c3e5d7f1b2a4c6e8f0a1b3c5d7e9f1a2b3c4d5e6f708192a3b4c5d6e7f809")
)

// ghostTestKey returns the ML-DSA-44 key made from a seed of 32 equal bytes.
func ghostTestKey(seed byte) *mldsa44.PrivateKey {
	var s [mldsa44.SeedSize]byte
	for i := range s {
		s[i] = seed
	}
	_, sk := mldsa44.NewKeyFromSeed(&s)
	return sk
}

func ghostTestSigner() Signer {
	return NewGhostAccountSigner(NewCancunSigner(ghostTestChainID), ghostTestGenesis)
}

func ghostTestTxData(to *common.Address) *GhostAccountTx {
	accessList := AccessList{{
		Address:     common.HexToAddress("0x00000000000000000000000000000000000000aa"),
		StorageKeys: []common.Hash{common.HexToHash("0x01")},
	}}
	return &GhostAccountTx{
		ChainID:    new(big.Int).Set(ghostTestChainID),
		Nonce:      7,
		GasTipCap:  big.NewInt(2_000_000_000),
		GasFeeCap:  big.NewInt(30_000_000_000),
		Gas:        200_000,
		To:         to,
		Value:      big.NewInt(123_456_789),
		Data:       []byte{0xde, 0xad, 0xbe, 0xef},
		AccessList: accessList,
	}
}

func ghostTestSign(t testing.TB, signer Signer, key *mldsa44.PrivateKey, txdata *GhostAccountTx) *Transaction {
	t.Helper()
	tx, err := SignGhostAccountTx(signer, key, txdata)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	return tx
}

func TestGhostAccountTxRoundTrip(t *testing.T) {
	signer := ghostTestSigner()
	key := ghostTestKey(1)
	to := common.HexToAddress("0x00000000000000000000000000000000000000bb")
	for _, tc := range []struct {
		name string
		to   *common.Address
	}{{"transfer", &to}, {"creation", nil}} {
		t.Run(tc.name, func(t *testing.T) {
			tx := ghostTestSign(t, signer, key, ghostTestTxData(tc.to))
			from, err := Sender(signer, tx)
			if err != nil {
				t.Fatalf("sender of the signed transaction: %v", err)
			}
			pk := key.Public().(*mldsa44.PublicKey).Bytes()
			if want := GhostAccountAddressOf(GhostSchemeMLDSA44, pk); from != want {
				t.Fatalf("sender %v, want %v", from, want)
			}

			// The binary envelope.
			enc, err := tx.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			if enc[0] != GhostAccountTxType {
				t.Fatalf("type byte %#x, want 0x52", enc[0])
			}
			if uint64(len(enc)) != tx.Size() {
				t.Fatalf("size %d, encoding %d bytes", tx.Size(), len(enc))
			}
			if tx.Hash() != prefixedRlpHash(GhostAccountTxType, tx.inner) {
				t.Fatal("hash is not keccak256 of the envelope")
			}
			var dec Transaction
			if err := dec.UnmarshalBinary(enc); err != nil {
				t.Fatalf("decoding: %v", err)
			}
			if dec.Hash() != tx.Hash() {
				t.Fatal("hash changed in the round trip")
			}
			if got, _ := dec.MarshalBinary(); !bytes.Equal(got, enc) {
				t.Fatal("encoding changed in the round trip")
			}
			if from2, err := Sender(signer, &dec); err != nil || from2 != from {
				t.Fatalf("sender after decoding %v %v, want %v", from2, err, from)
			}
			if (dec.To() == nil) != (tc.to == nil) {
				t.Fatal("recipient changed in the round trip")
			}

			// The RLP form in blocks.
			blockEnc, err := rlp.EncodeToBytes(tx)
			if err != nil {
				t.Fatal(err)
			}
			var dec2 Transaction
			if err := rlp.DecodeBytes(blockEnc, &dec2); err != nil {
				t.Fatalf("decoding the block form: %v", err)
			}
			if dec2.Hash() != tx.Hash() {
				t.Fatal("hash changed in the block form")
			}

			// JSON.
			js, err := json.Marshal(tx)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]interface{}
			if err := json.Unmarshal(js, &fields); err != nil {
				t.Fatal(err)
			}
			if fields["type"] != "0x52" || fields["scheme"] != "0x1" {
				t.Fatalf("JSON type %v scheme %v", fields["type"], fields["scheme"])
			}
			if fields["publicKey"] != hexutil.Encode(pk) {
				t.Fatal("JSON public key differs")
			}
			var dec3 Transaction
			if err := json.Unmarshal(js, &dec3); err != nil {
				t.Fatalf("decoding JSON: %v", err)
			}
			if dec3.Hash() != tx.Hash() {
				t.Fatal("hash changed in the JSON round trip")
			}

			// The receipt of an account transaction is a typed receipt.
			receipt := &Receipt{Type: GhostAccountTxType, Status: ReceiptStatusSuccessful, CumulativeGasUsed: 90_000, Logs: []*Log{}}
			renc, err := receipt.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			if renc[0] != GhostAccountTxType {
				t.Fatalf("receipt type byte %#x", renc[0])
			}
			var rdec Receipt
			if err := rdec.UnmarshalBinary(renc); err != nil {
				t.Fatalf("decoding the receipt: %v", err)
			}
			if rdec.Type != GhostAccountTxType || rdec.CumulativeGasUsed != 90_000 {
				t.Fatalf("receipt changed: %+v", rdec)
			}
			var buf bytes.Buffer
			Receipts{receipt}.EncodeIndex(0, &buf)
			if !bytes.Equal(buf.Bytes(), renc) {
				t.Fatal("receipt trie encoding differs from the receipt encoding")
			}
		})
	}
}

// ghostItems returns the twelve items of an account transaction, each RLP
// encoded on its own.
func ghostItems(t *testing.T, tx *GhostAccountTx) []rlp.RawValue {
	t.Helper()
	fields := []interface{}{tx.ChainID, tx.Nonce, tx.GasTipCap, tx.GasFeeCap, tx.Gas, tx.To, tx.Value, tx.Data, tx.AccessList, tx.Scheme, tx.PublicKey, tx.Signature}
	items := make([]rlp.RawValue, len(fields))
	for i, f := range fields {
		b, err := rlp.EncodeToBytes(f)
		if err != nil {
			t.Fatal(err)
		}
		items[i] = b
	}
	return items
}

func ghostEnvelope(t *testing.T, items []rlp.RawValue, trailing ...byte) []byte {
	t.Helper()
	list, err := rlp.EncodeToBytes(items)
	if err != nil {
		t.Fatal(err)
	}
	return append(append([]byte{GhostAccountTxType}, list...), trailing...)
}

func mustRLP(t *testing.T, v interface{}) rlp.RawValue {
	t.Helper()
	b, err := rlp.EncodeToBytes(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestGhostAccountTxStrictDecoding checks that every malformed envelope is
// refused, never repaired.
func TestGhostAccountTxStrictDecoding(t *testing.T) {
	to := common.HexToAddress("0x00000000000000000000000000000000000000bb")
	signed := ghostTestSign(t, ghostTestSigner(), ghostTestKey(1), ghostTestTxData(&to)).inner.(*GhostAccountTx)

	// The items as they are decode: the cases below differ from it in one
	// thing only.
	var ok Transaction
	if err := ok.UnmarshalBinary(ghostEnvelope(t, ghostItems(t, signed))); err != nil {
		t.Fatalf("the unchanged envelope does not decode: %v", err)
	}

	set := func(i int, v rlp.RawValue) func([]rlp.RawValue) []rlp.RawValue {
		return func(items []rlp.RawValue) []rlp.RawValue {
			items[i] = v
			return items
		}
	}
	for _, tc := range []struct {
		name     string
		edit     func([]rlp.RawValue) []rlp.RawValue
		trailing []byte
	}{
		{"thirteen items", func(items []rlp.RawValue) []rlp.RawValue { return append(items, mustRLP(t, uint64(0))) }, nil},
		{"eleven items", func(items []rlp.RawValue) []rlp.RawValue { return items[:11] }, nil},
		{"bytes after the list", nil, []byte{0x80}},
		{"nonce with a leading zero", set(1, rlp.RawValue{0x82, 0x00, 0x07}), nil},
		{"nonce as a one-byte string", set(1, rlp.RawValue{0x81, 0x07}), nil},
		{"chain ID with a leading zero", set(0, rlp.RawValue{0x83, 0x00, 0x05, 0x39}), nil},
		{"value of 33 bytes", set(6, mustRLP(t, new(big.Int).Lsh(big.NewInt(1), 260))), nil},
		{"fee cap of 33 bytes", set(3, mustRLP(t, new(big.Int).Lsh(big.NewInt(1), 260))), nil},
		{"recipient of 19 bytes", set(5, mustRLP(t, make([]byte, 19))), nil},
		{"recipient as a list", set(5, rlp.RawValue{0xc0}), nil},
		{"scheme of one byte", set(9, rlp.RawValue{0x01}), nil},
		{"scheme as an integer", set(9, mustRLP(t, uint64(1))), nil},
		{"scheme of three bytes", set(9, mustRLP(t, []byte{0, 0, 1})), nil},
		{"public key one byte short", set(10, mustRLP(t, signed.PublicKey[:GhostMLDSA44PublicKeySize-1])), nil},
		{"public key one byte long", set(10, mustRLP(t, append(common.CopyBytes(signed.PublicKey), 0))), nil},
		{"signature one byte short", set(11, mustRLP(t, signed.Signature[:GhostMLDSA44SignatureSize-1])), nil},
		{"signature one byte long", set(11, mustRLP(t, append(common.CopyBytes(signed.Signature), 0))), nil},
		{"signature of the other scheme's length", set(11, mustRLP(t, make([]byte, GhostSLHDSASignatureSize))), nil},
	} {
		items := ghostItems(t, signed)
		if tc.edit != nil {
			items = tc.edit(items)
		}
		var tx Transaction
		if err := tx.UnmarshalBinary(ghostEnvelope(t, items, tc.trailing...)); err == nil {
			t.Errorf("%s: decoded, want refused", tc.name)
		}
	}
}

// TestGhostAccountTxSenderVectors checks the address and signature hash
// against values computed by an implementation independent of the node, the
// pure Keccak-256 of scripts/test_ghost_account_vectors.py, which recomputes
// the constants below (QS-5).
func TestGhostAccountTxSenderVectors(t *testing.T) {
	counting := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(i)
		}
		return b
	}
	fill := func(n int, v byte) []byte { return bytes.Repeat([]byte{v}, n) }

	inputs := map[string]struct {
		scheme uint16
		pk     []byte
	}{
		"mldsa44-counting": {GhostSchemeMLDSA44, counting(GhostMLDSA44PublicKeySize)},
		"mldsa44-zero":     {GhostSchemeMLDSA44, fill(GhostMLDSA44PublicKeySize, 0)},
		"mldsa44-ones":     {GhostSchemeMLDSA44, fill(GhostMLDSA44PublicKeySize, 0xff)},
		"scheme2-counting": {GhostSchemeSLHDSA, counting(GhostSLHDSAPublicKeySize)},
	}
	sighashes := map[string][2]common.Hash{
		"sighash-11-22": {common.BytesToHash(fill(32, 0x11)), common.BytesToHash(fill(32, 0x22))},
	}
	vectors := []struct{ name, want string }{
		{"mldsa44-counting", "0xf1d74137fd6eadaca27f1f9d62e5b83b4bb8db4d"},
		{"mldsa44-zero", "0xe408ece3511352d74a33c4e8f6d4130d1320bccf"},
		{"mldsa44-ones", "0x7954a8678ed206b497203e586316a0194e7a6840"},
		{"scheme2-counting", "0x3bc5f85eb01e0fa6e335902b9bae0876af78cfa7"},
		{"sighash-11-22", "0x419ee98edaabbbb84eca3a3401379cc1a5ef1d7d4b074884a6aa18234b892947"},
	}
	if len(vectors) != len(inputs)+len(sighashes) {
		t.Fatal("a vector has no input")
	}
	for _, v := range vectors {
		var got string
		if in, ok := inputs[v.name]; ok {
			got = hexutil.Encode(GhostAccountAddressOf(in.scheme, in.pk).Bytes())
		} else if in, ok := sighashes[v.name]; ok {
			got = hexutil.Encode(ghostAccountSigHash(in[0], in[1]).Bytes())
		} else {
			t.Fatalf("vector %s has no input", v.name)
		}
		if got != v.want {
			t.Errorf("%s: got %s, want %s", v.name, got, v.want)
		}
	}

	// A signed transaction's sender is the address of its scheme and key,
	// and its signature hash is the vector formula over its unsigned hash.
	signer := ghostTestSigner()
	key := ghostTestKey(3)
	tx := ghostTestSign(t, signer, key, ghostTestTxData(nil))
	from, err := Sender(signer, tx)
	if err != nil {
		t.Fatal(err)
	}
	if want := GhostAccountAddressOf(GhostSchemeMLDSA44, key.Public().(*mldsa44.PublicKey).Bytes()); from != want {
		t.Fatalf("sender %v, want %v", from, want)
	}
	inner := tx.inner.(*GhostAccountTx)
	if signer.Hash(tx) != ghostAccountSigHash(ghostTestGenesis, inner.unsignedHash()) {
		t.Fatal("signer hash is not the signature hash")
	}
	unsigned, err := rlp.EncodeToBytes([]interface{}{inner.ChainID, inner.Nonce, inner.GasTipCap, inner.GasFeeCap, inner.Gas, inner.To, inner.Value, inner.Data, inner.AccessList, inner.Scheme, inner.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	if rlpHash(rlp.RawValue(unsigned)) != inner.unsignedHash() {
		t.Fatal("unsigned hash is not keccak256 of the eleven-item list")
	}
}

func TestGhostAccountTxSignatureBindsEveryField(t *testing.T) {
	signer := ghostTestSigner()
	key := ghostTestKey(1)
	to := common.HexToAddress("0x00000000000000000000000000000000000000bb")
	signed := ghostTestSign(t, signer, key, ghostTestTxData(&to))
	if _, err := Sender(signer, signed); err != nil {
		t.Fatalf("the signed transaction does not verify: %v", err)
	}
	other := common.HexToAddress("0x00000000000000000000000000000000000000cc")
	otherKey := ghostTestKey(2).Public().(*mldsa44.PublicKey).Bytes()

	for _, tc := range []struct {
		name   string
		edit   func(tx *GhostAccountTx)
		signer Signer
	}{
		{"chain ID", func(tx *GhostAccountTx) { tx.ChainID = big.NewInt(1338) }, NewGhostAccountSigner(NewCancunSigner(big.NewInt(1338)), ghostTestGenesis)},
		{"nonce", func(tx *GhostAccountTx) { tx.Nonce++ }, nil},
		{"max priority fee", func(tx *GhostAccountTx) { tx.GasTipCap = new(big.Int).Add(tx.GasTipCap, common.Big1) }, nil},
		{"max fee", func(tx *GhostAccountTx) { tx.GasFeeCap = new(big.Int).Add(tx.GasFeeCap, common.Big1) }, nil},
		{"gas limit", func(tx *GhostAccountTx) { tx.Gas++ }, nil},
		{"recipient", func(tx *GhostAccountTx) { tx.To = &other }, nil},
		{"recipient removed", func(tx *GhostAccountTx) { tx.To = nil }, nil},
		{"value", func(tx *GhostAccountTx) { tx.Value = new(big.Int).Add(tx.Value, common.Big1) }, nil},
		{"data", func(tx *GhostAccountTx) { tx.Data = append(common.CopyBytes(tx.Data), 0) }, nil},
		{"access list", func(tx *GhostAccountTx) { tx.AccessList = nil }, nil},
		{"access list key", func(tx *GhostAccountTx) {
			tx.AccessList = AccessList{{Address: tx.AccessList[0].Address, StorageKeys: []common.Hash{common.HexToHash("0x02")}}}
		}, nil},
		{"public key", func(tx *GhostAccountTx) { tx.PublicKey = common.CopyBytes(otherKey) }, nil},
		{"signature", func(tx *GhostAccountTx) {
			tx.Signature = common.CopyBytes(tx.Signature)
			tx.Signature[100] ^= 1
		}, nil},
		{"genesis", func(tx *GhostAccountTx) {}, NewGhostAccountSigner(NewCancunSigner(ghostTestChainID), common.HexToHash("0x01"))},
	} {
		inner := signed.inner.copy().(*GhostAccountTx)
		tc.edit(inner)
		s := tc.signer
		if s == nil {
			s = signer
		}
		_, err := s.Sender(NewTx(inner))
		if !errors.Is(err, ErrGhostAccountSignature) {
			t.Errorf("%s changed: sender error %v, want %v", tc.name, err, ErrGhostAccountSignature)
		}
	}

	// The scheme is in the signed list: changing it changes the hash.
	inner := signed.inner.copy().(*GhostAccountTx)
	inner.Scheme = GhostScheme(GhostSchemeSLHDSA)
	if signer.Hash(NewTx(inner)) == signer.Hash(signed) {
		t.Error("the signature hash does not cover the scheme")
	}
	// The type byte and the genesis hash are in the signature hash.
	unsigned := signed.inner.(*GhostAccountTx).unsignedHash()
	if ghostAccountSigHash(ghostTestGenesis, unsigned) == ghostTaggedHash(GhostAccountTxTag, []byte{GhostDataRevealTxType}, ghostTestGenesis[:], unsigned[:]) {
		t.Error("the signature hash does not cover the type byte")
	}
}

func TestGhostAccountTxRefusesUnknownScheme(t *testing.T) {
	signer := ghostTestSigner()
	for _, tc := range []struct {
		scheme     uint16
		pubKeySize int
		sigSize    int
	}{
		{0x0000, GhostMLDSA44PublicKeySize, GhostMLDSA44SignatureSize},
		{0x0000, GhostSLHDSAPublicKeySize, GhostSLHDSASignatureSize},
		{0x0005, GhostMLDSA44PublicKeySize, GhostMLDSA44SignatureSize},
		{0x0005, GhostSLHDSAPublicKeySize, GhostSLHDSASignatureSize},
		{0xffff, GhostMLDSA44PublicKeySize, GhostMLDSA44SignatureSize},
	} {
		inner := ghostTestTxData(nil)
		inner.Scheme = GhostScheme(tc.scheme)
		inner.PublicKey = bytes.Repeat([]byte{0x5a}, tc.pubKeySize)
		inner.Signature = bytes.Repeat([]byte{0xa5}, tc.sigSize)
		tx := NewTx(inner)

		enc, err := tx.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		var dec Transaction
		if err := dec.UnmarshalBinary(enc); !errors.Is(err, ErrGhostAccountScheme) {
			t.Errorf("scheme %#04x: decoding error %v, want %v", tc.scheme, err, ErrGhostAccountScheme)
		}
		js, err := json.Marshal(tx)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(js, &dec); !errors.Is(err, ErrGhostAccountScheme) {
			t.Errorf("scheme %#04x: JSON decoding error %v, want %v", tc.scheme, err, ErrGhostAccountScheme)
		}

		// The scheme is refused before any verification: the error is the
		// scheme's, not the garbage signature's.
		_, err = signer.Sender(tx)
		if !errors.Is(err, ErrGhostAccountScheme) || errors.Is(err, ErrInvalidSig) {
			t.Errorf("scheme %#04x: sender error %v, want %v", tc.scheme, err, ErrGhostAccountScheme)
		}
		if _, err := GhostAccountAddress(signer, tx); !errors.Is(err, ErrGhostAccountScheme) {
			t.Errorf("scheme %#04x: address error %v, want %v", tc.scheme, err, ErrGhostAccountScheme)
		}
	}
}

// TestGhostAccountTxSignerFailsClosed checks the signers that cannot take an
// account transaction: one without a genesis hash and a plain base signer.
func TestGhostAccountTxSignerFailsClosed(t *testing.T) {
	tx := ghostTestSign(t, ghostTestSigner(), ghostTestKey(1), ghostTestTxData(nil))
	if _, err := NewGhostAccountSigner(NewCancunSigner(ghostTestChainID), common.Hash{}).Sender(tx); !errors.Is(err, ErrGhostAccountGenesis) {
		t.Errorf("signer without genesis: %v, want %v", err, ErrGhostAccountGenesis)
	}
	if _, err := Sender(NewCancunSigner(ghostTestChainID), tx); err == nil {
		t.Error("a signer without the wrapper took an account transaction")
	}
	if _, err := Sender(ghostTestSigner(), tx); err != nil {
		t.Errorf("valid transaction refused: %v", err)
	}
	if _, err := Sender(NewGhostAccountSigner(NewCancunSigner(big.NewInt(1)), ghostTestGenesis), tx); !errors.Is(err, ErrInvalidChainId) {
		t.Errorf("wrong chain ID: %v, want %v", err, ErrInvalidChainId)
	}
}

// BenchmarkGhostAccountTxVerifySlowest is the measurement VERIFY_GAS of
// ML-DSA-44 is set from (spec 09, section 8.2): 1,000 verifications of valid
// signatures and 1,000 of invalid ones, each over a different key and
// transaction, timed one by one. It reports the slowest, t_ms, and the gas it
// gives, ceil(t_ms * 10,000) rounded up to a multiple of 1,000. Run it with
//
//	go test ./core/types/ -run '^$' -bench GhostAccountTxVerifySlowest -benchtime 1x
func BenchmarkGhostAccountTxVerifySlowest(b *testing.B) {
	signer := ghostTestSigner()
	ctx := []byte(GhostAccountTxContext)
	var times []time.Duration
	for n := 0; n < b.N; n++ {
		for round := 0; round < 2; round++ {
			for i := 0; i < 1000; i++ {
				data := ghostTestTxData(nil)
				data.Nonce = uint64(i)
				tx := ghostTestSign(b, signer, ghostTestKey(byte(i)), data)
				inner := tx.inner.(*GhostAccountTx)
				sig := inner.Signature
				if round == 1 {
					sig = common.CopyBytes(sig)
					sig[i%len(sig)] ^= 1
				}
				sighash := ghostAccountSigHash(ghostTestGenesis, inner.unsignedHash())
				start := time.Now()
				var pk mldsa44.PublicKey
				if err := pk.UnmarshalBinary(inner.PublicKey); err != nil {
					b.Fatal(err)
				}
				ok := mldsa44.Verify(&pk, sighash[:], ctx, sig)
				times = append(times, time.Since(start))
				if ok != (round == 0) {
					b.Fatal("unexpected verification result")
				}
			}
		}
	}
	ghostReportSlowest(b, times)
}

// ghostReportSlowest reports the slowest of the timed verifications, t_ms,
// the median and the gas the slowest gives, ceil(t_ms * 10,000) rounded up to
// a multiple of 1,000.
func ghostReportSlowest(b *testing.B, times []time.Duration) {
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
	slowest := float64(times[len(times)-1].Nanoseconds()) / 1e6
	gas := uint64(math.Ceil(slowest * 10_000))
	gas = (gas + 999) / 1000 * 1000
	b.ReportMetric(slowest, "slowest-ms")
	b.ReportMetric(float64(times[len(times)/2].Nanoseconds())/1e6, "median-ms")
	b.ReportMetric(float64(gas), "verify-gas")
	b.Logf("%d verifications on %s/%s, %d CPUs, %s", len(times), runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), runtime.Version())
}

// BenchmarkGhostAccountTxSLHDSAVerifySlowest is the measurement VERIFY_GAS of
// SLH-DSA-SHAKE-128s is set from (spec 09, section 8.2): 1,000 verifications
// of valid signatures and 1,000 of signatures with one bit changed, a
// different bit each time, timed one by one. Signing is slow, so the
// signatures are those of ghostSLHDSATimedKeys keys and transactions, each
// verified in turn. Run it with
//
//	go test ./core/types/ -run '^$' -bench GhostAccountTxSLHDSAVerifySlowest -benchtime 1x
func BenchmarkGhostAccountTxSLHDSAVerifySlowest(b *testing.B) {
	var times []time.Duration
	for n := 0; n < b.N; n++ {
		times = append(times, ghostSLHDSAVerifyTimes(b, ghostSLHDSATimedKeys, 1000)...)
	}
	ghostReportSlowest(b, times)
}

// ghostSLHDSATimedKeys is the number of keys, and signed transactions, of
// the SLH-DSA measurement.
const ghostSLHDSATimedKeys = 10

// ghostSLHDSAVerifyTimes signs one transaction with each of keys SLH-DSA keys
// and times n verifications of valid signatures and n of invalid ones, one by
// one, the public key decoding included.
func ghostSLHDSAVerifyTimes(tb testing.TB, keys, n int) []time.Duration {
	signer := ghostTestSigner()
	ctx := []byte(GhostAccountTxContext)
	txs := make([]*GhostAccountTx, keys)
	for i := range txs {
		data := ghostTestTxData(nil)
		data.Nonce = uint64(i)
		tx, err := SignGhostAccountTxSLHDSA(signer, ghostTestSLHDSAKey(tb, byte(i)), data)
		if err != nil {
			tb.Fatal(err)
		}
		txs[i] = tx.inner.(*GhostAccountTx)
	}
	times := make([]time.Duration, 0, 2*n)
	for round := 0; round < 2; round++ {
		for i := 0; i < n; i++ {
			inner := txs[i%keys]
			sig := inner.Signature
			if round == 1 {
				sig = common.CopyBytes(sig)
				sig[(i*7919)%len(sig)] ^= 1 << (i % 8)
			}
			sighash := ghostAccountSigHash(ghostTestGenesis, inner.unsignedHash())
			start := time.Now()
			pk := slhdsa.PublicKey{ID: slhdsa.SHAKE_128s}
			if err := pk.UnmarshalBinary(inner.PublicKey); err != nil {
				tb.Fatal(err)
			}
			ok := slhdsa.Verify(&pk, slhdsa.NewMessage(sighash[:]), sig, ctx)
			times = append(times, time.Since(start))
			if ok != (round == 0) {
				tb.Fatalf("round %d verification %d: unexpected result %v", round, i, ok)
			}
		}
	}
	return times
}

// ghostTestSLHDSAKey returns the SLH-DSA-SHAKE-128s key whose seeds are all
// the byte seed.
func ghostTestSLHDSAKey(tb testing.TB, seed byte) *slhdsa.PrivateKey {
	tb.Helper()
	_, sk, err := slhdsa.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{seed}, 48)), slhdsa.SHAKE_128s)
	if err != nil {
		tb.Fatal(err)
	}
	return &sk
}

// TestGhostAccountTxSLHDSA checks scheme 0x0002, SLH-DSA-SHAKE-128s in pure
// mode with the context ghost/tx/v1: a signed transaction verifies and keeps
// its sender through the encodings, the signature binds the transaction, the
// genesis and the context, and a key or signature of the other scheme is
// refused by its length before any verification (QS-4).
func TestGhostAccountTxSLHDSA(t *testing.T) {
	if s := slhdsa.SHAKE_128s.Scheme(); s.PublicKeySize() != GhostSLHDSAPublicKeySize || s.SignatureSize() != GhostSLHDSASignatureSize {
		t.Fatalf("SLH-DSA-SHAKE-128s has a %d-byte key and a %d-byte signature, scheme 0x0002 %d and %d",
			s.PublicKeySize(), s.SignatureSize(), GhostSLHDSAPublicKeySize, GhostSLHDSASignatureSize)
	}
	signer := ghostTestSigner()
	key := ghostTestSLHDSAKey(t, 1)
	pub, err := key.PublicKey().MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	to := common.HexToAddress("0x00000000000000000000000000000000000000bb")
	tx, err := SignGhostAccountTxSLHDSA(signer, key, ghostTestTxData(&to))
	if err != nil {
		t.Fatal(err)
	}
	scheme, gotPub, sig, _ := tx.GhostAccountAuth()
	if scheme != GhostSchemeSLHDSA || !bytes.Equal(gotPub, pub) || len(sig) != GhostSLHDSASignatureSize {
		t.Fatalf("signed scheme %#04x, key %d bytes, signature %d bytes", scheme, len(gotPub), len(sig))
	}
	from, err := Sender(signer, tx)
	if err != nil {
		t.Fatalf("sender of the signed transaction: %v", err)
	}
	if want := GhostAccountAddressOf(GhostSchemeSLHDSA, pub); from != want {
		t.Fatalf("sender %v, want %v", from, want)
	}
	if addr, err := GhostAccountAddress(signer, tx); err != nil || addr != from {
		t.Fatalf("address %v %v, want %v", addr, err, from)
	}

	// The signature is pure SLH-DSA (FIPS 205, algorithm 24) over the
	// signature hash with the context ghost/tx/v1, and with no other context.
	sighash := signer.Hash(tx)
	pk := slhdsa.PublicKey{ID: slhdsa.SHAKE_128s}
	if err := pk.UnmarshalBinary(pub); err != nil {
		t.Fatal(err)
	}
	if !slhdsa.Verify(&pk, slhdsa.NewMessage(sighash[:]), sig, []byte("ghost/tx/v1")) {
		t.Fatal("the signature is not SLH-DSA over the signature hash with the context ghost/tx/v1")
	}
	if slhdsa.Verify(&pk, slhdsa.NewMessage(sighash[:]), sig, nil) {
		t.Fatal("the signature verifies without its context")
	}

	// The encodings keep the transaction and its sender.
	enc, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var dec Transaction
	if err := dec.UnmarshalBinary(enc); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if dec.Hash() != tx.Hash() {
		t.Fatal("hash changed in the round trip")
	}
	if from2, err := Sender(signer, &dec); err != nil || from2 != from {
		t.Fatalf("sender after decoding %v %v, want %v", from2, err, from)
	}
	js, err := json.Marshal(tx)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]interface{}
	if err := json.Unmarshal(js, &fields); err != nil {
		t.Fatal(err)
	}
	if fields["scheme"] != "0x2" || fields["publicKey"] != hexutil.Encode(pub) {
		t.Fatalf("JSON scheme %v public key %v", fields["scheme"], fields["publicKey"])
	}
	var dec2 Transaction
	if err := json.Unmarshal(js, &dec2); err != nil || dec2.Hash() != tx.Hash() {
		t.Fatalf("JSON round trip: %v", err)
	}

	// The signature binds the transaction, the genesis and the context, and
	// is not in prehash mode.
	otherContext, err := slhdsa.SignRandomized(key, nil, slhdsa.NewMessage(sighash[:]), []byte("ghost/tx/v2"))
	if err != nil {
		t.Fatal(err)
	}
	preHash, err := slhdsa.NewPreHashWithXof(xof.SHAKE128)
	if err != nil {
		t.Fatal(err)
	}
	preHash.Write(sighash[:])
	preHashMsg, err := preHash.BuildMessage()
	if err != nil {
		t.Fatal(err)
	}
	preHashSig, err := slhdsa.SignRandomized(key, nil, preHashMsg, []byte(GhostAccountTxContext))
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := ghostTestSLHDSAKey(t, 2).PublicKey().MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		edit   func(tx *GhostAccountTx)
		signer Signer
	}{
		{"nonce changed", func(tx *GhostAccountTx) { tx.Nonce++ }, nil},
		{"value changed", func(tx *GhostAccountTx) { tx.Value = new(big.Int).Add(tx.Value, common.Big1) }, nil},
		{"public key changed", func(tx *GhostAccountTx) { tx.PublicKey = common.CopyBytes(otherKey) }, nil},
		{"first signature byte changed", func(tx *GhostAccountTx) {
			tx.Signature = common.CopyBytes(tx.Signature)
			tx.Signature[0] ^= 1
		}, nil},
		{"last signature byte changed", func(tx *GhostAccountTx) {
			tx.Signature = common.CopyBytes(tx.Signature)
			tx.Signature[GhostSLHDSASignatureSize-1] ^= 0x80
		}, nil},
		{"signed with another context", func(tx *GhostAccountTx) { tx.Signature = otherContext }, nil},
		{"signed in prehash mode", func(tx *GhostAccountTx) { tx.Signature = preHashSig }, nil},
		{"another genesis", func(tx *GhostAccountTx) {}, NewGhostAccountSigner(NewCancunSigner(ghostTestChainID), common.HexToHash("0x01"))},
	} {
		inner := tx.inner.copy().(*GhostAccountTx)
		tc.edit(inner)
		s := tc.signer
		if s == nil {
			s = signer
		}
		if _, err := s.Sender(NewTx(inner)); !errors.Is(err, ErrGhostAccountSignature) {
			t.Errorf("%s: sender error %v, want %v", tc.name, err, ErrGhostAccountSignature)
		}
	}

	// Only SLH-DSA-SHAKE-128s keys sign under scheme 0x0002.
	_, fast, err := slhdsa.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{1}, 48)), slhdsa.SHAKE_128f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignGhostAccountTxSLHDSA(signer, &fast, ghostTestTxData(&to)); !errors.Is(err, ErrGhostAccountScheme) {
		t.Errorf("signing with another SLH-DSA parameter set: %v, want %v", err, ErrGhostAccountScheme)
	}

	// QS-4: an ML-DSA-44 key or signature under scheme 0x0002, and an
	// SLH-DSA key or signature under scheme 0x0001, is refused for its length
	// before any verification, when decoded and by the signer.
	mlTx := ghostTestSign(t, signer, ghostTestKey(1), ghostTestTxData(&to))
	_, mlPub, mlSig, _ := mlTx.GhostAccountAuth()
	for _, tc := range []struct {
		name   string
		scheme uint16
		pub    []byte
		sig    []byte
	}{
		{"ML-DSA-44 key and signature under 0x0002", GhostSchemeSLHDSA, mlPub, mlSig},
		{"ML-DSA-44 signature under 0x0002", GhostSchemeSLHDSA, pub, mlSig},
		{"ML-DSA-44 key under 0x0002", GhostSchemeSLHDSA, mlPub, sig},
		{"SLH-DSA key and signature under 0x0001", GhostSchemeMLDSA44, pub, sig},
		{"SLH-DSA signature under 0x0001", GhostSchemeMLDSA44, mlPub, sig},
		{"SLH-DSA key under 0x0001", GhostSchemeMLDSA44, pub, mlSig},
		{"0x0002 key one byte long", GhostSchemeSLHDSA, append(common.CopyBytes(pub), 0), sig},
		{"0x0002 key one byte short", GhostSchemeSLHDSA, pub[:GhostSLHDSAPublicKeySize-1], sig},
		{"0x0002 signature one byte long", GhostSchemeSLHDSA, pub, append(common.CopyBytes(sig), 0)},
		{"0x0002 signature one byte short", GhostSchemeSLHDSA, pub, sig[:GhostSLHDSASignatureSize-1]},
	} {
		inner := tx.inner.copy().(*GhostAccountTx)
		inner.Scheme = GhostScheme(tc.scheme)
		inner.PublicKey = common.CopyBytes(tc.pub)
		inner.Signature = common.CopyBytes(tc.sig)
		bad := NewTx(inner)
		if _, err := signer.Sender(bad); !errors.Is(err, ErrGhostAccountLength) || errors.Is(err, ErrInvalidSig) {
			t.Errorf("%s: sender error %v, want %v", tc.name, err, ErrGhostAccountLength)
		}
		if _, err := GhostAccountAddress(signer, bad); !errors.Is(err, ErrGhostAccountLength) {
			t.Errorf("%s: address error %v, want %v", tc.name, err, ErrGhostAccountLength)
		}
		enc, err := bad.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		var dec Transaction
		if err := dec.UnmarshalBinary(enc); !errors.Is(err, ErrGhostAccountLength) {
			t.Errorf("%s: decoding error %v, want %v", tc.name, err, ErrGhostAccountLength)
		}
	}
}

// ghostTestRescueKeys returns the ML-DSA-44 and SLH-DSA-SHAKE-128s keys of a
// rescue-key account and its 1,344-byte public key.
func ghostTestRescueKeys(t testing.TB, seed byte) (*mldsa44.PrivateKey, *slhdsa.PrivateKey, []byte) {
	t.Helper()
	mlKey := ghostTestKey(seed)
	slhKey := ghostTestSLHDSAKey(t, seed)
	slhPub, err := slhKey.PublicKey().MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	pk := GhostRescuePublicKey(mlKey.Public().(*mldsa44.PublicKey).Bytes(), slhPub)
	if len(pk) != GhostRescuePublicKeySize || GhostRescuePublicKeySize != 1344 {
		t.Fatalf("rescue public key of %d bytes, want 1344", len(pk))
	}
	return mlKey, slhKey, pk
}

// ghostTestRescueTxs signs the same transaction data as scheme 0x0003 and as
// scheme 0x0004 with the keys of one rescue-key account.
func ghostTestRescueTxs(t testing.TB, signer Signer, mlKey *mldsa44.PrivateKey, slhKey *slhdsa.PrivateKey, pk []byte, txdata *GhostAccountTx) (tx3, tx4 *Transaction) {
	t.Helper()
	tx3, err := SignGhostAccountTxRescue(signer, mlKey, pk[GhostMLDSA44PublicKeySize:], txdata)
	if err != nil {
		t.Fatalf("signing scheme 0x0003: %v", err)
	}
	tx4, err = SignGhostAccountTxRescueSLHDSA(signer, pk[:GhostMLDSA44PublicKeySize], slhKey, txdata)
	if err != nil {
		t.Fatalf("signing scheme 0x0004: %v", err)
	}
	return tx3, tx4
}

// ghostRescueTx returns a copy of tx with the scheme, public key and
// signature replaced.
func ghostRescueTx(tx *Transaction, scheme uint16, pub, sig []byte) *Transaction {
	inner := tx.inner.copy().(*GhostAccountTx)
	inner.Scheme = GhostScheme(scheme)
	inner.PublicKey = common.CopyBytes(pub)
	inner.Signature = common.CopyBytes(sig)
	return NewTx(inner)
}

// TestGhostRescueSenderIsOneAccount checks that schemes 0x0003 and 0x0004
// over one rescue public key name one account, the address derived with
// scheme 0x0003, and that it is not the account of the ML-DSA-44 key alone.
func TestGhostRescueSenderIsOneAccount(t *testing.T) {
	signer := ghostTestSigner()
	mlKey, slhKey, pk := ghostTestRescueKeys(t, 1)
	to := common.HexToAddress("0x00000000000000000000000000000000000000bb")
	tx3, tx4 := ghostTestRescueTxs(t, signer, mlKey, slhKey, pk, ghostTestTxData(&to))

	for _, tc := range []struct {
		tx      *Transaction
		scheme  uint16
		sigSize int
	}{{tx3, GhostSchemeMLDSA44Rescue, GhostMLDSA44SignatureSize}, {tx4, GhostSchemeSLHDSARescue, GhostSLHDSASignatureSize}} {
		scheme, pub, sig, _ := tc.tx.GhostAccountAuth()
		if scheme != tc.scheme || !bytes.Equal(pub, pk) || len(sig) != tc.sigSize {
			t.Fatalf("signed scheme %#04x, key %d bytes, signature %d bytes; want %#04x, 1344 and %d", scheme, len(pub), len(sig), tc.scheme, tc.sigSize)
		}
	}
	from3, err := Sender(signer, tx3)
	if err != nil {
		t.Fatalf("sender of the 0x0003 transaction: %v", err)
	}
	from4, err := Sender(signer, tx4)
	if err != nil {
		t.Fatalf("sender of the 0x0004 transaction: %v", err)
	}
	want := GhostAccountAddressOf(GhostSchemeMLDSA44Rescue, pk)
	if from3 != want || from4 != want {
		t.Fatalf("senders %v (0x0003) and %v (0x0004), want both %v", from3, from4, want)
	}
	if got := GhostAccountAddressOf(GhostSchemeSLHDSARescue, pk); got != want {
		t.Fatalf("address of scheme 0x0004 %v, want the 0x0003 address %v", got, want)
	}
	id := GhostScheme(GhostSchemeMLDSA44Rescue)
	if h := ghostTaggedHash(GhostAccountAddressTag, id[:], pk); common.BytesToAddress(h[:common.AddressLength]) != want {
		t.Fatal("the rescue address is not K(ghost/account-address/v1, 0x0003, public_key)")
	}
	if plain := GhostAccountAddressOf(GhostSchemeMLDSA44, pk[:GhostMLDSA44PublicKeySize]); plain == want {
		t.Fatal("the rescue account is the account of its ML-DSA-44 key under scheme 0x0001")
	}
	for name, tx := range map[string]*Transaction{"0x0003": tx3, "0x0004": tx4} {
		if addr, err := GhostAccountAddress(signer, tx); err != nil || addr != want {
			t.Errorf("%s: address %v %v, want %v", name, addr, err, want)
		}
		enc, err := tx.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		var dec Transaction
		if err := dec.UnmarshalBinary(enc); err != nil {
			t.Fatalf("%s: decoding: %v", name, err)
		}
		if from, err := Sender(signer, &dec); err != nil || from != want {
			t.Errorf("%s: sender after decoding %v %v, want %v", name, from, err, want)
		}
		js, err := json.Marshal(tx)
		if err != nil {
			t.Fatal(err)
		}
		var decJSON Transaction
		if err := json.Unmarshal(js, &decJSON); err != nil || decJSON.Hash() != tx.Hash() {
			t.Errorf("%s: JSON round trip: %v", name, err)
		}
	}
}

// TestGhostRescueCrossSchemeSignatureRefused checks that each rescue scheme
// verifies with its own algorithm only: the signature of one scheme under the
// other is refused for its length before any verification, and a signature
// of the right length but of the other scheme's sighash, or of the other
// algorithm padded to length, does not verify.
func TestGhostRescueCrossSchemeSignatureRefused(t *testing.T) {
	signer := ghostTestSigner()
	mlKey, slhKey, pk := ghostTestRescueKeys(t, 1)
	to := common.HexToAddress("0x00000000000000000000000000000000000000bb")
	tx3, tx4 := ghostTestRescueTxs(t, signer, mlKey, slhKey, pk, ghostTestTxData(&to))
	_, _, mlSig, _ := tx3.GhostAccountAuth()
	_, _, slhSig, _ := tx4.GhostAccountAuth()

	// The signature of one scheme under the other: refused for its length.
	for _, tc := range []struct {
		name   string
		scheme uint16
		sig    []byte
	}{
		{"ML-DSA-44 signature under 0x0004", GhostSchemeSLHDSARescue, mlSig},
		{"SLH-DSA signature under 0x0003", GhostSchemeMLDSA44Rescue, slhSig},
	} {
		bad := ghostRescueTx(tx3, tc.scheme, pk, tc.sig)
		if _, err := signer.Sender(bad); !errors.Is(err, ErrGhostAccountLength) || errors.Is(err, ErrInvalidSig) {
			t.Errorf("%s: sender error %v, want %v before any verification", tc.name, err, ErrGhostAccountLength)
		}
		if _, err := GhostAccountAddress(signer, bad); !errors.Is(err, ErrGhostAccountLength) {
			t.Errorf("%s: address error %v, want %v", tc.name, err, ErrGhostAccountLength)
		}
		enc, err := bad.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		var dec Transaction
		if err := dec.UnmarshalBinary(enc); !errors.Is(err, ErrGhostAccountLength) {
			t.Errorf("%s: decoding error %v, want %v", tc.name, err, ErrGhostAccountLength)
		}
	}

	// Signatures of the right length that are not of the scheme's own
	// algorithm over its own sighash: refused by the verifier.
	sighash3 := signer.Hash(tx3)
	sighash4 := signer.Hash(tx4)
	if sighash3 == sighash4 {
		t.Fatal("the sighash does not cover the scheme")
	}
	ctx := []byte(GhostAccountTxContext)
	mlOver4 := make([]byte, mldsa44.SignatureSize)
	if err := mldsa44.SignTo(mlKey, sighash4[:], ctx, true, mlOver4); err != nil {
		t.Fatal(err)
	}
	slhOver3, err := slhdsa.SignRandomized(slhKey, nil, slhdsa.NewMessage(sighash3[:]), ctx)
	if err != nil {
		t.Fatal(err)
	}
	padded := append(common.CopyBytes(mlOver4), make([]byte, GhostSLHDSASignatureSize-GhostMLDSA44SignatureSize)...)
	for _, tc := range []struct {
		name   string
		scheme uint16
		sig    []byte
	}{
		{"ML-DSA-44 signature of the 0x0004 sighash, padded, under 0x0004", GhostSchemeSLHDSARescue, padded},
		{"SLH-DSA signature of the 0x0004 sighash, cut, under 0x0003", GhostSchemeMLDSA44Rescue, slhSig[:GhostMLDSA44SignatureSize]},
		{"ML-DSA-44 signature of the 0x0004 sighash under 0x0003", GhostSchemeMLDSA44Rescue, mlOver4},
		{"SLH-DSA signature of the 0x0003 sighash under 0x0004", GhostSchemeSLHDSARescue, slhOver3},
	} {
		bad := ghostRescueTx(tx3, tc.scheme, pk, tc.sig)
		if _, err := signer.Sender(bad); !errors.Is(err, ErrGhostAccountSignature) {
			t.Errorf("%s: sender error %v, want %v", tc.name, err, ErrGhostAccountSignature)
		}
	}

	// Each scheme verifies under its own half of the public key: the right
	// sighash signed by keys that are not the account's halves is refused.
	otherML, otherSLH, _ := ghostTestRescueKeys(t, 2)
	otherMLSig := make([]byte, mldsa44.SignatureSize)
	if err := mldsa44.SignTo(otherML, sighash3[:], ctx, true, otherMLSig); err != nil {
		t.Fatal(err)
	}
	if _, err := signer.Sender(ghostRescueTx(tx3, GhostSchemeMLDSA44Rescue, pk, otherMLSig)); !errors.Is(err, ErrGhostAccountSignature) {
		t.Errorf("0x0003 signed by a key that is not its ML-DSA-44 half: %v, want %v", err, ErrGhostAccountSignature)
	}
	otherSLHSig, err := slhdsa.SignRandomized(otherSLH, nil, slhdsa.NewMessage(sighash4[:]), ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.Sender(ghostRescueTx(tx4, GhostSchemeSLHDSARescue, pk, otherSLHSig)); !errors.Is(err, ErrGhostAccountSignature) {
		t.Errorf("0x0004 signed by a key that is not its SLH-DSA half: %v, want %v", err, ErrGhostAccountSignature)
	}
	// The untouched transactions verify.
	for name, tx := range map[string]*Transaction{"0x0003": tx3, "0x0004": tx4} {
		if _, err := signer.Sender(tx); err != nil {
			t.Errorf("%s: valid transaction refused: %v", name, err)
		}
	}
}

// TestGhostRescueRefusesWrongLengths checks that a rescue scheme takes only
// its exact lengths, a 1,344-byte key and its signature length, in the
// binary and JSON decoders and the signer, before any verification.
func TestGhostRescueRefusesWrongLengths(t *testing.T) {
	signer := ghostTestSigner()
	key := bytes.Repeat([]byte{0x5a}, GhostRescuePublicKeySize)
	mlSig := bytes.Repeat([]byte{0xa5}, GhostMLDSA44SignatureSize)
	slhSig := bytes.Repeat([]byte{0xa5}, GhostSLHDSASignatureSize)
	base := NewTx(ghostTestTxData(nil))
	for _, tc := range []struct {
		name   string
		scheme uint16
		pub    []byte
		sig    []byte
	}{
		{"0x0003 with a 1,312-byte key", GhostSchemeMLDSA44Rescue, key[:GhostMLDSA44PublicKeySize], mlSig},
		{"0x0003 with a 32-byte key", GhostSchemeMLDSA44Rescue, key[:GhostSLHDSAPublicKeySize], mlSig},
		{"0x0003 with a 1,343-byte key", GhostSchemeMLDSA44Rescue, key[:GhostRescuePublicKeySize-1], mlSig},
		{"0x0003 with a 1,345-byte key", GhostSchemeMLDSA44Rescue, append(common.CopyBytes(key), 0), mlSig},
		{"0x0003 with a 7,856-byte signature", GhostSchemeMLDSA44Rescue, key, slhSig},
		{"0x0003 with a signature one byte short", GhostSchemeMLDSA44Rescue, key, mlSig[:GhostMLDSA44SignatureSize-1]},
		{"0x0003 with a signature one byte long", GhostSchemeMLDSA44Rescue, key, append(common.CopyBytes(mlSig), 0)},
		{"0x0004 with a 1,312-byte key", GhostSchemeSLHDSARescue, key[:GhostMLDSA44PublicKeySize], slhSig},
		{"0x0004 with a 32-byte key", GhostSchemeSLHDSARescue, key[:GhostSLHDSAPublicKeySize], slhSig},
		{"0x0004 with a 1,343-byte key", GhostSchemeSLHDSARescue, key[:GhostRescuePublicKeySize-1], slhSig},
		{"0x0004 with a 1,345-byte key", GhostSchemeSLHDSARescue, append(common.CopyBytes(key), 0), slhSig},
		{"0x0004 with a 2,420-byte signature", GhostSchemeSLHDSARescue, key, mlSig},
		{"0x0004 with a signature one byte short", GhostSchemeSLHDSARescue, key, slhSig[:GhostSLHDSASignatureSize-1]},
		{"0x0004 with a signature one byte long", GhostSchemeSLHDSARescue, key, append(common.CopyBytes(slhSig), 0)},
	} {
		bad := ghostRescueTx(base, tc.scheme, tc.pub, tc.sig)
		enc, err := bad.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		var dec Transaction
		if err := dec.UnmarshalBinary(enc); !errors.Is(err, ErrGhostAccountLength) {
			t.Errorf("%s: decoding error %v, want %v", tc.name, err, ErrGhostAccountLength)
		}
		js, err := json.Marshal(bad)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(js, &dec); !errors.Is(err, ErrGhostAccountLength) {
			t.Errorf("%s: JSON decoding error %v, want %v", tc.name, err, ErrGhostAccountLength)
		}
		if _, err := signer.Sender(bad); !errors.Is(err, ErrGhostAccountLength) || errors.Is(err, ErrInvalidSig) {
			t.Errorf("%s: sender error %v, want %v before any verification", tc.name, err, ErrGhostAccountLength)
		}
		if _, err := GhostAccountAddress(signer, bad); !errors.Is(err, ErrGhostAccountLength) {
			t.Errorf("%s: address error %v, want %v", tc.name, err, ErrGhostAccountLength)
		}
	}
	// The exact lengths pass the shape checks and reach the verifier.
	for _, tc := range []struct {
		scheme uint16
		sig    []byte
	}{{GhostSchemeMLDSA44Rescue, mlSig}, {GhostSchemeSLHDSARescue, slhSig}} {
		if _, err := signer.Sender(ghostRescueTx(base, tc.scheme, key, tc.sig)); !errors.Is(err, ErrGhostAccountSignature) {
			t.Errorf("scheme %#04x with its exact lengths: %v, want %v", tc.scheme, err, ErrGhostAccountSignature)
		}
	}
	// The signing helpers refuse a partner key of the wrong length.
	mlKey, slhKey, pk := ghostTestRescueKeys(t, 1)
	if _, err := SignGhostAccountTxRescue(signer, mlKey, pk, ghostTestTxData(nil)); !errors.Is(err, ErrGhostAccountLength) {
		t.Errorf("signing 0x0003 with a 1,344-byte SLH-DSA key: %v, want %v", err, ErrGhostAccountLength)
	}
	if _, err := SignGhostAccountTxRescueSLHDSA(signer, pk, slhKey, ghostTestTxData(nil)); !errors.Is(err, ErrGhostAccountLength) {
		t.Errorf("signing 0x0004 with a 1,344-byte ML-DSA-44 key: %v, want %v", err, ErrGhostAccountLength)
	}
}

// TestGhostRescueRefusesUnassignedSchemes checks that the IDs after the
// rescue schemes stay unassigned: 0x0005 and 0xffff with the lengths of a
// rescue scheme are refused for their scheme.
func TestGhostRescueRefusesUnassignedSchemes(t *testing.T) {
	signer := ghostTestSigner()
	key := bytes.Repeat([]byte{0x5a}, GhostRescuePublicKeySize)
	base := NewTx(ghostTestTxData(nil))
	for _, scheme := range []uint16{0x0005, 0xffff} {
		for _, sigSize := range []int{GhostMLDSA44SignatureSize, GhostSLHDSASignatureSize} {
			bad := ghostRescueTx(base, scheme, key, bytes.Repeat([]byte{0xa5}, sigSize))
			enc, err := bad.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			var dec Transaction
			if err := dec.UnmarshalBinary(enc); !errors.Is(err, ErrGhostAccountScheme) {
				t.Errorf("scheme %#04x, %d-byte signature: decoding error %v, want %v", scheme, sigSize, err, ErrGhostAccountScheme)
			}
			js, err := json.Marshal(bad)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(js, &dec); !errors.Is(err, ErrGhostAccountScheme) {
				t.Errorf("scheme %#04x, %d-byte signature: JSON decoding error %v, want %v", scheme, sigSize, err, ErrGhostAccountScheme)
			}
			if _, err := signer.Sender(bad); !errors.Is(err, ErrGhostAccountScheme) || errors.Is(err, ErrInvalidSig) {
				t.Errorf("scheme %#04x, %d-byte signature: sender error %v, want %v", scheme, sigSize, err, ErrGhostAccountScheme)
			}
			if _, err := GhostAccountAddress(signer, bad); !errors.Is(err, ErrGhostAccountScheme) {
				t.Errorf("scheme %#04x, %d-byte signature: address error %v, want %v", scheme, sigSize, err, ErrGhostAccountScheme)
			}
		}
	}
	// ghostVerify itself knows no other scheme.
	for _, scheme := range []uint16{0x0000, 0x0005, 0xffff} {
		if err := ghostVerify(scheme, key, common.Hash{}, make([]byte, GhostSLHDSASignatureSize)); !errors.Is(err, ErrGhostAccountScheme) {
			t.Errorf("verifying scheme %#04x: %v, want %v", scheme, err, ErrGhostAccountScheme)
		}
	}
}

// BenchmarkGhostAccountTxVerify measures one ML-DSA-44 verification of an
// account transaction's signature, the work VERIFY_GAS pays for
// (docs/account-transactions.md).
func BenchmarkGhostAccountTxVerify(b *testing.B) {
	key := ghostTestKey(1)
	tx := ghostTestSign(b, ghostTestSigner(), key, ghostTestTxData(nil))
	inner := tx.inner.(*GhostAccountTx)
	sighash := ghostAccountSigHash(ghostTestGenesis, inner.unsignedHash())
	ctx := []byte(GhostAccountTxContext)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var pk mldsa44.PublicKey
		if err := pk.UnmarshalBinary(inner.PublicKey); err != nil {
			b.Fatal(err)
		}
		if !mldsa44.Verify(&pk, sighash[:], ctx, inner.Signature) {
			b.Fatal("signature does not verify")
		}
	}
}
