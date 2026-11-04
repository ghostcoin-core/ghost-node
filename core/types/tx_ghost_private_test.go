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
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
)

func testRevealEnvelope() []byte {
	env := make([]byte, GhostRevealEnvelopeSize)
	env[0] = GhostRevealTxType
	for i := 1; i < 400; i++ {
		env[i] = byte(i)
	}
	env[GhostRevealEnvelopeSize-1] = 0xee
	return env
}

func testDataRevealEnvelope() []byte {
	env := make([]byte, GhostDataRevealEnvelopeSize)
	env[0] = GhostDataRevealTxType
	for i := 1; i < 400; i++ {
		env[i] = byte(i)
	}
	env[GhostDataRevealEnvelopeSize-1] = 0xee
	return env
}

// TestRevealSizesAndGas pins the ordinary reveal's version 2 payload, with
// its 380-byte note, and its gas G_PRIV, and the data reveal's own payload,
// which keeps its 156-byte note slot, and its own gas G_DATA.
func TestRevealSizesAndGas(t *testing.T) {
	if GhostRevealPayloadSize != 1_311_290 || GhostRevealEnvelopeSize != 1_311_291 {
		t.Errorf("coin reveal payload %d, envelope %d", GhostRevealPayloadSize, GhostRevealEnvelopeSize)
	}
	if GhostDataRevealPayloadSize != 1_311_066 || GhostDataRevealEnvelopeSize != 1_311_067 {
		t.Errorf("data reveal payload %d, envelope %d", GhostDataRevealPayloadSize, GhostDataRevealEnvelopeSize)
	}
	if GhostRevealGas != 21_371_656 {
		t.Errorf("G_PRIV %d", GhostRevealGas)
	}
	if 16*GhostRevealEnvelopeSize+21_000+370_000 != 21_371_656 {
		t.Errorf("G_PRIV is not 16 per envelope byte, 21,000 and 370,000")
	}
	if GhostDataRevealGas != 21_090_372 {
		t.Errorf("G_DATA %d", GhostDataRevealGas)
	}
	if 16*GhostDataRevealEnvelopeSize+21_000+92_300 != 21_090_372 {
		t.Errorf("G_DATA is not 16 per envelope byte, 21,000 and 92,300")
	}
}

// TestPrivateTxRoundTrip wraps a reveal envelope into a transaction and
// checks its hash, size and every encoding round trip, that it has no sender
// under any signer, and that its receipt round-trips as a typed receipt.
func TestPrivateTxRoundTrip(t *testing.T) {
	env := testRevealEnvelope()
	tx, err := NewGhostRevealTx(env)
	if err != nil {
		t.Fatal(err)
	}
	env[5] ^= 0xff // the transaction holds its own copy
	env[5] ^= 0xff

	if tx.Type() != GhostRevealTxType {
		t.Fatalf("type %#x", tx.Type())
	}
	if want := crypto.Keccak256Hash(env); tx.Hash() != want {
		t.Fatalf("hash %x, want keccak256(0x50 || payload) %x", tx.Hash(), want)
	}
	if tx.Size() != GhostRevealEnvelopeSize {
		t.Fatalf("size %d, want %d", tx.Size(), GhostRevealEnvelopeSize)
	}
	if tx.Gas() != GhostRevealGas || tx.To() != nil || tx.Nonce() != 0 || tx.Value().Sign() != 0 {
		t.Fatalf("unexpected fields: gas %d to %v nonce %d value %v", tx.Gas(), tx.To(), tx.Nonce(), tx.Value())
	}
	if !bytes.Equal(tx.GhostRevealEnvelope(), env) {
		t.Fatal("envelope differs")
	}

	// Binary.
	bin, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bin, env) {
		t.Fatal("MarshalBinary is not the envelope")
	}
	var dec Transaction
	if err := dec.UnmarshalBinary(bin); err != nil {
		t.Fatal(err)
	}
	if dec.Hash() != tx.Hash() || !bytes.Equal(dec.GhostRevealEnvelope(), env) {
		t.Fatal("binary round trip changed the transaction")
	}

	// RLP, alone and in a list as in a block body.
	enc, err := rlp.EncodeToBytes(tx)
	if err != nil {
		t.Fatal(err)
	}
	var fromRLP Transaction
	if err := rlp.DecodeBytes(enc, &fromRLP); err != nil {
		t.Fatal(err)
	}
	if fromRLP.Hash() != tx.Hash() {
		t.Fatal("RLP round trip changed the hash")
	}
	list, err := rlp.EncodeToBytes(Transactions{tx})
	if err != nil {
		t.Fatal(err)
	}
	var txs Transactions
	if err := rlp.DecodeBytes(list, &txs); err != nil || len(txs) != 1 || txs[0].Hash() != tx.Hash() {
		t.Fatalf("list round trip: %v", err)
	}

	// JSON.
	js, err := json.Marshal(tx)
	if err != nil {
		t.Fatal(err)
	}
	var fromJSON Transaction
	if err := json.Unmarshal(js, &fromJSON); err != nil {
		t.Fatal(err)
	}
	if fromJSON.Hash() != tx.Hash() {
		t.Fatal("JSON round trip changed the hash")
	}

	// No sender under any signer, and no signature.
	for _, signer := range []Signer{
		NewCancunSigner(big.NewInt(1)), NewEIP1559Signer(big.NewInt(1)), NewEIP2930Signer(big.NewInt(1)),
		NewEIP155Signer(big.NewInt(1)), HomesteadSigner{}, FrontierSigner{},
	} {
		if addr, err := Sender(signer, tx); !errors.Is(err, ErrNoSender) || addr != (common.Address{}) {
			t.Errorf("%T: sender %x, error %v", signer, addr, err)
		}
		if _, err := signer.Sender(tx); err == nil {
			t.Errorf("%T: signer gave a sender", signer)
		}
	}
	key, _ := crypto.GenerateKey()
	if _, err := SignTx(tx, NewCancunSigner(big.NewInt(1)), key); err == nil {
		t.Error("a reveal was signed")
	}

	// Wrong envelopes.
	for name, bad := range map[string][]byte{
		"empty":      {},
		"type only":  {GhostRevealTxType},
		"short":      env[:len(env)-1],
		"long":       append(append([]byte{}, env...), 0),
		"other type": append([]byte{DynamicFeeTxType}, env[1:]...),
	} {
		if _, err := NewGhostRevealTx(bad); err == nil {
			t.Errorf("%s envelope accepted", name)
		}
		if name != "empty" && name != "other type" {
			var d Transaction
			if err := d.UnmarshalBinary(bad); err == nil {
				t.Errorf("%s envelope decoded", name)
			}
		}
	}

	// The receipt: typed, status 1, cumulative gas and one log.
	r := &Receipt{
		Type:              GhostRevealTxType,
		Status:            ReceiptStatusSuccessful,
		CumulativeGasUsed: GhostRevealGas,
		Logs:              []*Log{{Address: common.Address{1}, Topics: []common.Hash{{2}, {3}}, Data: []byte{4}}},
	}
	r.Bloom = CreateBloom(Receipts{r})
	rbin, err := r.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if rbin[0] != GhostRevealTxType {
		t.Fatalf("receipt type byte %#x", rbin[0])
	}
	var rdec Receipt
	if err := rdec.UnmarshalBinary(rbin); err != nil {
		t.Fatal(err)
	}
	if rdec.Type != GhostRevealTxType || rdec.Status != ReceiptStatusSuccessful || rdec.CumulativeGasUsed != GhostRevealGas || len(rdec.Logs) != 1 {
		t.Fatalf("receipt round trip: %+v", rdec)
	}
	renc, err := rlp.EncodeToBytes(r)
	if err != nil {
		t.Fatal(err)
	}
	var rfromRLP Receipt
	if err := rlp.DecodeBytes(renc, &rfromRLP); err != nil || rfromRLP.Type != GhostRevealTxType {
		t.Fatalf("receipt RLP round trip: %v", err)
	}
	var buf bytes.Buffer
	Receipts{r}.EncodeIndex(0, &buf)
	if !bytes.Equal(buf.Bytes(), rbin) {
		t.Fatal("receipt trie encoding differs from the binary encoding")
	}

	// Derived fields: no contract address, no sender needed.
	rs := Receipts{{Type: GhostRevealTxType, Status: ReceiptStatusSuccessful, CumulativeGasUsed: GhostRevealGas}}
	if err := rs.DeriveFields(params.TestChainConfig, common.Hash{9}, 4, 0, big.NewInt(7), nil, Transactions{tx}); err != nil {
		t.Fatal(err)
	}
	if rs[0].ContractAddress != (common.Address{}) || rs[0].GasUsed != GhostRevealGas || rs[0].TxHash != tx.Hash() {
		t.Fatalf("derived fields: %+v", rs[0])
	}
}

// TestGhostDataRevealTxRoundTrip wraps a data reveal envelope, type 0x51 of
// its own size, into a transaction and checks its hash, size and every
// encoding round trip, that it has no sender, that it is never taken for a
// coin reveal or the other way round, and its typed receipt.
func TestGhostDataRevealTxRoundTrip(t *testing.T) {
	env := testDataRevealEnvelope()
	tx, err := NewGhostDataRevealTx(env)
	if err != nil {
		t.Fatal(err)
	}
	if tx.Type() != GhostDataRevealTxType || !tx.IsGhostReveal() {
		t.Fatalf("type %#x", tx.Type())
	}
	if want := crypto.Keccak256Hash(env); tx.Hash() != want {
		t.Fatalf("hash %x, want keccak256(0x51 || payload) %x", tx.Hash(), want)
	}
	if tx.Size() != GhostDataRevealEnvelopeSize {
		t.Fatalf("size %d, want %d", tx.Size(), GhostDataRevealEnvelopeSize)
	}
	if tx.Gas() != GhostDataRevealGas || tx.To() != nil || tx.Nonce() != 0 || tx.Value().Sign() != 0 || tx.GasPrice().Sign() != 0 {
		t.Fatalf("unexpected fields: gas %d to %v nonce %d value %v", tx.Gas(), tx.To(), tx.Nonce(), tx.Value())
	}
	if !bytes.Equal(tx.GhostDataRevealEnvelope(), env) {
		t.Fatal("envelope differs")
	}
	if tx.GhostRevealEnvelope() != nil {
		t.Fatal("a data reveal gave a coin reveal envelope")
	}

	// A version 2 coin reveal is another transaction, of another size: it
	// does not wrap as a data reveal, whatever its type byte, and a data
	// reveal envelope does not wrap as a coin reveal.
	coinEnv := testRevealEnvelope()
	coinTx, err := NewGhostRevealTx(coinEnv)
	if err != nil {
		t.Fatal(err)
	}
	if coinTx.Hash() == tx.Hash() {
		t.Fatal("a coin reveal and a data reveal share a hash")
	}
	if coinTx.GhostDataRevealEnvelope() != nil {
		t.Fatal("a coin reveal gave a data reveal envelope")
	}
	if _, err := NewGhostDataRevealTx(coinEnv); err == nil {
		t.Fatal("a coin reveal envelope wrapped as a data reveal")
	}
	if _, err := NewGhostDataRevealTx(append([]byte{GhostDataRevealTxType}, coinEnv[1:]...)); err == nil {
		t.Fatal("a coin-sized envelope wrapped as a data reveal")
	}
	if _, err := NewGhostRevealTx(env); err == nil {
		t.Fatal("a data reveal envelope wrapped as a coin reveal")
	}
	// A data-sized payload under the coin type byte has the length of the
	// version 1 coin reveal: it wraps as a coin reveal of that layout, with
	// its own gas and a hash of its own, and its version and fields are
	// checked when a block includes it.
	v1Tx, err := NewGhostRevealTx(append([]byte{GhostRevealTxType}, env[1:]...))
	if err != nil {
		t.Fatalf("a version 1 sized coin envelope: %v", err)
	}
	if v1Tx.Type() != GhostRevealTxType || v1Tx.Size() != GhostRevealV1EnvelopeSize || v1Tx.Gas() != GhostRevealV1Gas || v1Tx.Hash() == tx.Hash() {
		t.Fatalf("version 1 coin reveal: type %#x size %d gas %d", v1Tx.Type(), v1Tx.Size(), v1Tx.Gas())
	}
	if v1Tx.GhostDataRevealEnvelope() != nil || tx.GhostRevealEnvelope() != nil {
		t.Fatal("one type gave the other's envelope")
	}
	for _, n := range []int{GhostRevealV1EnvelopeSize - 1, GhostRevealV1EnvelopeSize + 1, GhostRevealEnvelopeSize + 1} {
		e := make([]byte, n)
		e[0] = GhostRevealTxType
		if _, err := NewGhostRevealTx(e); !errors.Is(err, ErrGhostRevealLength) {
			t.Fatalf("a coin envelope of %d bytes: %v", n, err)
		}
	}

	// Binary.
	bin, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bin, env) {
		t.Fatal("MarshalBinary is not the envelope")
	}
	var dec Transaction
	if err := dec.UnmarshalBinary(bin); err != nil {
		t.Fatal(err)
	}
	if dec.Type() != GhostDataRevealTxType || dec.Hash() != tx.Hash() || !bytes.Equal(dec.GhostDataRevealEnvelope(), env) {
		t.Fatal("binary round trip changed the transaction")
	}

	// RLP, alone and in a list with a coin reveal as in a block body.
	enc, err := rlp.EncodeToBytes(tx)
	if err != nil {
		t.Fatal(err)
	}
	var fromRLP Transaction
	if err := rlp.DecodeBytes(enc, &fromRLP); err != nil {
		t.Fatal(err)
	}
	if fromRLP.Hash() != tx.Hash() || fromRLP.Type() != GhostDataRevealTxType {
		t.Fatal("RLP round trip changed the transaction")
	}
	list, err := rlp.EncodeToBytes(Transactions{tx, coinTx})
	if err != nil {
		t.Fatal(err)
	}
	var txs Transactions
	if err := rlp.DecodeBytes(list, &txs); err != nil || len(txs) != 2 || txs[0].Hash() != tx.Hash() || txs[1].Hash() != coinTx.Hash() {
		t.Fatalf("list round trip: %v", err)
	}
	if txs[0].Type() != GhostDataRevealTxType || txs[1].Type() != GhostRevealTxType {
		t.Fatal("list round trip changed the types")
	}

	// JSON.
	js, err := json.Marshal(tx)
	if err != nil {
		t.Fatal(err)
	}
	var fromJSON Transaction
	if err := json.Unmarshal(js, &fromJSON); err != nil {
		t.Fatal(err)
	}
	if fromJSON.Hash() != tx.Hash() || fromJSON.Type() != GhostDataRevealTxType {
		t.Fatal("JSON round trip changed the transaction")
	}

	// No sender under any signer, and no signature.
	for _, signer := range []Signer{
		NewCancunSigner(big.NewInt(1)), NewEIP1559Signer(big.NewInt(1)), NewEIP2930Signer(big.NewInt(1)),
		NewEIP155Signer(big.NewInt(1)), HomesteadSigner{}, FrontierSigner{},
	} {
		if addr, err := Sender(signer, tx); !errors.Is(err, ErrNoSender) || addr != (common.Address{}) {
			t.Errorf("%T: sender %x, error %v", signer, addr, err)
		}
		if _, err := signer.Sender(tx); err == nil {
			t.Errorf("%T: signer gave a sender", signer)
		}
	}
	key, _ := crypto.GenerateKey()
	if _, err := SignTx(tx, NewCancunSigner(big.NewInt(1)), key); err == nil {
		t.Error("a data reveal was signed")
	}

	// Wrong envelopes.
	for name, bad := range map[string][]byte{
		"empty":     {},
		"type only": {GhostDataRevealTxType},
		"short":     env[:len(env)-1],
		"long":      append(append([]byte{}, env...), 0),
	} {
		if _, err := NewGhostDataRevealTx(bad); err == nil {
			t.Errorf("%s envelope accepted", name)
		}
		if name != "empty" {
			var d Transaction
			if err := d.UnmarshalBinary(bad); err == nil {
				t.Errorf("%s envelope decoded", name)
			}
		}
	}

	// The receipt: typed 0x51, status 1, cumulative gas and one log.
	r := &Receipt{
		Type:              GhostDataRevealTxType,
		Status:            ReceiptStatusSuccessful,
		CumulativeGasUsed: GhostDataRevealGas,
		Logs:              []*Log{{Address: common.Address{1}, Topics: []common.Hash{{2}, {3}}, Data: []byte{4}}},
	}
	r.Bloom = CreateBloom(Receipts{r})
	rbin, err := r.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if rbin[0] != GhostDataRevealTxType {
		t.Fatalf("receipt type byte %#x", rbin[0])
	}
	var rdec Receipt
	if err := rdec.UnmarshalBinary(rbin); err != nil {
		t.Fatal(err)
	}
	if rdec.Type != GhostDataRevealTxType || rdec.Status != ReceiptStatusSuccessful || rdec.CumulativeGasUsed != GhostDataRevealGas || len(rdec.Logs) != 1 {
		t.Fatalf("receipt round trip: %+v", rdec)
	}
	var buf bytes.Buffer
	Receipts{r}.EncodeIndex(0, &buf)
	if !bytes.Equal(buf.Bytes(), rbin) {
		t.Fatal("receipt trie encoding differs from the binary encoding")
	}
	rs := Receipts{{Type: GhostDataRevealTxType, Status: ReceiptStatusSuccessful, CumulativeGasUsed: GhostDataRevealGas}}
	if err := rs.DeriveFields(params.TestChainConfig, common.Hash{9}, 4, 0, big.NewInt(7), nil, Transactions{tx}); err != nil {
		t.Fatal(err)
	}
	if rs[0].ContractAddress != (common.Address{}) || rs[0].GasUsed != GhostDataRevealGas || rs[0].TxHash != tx.Hash() {
		t.Fatalf("derived fields: %+v", rs[0])
	}
}
