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
	"encoding/binary"
	"encoding/json"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
)

// testBundleEnvelope is a bundle envelope of count bodies with a recognisable
// header, root proof and bodies; its fields are not checked here.
func testBundleEnvelope(count int) []byte {
	env := make([]byte, 1+GhostBundlePayloadSize(count))
	env[0] = GhostBundleTxType
	p := env[1:]
	binary.BigEndian.PutUint16(p[0:], 1)
	binary.BigEndian.PutUint64(p[2:], 0x0102030405060708)
	binary.BigEndian.PutUint16(p[10:], uint16(count))
	for i := 0; i < 64; i++ {
		p[GhostBundleHeaderSize+i] = byte(i*7 + 1)
	}
	for i := range count {
		body := p[GhostBundleFixedSize+i*GhostBundleBodySize:]
		body[0], body[1] = 0x00, 0x02
		body[GhostBundleBodySize-1] = byte(i + 1)
	}
	return env
}

// TestGhostBundleTxRoundTrip checks the bundle type 0x55: its layout
// constants, that it is a native transaction without a sender that is not a
// reveal (IsGhostReveal), its hash, size and fields, every encoding round
// trip, and the typed receipt round trip.
func TestGhostBundleTxRoundTrip(t *testing.T) {
	if GhostBundleTxType != 0x55 {
		t.Fatalf("type %#x", GhostBundleTxType)
	}
	if GhostBundleHeaderSize != 12 || GhostBundleProofSize != 1_310_720 || GhostBundleBodySize != 570 || GhostBundleMaxReveals != 1_408 {
		t.Fatalf("header %d, proof %d, body %d, max %d", GhostBundleHeaderSize, GhostBundleProofSize, GhostBundleBodySize, GhostBundleMaxReveals)
	}
	if GhostBundleFixedSize != 1_310_732 || GhostBundlePayloadSize(3) != 1_310_732+3*570 {
		t.Fatalf("fixed %d, payload of 3 %d", GhostBundleFixedSize, GhostBundlePayloadSize(3))
	}
	// A body is a version 2 reveal payload without its proof field.
	if GhostBundleBodySize != GhostRevealPayloadSize-GhostBundleProofSize {
		t.Fatal("a body is not a reveal payload without its proof field")
	}

	env := testBundleEnvelope(3)
	tx, err := NewGhostBundleTx(env)
	if err != nil {
		t.Fatal(err)
	}
	if tx.Type() != GhostBundleTxType || tx.IsGhostReveal() {
		t.Fatalf("type %#x, reveal %v", tx.Type(), tx.IsGhostReveal())
	}
	if err := CheckTxType(tx); err != nil {
		t.Fatalf("type check: %v", err)
	}
	if want := crypto.Keccak256Hash(env); tx.Hash() != want {
		t.Fatalf("hash %x, want keccak256(0x55 || payload) %x", tx.Hash(), want)
	}
	if tx.Size() != uint64(len(env)) {
		t.Fatalf("size %d, want %d", tx.Size(), len(env))
	}
	if tx.Gas() != 3*GhostRevealGas || tx.To() != nil || tx.Nonce() != 0 || tx.Value().Sign() != 0 || tx.GasPrice().Sign() != 0 || tx.Data() != nil {
		t.Fatalf("unexpected fields: gas %d to %v nonce %d value %v", tx.Gas(), tx.To(), tx.Nonce(), tx.Value())
	}
	if tx.ChainId().Uint64() != 0x0102030405060708 {
		t.Fatalf("chain id %v", tx.ChainId())
	}
	if !bytes.Equal(tx.GhostBundleEnvelope(), env) || tx.GhostRevealEnvelope() != nil || tx.GhostDataRevealEnvelope() != nil || tx.GhostPolicyRevealEnvelope() != nil || tx.GhostPolicyActionEnvelope() != nil {
		t.Fatal("envelopes differ")
	}
	// The envelope is a copy, both ways.
	env[100] ^= 0xff
	if bytes.Equal(tx.GhostBundleEnvelope(), env) {
		t.Fatal("the transaction shares the caller's envelope")
	}
	env[100] ^= 0xff
	tx.GhostBundleEnvelope()[100] ^= 0xff
	if !bytes.Equal(tx.GhostBundleEnvelope(), env) {
		t.Fatal("the envelope returned is not a copy")
	}
	coin, err := NewGhostRevealTx(testRevealEnvelope())
	if err != nil {
		t.Fatal(err)
	}
	if coin.GhostBundleEnvelope() != nil {
		t.Fatal("a reveal gave a bundle envelope")
	}

	// Binary, RLP in a block body list beside a reveal, and JSON.
	bin, err := tx.MarshalBinary()
	if err != nil || !bytes.Equal(bin, env) {
		t.Fatalf("MarshalBinary is not the envelope: %v", err)
	}
	var dec Transaction
	if err := dec.UnmarshalBinary(bin); err != nil || dec.Type() != GhostBundleTxType || dec.Hash() != tx.Hash() || !bytes.Equal(dec.GhostBundleEnvelope(), env) {
		t.Fatalf("binary round trip: %v", err)
	}
	list, err := rlp.EncodeToBytes(Transactions{coin, tx})
	if err != nil {
		t.Fatal(err)
	}
	var txs Transactions
	if err := rlp.DecodeBytes(list, &txs); err != nil || len(txs) != 2 || txs[1].Hash() != tx.Hash() || txs[1].Type() != GhostBundleTxType || txs[0].Hash() != coin.Hash() {
		t.Fatalf("list round trip: %v", err)
	}
	if txs[1].Size() != uint64(len(env)) {
		t.Fatalf("decoded size %d", txs[1].Size())
	}
	// A block body, and a list of header and body pairs as a node stores
	// its bad blocks, round trip with the bundle in them.
	type storedBlock struct {
		Header *Header
		Body   *Body
	}
	header := &Header{Number: big.NewInt(2), Difficulty: big.NewInt(1), BaseFee: big.NewInt(7)}
	stored := []*storedBlock{
		{Header: header, Body: &Body{Transactions: Transactions{coin, tx}}},
		{Header: header, Body: &Body{Transactions: Transactions{tx}}},
	}
	blob, err := rlp.EncodeToBytes(stored)
	if err != nil {
		t.Fatal(err)
	}
	var back []*storedBlock
	if err := rlp.DecodeBytes(blob, &back); err != nil {
		t.Fatalf("stored blocks round trip: %v", err)
	}
	if len(back) != 2 || len(back[0].Body.Transactions) != 2 || back[0].Body.Transactions[1].Hash() != tx.Hash() || back[1].Body.Transactions[0].Hash() != tx.Hash() {
		t.Fatal("stored blocks round trip lost the bundle")
	}
	js, err := json.Marshal(tx)
	if err != nil {
		t.Fatal(err)
	}
	var fromJSON Transaction
	if err := json.Unmarshal(js, &fromJSON); err != nil || fromJSON.Hash() != tx.Hash() || fromJSON.Type() != GhostBundleTxType {
		t.Fatalf("JSON round trip: %v", err)
	}

	// No sender under any signer, and no signature.
	for _, signer := range []Signer{NewCancunSigner(big.NewInt(1)), NewEIP155Signer(big.NewInt(1)), HomesteadSigner{}, NewGhostAccountSigner(NewCancunSigner(big.NewInt(1)), common.Hash{1})} {
		if addr, err := Sender(signer, tx); !errors.Is(err, ErrNoSender) || addr != (common.Address{}) {
			t.Errorf("%T: sender %x, error %v", signer, addr, err)
		}
	}
	key, _ := crypto.GenerateKey()
	if _, err := SignTx(tx, NewCancunSigner(big.NewInt(1)), key); err == nil {
		t.Error("a bundle was signed")
	}

	// The receipt: typed 0x55, status 1, the bundle's gas and the logs of
	// its reveals, round trip in every encoding.
	logs := []*Log{
		{Address: common.Address{1}, Topics: []common.Hash{{2}, {3}}, Data: []byte{4}},
		{Address: common.Address{1}, Topics: []common.Hash{{2}, {5}}, Data: []byte{6}},
	}
	r := &Receipt{
		Type:              GhostBundleTxType,
		Status:            ReceiptStatusSuccessful,
		CumulativeGasUsed: 3 * GhostRevealGas,
		Logs:              logs,
	}
	r.Bloom = CreateBloom(Receipts{r})
	rbin, err := r.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if rbin[0] != GhostBundleTxType {
		t.Fatalf("receipt type byte %#x", rbin[0])
	}
	var rdec Receipt
	if err := rdec.UnmarshalBinary(rbin); err != nil {
		t.Fatal(err)
	}
	if rdec.Type != GhostBundleTxType || rdec.Status != ReceiptStatusSuccessful || rdec.CumulativeGasUsed != 3*GhostRevealGas || len(rdec.Logs) != 2 {
		t.Fatalf("receipt round trip: %+v", rdec)
	}
	renc, err := rlp.EncodeToBytes(r)
	if err != nil {
		t.Fatal(err)
	}
	var rfromRLP Receipt
	if err := rlp.DecodeBytes(renc, &rfromRLP); err != nil || rfromRLP.Type != GhostBundleTxType {
		t.Fatalf("receipt RLP round trip: %v", err)
	}
	var buf bytes.Buffer
	Receipts{r}.EncodeIndex(0, &buf)
	if !bytes.Equal(buf.Bytes(), rbin) {
		t.Fatal("receipt trie encoding differs from the binary encoding")
	}
	rs := Receipts{{Type: GhostBundleTxType, Status: ReceiptStatusSuccessful, CumulativeGasUsed: 3 * GhostRevealGas}}
	if err := rs.DeriveFields(params.TestChainConfig, common.Hash{9}, 4, 0, big.NewInt(7), nil, Transactions{tx}); err != nil {
		t.Fatal(err)
	}
	if rs[0].ContractAddress != (common.Address{}) || rs[0].GasUsed != 3*GhostRevealGas || rs[0].TxHash != tx.Hash() || rs[0].EffectiveGasPrice.Sign() != 0 {
		t.Fatalf("derived fields: %+v", rs[0])
	}
}

// TestGhostBundleTxLengthChecks checks that a bundle envelope is taken only
// with its type byte, a count from 1 to 1,408 and exactly the length of that
// count: 1,310,733 + 570 * count bytes, by every decoder.
func TestGhostBundleTxLengthChecks(t *testing.T) {
	for _, n := range []int{1, 2, GhostBundleMaxReveals} {
		env := testBundleEnvelope(n)
		if len(env) != 1_310_733+570*n {
			t.Fatalf("count %d: envelope of %d bytes", n, len(env))
		}
		tx, err := NewGhostBundleTx(env)
		if err != nil {
			t.Fatalf("count %d refused: %v", n, err)
		}
		if tx.Gas() != uint64(n)*GhostRevealGas {
			t.Fatalf("count %d: gas %d", n, tx.Gas())
		}
	}
	withCount := func(env []byte, n uint16) []byte {
		env = common.CopyBytes(env)
		binary.BigEndian.PutUint16(env[11:], n)
		return env
	}
	two := testBundleEnvelope(2)
	over := testBundleEnvelope(GhostBundleMaxReveals + 1)
	for _, c := range []struct {
		name string
		env  []byte
	}{
		{"empty", []byte{}},
		{"type only", []byte{GhostBundleTxType}},
		{"header only", two[:1+GhostBundleHeaderSize]},
		{"no bodies", withCount(two[:1+GhostBundleFixedSize], 0)},
		{"no bodies, count 1", withCount(two[:1+GhostBundleFixedSize], 1)},
		{"count 0", withCount(two, 0)},
		{"count 1 with two bodies", withCount(two, 1)},
		{"count 3 with two bodies", withCount(two, 3)},
		{"one byte short", two[:len(two)-1]},
		{"one byte long", append(common.CopyBytes(two), 0)},
		{"half a body more", append(common.CopyBytes(two), make([]byte, GhostBundleBodySize/2)...)},
		{"count 1,409", over},
		{"count 65,535", withCount(two, 0xffff)},
		{"reveal type byte", append([]byte{GhostRevealTxType}, two[1:]...)},
		{"policy action type byte", append([]byte{GhostPolicyActionTxType}, two[1:]...)},
		{"a reveal envelope as 0x55", append([]byte{GhostBundleTxType}, testRevealEnvelope()[1:]...)},
	} {
		name, bad := c.name, c.env
		if _, err := NewGhostBundleTx(bad); err == nil {
			t.Errorf("%s: envelope accepted", name)
		}
		if len(bad) == 0 || bad[0] != GhostBundleTxType {
			continue
		}
		var dec Transaction
		if err := dec.UnmarshalBinary(bad); err == nil {
			t.Errorf("%s: binary decode accepted", name)
		}
		var itx GhostBundleTx
		if err := itx.decode(bad[1:]); !errors.Is(err, ErrGhostBundleLength) {
			t.Errorf("%s: decode error %v, want %v", name, err, ErrGhostBundleLength)
		}
		js, err := json.Marshal(map[string]any{"type": "0x55", "input": hexutil.Encode(bad[1:])})
		if err != nil {
			t.Fatal(err)
		}
		var fromJSON Transaction
		if err := json.Unmarshal(js, &fromJSON); err == nil {
			t.Errorf("%s: JSON decode accepted", name)
		}
	}
	// A bundle envelope is no reveal of any type.
	if _, err := NewGhostRevealTx(append([]byte{GhostRevealTxType}, two[1:]...)); err == nil {
		t.Error("a bundle-sized envelope wrapped as a coin reveal")
	}
}

// TestGhostBundleTxGasIsSumOfRevealGas checks that a bundle takes exactly
// count times G_PRIV, 21,111,656, the sum of what the same reveals take as
// lone reveals, for every count from 1 to 1,408, so it is never cheaper to
// include than the reveals it carries.
func TestGhostBundleTxGasIsSumOfRevealGas(t *testing.T) {
	if GhostRevealGas != 21_111_656 {
		t.Fatalf("G_PRIV %d", GhostRevealGas)
	}
	lone, err := NewGhostRevealTx(testRevealEnvelope())
	if err != nil {
		t.Fatal(err)
	}
	var sum uint64
	for n := 1; n <= GhostBundleMaxReveals; n++ {
		sum += lone.Gas()
		if got := GhostBundleGas(n); got != sum || got != uint64(n)*21_111_656 {
			t.Fatalf("count %d: gas %d, want the sum of lone reveals %d", n, got, sum)
		}
	}
	if GhostBundleGas(0) != 0 || GhostBundleGas(-1) != 0 {
		t.Fatal("a bundle of no reveals takes gas")
	}
	// The transaction's gas reads its count field.
	for _, n := range []int{1, 2, 44, 32 * 44} {
		tx, err := NewGhostBundleTx(testBundleEnvelope(n))
		if err != nil {
			t.Fatal(err)
		}
		if tx.Gas() != uint64(n)*lone.Gas() {
			t.Fatalf("count %d: transaction gas %d, want %d", n, tx.Gas(), uint64(n)*lone.Gas())
		}
	}
	// The largest bundle's gas: 1,408 * 21,111,656.
	if GhostBundleGas(GhostBundleMaxReveals) != 29_725_211_648 {
		t.Fatalf("largest bundle's gas %d", GhostBundleGas(GhostBundleMaxReveals))
	}
}
