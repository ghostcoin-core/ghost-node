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

// testDirectRevealEnvelope is a direct reveal envelope with version 3, a
// recognisable head, proof field and note; its fields are not checked here.
func testDirectRevealEnvelope() []byte {
	env := make([]byte, GhostDirectRevealEnvelopeSize)
	env[0] = GhostDirectRevealTxType
	p := env[1:]
	binary.BigEndian.PutUint16(p[0:], GhostDirectRevealVersion)
	binary.BigEndian.PutUint64(p[2:], 0x0102030405060708)
	for i := 10; i < GhostDirectRevealHeadSize; i++ {
		p[i] = byte(i*3 + 1)
	}
	proof := p[GhostDirectRevealHeadSize : GhostDirectRevealHeadSize+GhostDirectRevealProofSize]
	for i := 0; i < 64; i++ {
		proof[i] = byte(i*7 + 1)
	}
	// The last byte of the proof field, past the length of the version 2
	// field, is carried too.
	proof[GhostDirectRevealProofSize-1] = 0xaa
	p[GhostDirectRevealPayloadSize-1] = 0x5c
	return env
}

// TestGhostDirectRevealTxRoundTrip checks the direct reveal type 0x58: a
// proof field of at least 2,330,908 bytes, a multiple of 1,024, set to
// 2,331,648 bytes, the version 2 layout around it, its gas; that it is a
// native transaction without a sender, not a reveal the pools take and not a
// type a block takes yet; its hash, size and fields; every encoding round
// trip; the typed receipt round trip; and that every decoder takes exactly
// its length and version.
func TestGhostDirectRevealTxRoundTrip(t *testing.T) {
	// The layout.
	if GhostDirectRevealTxType != 0x58 || GhostDirectRevealVersion != 3 {
		t.Fatalf("type %#x, version %d", GhostDirectRevealTxType, GhostDirectRevealVersion)
	}
	if GhostDirectRevealProofFloor != 2_330_908 {
		t.Fatalf("proof floor %d", GhostDirectRevealProofFloor)
	}
	if GhostDirectRevealProofSize < GhostDirectRevealProofFloor || GhostDirectRevealProofSize%1024 != 0 {
		t.Fatalf("proof field of %d bytes is below the floor or not a multiple of 1,024", GhostDirectRevealProofSize)
	}
	rounded := (GhostDirectRevealProofFloor + 1023) / 1024 * 1024
	if rounded != 2_331_648 {
		t.Fatalf("ceil(floor / 1,024) * 1,024 is %d", rounded)
	}
	if GhostDirectRevealProofSize != rounded {
		t.Fatalf("proof field of %d bytes, want ceil(floor / 1,024) * 1,024 = %d", GhostDirectRevealProofSize, rounded)
	}
	if GhostDirectRevealProofSize <= GhostBundleProofSize {
		t.Fatalf("proof field of %d bytes is no larger than today's %d", GhostDirectRevealProofSize, GhostBundleProofSize)
	}
	// The fields around the proof are those of the version 2 coin reveal.
	around := GhostDirectRevealHeadSize + GhostDirectRevealNoteSize
	if around != GhostRevealPayloadSize-GhostBundleProofSize {
		t.Fatalf("head %d and note %d are not the version 2 reveal's", GhostDirectRevealHeadSize, GhostDirectRevealNoteSize)
	}
	if around != GhostBundleBodySize {
		t.Fatalf("head %d and note %d are not a bundle body", GhostDirectRevealHeadSize, GhostDirectRevealNoteSize)
	}
	if GhostDirectRevealPayloadSize != 2_332_218 || GhostDirectRevealEnvelopeSize != 2_332_219 {
		t.Fatalf("payload %d, envelope %d", GhostDirectRevealPayloadSize, GhostDirectRevealEnvelopeSize)
	}
	// G_PRIV's rule for the larger envelope: 16 per byte, 21,000 and 370,000.
	if GhostRevealGas != 16*GhostRevealEnvelopeSize+21_000+370_000 {
		t.Fatal("the rule does not give G_PRIV for the version 2 reveal")
	}
	if GhostDirectRevealGas != 37_706_504 {
		t.Fatalf("gas %d, want 37,706,504", GhostDirectRevealGas)
	}

	env := testDirectRevealEnvelope()
	tx, err := NewGhostDirectRevealTx(env)
	if err != nil {
		t.Fatal(err)
	}
	if tx.Type() != GhostDirectRevealTxType || tx.IsGhostReveal() {
		t.Fatalf("type %#x, pooled reveal %v", tx.Type(), tx.IsGhostReveal())
	}
	// No block takes it until its chain rules exist.
	if err := CheckTxType(tx); !errors.Is(err, ErrTxTypeNotSupported) || errors.Is(err, ErrSecp256k1TxType) {
		t.Fatalf("type check: %v, want %v", err, ErrTxTypeNotSupported)
	}
	if want := crypto.Keccak256Hash(env); tx.Hash() != want {
		t.Fatalf("hash %x, want keccak256(0x58 || payload) %x", tx.Hash(), want)
	}
	if tx.Size() != uint64(len(env)) {
		t.Fatalf("size %d, want %d", tx.Size(), len(env))
	}
	if tx.Gas() != GhostDirectRevealGas || tx.To() != nil || tx.Nonce() != 0 || tx.Value().Sign() != 0 || tx.GasPrice().Sign() != 0 || tx.Data() != nil {
		t.Fatalf("unexpected fields: gas %d to %v nonce %d value %v", tx.Gas(), tx.To(), tx.Nonce(), tx.Value())
	}
	if tx.ChainId().Uint64() != 0x0102030405060708 {
		t.Fatalf("chain id %v", tx.ChainId())
	}
	if !bytes.Equal(tx.GhostDirectRevealEnvelope(), env) || tx.GhostRevealEnvelope() != nil || tx.GhostBundleEnvelope() != nil || tx.GhostDataRevealEnvelope() != nil || tx.GhostPolicyRevealEnvelope() != nil {
		t.Fatal("envelopes differ")
	}
	proof := tx.GhostDirectRevealProof()
	if want := env[1+GhostDirectRevealHeadSize : 1+GhostDirectRevealHeadSize+GhostDirectRevealProofSize]; !bytes.Equal(proof, want) {
		t.Fatalf("proof field of %d bytes is not the envelope's", len(proof))
	}
	// The envelope and the proof are copies, both ways.
	env[100] ^= 0xff
	if bytes.Equal(tx.GhostDirectRevealEnvelope(), env) {
		t.Fatal("the transaction shares the caller's envelope")
	}
	env[100] ^= 0xff
	tx.GhostDirectRevealEnvelope()[100] ^= 0xff
	tx.GhostDirectRevealProof()[0] ^= 0xff
	if !bytes.Equal(tx.GhostDirectRevealEnvelope(), env) {
		t.Fatal("the envelope or the proof returned is not a copy")
	}
	coin, err := NewGhostRevealTx(testRevealEnvelope())
	if err != nil {
		t.Fatal(err)
	}
	if coin.GhostDirectRevealEnvelope() != nil || coin.GhostDirectRevealProof() != nil {
		t.Fatal("a coin reveal gave a direct reveal envelope")
	}

	// Binary, RLP in a list beside a coin reveal, a stored block, and JSON.
	bin, err := tx.MarshalBinary()
	if err != nil || !bytes.Equal(bin, env) {
		t.Fatalf("MarshalBinary is not the envelope: %v", err)
	}
	var dec Transaction
	if err := dec.UnmarshalBinary(bin); err != nil || dec.Type() != GhostDirectRevealTxType || dec.Hash() != tx.Hash() || !bytes.Equal(dec.GhostDirectRevealEnvelope(), env) {
		t.Fatalf("binary round trip: %v", err)
	}
	list, err := rlp.EncodeToBytes(Transactions{coin, tx})
	if err != nil {
		t.Fatal(err)
	}
	var txs Transactions
	if err := rlp.DecodeBytes(list, &txs); err != nil || len(txs) != 2 || txs[1].Hash() != tx.Hash() || txs[1].Type() != GhostDirectRevealTxType || txs[0].Hash() != coin.Hash() {
		t.Fatalf("list round trip: %v", err)
	}
	if txs[1].Size() != uint64(len(env)) || !bytes.Equal(txs[1].GhostDirectRevealEnvelope(), env) {
		t.Fatalf("decoded size %d", txs[1].Size())
	}
	type storedBlock struct {
		Header *Header
		Body   *Body
	}
	header := &Header{Number: big.NewInt(2), Difficulty: big.NewInt(1), BaseFee: big.NewInt(7)}
	blob, err := rlp.EncodeToBytes(&storedBlock{Header: header, Body: &Body{Transactions: Transactions{coin, tx}}})
	if err != nil {
		t.Fatal(err)
	}
	var back storedBlock
	if err := rlp.DecodeBytes(blob, &back); err != nil || len(back.Body.Transactions) != 2 || back.Body.Transactions[1].Hash() != tx.Hash() {
		t.Fatalf("stored block round trip: %v", err)
	}
	js, err := json.Marshal(tx)
	if err != nil {
		t.Fatal(err)
	}
	var fromJSON Transaction
	if err := json.Unmarshal(js, &fromJSON); err != nil || fromJSON.Hash() != tx.Hash() || fromJSON.Type() != GhostDirectRevealTxType || !bytes.Equal(fromJSON.GhostDirectRevealEnvelope(), env) {
		t.Fatalf("JSON round trip: %v", err)
	}
	if fromJSON.ChainId().Uint64() != 0x0102030405060708 {
		t.Fatalf("JSON chain id %v", fromJSON.ChainId())
	}

	// No sender under any signer, and no signature.
	for _, signer := range []Signer{NewCancunSigner(big.NewInt(1)), NewEIP155Signer(big.NewInt(1)), HomesteadSigner{}, NewGhostAccountSigner(NewCancunSigner(big.NewInt(1)), common.Hash{1})} {
		if addr, err := Sender(signer, tx); !errors.Is(err, ErrNoSender) || addr != (common.Address{}) {
			t.Errorf("%T: sender %x, error %v", signer, addr, err)
		}
	}
	key, _ := crypto.GenerateKey()
	if _, err := SignTx(tx, NewCancunSigner(big.NewInt(1)), key); err == nil {
		t.Error("a direct reveal was signed")
	}

	// The receipt: typed 0x58, round trip in every encoding, and no
	// contract address derived for it.
	r := &Receipt{
		Type:              GhostDirectRevealTxType,
		Status:            ReceiptStatusSuccessful,
		CumulativeGasUsed: GhostDirectRevealGas,
		Logs:              []*Log{{Address: common.Address{1}, Topics: []common.Hash{{2}}, Data: []byte{3}}},
	}
	r.Bloom = CreateBloom(Receipts{r})
	rbin, err := r.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if rbin[0] != GhostDirectRevealTxType {
		t.Fatalf("receipt type byte %#x", rbin[0])
	}
	var rdec Receipt
	if err := rdec.UnmarshalBinary(rbin); err != nil || rdec.Type != GhostDirectRevealTxType || rdec.CumulativeGasUsed != GhostDirectRevealGas || len(rdec.Logs) != 1 {
		t.Fatalf("receipt round trip: %v %+v", err, rdec)
	}
	var buf bytes.Buffer
	Receipts{r}.EncodeIndex(0, &buf)
	if !bytes.Equal(buf.Bytes(), rbin) {
		t.Fatal("receipt trie encoding differs from the binary encoding")
	}
	rs := Receipts{{Type: GhostDirectRevealTxType, Status: ReceiptStatusSuccessful, CumulativeGasUsed: GhostDirectRevealGas}}
	if err := rs.DeriveFields(params.TestChainConfig, common.Hash{9}, 4, 0, big.NewInt(7), nil, Transactions{tx}); err != nil {
		t.Fatal(err)
	}
	if rs[0].ContractAddress != (common.Address{}) || rs[0].GasUsed != GhostDirectRevealGas || rs[0].TxHash != tx.Hash() || rs[0].EffectiveGasPrice.Sign() != 0 {
		t.Fatalf("derived fields: %+v", rs[0])
	}

	// Every decoder takes exactly the length and the version: the version 2
	// reveal's length, one byte short or long, and versions 2 and 4 are
	// refused.
	withVersion := func(v uint16) []byte {
		e := common.CopyBytes(env)
		binary.BigEndian.PutUint16(e[1:], v)
		return e
	}
	v2Length := make([]byte, GhostRevealEnvelopeSize)
	v2Length[0] = GhostDirectRevealTxType
	binary.BigEndian.PutUint16(v2Length[1:], GhostDirectRevealVersion)
	cases := []struct {
		name string
		env  []byte
		want error
	}{
		{"the version 2 reveal's length", v2Length, ErrGhostDirectRevealLength},
		{"one byte short", env[:len(env)-1], ErrGhostDirectRevealLength},
		{"one byte long", append(common.CopyBytes(env), 0), ErrGhostDirectRevealLength},
		{"the floor's length", env[:1+GhostDirectRevealHeadSize+GhostDirectRevealProofFloor+GhostDirectRevealNoteSize], ErrGhostDirectRevealLength},
		{"version 2", withVersion(2), ErrGhostDirectRevealVersion},
		{"version 4", withVersion(4), ErrGhostDirectRevealVersion},
	}
	for _, c := range cases {
		if _, err := NewGhostDirectRevealTx(c.env); !errors.Is(err, c.want) {
			t.Errorf("%s: constructor %v, want %v", c.name, err, c.want)
		}
		var d Transaction
		if err := d.UnmarshalBinary(c.env); !errors.Is(err, c.want) {
			t.Errorf("%s: binary %v, want %v", c.name, err, c.want)
		}
		wrapped, err := rlp.EncodeToBytes(c.env)
		if err != nil {
			t.Fatal(err)
		}
		if err := rlp.DecodeBytes(wrapped, &d); !errors.Is(err, c.want) {
			t.Errorf("%s: RLP %v, want %v", c.name, err, c.want)
		}
		raw, err := json.Marshal(map[string]interface{}{"type": "0x58", "input": hexutil.Encode(c.env[1:])})
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &d); !errors.Is(err, c.want) {
			t.Errorf("%s: JSON %v, want %v", c.name, err, c.want)
		}
	}
	// A coin reveal's envelope is not a direct reveal's, nor the reverse.
	if _, err := NewGhostDirectRevealTx(testRevealEnvelope()); !errors.Is(err, ErrInvalidTxType) {
		t.Errorf("coin reveal envelope: %v, want %v", err, ErrInvalidTxType)
	}
	if _, err := NewGhostRevealTx(append([]byte{GhostRevealTxType}, env[1:]...)); !errors.Is(err, ErrGhostRevealLength) {
		t.Errorf("direct reveal payload as a coin reveal: %v, want %v", err, ErrGhostRevealLength)
	}
}
