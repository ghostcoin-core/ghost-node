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

func testActionEnvelope() []byte {
	env := make([]byte, GhostPolicyActionEnvelopeSize)
	env[0] = GhostPolicyActionTxType
	for i := 1; i < 300; i++ {
		env[i] = byte(i*7 + 1)
	}
	env[GhostPolicyActionEnvelopeSize-1] = 0xa5
	return env
}

// TestGhostActionTxRoundTrip checks the policy action type 0x54: decoding
// and encoding of the envelope, the hash keccak256(0x54 || payload), the
// JSON form, the RLP envelope in a block body list beside the other native
// types, no sender and no signature, and the typed receipt in every
// encoding.
func TestGhostActionTxRoundTrip(t *testing.T) {
	if GhostPolicyActionTxType != 0x54 {
		t.Fatalf("type %#x", GhostPolicyActionTxType)
	}
	env := testActionEnvelope()
	tx, err := NewGhostPolicyActionTx(env)
	if err != nil {
		t.Fatal(err)
	}
	if tx.Type() != GhostPolicyActionTxType || !tx.IsGhostReveal() {
		t.Fatalf("type %#x, no-account native %v", tx.Type(), tx.IsGhostReveal())
	}
	if err := CheckTxType(tx); err != nil {
		t.Fatalf("type check: %v", err)
	}
	if want := crypto.Keccak256Hash(env); tx.Hash() != want {
		t.Fatalf("hash %x, want keccak256(0x54 || payload) %x", tx.Hash(), want)
	}
	if tx.Size() != GhostPolicyActionEnvelopeSize {
		t.Fatalf("size %d", tx.Size())
	}
	if tx.Gas() != GhostPolicyActionGas || tx.To() != nil || tx.Nonce() != 0 || tx.Value().Sign() != 0 || tx.GasPrice().Sign() != 0 || len(tx.Data()) != 0 {
		t.Fatalf("unexpected fields: gas %d to %v nonce %d value %v", tx.Gas(), tx.To(), tx.Nonce(), tx.Value())
	}
	if tx.ChainId().Cmp(new(big.Int).SetBytes(env[3:11])) != 0 {
		t.Fatalf("chain id %v", tx.ChainId())
	}
	if !bytes.Equal(tx.GhostPolicyActionEnvelope(), env) || tx.GhostRevealEnvelope() != nil || tx.GhostDataRevealEnvelope() != nil || tx.GhostPolicyRevealEnvelope() != nil {
		t.Fatal("envelopes differ")
	}
	// The envelope is copied in and out.
	env[5] ^= 0xff
	if bytes.Equal(tx.GhostPolicyActionEnvelope(), env) {
		t.Fatal("the transaction shares the caller's envelope")
	}
	env[5] ^= 0xff

	// Another native type never gives an action envelope, and the envelope
	// of another type or size is not an action.
	policy, err := NewGhostPolicyRevealTx(testPolicyRevealEnvelope())
	if err != nil {
		t.Fatal(err)
	}
	coin, err := NewGhostRevealTx(testRevealEnvelope())
	if err != nil {
		t.Fatal(err)
	}
	if policy.GhostPolicyActionEnvelope() != nil || coin.GhostPolicyActionEnvelope() != nil {
		t.Fatal("a reveal gave an action envelope")
	}
	for name, bad := range map[string][]byte{
		"empty":         {},
		"type only":     {GhostPolicyActionTxType},
		"short":         env[:len(env)-1],
		"long":          append(append([]byte{}, env...), 0),
		"policy type":   append([]byte{GhostPolicyRevealTxType}, env[1:]...),
		"policy-sized":  append([]byte{GhostPolicyActionTxType}, testPolicyRevealEnvelope()[1:]...),
		"account type":  append([]byte{GhostAccountTxType}, env[1:]...),
		"coin-sized ac": append([]byte{GhostPolicyActionTxType}, testRevealEnvelope()[1:]...),
	} {
		if _, err := NewGhostPolicyActionTx(bad); err == nil {
			t.Errorf("%s envelope accepted", name)
		}
	}
	if _, err := NewGhostPolicyRevealTx(append([]byte{GhostPolicyRevealTxType}, env[1:]...)); err == nil {
		t.Error("an action-sized envelope wrapped as a policy reveal")
	}
	var short Transaction
	if err := short.UnmarshalBinary(env[:len(env)-1]); !errors.Is(err, ErrGhostRevealLength) {
		t.Errorf("short binary envelope: %v, want %v", err, ErrGhostRevealLength)
	}

	// Binary, RLP in a block body list and JSON.
	bin, err := tx.MarshalBinary()
	if err != nil || !bytes.Equal(bin, env) {
		t.Fatalf("MarshalBinary is not the envelope: %v", err)
	}
	var dec Transaction
	if err := dec.UnmarshalBinary(bin); err != nil || dec.Type() != GhostPolicyActionTxType || dec.Hash() != tx.Hash() || !bytes.Equal(dec.GhostPolicyActionEnvelope(), env) {
		t.Fatalf("binary round trip: %v", err)
	}
	list, err := rlp.EncodeToBytes(Transactions{tx, policy, coin})
	if err != nil {
		t.Fatal(err)
	}
	var txs Transactions
	if err := rlp.DecodeBytes(list, &txs); err != nil || len(txs) != 3 || txs[0].Hash() != tx.Hash() || txs[0].Type() != GhostPolicyActionTxType || txs[1].Type() != GhostPolicyRevealTxType {
		t.Fatalf("list round trip: %v", err)
	}
	if !bytes.Equal(txs[0].GhostPolicyActionEnvelope(), env) {
		t.Fatal("the list round trip changed the envelope")
	}
	js, err := json.Marshal(tx)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(js, &fields); err != nil {
		t.Fatal(err)
	}
	if fields["type"] != "0x54" || fields["input"] == nil || fields["nonce"] != nil || fields["v"] != nil || fields["to"] != nil {
		t.Fatalf("JSON fields: type %v, nonce %v, v %v, to %v", fields["type"], fields["nonce"], fields["v"], fields["to"])
	}
	var fromJSON Transaction
	if err := json.Unmarshal(js, &fromJSON); err != nil || fromJSON.Hash() != tx.Hash() || fromJSON.Type() != GhostPolicyActionTxType {
		t.Fatalf("JSON round trip: %v", err)
	}
	if err := json.Unmarshal([]byte(`{"type":"0x54"}`), &fromJSON); err == nil {
		t.Error("an action without input decoded from JSON")
	}

	// No sender under any signer, and no signature.
	for _, signer := range []Signer{NewCancunSigner(big.NewInt(1)), NewEIP155Signer(big.NewInt(1)), HomesteadSigner{}} {
		if addr, err := Sender(signer, tx); !errors.Is(err, ErrNoSender) || addr != (common.Address{}) {
			t.Errorf("%T: sender %x, error %v", signer, addr, err)
		}
	}
	key, _ := crypto.GenerateKey()
	if _, err := SignTx(tx, NewCancunSigner(big.NewInt(1)), key); err == nil {
		t.Error("a policy action was signed")
	}

	// The receipt: typed 0x54, status 1, G_ACTION and the action-result log,
	// round trip in every encoding.
	r := &Receipt{
		Type:              GhostPolicyActionTxType,
		Status:            ReceiptStatusSuccessful,
		CumulativeGasUsed: GhostPolicyActionGas,
		Logs:              []*Log{{Address: common.Address{8}, Topics: []common.Hash{{5}, {6}}, Data: make([]byte, 160)}},
	}
	r.Bloom = CreateBloom(Receipts{r})
	rbin, err := r.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if rbin[0] != GhostPolicyActionTxType {
		t.Fatalf("receipt type byte %#x", rbin[0])
	}
	var rdec Receipt
	if err := rdec.UnmarshalBinary(rbin); err != nil {
		t.Fatal(err)
	}
	if rdec.Type != GhostPolicyActionTxType || rdec.Status != ReceiptStatusSuccessful || rdec.CumulativeGasUsed != GhostPolicyActionGas || len(rdec.Logs) != 1 || len(rdec.Logs[0].Data) != 160 {
		t.Fatalf("receipt round trip: %+v", rdec)
	}
	renc, err := rlp.EncodeToBytes(r)
	if err != nil {
		t.Fatal(err)
	}
	var rfromRLP Receipt
	if err := rlp.DecodeBytes(renc, &rfromRLP); err != nil || rfromRLP.Type != GhostPolicyActionTxType {
		t.Fatalf("receipt RLP round trip: %v", err)
	}
	var buf bytes.Buffer
	Receipts{r}.EncodeIndex(0, &buf)
	if !bytes.Equal(buf.Bytes(), rbin) {
		t.Fatal("receipt trie encoding differs from the binary encoding")
	}
	stored, err := rlp.EncodeToBytes((*ReceiptForStorage)(r))
	if err != nil {
		t.Fatal(err)
	}
	var fromStore ReceiptForStorage
	if err := rlp.DecodeBytes(stored, &fromStore); err != nil || fromStore.CumulativeGasUsed != GhostPolicyActionGas || len(fromStore.Logs) != 1 {
		t.Fatalf("receipt storage round trip: %v", err)
	}
	rs := Receipts{{Type: GhostPolicyActionTxType, Status: ReceiptStatusSuccessful, CumulativeGasUsed: GhostPolicyActionGas}}
	if err := rs.DeriveFields(params.TestChainConfig, common.Hash{9}, 4, 0, big.NewInt(7), nil, Transactions{tx}); err != nil {
		t.Fatal(err)
	}
	if rs[0].ContractAddress != (common.Address{}) || rs[0].GasUsed != GhostPolicyActionGas || rs[0].TxHash != tx.Hash() {
		t.Fatalf("derived fields: %+v", rs[0])
	}
}

// TestGhostActionTxGasAndSize checks the sizes and gas of the policy action:
// an envelope of 949,373 bytes and a payload of 949,372, and G_ACTION =
// 15,905,968, 16 per envelope byte, 21,000 and the fixed action charge of
// 695,000, which holds ACTION_CALL_GAS of 250,000. The gas is the same for
// every action, whatever its payload, and is the smallest of the native
// classes.
func TestGhostActionTxGasAndSize(t *testing.T) {
	if GhostPolicyActionEnvelopeSize != 949_373 || GhostPolicyActionPayloadSize != 949_372 {
		t.Fatalf("envelope %d, payload %d", GhostPolicyActionEnvelopeSize, GhostPolicyActionPayloadSize)
	}
	if GhostPolicyActionGas != 15_905_968 {
		t.Fatalf("G_ACTION %d", GhostPolicyActionGas)
	}
	const actionCharge = 695_000
	if GhostPolicyActionGas != 16*GhostPolicyActionEnvelopeSize+21_000+actionCharge {
		t.Fatal("G_ACTION is not 16 per envelope byte, 21,000 and the action charge")
	}
	if actionCharge < 250_000 {
		t.Fatal("the action charge does not hold ACTION_CALL_GAS")
	}
	for _, other := range []uint64{GhostRevealGas, GhostRevealV1Gas, GhostPolicyRevealGas, GhostDataRevealGas} {
		if GhostPolicyActionGas >= other {
			t.Errorf("G_ACTION %d not below the reveal class gas %d", GhostPolicyActionGas, other)
		}
	}
	a := testActionEnvelope()
	b := make([]byte, GhostPolicyActionEnvelopeSize)
	b[0] = GhostPolicyActionTxType
	for i, env := range [][]byte{a, b} {
		tx, err := NewGhostPolicyActionTx(env)
		if err != nil {
			t.Fatal(err)
		}
		if tx.Gas() != GhostPolicyActionGas || tx.Size() != GhostPolicyActionEnvelopeSize {
			t.Errorf("action %d: gas %d, size %d", i, tx.Gas(), tx.Size())
		}
		bin, err := tx.MarshalBinary()
		if err != nil || len(bin) != GhostPolicyActionEnvelopeSize {
			t.Errorf("action %d: binary of %d bytes: %v", i, len(bin), err)
		}
	}
	// One byte more or less is no action.
	for _, n := range []int{GhostPolicyActionEnvelopeSize - 1, GhostPolicyActionEnvelopeSize + 1} {
		env := make([]byte, n)
		env[0] = GhostPolicyActionTxType
		if _, err := NewGhostPolicyActionTx(env); !errors.Is(err, ErrGhostRevealLength) {
			t.Errorf("envelope of %d bytes: %v, want %v", n, err, ErrGhostRevealLength)
		}
	}
}
