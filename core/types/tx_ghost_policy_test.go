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

func testPolicyRevealEnvelope() []byte {
	env := make([]byte, GhostPolicyRevealEnvelopeSize)
	env[0] = GhostPolicyRevealTxType
	for i := 1; i < 400; i++ {
		env[i] = byte(i * 3)
	}
	env[GhostPolicyRevealEnvelopeSize-1] = 0xee
	return env
}

// TestPolicyRevealTypeAndGas checks the policy reveal type 0x53: its
// envelope of 1,311,451 bytes, the three gas constants of the classes and
// that each type takes its own, that it is a reveal without a sender, never
// taken for another reveal, every encoding round trip, and the typed receipt
// round trip.
func TestPolicyRevealTypeAndGas(t *testing.T) {
	if GhostPolicyRevealTxType != 0x53 {
		t.Fatalf("type %#x", GhostPolicyRevealTxType)
	}
	if GhostPolicyRevealPayloadSize != 1_311_450 || GhostPolicyRevealEnvelopeSize != 1_311_451 {
		t.Fatalf("payload %d, envelope %d", GhostPolicyRevealPayloadSize, GhostPolicyRevealEnvelopeSize)
	}
	// The three classes and their gas (spec 10, section 10).
	for _, c := range []struct {
		name          string
		gas, envelope uint64
		verify, extra uint64
		want          uint64
	}{
		{"G_PRIV", GhostRevealGas, GhostRevealEnvelopeSize, 110_000, 0, 21_111_656},
		{"G_POLICY", GhostPolicyRevealGas, GhostPolicyRevealEnvelopeSize, 110_000, 160_000, 21_274_216},
		{"G_DATA", GhostDataRevealGas, GhostDataRevealEnvelopeSize, 92_300, 0, 21_090_372},
	} {
		if c.gas != c.want || c.gas != 16*c.envelope+21_000+c.verify+c.extra {
			t.Errorf("%s is %d, want %d", c.name, c.gas, c.want)
		}
	}

	env := testPolicyRevealEnvelope()
	tx, err := NewGhostPolicyRevealTx(env)
	if err != nil {
		t.Fatal(err)
	}
	if tx.Type() != GhostPolicyRevealTxType || !tx.IsGhostReveal() {
		t.Fatalf("type %#x, reveal %v", tx.Type(), tx.IsGhostReveal())
	}
	if err := CheckTxType(tx); err != nil {
		t.Fatalf("type check: %v", err)
	}
	if want := crypto.Keccak256Hash(env); tx.Hash() != want {
		t.Fatalf("hash %x, want keccak256(0x53 || payload) %x", tx.Hash(), want)
	}
	if tx.Size() != GhostPolicyRevealEnvelopeSize {
		t.Fatalf("size %d", tx.Size())
	}
	if tx.Gas() != GhostPolicyRevealGas || tx.To() != nil || tx.Nonce() != 0 || tx.Value().Sign() != 0 || tx.GasPrice().Sign() != 0 {
		t.Fatalf("unexpected fields: gas %d to %v nonce %d value %v", tx.Gas(), tx.To(), tx.Nonce(), tx.Value())
	}
	if tx.ChainId().Cmp(new(big.Int).SetBytes(env[3:11])) != 0 {
		t.Fatalf("chain id %v", tx.ChainId())
	}
	if !bytes.Equal(tx.GhostPolicyRevealEnvelope(), env) || tx.GhostRevealEnvelope() != nil || tx.GhostDataRevealEnvelope() != nil {
		t.Fatal("envelopes differ")
	}

	// Each type takes its own gas.
	coin, err := NewGhostRevealTx(testRevealEnvelope())
	if err != nil {
		t.Fatal(err)
	}
	data, err := NewGhostDataRevealTx(testDataRevealEnvelope())
	if err != nil {
		t.Fatal(err)
	}
	if coin.Gas() != GhostRevealGas || data.Gas() != GhostDataRevealGas || tx.Gas() != GhostPolicyRevealGas {
		t.Fatalf("gas: coin %d, data %d, policy %d", coin.Gas(), data.Gas(), tx.Gas())
	}
	if coin.GhostPolicyRevealEnvelope() != nil || data.GhostPolicyRevealEnvelope() != nil {
		t.Fatal("another reveal gave a policy reveal envelope")
	}

	// The envelope of another type, or another size, is not a policy reveal.
	for name, bad := range map[string][]byte{
		"empty":           {},
		"type only":       {GhostPolicyRevealTxType},
		"short":           env[:len(env)-1],
		"long":            append(append([]byte{}, env...), 0),
		"coin type":       append([]byte{GhostRevealTxType}, env[1:]...),
		"coin-sized 0x53": append([]byte{GhostPolicyRevealTxType}, testRevealEnvelope()[1:]...),
	} {
		if _, err := NewGhostPolicyRevealTx(bad); err == nil {
			t.Errorf("%s envelope accepted", name)
		}
	}
	if _, err := NewGhostRevealTx(append([]byte{GhostRevealTxType}, env[1:]...)); err == nil {
		t.Error("a policy-sized envelope wrapped as a coin reveal")
	}

	// Binary, RLP in a block body list and JSON.
	bin, err := tx.MarshalBinary()
	if err != nil || !bytes.Equal(bin, env) {
		t.Fatalf("MarshalBinary is not the envelope: %v", err)
	}
	var dec Transaction
	if err := dec.UnmarshalBinary(bin); err != nil || dec.Type() != GhostPolicyRevealTxType || dec.Hash() != tx.Hash() {
		t.Fatalf("binary round trip: %v", err)
	}
	list, err := rlp.EncodeToBytes(Transactions{tx, coin, data})
	if err != nil {
		t.Fatal(err)
	}
	var txs Transactions
	if err := rlp.DecodeBytes(list, &txs); err != nil || len(txs) != 3 || txs[0].Hash() != tx.Hash() || txs[0].Type() != GhostPolicyRevealTxType {
		t.Fatalf("list round trip: %v", err)
	}
	js, err := json.Marshal(tx)
	if err != nil {
		t.Fatal(err)
	}
	var fromJSON Transaction
	if err := json.Unmarshal(js, &fromJSON); err != nil || fromJSON.Hash() != tx.Hash() || fromJSON.Type() != GhostPolicyRevealTxType {
		t.Fatalf("JSON round trip: %v", err)
	}

	// No sender under any signer, and no signature.
	for _, signer := range []Signer{NewCancunSigner(big.NewInt(1)), NewEIP155Signer(big.NewInt(1)), HomesteadSigner{}} {
		if addr, err := Sender(signer, tx); !errors.Is(err, ErrNoSender) || addr != (common.Address{}) {
			t.Errorf("%T: sender %x, error %v", signer, addr, err)
		}
	}
	key, _ := crypto.GenerateKey()
	if _, err := SignTx(tx, NewCancunSigner(big.NewInt(1)), key); err == nil {
		t.Error("a policy reveal was signed")
	}

	// The receipt: typed 0x53, status 1, its gas and one log, round trip in
	// every encoding.
	r := &Receipt{
		Type:              GhostPolicyRevealTxType,
		Status:            ReceiptStatusSuccessful,
		CumulativeGasUsed: GhostPolicyRevealGas,
		Logs:              []*Log{{Address: common.Address{1}, Topics: []common.Hash{{2}, {3}}, Data: []byte{4}}},
	}
	r.Bloom = CreateBloom(Receipts{r})
	rbin, err := r.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if rbin[0] != GhostPolicyRevealTxType {
		t.Fatalf("receipt type byte %#x", rbin[0])
	}
	var rdec Receipt
	if err := rdec.UnmarshalBinary(rbin); err != nil {
		t.Fatal(err)
	}
	if rdec.Type != GhostPolicyRevealTxType || rdec.Status != ReceiptStatusSuccessful || rdec.CumulativeGasUsed != GhostPolicyRevealGas || len(rdec.Logs) != 1 {
		t.Fatalf("receipt round trip: %+v", rdec)
	}
	renc, err := rlp.EncodeToBytes(r)
	if err != nil {
		t.Fatal(err)
	}
	var rfromRLP Receipt
	if err := rlp.DecodeBytes(renc, &rfromRLP); err != nil || rfromRLP.Type != GhostPolicyRevealTxType {
		t.Fatalf("receipt RLP round trip: %v", err)
	}
	var buf bytes.Buffer
	Receipts{r}.EncodeIndex(0, &buf)
	if !bytes.Equal(buf.Bytes(), rbin) {
		t.Fatal("receipt trie encoding differs from the binary encoding")
	}
	rs := Receipts{{Type: GhostPolicyRevealTxType, Status: ReceiptStatusSuccessful, CumulativeGasUsed: GhostPolicyRevealGas}}
	if err := rs.DeriveFields(params.TestChainConfig, common.Hash{9}, 4, 0, big.NewInt(7), nil, Transactions{tx}); err != nil {
		t.Fatal(err)
	}
	if rs[0].ContractAddress != (common.Address{}) || rs[0].GasUsed != GhostPolicyRevealGas || rs[0].TxHash != tx.Hash() {
		t.Fatalf("derived fields: %+v", rs[0])
	}
}
