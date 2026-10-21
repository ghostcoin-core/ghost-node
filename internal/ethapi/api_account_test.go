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

package ethapi

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/beacon"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
	"github.com/ethereum/go-ethereum/params/vars"
	"github.com/ethereum/go-ethereum/rpc"
)

// accountTestBackend is a test backend whose genesis funds the keystore
// account, and whose pool takes a transaction the way the node's pool does:
// the stateless checks of txpool.ValidateTransaction, then the signature.
type accountTestBackend struct {
	*testBackend
	engine consensus.Engine

	mu   sync.Mutex
	sent []*types.Transaction

	mined [][]*types.Transaction // the transactions of each block mined
}

func newAccountTestBackend(t *testing.T) *accountTestBackend {
	t.Helper()
	genesis := &genesisT.Genesis{
		Config: params.MergedTestChainConfig,
		Alloc: genesisT.GenesisAlloc{
			testAccountAddress(): {Balance: big.NewInt(vars.Ether)},
		},
	}
	engine := beacon.New(ethash.NewFaker())
	b := newTestBackend(t, 0, genesis, engine, nil)
	return &accountTestBackend{testBackend: b, engine: engine}
}

// signer is the signer of the chain's account transactions.
func (b *accountTestBackend) signer() types.Signer {
	head := b.chain.CurrentBlock()
	return types.NewGhostAccountSigner(types.MakeSigner(b.chain.Config(), head.Number, head.Time), b.chain.Genesis().Hash())
}

func (b *accountTestBackend) SendTx(ctx context.Context, tx *types.Transaction) error {
	opts := &txpool.ValidationOptions{
		Config:             b.chain.Config(),
		Accept:             1<<types.LegacyTxType | 1<<types.AccessListTxType | 1<<types.DynamicFeeTxType,
		MaxSize:            128 * 1024,
		MinTip:             new(big.Int),
		AcceptGhostAccount: true,
	}
	if err := txpool.ValidateTransaction(tx, b.chain.CurrentBlock(), b.signer(), opts); err != nil {
		return err
	}
	if _, err := types.Sender(b.signer(), tx); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sent = append(b.sent, tx)
	return nil
}

// mine imports a block on the head of the chain that holds txs, and returns
// their receipts. The chain verifies the signatures of the block. The chain
// maker binds account transactions to the genesis only when it starts there,
// so the blocks are made again from the genesis; those the chain has are the
// same blocks.
func (b *accountTestBackend) mine(t *testing.T, txs ...*types.Transaction) types.Receipts {
	t.Helper()
	b.mined = append(b.mined, txs)
	blocks, receipts := core.GenerateChain(b.chain.Config(), b.chain.Genesis(), b.engine, b.db, len(b.mined), func(i int, g *core.BlockGen) {
		g.SetPoS()
		for _, tx := range b.mined[i] {
			g.AddTx(tx)
		}
	})
	if n, err := b.chain.InsertChain(blocks); err != nil {
		t.Fatalf("block %d of the signed transactions refused: %v", n, err)
	}
	if head := b.chain.CurrentBlock(); head.Hash() != blocks[len(blocks)-1].Hash() {
		t.Fatalf("chain head %d is not the mined block", head.Number)
	}
	last := receipts[len(receipts)-1]
	for i, r := range last {
		if r.Status != types.ReceiptStatusSuccessful {
			t.Fatalf("transaction %d failed in the block", i)
		}
	}
	return last
}

// client serves the node's APIs over an in-process connection.
func (b *accountTestBackend) client(t *testing.T) *rpc.Client {
	t.Helper()
	server := rpc.NewServer()
	for _, api := range GetAPIs(b) {
		if err := server.RegisterName(api.Namespace, api.Service); err != nil {
			t.Fatal(err)
		}
	}
	client := rpc.DialInProc(server)
	t.Cleanup(func() {
		client.Close()
		server.Stop()
	})
	return client
}

// checkAccountTx checks that tx is an ML-DSA-44 account transaction of the
// keystore account that the signer of the chain verifies.
func checkAccountTx(t *testing.T, b *accountTestBackend, tx *types.Transaction) {
	t.Helper()
	if tx.Type() != types.GhostAccountTxType {
		t.Fatalf("transaction of type %#x, want %#x", tx.Type(), types.GhostAccountTxType)
	}
	scheme, publicKey, _, _ := tx.GhostAccountAuth()
	if scheme != types.GhostSchemeMLDSA44 || types.GhostAccountAddressOf(scheme, publicKey) != b.qacc.Address {
		t.Fatalf("transaction of scheme %#04x is not of the keystore account", scheme)
	}
	if from, err := types.Sender(b.signer(), tx); err != nil || from != b.qacc.Address {
		t.Fatalf("transaction has sender %x (error %v), want %x", from, err, b.qacc.Address)
	}
}

// TestPersonalSignTransactionAccountTx checks that personal_signTransaction
// signs an account transaction with the password of the keystore account,
// that the chain imports a block that holds it, and that a wrong password
// signs nothing.
func TestPersonalSignTransactionAccountTx(t *testing.T) {
	b := newAccountTestBackend(t)
	client := b.client(t)

	to := common.Address{0xaa}
	args := map[string]interface{}{
		"from":                 b.qacc.Address,
		"to":                   to,
		"value":                "0x3e8",
		"nonce":                "0x0",
		"gas":                  hexutil.Uint64(100000),
		"maxFeePerGas":         (*hexutil.Big)(big.NewInt(2 * vars.GWei)),
		"maxPriorityFeePerGas": "0x1",
	}
	var res struct {
		Raw hexutil.Bytes   `json:"raw"`
		Tx  json.RawMessage `json:"tx"`
	}
	if err := client.Call(&res, "personal_signTransaction", args, ""); err != nil {
		t.Fatalf("personal_signTransaction: %v", err)
	}
	tx := new(types.Transaction)
	if err := tx.UnmarshalBinary(res.Raw); err != nil {
		t.Fatalf("raw transaction does not decode: %v", err)
	}
	checkAccountTx(t, b, tx)
	var fromJSON types.Transaction
	if err := fromJSON.UnmarshalJSON(res.Tx); err != nil || fromJSON.Hash() != tx.Hash() {
		t.Fatalf("transaction in JSON has hash %x (error %v), want %x", fromJSON.Hash(), err, tx.Hash())
	}
	if *tx.To() != to || tx.Value().Uint64() != 1000 || tx.Nonce() != 0 || tx.Gas() != 100000 {
		t.Fatalf("transaction does not carry the given fields")
	}
	// The node takes it into its pool and into a block.
	if err := b.SendTx(context.Background(), tx); err != nil {
		t.Fatalf("pool refused the signed transaction: %v", err)
	}
	b.mine(t, tx)
	state, err := b.chain.State()
	if err != nil {
		t.Fatal(err)
	}
	if nonce := state.GetNonce(b.qacc.Address); nonce != 1 {
		t.Fatalf("account nonce %d after the block, want 1", nonce)
	}

	// A wrong password signs nothing.
	err = client.Call(&res, "personal_signTransaction", args, "wrong")
	if err == nil || !strings.Contains(err.Error(), keystore.ErrDecrypt.Error()) {
		t.Fatalf("personal_signTransaction with a wrong password: error %v, want %v", err, keystore.ErrDecrypt)
	}
}

// TestEthSendTransactionAccountTx checks that eth_sendTransaction, with the
// keystore account unlocked and the gas left to the node, submits an account
// transaction that the pool takes and the chain imports in a block, and that
// eth_signTransaction signs one as well.
func TestEthSendTransactionAccountTx(t *testing.T) {
	b := newAccountTestBackend(t)
	client := b.client(t)

	to := common.Address{0xbb}
	var hash common.Hash
	if err := client.Call(&hash, "eth_sendTransaction", map[string]interface{}{
		"from":  b.qacc.Address,
		"to":    to,
		"value": "0x7",
	}); err != nil {
		t.Fatalf("eth_sendTransaction: %v", err)
	}
	b.mu.Lock()
	sent := b.sent
	b.mu.Unlock()
	if len(sent) != 1 || sent[0].Hash() != hash {
		t.Fatalf("pool took %d transactions, want the one of hash %x", len(sent), hash)
	}
	tx := sent[0]
	checkAccountTx(t, b, tx)
	if want := vars.TxGas + accountTxExtraGas; tx.Gas() < want {
		t.Fatalf("estimated gas %d is below the %d of an account transfer", tx.Gas(), want)
	}
	b.mine(t, tx)

	// eth_signTransaction signs the next one with the unlocked key.
	var res struct {
		Raw hexutil.Bytes `json:"raw"`
	}
	if err := client.Call(&res, "eth_signTransaction", map[string]interface{}{
		"from":     b.qacc.Address,
		"to":       to,
		"nonce":    "0x1",
		"gas":      hexutil.Uint64(100000),
		"gasPrice": (*hexutil.Big)(big.NewInt(2 * vars.GWei)),
	}); err != nil {
		t.Fatalf("eth_signTransaction: %v", err)
	}
	signed := new(types.Transaction)
	if err := signed.UnmarshalBinary(res.Raw); err != nil {
		t.Fatal(err)
	}
	checkAccountTx(t, b, signed)
	b.mine(t, signed)

	// A locked account signs nothing.
	if err := b.accman.Backends(keystore.KeyStoreType)[0].(*keystore.KeyStore).Lock(b.qacc.Address); err != nil {
		t.Fatal(err)
	}
	err := client.Call(&hash, "eth_sendTransaction", map[string]interface{}{"from": b.qacc.Address, "to": to, "value": "0x7"})
	if err == nil || !strings.Contains(err.Error(), "unlock") {
		t.Fatalf("eth_sendTransaction with a locked account: error %v, want it locked", err)
	}
}

// TestRemovedSigningMethodsAreNotServed checks that eth_sign, personal_sign
// and personal_ecRecover, which sign or recover secp256k1 message
// signatures, are not served, and that the account methods that stay are.
func TestRemovedSigningMethodsAreNotServed(t *testing.T) {
	b := newAccountTestBackend(t)
	client := b.client(t)
	addr := b.qacc.Address

	removed := []struct {
		method string
		args   []interface{}
	}{
		{"eth_sign", []interface{}{addr, "0x00"}},
		{"personal_sign", []interface{}{"0x00", addr, ""}},
		{"personal_ecRecover", []interface{}{"0x00", "0x" + strings.Repeat("00", 65)}},
	}
	for _, m := range removed {
		var res interface{}
		err := client.Call(&res, m.method, m.args...)
		var rpcErr rpc.Error
		if !errors.As(err, &rpcErr) || rpcErr.ErrorCode() != -32601 {
			t.Errorf("%s: error %v, want the method not found error -32601", m.method, err)
		}
	}

	// The methods that stay are served.
	var listed []common.Address
	if err := client.Call(&listed, "eth_accounts"); err != nil || len(listed) != 1 || listed[0] != addr {
		t.Fatalf("eth_accounts: %v (error %v), want [%x]", listed, err, addr)
	}
	var created common.Address
	if err := client.Call(&created, "personal_newAccount", "new password"); err != nil {
		t.Fatalf("personal_newAccount: %v", err)
	}
	var seed [mldsa44.SeedSize]byte
	seed[0] = 0x77
	pub, _ := mldsa44.NewKeyFromSeed(&seed)
	var imported common.Address
	if err := client.Call(&imported, "personal_importRawKey", hex.EncodeToString(seed[:]), "import password"); err != nil {
		t.Fatalf("personal_importRawKey: %v", err)
	}
	if want := types.GhostAccountAddressOf(types.GhostSchemeMLDSA44, pub.Bytes()); imported != want {
		t.Fatalf("personal_importRawKey gave %x, want the address of the seed %x", imported, want)
	}
	var ignored common.Address
	if err := client.Call(&ignored, "personal_importRawKey", hex.EncodeToString(seed[:31]), "import password"); err == nil {
		t.Fatal("personal_importRawKey took a seed of 31 bytes")
	}
	if err := client.Call(&listed, "personal_listAccounts"); err != nil || len(listed) != 3 {
		t.Fatalf("personal_listAccounts: %v (error %v), want 3 accounts", listed, err)
	}
	for _, want := range []common.Address{addr, created, imported} {
		found := false
		for _, a := range listed {
			found = found || a == want
		}
		if !found {
			t.Fatalf("personal_listAccounts %v lacks %x", listed, want)
		}
	}
	var ok bool
	if err := client.Call(&ok, "personal_unlockAccount", created, "new password", 60); err != nil || !ok {
		t.Fatalf("personal_unlockAccount: %v (error %v)", ok, err)
	}
	ok = false
	if err := client.Call(&ok, "personal_unlockAccount", imported, "wrong", 60); err == nil || ok {
		t.Fatal("personal_unlockAccount unlocked with a wrong password")
	}
	if err := client.Call(&ok, "personal_lockAccount", created); err != nil || !ok {
		t.Fatalf("personal_lockAccount: %v (error %v)", ok, err)
	}
}

// TestRPCTransactionShowsSchemeAndPublicKey checks that an account
// transaction in an RPC response, mined or pending, carries its scheme as two
// bytes, its public key and its signature, has its from derived from the
// scheme and the public key, and has no v, r, s or yParity; and that the
// receipt's from is the derived address.
func TestRPCTransactionShowsSchemeAndPublicKey(t *testing.T) {
	b := newAccountTestBackend(t)
	client := b.client(t)

	ks := b.accman.Backends(keystore.KeyStoreType)[0].(*keystore.KeyStore)
	tx, err := ks.SignAccountTx(b.qacc, b.signer(), &types.GhostAccountTx{
		ChainID:   b.chain.Config().GetChainID(),
		Nonce:     0,
		GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(2 * vars.GWei),
		Gas:       100000,
		To:        &common.Address{0xcc},
		Value:     big.NewInt(5),
	})
	if err != nil {
		t.Fatal(err)
	}
	scheme, publicKey, signature, _ := tx.GhostAccountAuth()
	derived := types.GhostAccountAddressOf(scheme, publicKey)
	if derived != b.qacc.Address || derived == (common.Address{}) {
		t.Fatalf("derived address %x, want the account %x", derived, b.qacc.Address)
	}

	check := func(name string, raw []byte) {
		t.Helper()
		var fields map[string]interface{}
		if err := json.Unmarshal(raw, &fields); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if fields["type"] != "0x52" || fields["hash"] != tx.Hash().Hex() {
			t.Fatalf("%s: type %v, hash %v, want 0x52 and %s", name, fields["type"], fields["hash"], tx.Hash().Hex())
		}
		if fields["scheme"] != "0x0001" {
			t.Fatalf("%s: scheme %v, want 0x0001", name, fields["scheme"])
		}
		if fields["publicKey"] != hexutil.Encode(publicKey) || len(publicKey) != types.GhostMLDSA44PublicKeySize {
			t.Fatalf("%s: publicKey is not the public key of the transaction", name)
		}
		if fields["signature"] != hexutil.Encode(signature) {
			t.Fatalf("%s: signature is not the signature of the transaction", name)
		}
		from, _ := fields["from"].(string)
		if common.HexToAddress(from) != derived {
			t.Fatalf("%s: from %v, want the derived %x", name, fields["from"], derived)
		}
		for _, absent := range []string{"v", "r", "s", "yParity"} {
			if _, ok := fields[absent]; ok {
				t.Fatalf("%s: carries %s", name, absent)
			}
		}
		// The response decodes back to the transaction.
		var dec RPCTransaction
		if err := json.Unmarshal(raw, &dec); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if dec.Scheme == nil || !bytes.Equal(*dec.Scheme, []byte{0x00, 0x01}) || dec.PublicKey == nil || !bytes.Equal(*dec.PublicKey, publicKey) {
			t.Fatalf("%s: scheme and public key do not decode", name)
		}
	}

	// Pending.
	pending, err := json.Marshal(NewRPCPendingTransaction(tx, b.chain.CurrentBlock(), b.chain.Config()))
	if err != nil {
		t.Fatal(err)
	}
	check("pending transaction", pending)

	// Mined, by hash and in its block.
	b.mine(t, tx)
	var byHash json.RawMessage
	if err := client.Call(&byHash, "eth_getTransactionByHash", tx.Hash()); err != nil {
		t.Fatal(err)
	}
	check("eth_getTransactionByHash", byHash)
	var block struct {
		Transactions []json.RawMessage `json:"transactions"`
	}
	if err := client.Call(&block, "eth_getBlockByNumber", "0x1", true); err != nil {
		t.Fatal(err)
	}
	if len(block.Transactions) != 1 {
		t.Fatalf("block has %d transactions, want 1", len(block.Transactions))
	}
	check("eth_getBlockByNumber", block.Transactions[0])

	var receipt map[string]interface{}
	if err := client.Call(&receipt, "eth_getTransactionReceipt", tx.Hash()); err != nil {
		t.Fatal(err)
	}
	if from, _ := receipt["from"].(string); common.HexToAddress(from) != derived {
		t.Fatalf("receipt from %v, want the derived %x", receipt["from"], derived)
	}

	// A secp256k1 transaction of type 0 keeps v, r and s and has no scheme.
	typeZero := newRPCTransaction(types.NewTx(&types.LegacyTx{Gas: 21000, GasPrice: big.NewInt(1), V: big.NewInt(27), R: big.NewInt(1), S: big.NewInt(1)}), common.Hash{}, 0, 0, 0, nil, b.chain.Config())
	raw, err := json.Marshal(typeZero)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]interface{}
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"v", "r", "s"} {
		if _, ok := fields[key]; !ok {
			t.Fatalf("type 0 transaction lacks %s", key)
		}
	}
	if _, ok := fields["scheme"]; ok {
		t.Fatal("type 0 transaction carries a scheme")
	}
}
