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
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/txpool/legacypool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/internal/web3ext"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
	"github.com/ethereum/go-ethereum/params/vars"
	"github.com/ethereum/go-ethereum/rpc"
)

// accountTxBackend is the test backend with its transactions sent to a
// legacy pool on its chain, which takes account transactions.
type accountTxBackend struct {
	*testBackend
	pool *legacypool.LegacyPool
	sent []*types.Transaction
}

func (b *accountTxBackend) SendTx(ctx context.Context, tx *types.Transaction) error {
	if err := b.pool.Add([]*types.Transaction{tx}, true, true)[0]; err != nil {
		return err
	}
	b.sent = append(b.sent, tx)
	return nil
}

func (b *accountTxBackend) GetPoolNonce(ctx context.Context, addr common.Address) (uint64, error) {
	return b.pool.Nonce(addr), nil
}

func (b *accountTxBackend) GetPoolTransaction(hash common.Hash) *types.Transaction {
	return b.pool.Get(hash)
}

func (b *accountTxBackend) GetPoolTransactions() (types.Transactions, error) {
	var txs types.Transactions
	for _, tx := range b.sent {
		if b.pool.Get(tx.Hash()) != nil {
			txs = append(txs, tx)
		}
	}
	return txs, nil
}

// newAccountTxBackend returns a test backend of one block, whose keystore
// account (the ML-DSA-44 account of testAccountSeed) is funded at genesis.
// gen, if set, adds the transactions of block 1.
func newAccountTxBackend(t *testing.T, gen func(gspec *genesisT.Genesis, b *core.BlockGen)) *accountTxBackend {
	t.Helper()
	gspec := &genesisT.Genesis{
		Config:  params.TestChainConfig,
		Alloc:   genesisT.GenesisAlloc{},
		BaseFee: big.NewInt(vars.InitialBaseFee),
	}
	tb := newTestBackend(t, 1, gspec, ethash.NewFaker(), func(i int, b *core.BlockGen) {
		if gen != nil {
			gen(gspec, b)
		}
	})
	t.Cleanup(tb.chain.Stop)
	// No journal: each test's pool starts empty and writes no file.
	config := legacypool.DefaultConfig
	config.Journal = ""
	pool := legacypool.New(config, tb.chain)
	if err := pool.Init(0, tb.chain.CurrentBlock(), func(common.Address, bool) error { return nil }); err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	return &accountTxBackend{testBackend: tb, pool: pool}
}

// checkAccountTx checks that tx is an ML-DSA-44 account transaction carrying
// publicKey, whose sender, derived from the scheme and public key and with a
// signature that verifies for the backend's chain, is want.
func checkAccountTx(t *testing.T, b *accountTxBackend, tx *types.Transaction, publicKey []byte, want common.Address) {
	t.Helper()
	if tx.Type() != types.GhostAccountTxType {
		t.Fatalf("transaction of type %#x, want an account transaction", tx.Type())
	}
	scheme, pub, _, _ := tx.GhostAccountAuth()
	if scheme != types.GhostSchemeMLDSA44 {
		t.Errorf("scheme %#04x, want ML-DSA-44", scheme)
	}
	if publicKey != nil && !bytes.Equal(pub, publicKey) {
		t.Errorf("public key is not the account's")
	}
	if derived := types.GhostAccountAddressOf(scheme, pub); derived != want {
		t.Errorf("derived sender %v, want %v", derived, want)
	}
	signer := types.NewGhostAccountSigner(types.LatestSigner(b.chain.Config()), b.chain.Genesis().Hash())
	from, err := types.Sender(signer, tx)
	if err != nil {
		t.Fatalf("sender: %v", err)
	}
	if from != want {
		t.Errorf("sender %v, want %v", from, want)
	}
}

// decodeSigned decodes the raw transaction of a signing result, which must be
// the result's transaction.
func decodeSigned(t *testing.T, res *SignTransactionResult) *types.Transaction {
	t.Helper()
	tx := new(types.Transaction)
	if err := tx.UnmarshalBinary(res.Raw); err != nil {
		t.Fatalf("decode signed transaction: %v", err)
	}
	if tx.Hash() != res.Tx.Hash() {
		t.Fatalf("raw transaction %v is not the result's transaction %v", tx.Hash(), res.Tx.Hash())
	}
	return tx
}

// waitForAccount waits until the account manager, which learns of new
// keystore accounts by an event, has the account.
func waitForAccount(t *testing.T, b *accountTxBackend, addr common.Address) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if _, err := b.AccountManager().Find(accounts.Account{Address: addr}); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("account manager does not have the account %v", addr)
		}
	}
}

var accountTxRecipient = common.HexToAddress("0x5252525252525252525252525252525252525252")

// signArgs returns the arguments of a transfer from from with every field the
// signing methods require set.
func signArgs(from common.Address, nonce uint64) TransactionArgs {
	gas := hexutil.Uint64(accountSenderGas)
	n := hexutil.Uint64(nonce)
	return TransactionArgs{
		From:                 &from,
		To:                   &accountTxRecipient,
		Gas:                  &gas,
		MaxFeePerGas:         (*hexutil.Big)(big.NewInt(100 * vars.GWei)),
		MaxPriorityFeePerGas: (*hexutil.Big)(big.NewInt(vars.GWei)),
		Value:                (*hexutil.Big)(big.NewInt(1000)),
		Nonce:                &n,
	}
}

// TestPersonalSignTransactionAccountTx checks that personal_signTransaction
// and personal_sendTransaction sign account transactions with the keystore's
// ML-DSA-44 keys, that the node accepts them and that their sender is the
// account, and that personal_newAccount and personal_importRawKey hold
// ML-DSA-44 keys.
func TestPersonalSignTransactionAccountTx(t *testing.T) {
	t.Parallel()

	b := newAccountTxBackend(t, nil)
	_, pub, addr := testAccount(testAccountSeed[0])
	if b.acc.Address != addr {
		t.Fatalf("keystore account %v, want the ML-DSA-44 account %v of the seed", b.acc.Address, addr)
	}
	api := NewPersonalAccountAPI(b, new(AddrLocker))
	ctx := context.Background()

	// personal_signTransaction.
	res, err := api.SignTransaction(ctx, signArgs(addr, 0), "")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	signed := decodeSigned(t, res)
	checkAccountTx(t, b, signed, pub, addr)
	if signed.Gas() != accountSenderGas || signed.Nonce() != 0 || signed.Value().Cmp(big.NewInt(1000)) != 0 || *signed.To() != accountTxRecipient {
		t.Errorf("signed transaction gas %d, nonce %d, value %v, to %v: not the arguments", signed.Gas(), signed.Nonce(), signed.Value(), signed.To())
	}
	if err := b.SendTx(ctx, signed); err != nil {
		t.Fatalf("node refuses the signed transaction: %v", err)
	}
	if b.pool.Get(signed.Hash()) == nil {
		t.Fatal("signed transaction not in the pool")
	}

	// A wrong passphrase, and a blob transaction, are refused.
	if _, err := api.SignTransaction(ctx, signArgs(addr, 1), "wrong"); err == nil || !strings.Contains(err.Error(), "could not decrypt") {
		t.Errorf("wrong passphrase: error %v, want could not decrypt", err)
	}
	blobArgs := signArgs(addr, 1)
	blobArgs.BlobHashes = []common.Hash{{0x01, 0x22}}
	if _, err := api.SignTransaction(ctx, blobArgs, ""); !errors.Is(err, errBlobTxNotSupported) {
		t.Errorf("blob transaction: error %v, want %v", err, errBlobTxNotSupported)
	}

	// personal_sendTransaction fills in the nonce and the gas, the signature
	// gas included.
	hash, err := api.SendTransaction(ctx, TransactionArgs{From: &addr, To: &accountTxRecipient, Value: (*hexutil.Big)(big.NewInt(7))}, "")
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	sent := b.pool.Get(hash)
	if sent == nil {
		t.Fatal("sent transaction not in the pool")
	}
	checkAccountTx(t, b, sent, pub, addr)
	if sent.Nonce() != 1 {
		t.Errorf("sent transaction nonce %d, want 1", sent.Nonce())
	}
	if want := vars.TxGas + accountTxSigGas; sent.Gas() != want {
		t.Errorf("sent transaction gas %d, want %d", sent.Gas(), want)
	}

	// personal_importRawKey takes a 32-byte seed in hex.
	seed := bytes.Repeat([]byte{0x77}, len(testAccountSeed))
	_, importedPub, importedAddr := testAccount(0x77)
	imported, err := api.ImportRawKey(hex.EncodeToString(seed), "pw")
	if err != nil {
		t.Fatalf("import seed: %v", err)
	}
	if imported != importedAddr {
		t.Errorf("imported account %v, want the ML-DSA-44 account %v of the seed", imported, importedAddr)
	}
	if _, err := api.ImportRawKey(hex.EncodeToString(seed[1:]), "pw"); err == nil || !strings.Contains(err.Error(), "seed is 32 bytes") {
		t.Errorf("31-byte seed: error %v, want the seed size error", err)
	}
	if _, err := api.ImportRawKey("not hex", "pw"); err == nil {
		t.Error("seed that is not hex imported")
	}
	waitForAccount(t, b, imported)
	res, err = api.SignTransaction(ctx, signArgs(imported, 0), "pw")
	if err != nil {
		t.Fatalf("sign with the imported account: %v", err)
	}
	checkAccountTx(t, b, decodeSigned(t, res), importedPub, importedAddr)

	// personal_newAccount creates an ML-DSA-44 account.
	created, err := api.NewAccount("pw")
	if err != nil {
		t.Fatalf("new account: %v", err)
	}
	createdAddr := common.Address(created)
	waitForAccount(t, b, createdAddr)
	res, err = api.SignTransaction(ctx, signArgs(createdAddr, 0), "pw")
	if err != nil {
		t.Fatalf("sign with the new account: %v", err)
	}
	checkAccountTx(t, b, decodeSigned(t, res), nil, createdAddr)
}

// TestEthSendTransactionAccountTx checks that eth_sendTransaction,
// eth_signTransaction and eth_resend sign account transactions with the
// unlocked ML-DSA-44 key, that the node accepts them and that their sender is
// the account.
func TestEthSendTransactionAccountTx(t *testing.T) {
	t.Parallel()

	b := newAccountTxBackend(t, nil)
	_, pub, addr := testAccount(testAccountSeed[0])
	api := NewTransactionAPI(b, new(AddrLocker))
	ctx := context.Background()

	// eth_sendTransaction estimates the gas and adds the signature gas.
	value := (*hexutil.Big)(big.NewInt(1000))
	hash, err := api.SendTransaction(ctx, TransactionArgs{From: &addr, To: &accountTxRecipient, Value: value})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	sent := b.pool.Get(hash)
	if sent == nil {
		t.Fatal("sent transaction not in the pool")
	}
	checkAccountTx(t, b, sent, pub, addr)
	if want := vars.TxGas + accountTxSigGas; sent.Gas() != want {
		t.Errorf("sent transaction gas %d, want %d", sent.Gas(), want)
	}
	if sent.Nonce() != 0 {
		t.Errorf("sent transaction nonce %d, want 0", sent.Nonce())
	}

	// eth_signTransaction.
	res, err := api.SignTransaction(ctx, signArgs(addr, 1))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	signed := decodeSigned(t, res)
	checkAccountTx(t, b, signed, pub, addr)
	if err := b.SendTx(ctx, signed); err != nil {
		t.Fatalf("node refuses the signed transaction: %v", err)
	}

	// eth_resend replaces the sent transaction with one of a higher price.
	nonce := hexutil.Uint64(0)
	resendArgs := TransactionArgs{From: &addr, To: &accountTxRecipient, Value: value, Nonce: &nonce}
	price := (*hexutil.Big)(new(big.Int).Mul(sent.GasFeeCap(), big.NewInt(2)))
	other := resendArgs
	other.Value = (*hexutil.Big)(big.NewInt(1001))
	if _, err := api.Resend(ctx, other, price, nil); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("resend of a transaction not sent: error %v, want not found", err)
	}
	replacedHash, err := api.Resend(ctx, resendArgs, price, nil)
	if err != nil {
		t.Fatalf("resend: %v", err)
	}
	replaced := b.pool.Get(replacedHash)
	if replaced == nil {
		t.Fatal("resent transaction not in the pool")
	}
	checkAccountTx(t, b, replaced, pub, addr)
	if replaced.Nonce() != 0 || replaced.GasFeeCap().Cmp(price.ToInt()) != 0 || replaced.GasTipCap().Cmp(price.ToInt()) != 0 {
		t.Errorf("resent transaction nonce %d, fee cap %v, tip cap %v, want 0 and %v", replaced.Nonce(), replaced.GasFeeCap(), replaced.GasTipCap(), price)
	}
	if b.pool.Get(hash) != nil {
		t.Error("the replaced transaction is still in the pool")
	}

	// A blob transaction is refused.
	if _, err := api.SendTransaction(ctx, TransactionArgs{From: &addr, To: &accountTxRecipient, BlobHashes: []common.Hash{{0x01, 0x22}}}); !errors.Is(err, errBlobTxNotSupported) {
		t.Errorf("blob transaction: error %v, want %v", err, errBlobTxNotSupported)
	}
}

// TestRemovedSigningMethodsAreNotServed checks that eth_sign, personal_sign
// and personal_ecRecover are neither served nor in the console's extensions,
// while the transaction signing methods are.
func TestRemovedSigningMethodsAreNotServed(t *testing.T) {
	t.Parallel()

	b := newAccountTxBackend(t, nil)
	server := rpc.NewServer()
	defer server.Stop()
	for _, api := range GetAPIs(b) {
		if err := server.RegisterName(api.Namespace, api.Service); err != nil {
			t.Fatalf("register %s: %v", api.Namespace, err)
		}
	}
	client := rpc.DialInProc(server)
	defer client.Close()

	addr := b.acc.Address
	removed := map[string][]interface{}{
		"eth_sign":           {addr, hexutil.Bytes("message")},
		"personal_sign":      {hexutil.Bytes("message"), addr, ""},
		"personal_ecRecover": {hexutil.Bytes("message"), hexutil.Bytes(make([]byte, 65))},
	}
	for method, params := range removed {
		var result interface{}
		err := client.Call(&result, method, params...)
		var rpcErr rpc.Error
		if !errors.As(err, &rpcErr) || rpcErr.ErrorCode() != -32601 {
			t.Errorf("%s: error %v, want method not found", method, err)
		}
	}
	for ns, js := range web3ext.Modules {
		for method := range removed {
			if strings.Contains(js, "'"+method+"'") {
				t.Errorf("console extension %s still has %s", ns, method)
			}
		}
	}

	// The signing methods are still served.
	var listed []common.Address
	if err := client.Call(&listed, "personal_listAccounts"); err != nil || len(listed) != 1 || listed[0] != addr {
		t.Errorf("personal_listAccounts: %v, %v", listed, err)
	}
	var res SignTransactionResult
	if err := client.Call(&res, "eth_signTransaction", signArgs(addr, 0)); err != nil {
		t.Fatalf("eth_signTransaction: %v", err)
	}
	checkAccountTx(t, b, decodeSigned(t, &res), nil, addr)
}

// checkAccountTxJSON checks the JSON object of an account transaction or its
// receipt: from is the account, the scheme is 2 bytes and the public key the
// account's, and there are no v, r, s, yParity or signature.
func checkAccountTxJSON(t *testing.T, name string, v interface{}, pub []byte, addr common.Address) {
	t.Helper()
	enc, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	var fields map[string]interface{}
	if err := json.Unmarshal(enc, &fields); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if fields["scheme"] != "0x0001" {
		t.Errorf("%s: scheme %v, want 0x0001", name, fields["scheme"])
	}
	if fields["publicKey"] != hexutil.Encode(pub) {
		t.Errorf("%s: publicKey is not the account's", name)
	}
	if from, _ := fields["from"].(string); !strings.EqualFold(from, addr.Hex()) {
		t.Errorf("%s: from %v, want %v", name, fields["from"], addr)
	}
	for _, key := range []string{"v", "r", "s", "yParity", "signature"} {
		if _, ok := fields[key]; ok {
			t.Errorf("%s: has %s", name, key)
		}
	}
}

// TestRPCTransactionShowsSchemeAndPublicKey checks the JSON of a mined
// account transaction, of a block with full transactions, of its receipt and
// of a pending account transaction.
func TestRPCTransactionShowsSchemeAndPublicKey(t *testing.T) {
	t.Parallel()

	key, pub, addr := testAccount(testAccountSeed[0])
	var mined *types.Transaction
	b := newAccountTxBackend(t, func(gspec *genesisT.Genesis, bg *core.BlockGen) {
		signer := types.NewGhostAccountSigner(types.LatestSigner(gspec.Config), core.GenesisToBlock(gspec, nil).Hash())
		tx, err := types.SignGhostAccountTx(signer, key, &types.GhostAccountTx{
			ChainID:   gspec.Config.GetChainID(),
			GasTipCap: big.NewInt(vars.GWei),
			GasFeeCap: big.NewInt(100 * vars.GWei),
			Gas:       accountSenderGas,
			To:        &accountTxRecipient,
			Value:     big.NewInt(1000),
		})
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		mined = tx
		bg.AddTx(tx)
	})
	ctx := context.Background()
	chainAPI := NewBlockChainAPI(b)
	txAPI := NewTransactionAPI(b, new(AddrLocker))

	rpcTx, err := txAPI.GetTransactionByHash(ctx, mined.Hash())
	if err != nil || rpcTx == nil {
		t.Fatalf("transaction by hash: %v, %v", rpcTx, err)
	}
	checkAccountTxJSON(t, "transaction", rpcTx, pub, addr)

	block, err := chainAPI.GetBlockByNumber(ctx, 1, true)
	if err != nil {
		t.Fatalf("block: %v", err)
	}
	enc, err := json.Marshal(block)
	if err != nil {
		t.Fatal(err)
	}
	var full struct {
		Transactions []json.RawMessage `json:"transactions"`
	}
	if err := json.Unmarshal(enc, &full); err != nil {
		t.Fatal(err)
	}
	if len(full.Transactions) != 1 {
		t.Fatalf("block has %d transactions, want 1", len(full.Transactions))
	}
	checkAccountTxJSON(t, "block transaction", full.Transactions[0], pub, addr)

	receipt, err := txAPI.GetTransactionReceipt(ctx, mined.Hash())
	if err != nil || receipt == nil {
		t.Fatalf("receipt: %v, %v", receipt, err)
	}
	checkAccountTxJSON(t, "receipt", receipt, pub, addr)

	// A pending account transaction, as a subscription shows it, has its
	// from derived without a signer.
	pending := NewRPCPendingTransaction(mined, b.chain.CurrentHeader(), b.chain.Config())
	checkAccountTxJSON(t, "pending transaction", pending, pub, addr)
}
