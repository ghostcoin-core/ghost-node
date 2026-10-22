// Copyright 2026 The Ghost Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"
)

// spendSecp256k1Key returns a fixed secp256k1 test key and its address. It is
// a test key only, never a launch key.
func spendSecp256k1Key(t *testing.T) (*ecdsa.PrivateKey, common.Address) {
	t.Helper()
	key, err := crypto.ToECDSA(common.LeftPadBytes([]byte{0x5e, 0xc9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return key, crypto.PubkeyToAddress(key.PublicKey)
}

// spendReceipt is the part of a receipt the spend tests read.
type spendReceipt struct {
	Status            hexutil.Uint64  `json:"status"`
	BlockHash         common.Hash     `json:"blockHash"`
	BlockNumber       hexutil.Uint64  `json:"blockNumber"`
	GasUsed           hexutil.Uint64  `json:"gasUsed"`
	EffectiveGasPrice *hexutil.Big    `json:"effectiveGasPrice"`
	ContractAddress   *common.Address `json:"contractAddress"`
}

// spendSend signs an account transaction and gives it to a node, retrying
// while the node's pool has not yet moved to the head that funds it.
func spendSend(t *testing.T, via *internalNode, key *mldsa44.PrivateKey, data *types.GhostAccountTx) *types.Transaction {
	t.Helper()
	tx, err := types.SignGhostAccountTx(internalNetSigner(), key, data)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Minute, "the "+via.name+" to take the transaction", func() (bool, error) {
		err := via.eth.SendTransaction(context.Background(), tx)
		if err != nil && strings.Contains(err.Error(), "insufficient funds") {
			return false, nil
		}
		return err == nil, err
	})
	return tx
}

// spendMined waits until every node has the transaction in the same block
// with a successful receipt, and returns the first node's receipt.
func spendMined(t *testing.T, nodes []*internalNode, hash common.Hash) *spendReceipt {
	t.Helper()
	receipts := make([]*spendReceipt, len(nodes))
	for i, n := range nodes {
		waitFor(t, 5*time.Minute, fmt.Sprintf("the %s to have transaction %x mined", n.name, hash), func() (bool, error) {
			err := n.rpc.Call(&receipts[i], "eth_getTransactionReceipt", hash)
			// A node still syncing has not indexed the transaction yet.
			if err != nil && strings.Contains(err.Error(), "transaction indexing is in progress") {
				return false, nil
			}
			if err != nil || receipts[i] == nil {
				return false, err
			}
			if uint64(receipts[i].Status) != types.ReceiptStatusSuccessful {
				return false, fmt.Errorf("transaction %x failed", hash)
			}
			return true, nil
		})
		if receipts[i].BlockHash != receipts[0].BlockHash {
			t.Fatalf("transaction %x is in block %x on the %s and %x on the %s", hash, receipts[0].BlockHash, nodes[0].name, receipts[i].BlockHash, n.name)
		}
	}
	return receipts[0]
}

// spendUnknown checks that a node knows no transaction of the hash, neither
// in its pool nor in its chain.
func spendUnknown(t *testing.T, n *internalNode, hash common.Hash, what string) {
	t.Helper()
	waitFor(t, time.Minute, fmt.Sprintf("the %s to answer for the %s", n.name, what), func() (bool, error) {
		_, _, err := n.eth.TransactionByHash(context.Background(), hash)
		if err != nil && strings.Contains(err.Error(), "transaction indexing is in progress") {
			return false, nil
		}
		if !errors.Is(err, ethereum.NotFound) {
			return false, fmt.Errorf("the %s is known to the %s: %v", what, n.name, err)
		}
		return true, nil
	})
}

// spendBlockChange returns how a block mined to account changes its balance:
// the block reward and every tip in the block are credited to it, what its own
// transactions pay and send is taken from it, and what a SELFDESTRUCT run by
// one of the transactions in sent sends to it is credited to it.
func spendBlockChange(t *testing.T, n *internalNode, number uint64, account common.Address, sent map[common.Hash]*big.Int) *big.Int {
	t.Helper()
	var block *struct {
		Miner        common.Address `json:"miner"`
		BaseFee      *hexutil.Big   `json:"baseFeePerGas"`
		Transactions []common.Hash  `json:"transactions"`
	}
	if err := n.rpc.Call(&block, "eth_getBlockByNumber", hexutil.EncodeUint64(number), false); err != nil || block == nil {
		t.Fatalf("%s: block %d: %v", n.name, number, err)
	}
	if block.Miner != account {
		t.Fatalf("%s: block %d is mined to %v, not %v", n.name, number, block.Miner, account)
	}
	change := ghost.InternalNetParams().BlockReward(number).ToBig()
	for _, hash := range block.Transactions {
		var (
			r  *spendReceipt
			tx *struct {
				From  common.Address `json:"from"`
				Value *hexutil.Big   `json:"value"`
			}
		)
		if err := n.rpc.Call(&r, "eth_getTransactionReceipt", hash); err != nil || r == nil {
			t.Fatalf("%s: receipt of %x: %v", n.name, hash, err)
		}
		if err := n.rpc.Call(&tx, "eth_getTransactionByHash", hash); err != nil || tx == nil {
			t.Fatalf("%s: transaction %x: %v", n.name, hash, err)
		}
		gas := new(big.Int).SetUint64(uint64(r.GasUsed))
		price := r.EffectiveGasPrice.ToInt()
		tip := new(big.Int).Sub(price, block.BaseFee.ToInt())
		if tip.Sign() <= 0 {
			t.Fatalf("%s: transaction %x pays no tip", n.name, hash)
		}
		change.Add(change, tip.Mul(tip, gas))
		if tx.From == account {
			change.Sub(change, gas.Mul(gas, price))
			change.Sub(change, tx.Value.ToInt())
		}
		if v, ok := sent[hash]; ok {
			change.Add(change, v)
		}
	}
	return change
}

// spendSetCodeTx returns the envelope of an EIP-7702 (type 0x04) transfer
// signed with key, which the node does not decode.
func spendSetCodeTx(t *testing.T, key *ecdsa.PrivateKey, to common.Address, price *big.Int) []byte {
	t.Helper()
	chainID := big.NewInt(ghost.InternalNetChainID)
	fields := []interface{}{chainID, uint64(0), price, price, uint64(21_000), to, big.NewInt(1), []byte{}, types.AccessList{}, []interface{}{}}
	payload, err := rlp.EncodeToBytes(fields)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := crypto.Sign(crypto.Keccak256(append([]byte{0x04}, payload...)), key)
	if err != nil {
		t.Fatal(err)
	}
	if payload, err = rlp.EncodeToBytes(append(fields, uint64(sig[64]), new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:64]))); err != nil {
		t.Fatal(err)
	}
	return append([]byte{0x04}, payload...)
}

// TestInternalNetGenesisAllocationStaysEmpty checks that the internal network
// gives no account any funds at genesis: InternalNetGenesis and the genesis of
// scripts/internal-net.sh allocate nothing, the genesis state is empty, and a
// node started from it shows no balance for the test accounts at block 0.
func TestInternalNetGenesisAllocationStaysEmpty(t *testing.T) {
	g := ghost.InternalNetGenesis()
	if len(g.Alloc) != 0 {
		t.Fatalf("InternalNetGenesis allocates %d accounts", len(g.Alloc))
	}
	genesis := core.GenesisToBlock(g, nil)
	if genesis.Root() != types.EmptyRootHash {
		t.Fatalf("the genesis state root is %x, want the empty root %x", genesis.Root(), types.EmptyRootHash)
	}

	script, err := os.ReadFile(filepath.Join("..", "..", "scripts", "internal-net.sh"))
	if err != nil {
		t.Fatal(err)
	}
	const open, end = "<<'GENESIS'\n", "\nGENESIS\n"
	text := string(script)
	start := strings.Index(text, open)
	if start < 0 {
		t.Fatal("the script has no genesis document")
	}
	body := text[start+len(open):]
	stop := strings.Index(body, end)
	if stop < 0 {
		t.Fatal("the script's genesis document does not end")
	}
	var fromScript genesisT.Genesis
	if err := json.Unmarshal([]byte(body[:stop]), &fromScript); err != nil {
		t.Fatalf("the script's genesis does not parse: %v", err)
	}
	if len(fromScript.Alloc) != 0 {
		t.Fatalf("the script's genesis allocates %d accounts", len(fromScript.Alloc))
	}

	node := startInternalNode(t, "node", initDatadir(t, writeGenesis(t, g)))
	var block0 *struct {
		Hash      common.Hash `json:"hash"`
		StateRoot common.Hash `json:"stateRoot"`
	}
	if err := node.rpc.Call(&block0, "eth_getBlockByNumber", "0x0", false); err != nil || block0 == nil {
		t.Fatalf("block 0: %v", err)
	}
	if block0.Hash != genesis.Hash() || block0.StateRoot != types.EmptyRootHash {
		t.Fatalf("the node's block 0 is %x with state root %x, want %x with the empty root", block0.Hash, block0.StateRoot, genesis.Hash())
	}
	_, _, minerAccount := testAccount(minerAccountSeed)
	_, _, receiver := testAccount(receiverAccountSeed)
	_, secpAddr := spendSecp256k1Key(t)
	for _, account := range []common.Address{minerAccount, receiver, secpAddr} {
		if got := node.balance(t, account, common.Big0); got.Sign() != 0 {
			t.Errorf("%v holds %v at block 0", account, got)
		}
	}
}

// TestInternalNetCreditedFundsMoveOnlyByAccountTx runs the internal network
// with the miner mining to the account of a fixed ML-DSA-44 seed. The account
// is credited a block reward for each block, the tips of its own
// transactions, and the value a contract's SELFDESTRUCT sends to it as
// beneficiary; each block changes its balance by exactly that. The funds move
// with an account transaction signed with the account's key, and an account
// transaction carrying the account's public key but signed with another key
// is refused.
func TestInternalNetCreditedFundsMoveOnlyByAccountTx(t *testing.T) {
	miner, peer, account := startInternalNet(t)
	var (
		ctx                   = context.Background()
		nodes                 = []*internalNode{miner, peer}
		chainID               = big.NewInt(ghost.InternalNetChainID)
		key, pub, _           = testAccount(minerAccountSeed)
		otherKey, _, receiver = testAccount(receiverAccountSeed)
		ether                 = big.NewInt(1_000_000_000_000_000_000)
		gwei                  = big.NewInt(1_000_000_000)
		tip                   = new(big.Int).Mul(big.NewInt(2), gwei)
		feeCap                = new(big.Int).Mul(big.NewInt(100), gwei)
		value                 = new(big.Int).Div(ether, big.NewInt(10))
	)
	waitFor(t, 5*time.Minute, "the peer to see mined funds", func() (bool, error) {
		balance, err := peer.eth.BalanceAt(ctx, account, nil)
		return err == nil && balance.Cmp(ether) > 0, err
	})

	// Before it sends anything the account holds exactly the rewards of the
	// blocks mined to it.
	head := uint64(peer.block(t, "latest").Number)
	for _, n := range nodes {
		if got, want := n.balance(t, account, new(big.Int).SetUint64(head)), rewardsUpTo(head); got.Cmp(want) != 0 {
			t.Fatalf("%s: account balance at block %d is %v, want the rewards %v", n.name, head, got, want)
		}
	}

	// A contract that sends its whole balance to the account when called:
	// PUSH20 account, SELFDESTRUCT. Its init code, eleven bytes, copies it
	// out and returns it: PUSH1 len, DUP1, PUSH1 11, PUSH1 0, CODECOPY,
	// PUSH1 0, RETURN.
	runtime := append(append([]byte{0x73}, account.Bytes()...), 0xff)
	initCode := append([]byte{0x60, byte(len(runtime)), 0x80, 0x60, 0x0b, 0x60, 0x00, 0x39, 0x60, 0x00, 0xf3}, runtime...)
	nonce, err := miner.eth.PendingNonceAt(ctx, account)
	if err != nil {
		t.Fatal(err)
	}
	contract := crypto.CreateAddress(account, nonce)
	create := spendSend(t, miner, key, &types.GhostAccountTx{
		ChainID:   chainID,
		Nonce:     nonce,
		GasTipCap: tip,
		GasFeeCap: feeCap,
		Gas:       accountTxGas + 200_000,
		Value:     value,
		Data:      initCode,
	})
	created := spendMined(t, nodes, create.Hash())
	if created.ContractAddress == nil || *created.ContractAddress != contract {
		t.Fatalf("contract created at %v, want %v", created.ContractAddress, contract)
	}
	for _, n := range nodes {
		if got := n.balance(t, contract, new(big.Int).SetUint64(uint64(created.BlockNumber))); got.Cmp(value) != 0 {
			t.Fatalf("%s: contract holds %v, want %v", n.name, got, value)
		}
	}
	call := spendSend(t, miner, key, &types.GhostAccountTx{
		ChainID:   chainID,
		Nonce:     nonce + 1,
		GasTipCap: tip,
		GasFeeCap: feeCap,
		Gas:       accountTxGas + 50_000,
		To:        &contract,
		Value:     new(big.Int),
	})
	called := spendMined(t, nodes, call.Hash())
	for _, n := range nodes {
		if got := n.balance(t, contract, new(big.Int).SetUint64(uint64(called.BlockNumber))); got.Sign() != 0 {
			t.Fatalf("%s: contract holds %v after SELFDESTRUCT", n.name, got)
		}
	}
	// Each block holding one of the transactions changes the account's
	// balance by its reward and tips, less the transaction's cost, plus the
	// SELFDESTRUCT's value.
	sent := map[common.Hash]*big.Int{call.Hash(): value}
	for _, number := range []uint64{uint64(created.BlockNumber), uint64(called.BlockNumber)} {
		for _, n := range nodes {
			before := n.balance(t, account, new(big.Int).SetUint64(number-1))
			after := n.balance(t, account, new(big.Int).SetUint64(number))
			got := new(big.Int).Sub(after, before)
			if want := spendBlockChange(t, n, number, account, sent); got.Cmp(want) != 0 {
				t.Errorf("%s: block %d changes the account's balance by %v, want %v", n.name, number, got, want)
			}
		}
	}

	// An account transaction signed with the account's key moves the funds.
	spend := &types.GhostAccountTx{
		ChainID:   chainID,
		Nonce:     nonce + 2,
		GasTipCap: tip,
		GasFeeCap: feeCap,
		Gas:       accountTxGas,
		To:        &receiver,
		Value:     ether,
	}
	// The same transfer with the account's public key and another key's
	// signature names the account as sender, and is refused.
	other, err := types.SignGhostAccountTx(internalNetSigner(), otherKey, spend)
	if err != nil {
		t.Fatal(err)
	}
	_, _, otherSig, _ := other.GhostAccountAuth()
	forged := *spend
	forged.Scheme, forged.PublicKey, forged.Signature = types.GhostScheme(types.GhostSchemeMLDSA44), pub, otherSig
	forgedTx := types.NewTx(&forged)
	if from, err := types.GhostAccountAddress(internalNetSigner(), forgedTx); err != nil || from != account {
		t.Fatalf("the forged transfer names %v (%v), want the account %v", from, err, account)
	}
	for _, n := range nodes {
		err := n.eth.SendTransaction(ctx, forgedTx)
		if err == nil || !strings.Contains(err.Error(), "signature does not verify") {
			t.Errorf("%s: forged transfer error %v, want a refused signature", n.name, err)
		}
		spendUnknown(t, n, forgedTx.Hash(), "forged transfer")
	}

	moved := spendMined(t, nodes, spendSend(t, peer, key, spend).Hash())
	for _, n := range nodes {
		if got := n.balance(t, receiver, new(big.Int).SetUint64(uint64(moved.BlockNumber))); got.Cmp(ether) != 0 {
			t.Errorf("%s: receiver holds %v after the transfer, want %v", n.name, got, ether)
		}
		if got, err := n.eth.NonceAt(ctx, account, new(big.Int).SetUint64(uint64(moved.BlockNumber))); err != nil || got != nonce+3 {
			t.Errorf("%s: account nonce %d (%v), want %d", n.name, got, err, nonce+3)
		}
	}
}

// TestInternalNetSecp256k1TypesRejectedByPool funds the address of a
// secp256k1 key with an account transaction, then gives both nodes a legacy,
// EIP-2930, EIP-1559 and EIP-4844 transfer of those funds signed with that
// key, and an EIP-7702 one. Each is refused, none is mined, and the funds stay
// where they are.
func TestInternalNetSecp256k1TypesRejectedByPool(t *testing.T) {
	miner, peer, account := startInternalNet(t)
	var (
		ctx               = context.Background()
		nodes             = []*internalNode{miner, peer}
		chainID           = big.NewInt(ghost.InternalNetChainID)
		key, _, _         = testAccount(minerAccountSeed)
		secpKey, secpAddr = spendSecp256k1Key(t)
		recipient         = common.HexToAddress("0x00000000000000000000000000000000000000bb")
		ether             = big.NewInt(1_000_000_000_000_000_000)
		gwei              = big.NewInt(1_000_000_000)
		price             = new(big.Int).Mul(big.NewInt(100), gwei)
		send              = new(big.Int).Div(ether, big.NewInt(10))
	)
	waitFor(t, 5*time.Minute, "the peer to see mined funds", func() (bool, error) {
		balance, err := peer.eth.BalanceAt(ctx, account, nil)
		return err == nil && balance.Cmp(ether) > 0, err
	})
	nonce, err := miner.eth.PendingNonceAt(ctx, account)
	if err != nil {
		t.Fatal(err)
	}
	funded := spendMined(t, nodes, spendSend(t, miner, key, &types.GhostAccountTx{
		ChainID:   chainID,
		Nonce:     nonce,
		GasTipCap: price,
		GasFeeCap: price,
		Gas:       accountTxGas,
		To:        &secpAddr,
		Value:     ether,
	}).Hash())
	for _, n := range nodes {
		if got := n.balance(t, secpAddr, nil); got.Cmp(ether) != 0 {
			t.Fatalf("%s: the secp256k1 address holds %v, want %v", n.name, got, ether)
		}
	}

	signer := types.NewCancunSigner(chainID)
	var txs []*types.Transaction
	for _, data := range []types.TxData{
		&types.LegacyTx{GasPrice: price, Gas: 21_000, To: &recipient, Value: send},
		&types.AccessListTx{ChainID: chainID, GasPrice: price, Gas: 21_000, To: &recipient, Value: send},
		&types.DynamicFeeTx{ChainID: chainID, GasTipCap: price, GasFeeCap: price, Gas: 21_000, To: &recipient, Value: send},
		&types.BlobTx{
			ChainID:    uint256.MustFromBig(chainID),
			GasTipCap:  uint256.MustFromBig(price),
			GasFeeCap:  uint256.MustFromBig(price),
			Gas:        21_000,
			To:         recipient,
			Value:      uint256.MustFromBig(send),
			BlobFeeCap: uint256.MustFromBig(price),
			BlobHashes: []common.Hash{{0x01}},
		},
	} {
		tx, err := types.SignTx(types.NewTx(data), signer, secpKey)
		if err != nil {
			t.Fatal(err)
		}
		if _, r, s := tx.RawSignatureValues(); r.Sign() == 0 || s.Sign() == 0 {
			t.Fatalf("type %#x not signed", tx.Type())
		}
		txs = append(txs, tx)
	}
	setCode := spendSetCodeTx(t, secpKey, recipient, price)
	want := types.ErrTxTypeNotSupported.Error()
	for _, n := range nodes {
		for _, tx := range txs {
			if err := n.eth.SendTransaction(ctx, tx); err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("%s: type %#x: send error %v, want %q", n.name, tx.Type(), err, want)
			}
			spendUnknown(t, n, tx.Hash(), fmt.Sprintf("type %#x transfer", tx.Type()))
		}
		var hash common.Hash
		if err := n.rpc.Call(&hash, "eth_sendRawTransaction", hexutil.Bytes(setCode)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: type 0x04: send error %v, want %q", n.name, err, want)
		}
	}

	// Blocks go on being mined, and none of them moves the funds.
	after := uint64(funded.BlockNumber) + 5
	for _, n := range nodes {
		waitFor(t, 5*time.Minute, fmt.Sprintf("the %s to reach block %d", n.name, after), func() (bool, error) {
			number, err := n.eth.BlockNumber(ctx)
			return number >= after, err
		})
	}
	at := new(big.Int).SetUint64(after)
	for _, n := range nodes {
		if got := n.balance(t, secpAddr, at); got.Cmp(ether) != 0 {
			t.Errorf("%s: the secp256k1 address holds %v at block %d, want %v", n.name, got, after, ether)
		}
		if got := n.balance(t, recipient, at); got.Sign() != 0 {
			t.Errorf("%s: the recipient holds %v at block %d, want nothing", n.name, got, after)
		}
		if got, err := n.eth.NonceAt(ctx, secpAddr, at); err != nil || got != 0 {
			t.Errorf("%s: the secp256k1 address has nonce %d (%v), want 0", n.name, got, err)
		}
	}
}
