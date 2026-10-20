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

package legacypool

import (
	"errors"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/vars"
	"github.com/holiman/uint256"
)

// setupGhostAccountPool returns a pool on a test chain with a genesis block,
// which lets it take account transactions, and the genesis hash.
func setupGhostAccountPool(t *testing.T) (*LegacyPool, common.Hash) {
	t.Helper()
	pool, _, _ := setupPool()
	return pool, testGenesis.Hash()
}

type ghostPoolTx struct {
	nonce   uint64
	gas     uint64
	chainID *big.Int
	badSig  bool
	scheme  uint16 // replaces the scheme when not zero
}

func makeGhostPoolTx(t *testing.T, genesis common.Hash, key *mldsa44.PrivateKey, p ghostPoolTx) *types.Transaction {
	t.Helper()
	chainID := params.TestChainConfig.GetChainID()
	if p.chainID != nil {
		chainID = p.chainID
	}
	to := common.HexToAddress("0x00000000000000000000000000000000000000bb")
	signer := types.NewGhostAccountSigner(types.LatestSignerForChainID(chainID), genesis)
	tx, err := types.SignGhostAccountTx(signer, key, &types.GhostAccountTx{
		ChainID:   chainID,
		Nonce:     p.nonce,
		GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(1),
		Gas:       p.gas,
		To:        &to,
		Value:     big.NewInt(100),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !p.badSig && p.scheme == 0 {
		return tx
	}
	_, pk, sig, _ := tx.GhostAccountAuth()
	scheme := types.GhostSchemeMLDSA44
	if p.scheme != 0 {
		scheme = p.scheme
	}
	if p.badSig {
		sig[7] ^= 0x01
	}
	return types.NewTx(&types.GhostAccountTx{
		ChainID:   tx.ChainId(),
		Nonce:     tx.Nonce(),
		GasTipCap: tx.GasTipCap(),
		GasFeeCap: tx.GasFeeCap(),
		Gas:       tx.Gas(),
		To:        tx.To(),
		Value:     tx.Value(),
		Scheme:    types.GhostScheme(scheme),
		PublicKey: pk,
		Signature: sig,
	})
}

func TestGhostAccountTxPool(t *testing.T) {
	pool, genesis := setupGhostAccountPool(t)
	defer pool.Close()

	if ghost.AccountTxVerifyGasMLDSA44 == 0 {
		t.Fatal("the verification gas of ML-DSA-44 is not set")
	}
	key, _, from := testAccount(1)
	testAddBalance(pool, from, big.NewInt(1_000_000_000_000_000_000))

	// A valid account transaction is admitted, under its derived sender.
	valid := makeGhostPoolTx(t, genesis, key, ghostPoolTx{nonce: 0, gas: txGas})
	if !pool.Filter(valid) {
		t.Fatal("the pool does not take account transactions")
	}
	if err := pool.addRemoteSync(valid); err != nil {
		t.Fatalf("valid account transaction refused: %v", err)
	}
	if pool.Get(valid.Hash()) == nil {
		t.Fatal("valid account transaction not in the pool")
	}
	if pending, _ := pool.Stats(); pending != 1 {
		t.Fatalf("pending %d, want 1", pending)
	}
	if list := pool.pending[from]; list == nil || list.Len() != 1 {
		t.Fatal("the transaction is not pending under the derived sender")
	}

	// Refused: a bad signature, a wrong chain ID, an intrinsic gas too low.
	for _, tc := range []struct {
		name string
		tx   ghostPoolTx
		want error
	}{
		{"bad signature", ghostPoolTx{nonce: 1, gas: txGas, badSig: true}, types.ErrInvalidSig},
		{"wrong chain ID", ghostPoolTx{nonce: 1, gas: txGas, chainID: big.NewInt(999)}, types.ErrInvalidChainId},
		{"gas one below the intrinsic gas", ghostPoolTx{nonce: 1, gas: txGas - 1}, core.ErrIntrinsicGas},
		{"gas of a type 0x02 transfer", ghostPoolTx{nonce: 1, gas: vars.TxGas}, core.ErrIntrinsicGas},
	} {
		tx := makeGhostPoolTx(t, genesis, key, tc.tx)
		if err := pool.addRemoteSync(tx); !errors.Is(err, tc.want) {
			t.Errorf("%s: error %v, want %v", tc.name, err, tc.want)
		}
		if pool.Get(tx.Hash()) != nil {
			t.Errorf("%s: transaction in the pool", tc.name)
		}
	}

	// The signature is not checked when a cheap check fails: each of these
	// carries a bad signature too, and is refused for the cheap check.
	poor, _, _ := testAccount(2) // no balance
	contract, _, contractAddr := testAccount(3)
	pool.mu.Lock()
	pool.currentState.AddBalance(contractAddr, uint256.NewInt(1_000_000_000_000_000_000))
	pool.currentState.SetCode(contractAddr, []byte{0x00})
	pool.mu.Unlock()
	stale, _, staleAddr := testAccount(4)
	testAddBalance(pool, staleAddr, big.NewInt(1_000_000_000_000_000_000))
	testSetNonce(pool, staleAddr, 5)

	for _, tc := range []struct {
		name string
		key  *mldsa44.PrivateKey
		tx   ghostPoolTx
		want error
	}{
		{"unknown scheme", key, ghostPoolTx{nonce: 1, gas: txGas, badSig: true, scheme: 0x0003}, types.ErrGhostAccountScheme},
		{"lengths of another scheme", key, ghostPoolTx{nonce: 1, gas: txGas, badSig: true, scheme: types.GhostSchemeHashBased}, types.ErrGhostAccountLength},
		{"wrong chain ID", key, ghostPoolTx{nonce: 1, gas: txGas, badSig: true, chainID: big.NewInt(999)}, types.ErrInvalidChainId},
		{"intrinsic gas too low", key, ghostPoolTx{nonce: 1, gas: txGas - 1, badSig: true}, core.ErrIntrinsicGas},
		{"code at the sender", contract, ghostPoolTx{nonce: 0, gas: txGas, badSig: true}, core.ErrSenderNoEOA},
		{"nonce too low", stale, ghostPoolTx{nonce: 4, gas: txGas, badSig: true}, core.ErrNonceTooLow},
		{"balance too low", poor, ghostPoolTx{nonce: 0, gas: txGas, badSig: true}, core.ErrInsufficientFunds},
	} {
		tx := makeGhostPoolTx(t, genesis, tc.key, tc.tx)
		err := pool.addRemoteSync(tx)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: error %v, want %v", tc.name, err, tc.want)
		}
		if errors.Is(err, types.ErrInvalidSig) {
			t.Errorf("%s: the signature was checked before the cheap check", tc.name)
		}
	}
	// The same transactions with a good signature where the cheap check
	// passes are admitted: the cases above failed for the cheap check alone.
	if err := pool.addRemoteSync(makeGhostPoolTx(t, genesis, stale, ghostPoolTx{nonce: 5, gas: txGas})); err != nil {
		t.Errorf("stale account at its nonce: %v", err)
	}
	if err := pool.addRemoteSync(makeGhostPoolTx(t, genesis, key, ghostPoolTx{nonce: 1, gas: txGas})); err != nil {
		t.Errorf("next nonce: %v", err)
	}
	if err := validatePoolInternals(pool); err != nil {
		t.Fatal(err)
	}
}

// TestGhostAccountTxPoolWithoutGenesis checks that a pool whose chain gives
// no genesis block refuses account transactions.
func TestGhostAccountTxPoolWithoutGenesis(t *testing.T) {
	// The test chain without its genesis block.
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	chain := newTestBlockChain(params.TestChainConfig, 10_000_000, statedb, new(event.Feed))
	chain.genesis = nil
	pool := New(testTxPoolConfig, chain)
	if err := pool.Init(testTxPoolConfig.PriceLimit, chain.CurrentBlock(), makeAddressReserver()); err != nil {
		t.Fatal(err)
	}
	<-pool.initDoneCh
	defer pool.Close()

	key, _, from := testAccount(1)
	testAddBalance(pool, from, big.NewInt(1_000_000_000_000_000_000))
	tx := makeGhostPoolTx(t, testGenesis.Hash(), key, ghostPoolTx{nonce: 0, gas: txGas})
	if pool.Filter(tx) {
		t.Error("the pool takes account transactions without a genesis hash")
	}
	if err := pool.addRemoteSync(tx); !errors.Is(err, core.ErrTxTypeNotSupported) {
		t.Errorf("error %v, want %v", err, core.ErrTxTypeNotSupported)
	}
	if err := pool.addRemoteSync(tx); errors.Is(err, txpool.ErrAlreadyKnown) {
		t.Error("the refused transaction was kept")
	}
}
