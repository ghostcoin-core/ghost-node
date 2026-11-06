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

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/vars"
)

// TestLegacyPoolRawSignatureBoundsUnchangedByPublicRoot checks that the
// public root changes none of the bounds of spec 09, section 8.3, on the
// account transactions with their raw signatures (0x52): the pool's
// signature verifier keeps its workers, its queue and its shares, and its
// size cap is TX_MAX_BYTES; a public root (0x56) and a binding transaction
// (0x57) are not taken, from a peer or from RPC, and cost no signature
// check and no queue slot; and a raw-signature transaction still has its
// signature verified, once, a failure cached, after the cheap checks, among
// them its intrinsic gas, signature bytes and VERIFY_GAS included.
func TestLegacyPoolRawSignatureBoundsUnchangedByPublicRoot(t *testing.T) {
	pool, genesis := setupGhostAccountPool(t)
	defer pool.Close()

	// The bounds the pool starts with.
	if txMaxSize != ghost.AccountTxMaxBytes {
		t.Fatalf("size cap %d, want TX_MAX_BYTES %d", txMaxSize, ghost.AccountTxMaxBytes)
	}
	if peers, rpc := pool.sigVerifier.Share(txpool.SigFromPeer), pool.sigVerifier.Share(txpool.SigFromRPC); peers != ghost.SigVerifyQueue*3/4 || rpc != ghost.SigVerifyQueue/4 {
		t.Fatalf("the pool's verifier shares %d for peers and %d for RPC, want %d and %d", peers, rpc, ghost.SigVerifyQueue*3/4, ghost.SigVerifyQueue/4)
	}
	counter := newCountingVerify(true)
	v := useVerifier(pool, counter, ghost.SigFailureCacheSize)

	key, _, from := testAccount(1)
	testAddBalance(pool, from, new(big.Int).Lsh(big.NewInt(1), 100))
	chainID := params.TestChainConfig.GetChainID()

	// A public root and a binding transaction of the funded account.
	binding := types.NewGhostBinding(from, common.Hash{0x1d}, common.Hash{0x7a})
	env, err := (&ghostpriv.PublicRoot{Version: ghostpriv.PublicRootVersion, ChainID: chainID.Uint64(), Bindings: []types.GhostBinding{binding}}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	root, err := types.NewGhostPublicRootTx(env)
	if err != nil {
		t.Fatal(err)
	}
	to := common.Address{0xbb}
	bind := types.NewTx(&types.GhostBindingTx{
		ChainID:   chainID,
		GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(1),
		Gas:       txGas,
		To:        &to,
		Value:     big.NewInt(100),
		Scheme:    types.GhostScheme(types.GhostSchemeMLDSA44),
		Binding:   binding,
	})
	for _, tx := range []*types.Transaction{root, bind} {
		if pool.Filter(tx) {
			t.Fatalf("the legacy pool's Filter takes type %#x", tx.Type())
		}
		for _, local := range []bool{false, true} {
			if err := pool.Add([]*types.Transaction{tx}, local, true)[0]; !errors.Is(err, core.ErrTxTypeNotSupported) {
				t.Fatalf("type %#x, local %v: error %v, want %v", tx.Type(), local, err, core.ErrTxTypeNotSupported)
			}
			if pool.Has(tx.Hash()) {
				t.Fatalf("type %#x, local %v: held", tx.Type(), local)
			}
		}
	}
	if calls, _, _ := counter.stats(); calls != 0 {
		t.Fatalf("%d signatures verified for a public root and a binding transaction, want none", calls)
	}
	if peers, rpc := v.InFlight(txpool.SigFromPeer), v.InFlight(txpool.SigFromRPC); peers != 0 || rpc != 0 {
		t.Fatalf("%d peer and %d RPC queue slots taken, want none", peers, rpc)
	}

	// A raw-signature transaction whose gas covers a binding transaction's
	// price but not its own signature is refused before its signature check.
	bindingGas, err := core.GhostBindingExtraIntrinsicGas(types.GhostSchemeMLDSA44)
	if err != nil {
		t.Fatal(err)
	}
	if vars.TxGas+bindingGas >= txGas {
		t.Fatalf("a binding transaction's gas %d is not below a raw-signature one's %d", vars.TxGas+bindingGas, txGas)
	}
	short := makeGhostPoolTx(t, genesis, key, ghostPoolTx{nonce: 0, gas: vars.TxGas + bindingGas})
	if err := pool.addRemoteSync(short); !errors.Is(err, core.ErrIntrinsicGas) {
		t.Fatalf("raw-signature transaction at a binding transaction's gas: error %v, want %v", err, core.ErrIntrinsicGas)
	}
	if calls, _, _ := counter.stats(); calls != 0 {
		t.Fatalf("%d signatures verified for a transaction short of gas, want none", calls)
	}

	// A bad signature is verified once and its failure cached.
	bad := makeGhostPoolTx(t, genesis, key, ghostPoolTx{nonce: 0, gas: txGas, badSig: true})
	for i := 0; i < 2; i++ {
		if err := pool.addRemoteSync(bad); !errors.Is(err, txpool.ErrSignatureFailed) {
			t.Fatalf("bad signature, attempt %d: error %v, want %v", i, err, txpool.ErrSignatureFailed)
		}
		if calls, _, _ := counter.stats(); calls != 1 {
			t.Fatalf("bad signature, attempt %d: %d verifications, want 1", i, calls)
		}
	}
	// A good one is verified and taken, from a peer and from RPC.
	good := makeGhostPoolTx(t, genesis, key, ghostPoolTx{nonce: 0, gas: txGas})
	if err := pool.addRemoteSync(good); err != nil {
		t.Fatalf("raw-signature transaction refused: %v", err)
	}
	next := makeGhostPoolTx(t, genesis, key, ghostPoolTx{nonce: 1, gas: txGas})
	if err := pool.Add([]*types.Transaction{next}, true, true)[0]; err != nil {
		t.Fatalf("raw-signature transaction from RPC refused: %v", err)
	}
	if !pool.Has(good.Hash()) || !pool.Has(next.Hash()) {
		t.Fatal("the pool does not hold the raw-signature transactions")
	}
	if calls, _, peak := counter.stats(); calls != 3 || peak > ghost.SigVerifyWorkers {
		t.Fatalf("%d verifications, at most %d at once; want 3, at most %d", calls, peak, ghost.SigVerifyWorkers)
	}
}
