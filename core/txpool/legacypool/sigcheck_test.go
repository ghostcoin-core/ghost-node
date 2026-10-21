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
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params/ghost"
)

// countingVerify verifies signatures as the pool does, behind a gate, and
// counts the verifications started and the most running at once.
type countingVerify struct {
	gate chan struct{} // closed to let the verifications run

	mu     sync.Mutex
	calls  int
	active int
	peak   int
}

func newCountingVerify(open bool) *countingVerify {
	c := &countingVerify{gate: make(chan struct{})}
	if open {
		close(c.gate)
	}
	return c
}

func (c *countingVerify) verify(signer types.Signer, tx *types.Transaction) error {
	c.mu.Lock()
	c.calls++
	c.active++
	if c.active > c.peak {
		c.peak = c.active
	}
	c.mu.Unlock()

	<-c.gate
	_, err := types.Sender(signer, tx)

	c.mu.Lock()
	c.active--
	c.mu.Unlock()
	return err
}

func (c *countingVerify) stats() (calls, active, peak int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls, c.active, c.peak
}

// useVerifier replaces the pool's signature verifier with one of the node's
// bounds that verifies through c.
func useVerifier(pool *LegacyPool, c *countingVerify, failures int) *txpool.SigVerifier {
	pool.sigVerifier.Close()
	pool.sigVerifier = txpool.NewSigVerifier(ghost.SigVerifyWorkers, ghost.SigVerifyQueue, failures, c.verify)
	return pool.sigVerifier
}

// waitUntil yields until cond holds, and fails the test after ten seconds.
func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting until %s", what)
		}
		runtime.Gosched()
	}
}

// fundedTxs returns n account transactions of a funded test account, of
// nonces from first on.
func fundedTxs(pool *LegacyPool, seed byte, first uint64, n int) []*types.Transaction {
	key, _, from := testAccount(seed)
	testAddBalance(pool, from, new(big.Int).Lsh(big.NewInt(1), 100))
	txs := make([]*types.Transaction, n)
	for i := range txs {
		txs[i] = transaction(first+uint64(i), txGas, key)
	}
	return txs
}

// TestSignatureLimitsAreSet checks that none of the bounds is zero and that
// the queue is split 3 slots in 4 for peers and 1 in 4 for RPC.
func TestSignatureLimitsAreSet(t *testing.T) {
	for name, v := range map[string]uint64{
		"SigVerifyWorkers":    ghost.SigVerifyWorkers,
		"SigVerifyQueue":      ghost.SigVerifyQueue,
		"SigFailureCacheSize": ghost.SigFailureCacheSize,
		"SigPeerBudget":       ghost.SigPeerBudget,
		"SigRPCConnBudget":    ghost.SigRPCConnBudget,
		"SigRPCBudget":        ghost.SigRPCBudget,
	} {
		if v == 0 {
			t.Errorf("%s is zero", name)
		}
	}
	if ghost.SigRPCConnBudget > ghost.SigRPCBudget {
		t.Errorf("the budget of one RPC connection %d is above the overall RPC budget %d", ghost.SigRPCConnBudget, ghost.SigRPCBudget)
	}
	// One check is paid at the dearest scheme: its VERIFY_GAS / 10,000 is at
	// least its slowest verification in milliseconds. The default 50 peers
	// at their budget fit in the peers' 3 quarters of the workers, and the
	// RPC budget in the remaining quarter.
	dearest := max(ghost.AccountTxVerifyGas(types.GhostSchemeMLDSA44), ghost.AccountTxVerifyGas(types.GhostSchemeSLHDSA))
	perSecond := uint64(ghost.SigVerifyWorkers) * 1000 * ghost.AccountTxGasPerMs // times the gas of one check
	if ghost.SigPeerBudget*50*dearest*4 > 3*perSecond {
		t.Errorf("50 peers at %d checks per second exceed the peers' share of %d workers at %d gas a check", ghost.SigPeerBudget, ghost.SigVerifyWorkers, dearest)
	}
	if ghost.SigRPCBudget*dearest*4 > perSecond {
		t.Errorf("RPC at %d checks per second exceeds its share of %d workers at %d gas a check", ghost.SigRPCBudget, ghost.SigVerifyWorkers, dearest)
	}
	// An SLH-DSA transaction, 7,890 bytes of scheme, key and signature, is
	// well under the pool's size cap.
	if 2+types.GhostSLHDSAPublicKeySize+types.GhostSLHDSASignatureSize >= txMaxSize/2 {
		t.Errorf("the SLH-DSA key and signature take half the pool's size cap %d", txMaxSize)
	}
	v := txpool.NewSigVerifier(ghost.SigVerifyWorkers, ghost.SigVerifyQueue, ghost.SigFailureCacheSize, nil)
	defer v.Close()
	if peers, rpc := v.Share(txpool.SigFromPeer), v.Share(txpool.SigFromRPC); peers != ghost.SigVerifyQueue*3/4 || rpc != ghost.SigVerifyQueue/4 {
		t.Errorf("shares %d for peers and %d for RPC, want %d and %d", peers, rpc, ghost.SigVerifyQueue*3/4, ghost.SigVerifyQueue/4)
	}
}

// TestSignatureFailureCacheSkipsReverify checks that a transaction whose
// signature failed is refused again without being verified again, that
// another signature over the same hash and key is still verified, and that
// the failure cache is bounded.
func TestSignatureFailureCacheSkipsReverify(t *testing.T) {
	t.Parallel()

	pool, genesis := setupGhostAccountPool(t)
	defer pool.Close()
	counter := newCountingVerify(true)
	useVerifier(pool, counter, ghost.SigFailureCacheSize)

	key, _, from := testAccount(1)
	testAddBalance(pool, from, new(big.Int).Lsh(big.NewInt(1), 100))
	bad := makeGhostPoolTx(t, genesis, key, ghostPoolTx{nonce: 0, gas: txGas, badSig: true})

	for i := 0; i < 3; i++ {
		if err := pool.addRemoteSync(bad); !errors.Is(err, txpool.ErrSignatureFailed) || !errors.Is(err, types.ErrInvalidSig) {
			t.Fatalf("attempt %d: error %v, want %v", i, err, txpool.ErrSignatureFailed)
		}
		if calls, _, _ := counter.stats(); calls != 1 {
			t.Fatalf("attempt %d: %d verifications, want the first only", i, calls)
		}
	}
	// A good signature of the same transaction, same hash and key, is
	// verified and admitted.
	good := makeGhostPoolTx(t, genesis, key, ghostPoolTx{nonce: 0, gas: txGas})
	if err := pool.addRemoteSync(good); err != nil {
		t.Fatalf("good signature refused: %v", err)
	}
	if calls, _, _ := counter.stats(); calls != 2 {
		t.Fatalf("%d verifications, want 2", calls)
	}
	// A state failure is not a signature failure: it is not cached, and the
	// transaction is not verified.
	poor, _, _ := testAccount(2)
	unfunded := makeGhostPoolTx(t, genesis, poor, ghostPoolTx{nonce: 0, gas: txGas})
	if err := pool.addRemoteSync(unfunded); !errors.Is(err, core.ErrInsufficientFunds) || errors.Is(err, txpool.ErrSignatureFailed) {
		t.Fatalf("unfunded: error %v, want %v", err, core.ErrInsufficientFunds)
	}
	if calls, _, _ := counter.stats(); calls != 2 {
		t.Fatalf("%d verifications after a state failure, want 2", calls)
	}

	// The cache is bounded: with room for two failures, the oldest of three
	// is verified again, the newest is not.
	small := newCountingVerify(true)
	v := txpool.NewSigVerifier(ghost.SigVerifyWorkers, ghost.SigVerifyQueue, 2, small.verify)
	defer v.Close()
	bads := []*types.Transaction{
		makeGhostPoolTx(t, genesis, key, ghostPoolTx{nonce: 10, gas: txGas, badSig: true}),
		makeGhostPoolTx(t, genesis, key, ghostPoolTx{nonce: 11, gas: txGas, badSig: true}),
		makeGhostPoolTx(t, genesis, key, ghostPoolTx{nonce: 12, gas: txGas, badSig: true}),
	}
	for _, err := range v.Verify(txpool.SigFromPeer, pool.signer, bads) {
		if !errors.Is(err, txpool.ErrSignatureFailed) {
			t.Fatalf("error %v, want %v", err, txpool.ErrSignatureFailed)
		}
	}
	v.Verify(txpool.SigFromPeer, pool.signer, bads[2:])
	if calls, _, _ := small.stats(); calls != 3 {
		t.Fatalf("%d verifications, want 3: the newest failure is cached", calls)
	}
	v.Verify(txpool.SigFromPeer, pool.signer, bads[:1])
	if calls, _, _ := small.stats(); calls != 4 {
		t.Fatalf("%d verifications, want 4: the oldest failure left the bounded cache", calls)
	}
}

// TestSignatureQueueSharesAreSeparate checks that a full peer share drops a
// peer transaction unverified while RPC keeps its own share, and that a full
// RPC share returns the busy error without touching the peers' share.
func TestSignatureQueueSharesAreSeparate(t *testing.T) {
	t.Parallel()

	pool, _, _ := setupPool()
	defer pool.Close()
	counter := newCountingVerify(false)
	v := useVerifier(pool, counter, ghost.SigFailureCacheSize)
	peerShare, rpcShare := v.Share(txpool.SigFromPeer), v.Share(txpool.SigFromRPC)

	var (
		peerTxs = fundedTxs(pool, 1, 0, peerShare+1)
		rpcTxs  = fundedTxs(pool, 2, 0, rpcShare+1)
		wg      sync.WaitGroup
		peerErr []error
		rpcErr  []error
	)
	// Fill the peers' share: the verifications wait at the gate.
	wg.Add(1)
	go func() {
		defer wg.Done()
		peerErr = pool.Add(peerTxs[:peerShare], false, false)
	}()
	waitUntil(t, "the peer share is full", func() bool { return v.InFlight(txpool.SigFromPeer) == peerShare })

	// One more peer transaction is dropped unverified.
	if err := pool.Add(peerTxs[peerShare:], false, false)[0]; err != txpool.ErrSignatureQueueBusy {
		t.Fatalf("peer transaction with a full peer share: error %v, want %v", err, txpool.ErrSignatureQueueBusy)
	}
	// RPC still has its whole share.
	if n := v.InFlight(txpool.SigFromRPC); n != 0 {
		t.Fatalf("RPC share has %d taken, want 0", n)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		rpcErr = pool.Add(rpcTxs[:rpcShare], true, false)
	}()
	waitUntil(t, "the RPC share is full", func() bool { return v.InFlight(txpool.SigFromRPC) == rpcShare })

	// One more RPC transaction gets the busy error; the peers' share is
	// unchanged.
	err := pool.Add(rpcTxs[rpcShare:], true, false)[0]
	if err != txpool.ErrSignatureQueueBusy {
		t.Fatalf("RPC transaction with a full RPC share: error %v, want %v", err, txpool.ErrSignatureQueueBusy)
	}
	if coded, ok := err.(interface{ ErrorCode() int }); !ok || coded.ErrorCode() != -32005 {
		t.Fatalf("busy error %v has no JSON-RPC code -32005", err)
	}
	if n := v.InFlight(txpool.SigFromPeer); n != peerShare {
		t.Fatalf("peer share has %d taken, want %d", n, peerShare)
	}
	if calls, _, _ := counter.stats(); calls > ghost.SigVerifyWorkers {
		t.Fatalf("%d verifications started behind the gate, want at most %d", calls, ghost.SigVerifyWorkers)
	}

	// Open the gate: everything queued is verified and admitted, and the
	// refused transactions now fit.
	close(counter.gate)
	wg.Wait()
	for i, err := range append(peerErr, rpcErr...) {
		if err != nil {
			t.Fatalf("queued transaction %d: %v", i, err)
		}
	}
	if err := pool.Add(peerTxs[peerShare:], false, true)[0]; err != nil {
		t.Fatalf("peer transaction after the queue drained: %v", err)
	}
	if err := pool.Add(rpcTxs[rpcShare:], true, true)[0]; err != nil {
		t.Fatalf("RPC transaction after the queue drained: %v", err)
	}
	if calls, _, peak := counter.stats(); calls != peerShare+rpcShare+2 || peak > ghost.SigVerifyWorkers {
		t.Fatalf("%d verifications, at most %d at once; want %d, at most %d", calls, peak, peerShare+rpcShare+2, ghost.SigVerifyWorkers)
	}
}

// TestSignatureFloodStaysWithinWorkers floods the pool from many peers at
// once and checks that no more signatures are verified at once than there
// are workers, that the queue holds no more than the peers' share, that a
// transaction beyond it is dropped unverified, and that no transaction is
// verified twice.
func TestSignatureFloodStaysWithinWorkers(t *testing.T) {
	t.Parallel()

	pool, _, _ := setupPool()
	defer pool.Close()
	counter := newCountingVerify(false)
	v := useVerifier(pool, counter, ghost.SigFailureCacheSize)
	peerShare := v.Share(txpool.SigFromPeer)

	const peers = 24
	var (
		batches = make([][]*types.Transaction, peers)
		results = make([][]error, peers)
		total   int
		wg      sync.WaitGroup
	)
	for i := range batches {
		batches[i] = fundedTxs(pool, byte(10+i), 0, 2*peerShare/peers+1)
		total += len(batches[i])
	}
	if total <= peerShare {
		t.Fatalf("flood of %d transactions does not exceed the peer share %d", total, peerShare)
	}
	for i := range batches {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = pool.Add(batches[i], false, false)
		}(i)
	}
	// Behind the gate, the workers hold one verification each and the rest
	// of the share waits in the queue.
	waitUntil(t, "the peer share is full", func() bool { return v.InFlight(txpool.SigFromPeer) == peerShare })
	waitUntil(t, "every worker is busy", func() bool { _, active, _ := counter.stats(); return active == ghost.SigVerifyWorkers })
	if _, active, peak := counter.stats(); active > ghost.SigVerifyWorkers || peak > ghost.SigVerifyWorkers {
		t.Fatalf("%d verifications running, %d at most, want at most %d", active, peak, ghost.SigVerifyWorkers)
	}
	extra := fundedTxs(pool, 200, 0, 1)
	if err := pool.Add(extra, false, false)[0]; err != txpool.ErrSignatureQueueBusy {
		t.Fatalf("transaction beyond the flood: error %v, want %v", err, txpool.ErrSignatureQueueBusy)
	}

	close(counter.gate)
	wg.Wait()

	var admitted, busy int
	for i, errs := range results {
		for j, err := range errs {
			switch {
			case err == nil:
				admitted++
			case err == txpool.ErrSignatureQueueBusy:
				busy++
			default:
				t.Fatalf("peer %d transaction %d: %v", i, j, err)
			}
		}
	}
	calls, _, peak := counter.stats()
	if peak > ghost.SigVerifyWorkers {
		t.Fatalf("%d verifications at once, want at most %d", peak, ghost.SigVerifyWorkers)
	}
	if admitted+busy != total || calls != admitted {
		t.Fatalf("%d admitted and %d dropped of %d, %d verifications: want every admitted one verified once and no other", admitted, busy, total, calls)
	}
	if n := v.InFlight(txpool.SigFromPeer); n != 0 {
		t.Fatalf("%d queue slots still taken after the flood", n)
	}
}
