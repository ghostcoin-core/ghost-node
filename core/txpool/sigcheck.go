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

package txpool

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/lru"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// busyError is an error of the signature bounds that JSON-RPC reports with
// code -32005, the code of a limit exceeded.
type busyError struct{ msg string }

func (e *busyError) Error() string  { return e.msg }
func (e *busyError) ErrorCode() int { return -32005 }

var (
	// ErrSignatureFailed is returned for a transaction whose signature does
	// not verify. A peer that sends one is disconnected.
	ErrSignatureFailed = fmt.Errorf("%w: signature check failed", ErrInvalidSender)

	// ErrSignatureQueueBusy is returned for a transaction dropped unverified
	// because its share of the signature queue is full.
	ErrSignatureQueueBusy error = &busyError{"signature queue busy"}

	// ErrSignatureBudget is returned for a transaction dropped unverified
	// because its sender, a peer or an RPC connection, has used its budget of
	// signature checks for the second.
	ErrSignatureBudget error = &busyError{"signature budget exceeded"}

	// ErrSignaturePeerUnknown is returned for a transaction dropped unverified
	// because the peer that sent it cannot be identified.
	ErrSignaturePeerUnknown = errors.New("signature check from an unknown peer")

	// errSigVerifierClosed is returned for a check still waiting when the
	// verifier is closed.
	errSigVerifierClosed = errors.New("signature verifier closed")
)

// SigOrigin tells where a transaction to verify comes from. Each origin has
// its own share of the signature queue.
type SigOrigin int

const (
	SigFromPeer SigOrigin = iota // a transaction from a peer
	SigFromRPC                   // a transaction submitted locally, by RPC
)

// sigFailureKey identifies a signature that failed: the signature hash, the
// public key and the signature itself. The signature is part of the key
// because a signature is hedged: another signature of the same key over the
// same hash may verify, and must not be refused for this one.
type sigFailureKey struct {
	sighash   common.Hash
	publicKey common.Hash
	signature common.Hash
}

type sigJob struct {
	signer types.Signer
	tx     *types.Transaction
	origin SigOrigin
	done   chan error
}

// SigVerifier verifies the signatures of account transactions on a bounded
// set of workers, from a bounded queue split between peers (3 slots in 4) and
// local RPC (1 in 4). A check that finds its share full is dropped
// unverified. Signatures that fail are kept in a bounded cache, so that the
// same failing transaction is refused without being verified again.
type SigVerifier struct {
	workers int
	verify  func(types.Signer, *types.Transaction) error

	jobs  chan sigJob
	slots [2]chan struct{} // The queue slots taken, by origin

	failMu   sync.Mutex
	failures lru.BasicLRU[sigFailureKey, struct{}]

	quit      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

// NewSigVerifier starts a verifier of the given number of workers, queue
// length and failure cache size. A nil verify checks the signature with
// types.Sender, which caches the sender in the transaction.
func NewSigVerifier(workers, queue, failures int, verify func(types.Signer, *types.Transaction) error) *SigVerifier {
	if workers < 1 {
		workers = 1
	}
	if failures < 1 {
		failures = 1
	}
	peers := queue * 3 / 4
	if peers < 1 {
		peers = 1
	}
	rpc := queue - peers
	if rpc < 1 {
		rpc = 1
	}
	if verify == nil {
		verify = func(signer types.Signer, tx *types.Transaction) error {
			_, err := types.Sender(signer, tx)
			return err
		}
	}
	v := &SigVerifier{
		workers:  workers,
		verify:   verify,
		jobs:     make(chan sigJob, peers+rpc),
		failures: lru.NewBasicLRU[sigFailureKey, struct{}](failures),
		quit:     make(chan struct{}),
	}
	v.slots[SigFromPeer] = make(chan struct{}, peers)
	v.slots[SigFromRPC] = make(chan struct{}, rpc)

	v.wg.Add(workers)
	for i := 0; i < workers; i++ {
		go v.loop()
	}
	return v
}

// loop is a worker: it verifies the queued signatures one by one.
func (v *SigVerifier) loop() {
	defer v.wg.Done()
	for {
		select {
		case job := <-v.jobs:
			err := v.verify(job.signer, job.tx)
			<-v.slots[job.origin]
			job.done <- err
		case <-v.quit:
			return
		}
	}
}

// Close stops the workers. Checks still waiting are refused.
func (v *SigVerifier) Close() {
	v.closeOnce.Do(func() {
		close(v.quit)
		v.wg.Wait()
	})
}

// Workers returns the number of workers.
func (v *SigVerifier) Workers() int { return v.workers }

// Share returns the number of queue slots of an origin.
func (v *SigVerifier) Share(origin SigOrigin) int { return cap(v.slots[origin]) }

// InFlight returns the number of queue slots of an origin taken, by checks
// waiting or running.
func (v *SigVerifier) InFlight(origin SigOrigin) int { return len(v.slots[origin]) }

// Verify verifies the signatures of txs, all from one origin, and returns an
// error for each: nil, ErrSignatureFailed for a signature that does not
// verify, or ErrSignatureQueueBusy for one dropped unverified because the
// origin's share was full. While the batch has checks of its own in the queue
// it waits for them to free a slot; it drops a transaction only when the
// share is full without it.
func (v *SigVerifier) Verify(origin SigOrigin, signer types.Signer, txs []*types.Transaction) []error {
	type pending struct {
		index int
		key   sigFailureKey
		done  chan error
	}
	var (
		errs  = make([]error, len(txs))
		queue []pending
	)
	settle := func(p pending) {
		var err error
		select {
		case err = <-p.done:
		case <-v.quit:
			err = errSigVerifierClosed
		}
		if err != nil && err != errSigVerifierClosed {
			v.failMu.Lock()
			v.failures.Add(p.key, struct{}{})
			v.failMu.Unlock()
			err = fmt.Errorf("%w: %w", ErrSignatureFailed, err)
		}
		errs[p.index] = err
	}
	for i, tx := range txs {
		key := sigFailureKeyOf(signer, tx)
		v.failMu.Lock()
		failed := v.failures.Contains(key)
		v.failMu.Unlock()
		if failed {
			errs[i] = fmt.Errorf("%w: %w", ErrSignatureFailed, types.ErrGhostAccountSignature)
			continue
		}
		taken := false
		for !taken {
			select {
			case v.slots[origin] <- struct{}{}:
				taken = true
			default:
			}
			if taken || len(queue) == 0 {
				break
			}
			settle(queue[0])
			queue = queue[1:]
		}
		if !taken {
			errs[i] = ErrSignatureQueueBusy
			continue
		}
		done := make(chan error, 1)
		v.jobs <- sigJob{signer: signer, tx: tx, origin: origin, done: done}
		queue = append(queue, pending{index: i, key: key, done: done})
	}
	for _, p := range queue {
		settle(p)
	}
	return errs
}

// sigFailureKeyOf returns the failure cache key of a transaction.
func sigFailureKeyOf(signer types.Signer, tx *types.Transaction) sigFailureKey {
	_, publicKey, signature, _ := tx.GhostAccountAuth()
	return sigFailureKey{
		sighash:   signer.Hash(tx),
		publicKey: crypto.Keccak256Hash(publicKey),
		signature: crypto.Keccak256Hash(signature),
	}
}

// SigBudget is a token bucket of signature checks: it holds a number of
// checks per second and is refilled every second.
type SigBudget struct {
	mu     sync.Mutex
	rate   uint64
	tokens uint64
	last   time.Time
	now    func() time.Time
}

// NewSigBudget returns a full budget of rate checks per second. A nil now
// reads the system clock.
func NewSigBudget(rate uint64, now func() time.Time) *SigBudget {
	if now == nil {
		now = time.Now
	}
	return &SigBudget{rate: rate, tokens: rate, last: now(), now: now}
}

// refill fills the bucket when a second has passed since it was last filled.
// The caller holds the lock.
func (b *SigBudget) refill() {
	if now := b.now(); now.Sub(b.last) >= time.Second {
		b.tokens, b.last = b.rate, now
	}
}

// Take spends one check of the budget, and reports false when none is left.
func (b *SigBudget) Take() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refill()
	if b.tokens == 0 {
		return false
	}
	b.tokens--
	return true
}

// Available returns the number of checks left in the budget.
func (b *SigBudget) Available() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refill()
	return b.tokens
}

// SigBudgets holds a budget for each of a bounded number of keys (peers or
// RPC connections). A key not seen recently starts with a full budget.
type SigBudgets struct {
	mu      sync.Mutex
	rate    uint64
	now     func() time.Time
	budgets lru.BasicLRU[string, *SigBudget]
}

// NewSigBudgets returns budgets of rate checks per second for up to size
// keys. A nil now reads the system clock.
func NewSigBudgets(rate uint64, size int, now func() time.Time) *SigBudgets {
	if size < 1 {
		size = 1
	}
	return &SigBudgets{rate: rate, now: now, budgets: lru.NewBasicLRU[string, *SigBudget](size)}
}

// Get returns the budget of a key.
func (s *SigBudgets) Get(key string) *SigBudget {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b, ok := s.budgets.Get(key); ok {
		return b
	}
	b := NewSigBudget(s.rate, s.now)
	s.budgets.Add(key, b)
	return b
}

// Forget drops the budget of a key, of a peer that left.
func (s *SigBudgets) Forget(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.budgets.Remove(key)
}
