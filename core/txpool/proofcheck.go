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
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/lru"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params/ghost"
)

// Proof-carrying account transactions (docs/account-transactions.md). An
// account transaction (type 0x52) above the account transaction cap,
// ghost.AccountTxMaxBytes, is taken only as a proof-carrying transaction:
// its to is a frozen policy created before the next block, and the last
// ghostpriv.PreimageInputSize bytes of its data are the statement checker's
// input, a KNOW_PREIMAGE_v1 statement and its proof, made for that policy.
// It is at most ghost.ProofTxMaxBytes. The pool checks its cheap and state
// checks, then its signature, then the checker input, then the proof, on a
// ProofGate. The network handler keeps each peer's ProofPeers budget and
// counts the failures ProofCharged reports against it.

var (
	// ErrProofTxOversized is returned for an account transaction above
	// ghost.ProofTxMaxBytes. It is dropped unread and, from a peer, counts
	// as one failed check.
	ErrProofTxOversized = fmt.Errorf("%w: account transaction above the proof-carrying cap of %d bytes", ErrOversizedData, ghost.ProofTxMaxBytes)

	// ErrProofFailed is returned for a proof-carrying transaction whose
	// checker input or proof does not verify. A peer that sends one is
	// charged a failed check.
	ErrProofFailed = errors.New("statement proof check failed")

	// ErrProofRejectedBefore is returned, wrapping the first refusal, for a
	// transaction whose proof failed before: it is refused again without a
	// check, and charged as a failed check.
	ErrProofRejectedBefore = fmt.Errorf("%w: refused before", ErrProofFailed)

	// ErrProofBusy is returned for a proof-carrying transaction dropped
	// unverified because the check slot of its origin is taken or the checks
	// of the head are used up. It is no fault of the peer.
	ErrProofBusy error = &busyError{"statement proof checks busy"}

	// ErrProofPeerBudget is returned for a proof-carrying transaction
	// dropped unverified because its peer used its budget of the head.
	ErrProofPeerBudget error = &busyError{"peer statement proof budget used up"}

	// ErrProofHeldCap is returned for a proof-carrying transaction when the
	// pool holds ghost.ProofTxMaxHeld of them, or one of its sender at
	// another nonce.
	ErrProofHeldCap = errors.New("pool holds its cap of proof-carrying transactions")

	// ErrProofUnsupported is returned for a proof-carrying transaction the
	// node cannot verify: its verifier has no proof system for the
	// statement. It is no fault of the peer and not remembered.
	ErrProofUnsupported = errors.New("node cannot verify the statement proof")

	// ErrProofUnchecked is returned for a proof-carrying transaction that
	// reaches the pool without a proof check that passed.
	ErrProofUnchecked = errors.New("proof-carrying transaction without a passed proof check")
)

// IsProofTxClass reports whether tx is above the account transaction cap,
// so that only the proof-carrying class may take it.
func IsProofTxClass(tx *types.Transaction) bool {
	return tx.Size() > ghost.AccountTxMaxBytes
}

// ProofTxInput returns the statement checker input tx carries, the last
// ghostpriv.PreimageInputSize bytes of its data, or nil when tx is not an
// account transaction to an address with data that long.
func ProofTxInput(tx *types.Transaction) []byte {
	data := tx.Data()
	if tx.Type() != types.GhostAccountTxType || tx.To() == nil || len(data) < ghostpriv.PreimageInputSize {
		return nil
	}
	return data[len(data)-ghostpriv.PreimageInputSize:]
}

// CheckProofTxSize is the size class check, on the bytes alone: nil for a
// transaction at most ghost.AccountTxMaxBytes; ErrProofTxOversized above
// ghost.ProofTxMaxBytes; ErrOversizedData for one between the two that does
// not have the proof-carrying shape; nil, provisionally, for one that does,
// which the state checks then take or refuse.
func CheckProofTxSize(tx *types.Transaction) error {
	size := tx.Size()
	switch {
	case size <= ghost.AccountTxMaxBytes:
		return nil
	case size > ghost.ProofTxMaxBytes:
		return fmt.Errorf("%w: transaction size %d", ErrProofTxOversized, size)
	case ProofTxInput(tx) == nil:
		return fmt.Errorf("%w: transaction size %d, limit %d, not a proof-carrying transaction", ErrOversizedData, size, ghost.AccountTxMaxBytes)
	}
	return nil
}

// CheckProofTxState is the state part of the size class: a transaction
// above ghost.AccountTxMaxBytes is refused with ErrOversizedData unless its
// to is a policy callable from the block of number, a frozen policy created
// in an earlier block. A refusal here is a state failure, no fault of the
// peer.
func CheckProofTxState(tx *types.Transaction, st ghost.PolicyStateReader, number uint64) error {
	if !IsProofTxClass(tx) {
		return nil
	}
	if err := CheckProofTxSize(tx); err != nil {
		return err
	}
	if !ghost.IsCallablePolicy(st, *tx.To(), number) {
		return fmt.Errorf("%w: transaction size %d, limit %d, to %v is not a frozen policy of an earlier block", ErrOversizedData, tx.Size(), ghost.AccountTxMaxBytes, *tx.To())
	}
	return nil
}

// ProofCharged reports whether err, the refusal of a transaction a peer
// sent, counts as one failed proof check of the peer: a proof or checker
// input that failed, now or before, and a transaction above
// ghost.ProofTxMaxBytes. State failures, busy checks and a node that cannot
// verify the statement do not.
func ProofCharged(err error) bool {
	return errors.Is(err, ErrProofFailed) || errors.Is(err, ErrProofTxOversized)
}

// ProofGate runs the proof checks of proof-carrying transactions within the
// node's bounds: ghost.ProofCheckSlots verifications at once, one slot open
// to peers and one kept for local RPC, and ghost.ProofChecksPerHead
// verifications per chain head, past which a transaction is dropped
// unverified with ErrProofBusy. It remembers the last
// ghost.ProofRejectedMemory hashes whose proof failed, refused again
// without a check, and the hashes whose proof passed, which are never
// verified again: their public inputs (the chain, the genesis, the policy
// to, y and the context) do not depend on the state.
type ProofGate struct {
	chainID  uint64
	genesis  common.Hash
	verifier ghostpriv.Verifier // nil: the active verifier at each check

	slots [2]chan struct{} // the check slots taken, by origin

	mu       sync.Mutex
	head     common.Hash // the head the checks are counted at
	checks   int         // verifications started at head
	rejected lru.BasicLRU[common.Hash, error]
	passed   lru.BasicLRU[common.Hash, struct{}]

	verified atomic.Uint64 // verifications run, for the tests
}

// NewProofGate returns a gate for the chain of chainID and genesis that
// verifies through verifier, the active verifier when nil.
func NewProofGate(chainID uint64, genesis common.Hash, verifier ghostpriv.Verifier) *ProofGate {
	g := &ProofGate{
		chainID:  chainID,
		genesis:  genesis,
		verifier: verifier,
		rejected: lru.NewBasicLRU[common.Hash, error](ghost.ProofRejectedMemory),
		passed:   lru.NewBasicLRU[common.Hash, struct{}](ghost.ProofRejectedMemory),
	}
	// One slot for peers, the others for local RPC.
	g.slots[SigFromPeer] = make(chan struct{}, 1)
	g.slots[SigFromRPC] = make(chan struct{}, ghost.ProofCheckSlots-1)
	return g
}

// Check checks the checker input and the proof of tx, a proof-carrying
// transaction from origin, at the chain head head, and returns nil only for
// a proof that verifies. The binding is the node's: the chain id and genesis
// of the gate and tx's to as the policy. A hash whose proof passed before is
// taken without a check, one whose proof failed before is refused with
// ErrProofRejectedBefore. Otherwise a statement code other than 0x06 is
// ErrProofFailed without taking a check; the proof is verified in a check
// slot of origin, or dropped with ErrProofBusy when the slot is taken or the
// head's checks are used up; a proof the verifier rejects is ErrProofFailed
// and remembered, and a statement the node cannot verify
// ErrProofUnsupported.
func (g *ProofGate) Check(origin SigOrigin, head common.Hash, tx *types.Transaction) error {
	if origin != SigFromPeer && origin != SigFromRPC {
		return fmt.Errorf("%w: unknown origin %d", ErrProofBusy, origin)
	}
	hash := tx.Hash()
	g.mu.Lock()
	if first, ok := g.rejected.Peek(hash); ok {
		g.mu.Unlock()
		return fmt.Errorf("%w: %w", ErrProofRejectedBefore, first)
	}
	if g.passed.Contains(hash) {
		g.mu.Unlock()
		return nil
	}
	g.mu.Unlock()

	input := ProofTxInput(tx)
	if input == nil {
		return fmt.Errorf("%w: not a proof-carrying transaction", ErrOversizedData)
	}
	if _, err := ghostpriv.DecodePreimageInput(input); err != nil {
		return g.reject(hash, err)
	}

	g.mu.Lock()
	if head != g.head {
		g.head, g.checks = head, 0
	}
	if g.checks >= ghost.ProofChecksPerHead {
		g.mu.Unlock()
		return fmt.Errorf("%w: %d checks at this head", ErrProofBusy, ghost.ProofChecksPerHead)
	}
	select {
	case g.slots[origin] <- struct{}{}:
	default:
		g.mu.Unlock()
		return ErrProofBusy
	}
	g.checks++
	g.mu.Unlock()

	err := ghostpriv.VerifyPreimage(g.verifier, g.chainID, g.genesis, *tx.To(), input)
	<-g.slots[origin]
	g.verified.Add(1)

	switch {
	case err == nil:
		g.mu.Lock()
		g.passed.Add(hash, struct{}{})
		g.mu.Unlock()
		return nil
	case errors.Is(err, ghostpriv.ErrNoVerifier), errors.Is(err, ghostpriv.ErrStatementUnsupported), errors.Is(err, ghostpriv.ErrPreimageDomain):
		return fmt.Errorf("%w: %w", ErrProofUnsupported, err)
	}
	return g.reject(hash, err)
}

// reject remembers hash as a failed proof and returns its refusal.
func (g *ProofGate) reject(hash common.Hash, err error) error {
	err = fmt.Errorf("%w: %w", ErrProofFailed, err)
	g.mu.Lock()
	if !g.rejected.Contains(hash) {
		g.rejected.Add(hash, err)
	}
	g.mu.Unlock()
	return err
}

// Passed reports whether the proof of the transaction of hash was checked
// and passed.
func (g *ProofGate) Passed(hash common.Hash) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.passed.Contains(hash)
}

// Rejected reports whether the hash is remembered as a failed proof.
func (g *ProofGate) Rejected(hash common.Hash) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.rejected.Contains(hash)
}

// Verified returns the number of proof verifications the gate ran.
func (g *ProofGate) Verified() uint64 { return g.verified.Load() }

// Slots returns the number of check slots of an origin.
func (g *ProofGate) Slots(origin SigOrigin) int { return cap(g.slots[origin]) }

// InFlight returns the number of check slots of an origin taken.
func (g *ProofGate) InFlight(origin SigOrigin) int { return len(g.slots[origin]) }

// ProofPeers holds, for a bounded number of peers, the budget of
// proof-carrying deliveries and the failed checks of the current head:
// ghost.ProofPeerBudget deliveries, and the peer is to be dropped at its
// ghost.ProofFailLimit-th failure. Both start again when the head moves. The
// record outlives a disconnect, so that a peer that reconnects at the same
// head has neither its budget nor its failures back; a peer not seen
// recently, forgotten past the bound, starts afresh.
type ProofPeers struct {
	mu    sync.Mutex
	peers lru.BasicLRU[string, *proofPeer]
}

type proofPeer struct {
	head   common.Hash
	tokens int
	failed int
}

// NewProofPeers returns the budgets of up to size peers.
func NewProofPeers(size int) *ProofPeers {
	if size < 1 {
		size = 1
	}
	return &ProofPeers{peers: lru.NewBasicLRU[string, *proofPeer](size)}
}

// at returns the record of peer at head, refilled when the head moved. The
// caller holds the lock.
func (p *ProofPeers) at(peer string, head common.Hash) *proofPeer {
	b, ok := p.peers.Get(peer)
	if !ok {
		b = &proofPeer{head: head, tokens: ghost.ProofPeerBudget}
		p.peers.Add(peer, b)
	}
	if b.head != head {
		b.head, b.tokens, b.failed = head, ghost.ProofPeerBudget, 0
	}
	return b
}

// Take spends one delivery of the peer's budget at head, and reports false
// when none is left.
func (p *ProofPeers) Take(peer string, head common.Hash) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	b := p.at(peer, head)
	if b.tokens == 0 {
		return false
	}
	b.tokens--
	return true
}

// Available returns the deliveries left of the peer's budget at head.
func (p *ProofPeers) Available(peer string, head common.Hash) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.at(peer, head).tokens
}

// Fail counts one failed proof check of the peer at head, and reports
// whether the peer reached ghost.ProofFailLimit and is to be dropped.
func (p *ProofPeers) Fail(peer string, head common.Hash) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	b := p.at(peer, head)
	b.failed++
	return b.failed >= ghost.ProofFailLimit
}
