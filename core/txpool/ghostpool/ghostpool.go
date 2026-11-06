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

// Package ghostpool is the transaction pool of the native transactions
// without an account: the coin reveal (type 0x50), the data reveal (type
// 0x51), the policy reveal (type 0x53) and the policy action (type 0x54). None
// has a sender account, a nonce of an account or a gas price, so none can
// live in the legacy pool, which is ordered per account; they live here,
// beside the legacy pool, as a subpool of core/txpool.
//
// The pool checks a reveal with the chain rules of core/ghostpriv against
// the block that would come next on the current head, with the active
// verifier, at a cost bounded per reveal: the root rule is answered by the
// chain's tree-root index for the pool's head, the other checks read at most
// the headers of the fee window and of the window before it, whose fee is
// accepted too, and the proof is verified last, only for a
// reveal every other check passed. A transaction refused for a reason no
// head can change, a bad proof among them, is remembered by its hash in a
// bounded set and refused again without any check. It holds at most one
// reveal per marker, the first seen, across the three coin reveal types: a
// later reveal of the same marker is refused, and a held reveal whose marker
// another reveal spent in a block is dropped when the pool rechecks on the
// new head.
//
// A policy action is checked with checks 1 to 8 of core/ghostpriv first,
// against the pool's head, and its proof only after them. It is keyed by its
// slot's marker and its nonce, and takes that key only when it is inserted,
// after its proof verified: an action that fails reserves nothing, so a
// flood of bad actions for one slot never keeps a valid one out. Reveals and
// actions have caps of their own and share every peer budget. On each new
// head a held action runs checks 1 to 8 again, never its proof.
//
// A private bundle (type 0x55) is checked by its structure first: its
// decoding, its count and the chain id of the bundle and of every body, all
// read from its bytes, and that some body's marker is not spent yet. Then its
// root proof is verified natively, once, last: an invalid root costs one
// verification and nothing more, is remembered as refused, and counts as a
// failed proof of the peer under the same limit as the reveals' and the
// actions' proofs. A bundle takes no marker: a bundled reveal whose marker a
// block spent first is skipped when the bundle is applied. Bundles have a
// cap of their own; a held bundle is dropped on the head where every
// bundled marker is spent.
//
// The pool takes no account transaction (type 0x52): those stay in the
// legacy pool under its raw-signature bounds, a peer's signature budget among
// them.
//
// A public root (type 0x56) is checked and never held: it is valid only in a
// block beside the binding transactions (type 0x57) it proves, which no pool
// takes. Its cheap checks run first, under the lock: the shape, the chain id
// and, for every binding it lists, the key identity recorded in the head's
// state for the binding's account. Then its proof is verified once, against
// the public inputs the pool builds from those bindings, the chain id and
// the genesis hash. An invalid root so costs at most one native verification
// and is refused (ghostpriv.ErrPublicRootProof, a failed proof of the peer);
// a valid one is refused with ErrPublicRootNotPooled. Either is remembered by
// its hash and refused again without any check. The account transactions
// with their raw signatures stay in the legacy pool under its signature
// bounds, which a public root does not change.
//
// A peer whose transactions fail their proof PeerMaxFailedProofs times on
// one head is refused with ErrPeerFailLimit, which the network handler
// answers by disconnecting it.
package ghostpool

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params/types/ctypes"
	"github.com/ethereum/go-ethereum/params/vars"
	"github.com/holiman/uint256"
)

// The caps of the pool and the budgets of one peer.
const (
	// MaxReveals is the most reveals the pool holds, of the coin reveal
	// (both versions), the data reveal and the policy reveal together.
	MaxReveals = 16

	// MaxBytes is the most reveal envelope bytes the pool holds, 16
	// envelopes of the policy reveal, the largest of the envelopes the pool
	// takes: 20,983,216 bytes.
	MaxBytes = MaxReveals * types.GhostPolicyRevealEnvelopeSize

	// MaxActions is the most policy actions the pool holds, apart from the
	// reveals.
	MaxActions = 8

	// MaxActionBytes is the most policy action envelope bytes the pool
	// holds, 8 envelopes: 7,594,984 bytes.
	MaxActionBytes = MaxActions * types.GhostPolicyActionEnvelopeSize

	// PeerRevealsPerBlock is the number of transactions of this pool, of
	// any of its types, a peer may have the node fetch or take from it per
	// chain head: each announced one the node agrees to fetch, and each one
	// delivered without an announcement, takes one. The budget is refilled
	// when the head moves.
	PeerRevealsPerBlock = 4

	// PeerMaxInFlight is the most transactions of this pool of one peer
	// that are announced and agreed to be fetched but not delivered yet.
	PeerMaxInFlight = 4

	// PeerMaxHeld is the most transactions the pool holds, of any of its
	// types, that one peer was the first to deliver.
	PeerMaxHeld = 4

	// PeerMaxHeldBytes is the most envelope bytes the pool holds that one
	// peer was the first to deliver, PeerMaxHeld policy reveal envelopes.
	PeerMaxHeldBytes = PeerMaxHeld * types.GhostPolicyRevealEnvelopeSize

	// PeerMaxFailedProofs is the number of proofs of one peer's
	// transactions, of any of the pool's types, that may fail on one head:
	// at the last of them the pool refuses the transaction with
	// ErrPeerFailLimit, and the peer is dropped. The count starts again when
	// the head moves.
	PeerMaxFailedProofs = 3

	// MaxBundles is the most private bundles the pool holds, apart from the
	// reveals and the actions: with the largest bundle envelope, of 1,408
	// bodies, 4,226,586 bytes.
	MaxBundles = 2

	// announceExpiry is how long an agreed fetch counts against a peer's
	// in-flight budget when the transaction never arrives.
	announceExpiry = time.Minute
)

var (
	// ErrPoolFull is returned for a transaction that would take the pool
	// over the cap of its class: MaxReveals reveals or MaxBytes bytes for a
	// reveal, MaxActions actions or MaxActionBytes bytes for an action.
	ErrPoolFull = errors.New("reveal pool full")

	// ErrMarkerPending is returned for a reveal of a marker the pool already
	// holds a different reveal for. The first seen is kept.
	ErrMarkerPending = errors.New("marker already has a pending reveal")

	// ErrActionPending is returned for a policy action whose slot marker
	// and nonce the pool already holds a different verified action for. The
	// first held is kept, and the peer is not counted a failed proof.
	ErrActionPending = errors.New("policy action marker and nonce already have a pending action")

	// ErrPeerBudget is returned for a reveal from a peer that has used up its
	// budget.
	ErrPeerBudget = errors.New("peer reveal budget used up")

	// ErrPeerFailLimit is returned for a transaction of a peer that reached
	// PeerMaxFailedProofs failed proofs on the current head, wrapping the
	// refusal of the transaction: the peer is to be dropped.
	ErrPeerFailLimit = errors.New("peer reached the failed proof limit of the head")

	// ErrNoPeer is returned for a remote reveal that does not name the peer
	// it came from: remote reveals enter only through AddFromPeer, so that
	// the peer budgets apply.
	ErrNoPeer = errors.New("remote reveal without a peer")

	// ErrPeerBusy is returned for a reveal from a peer that has another
	// reveal being checked: one peer holds at most one check slot.
	ErrPeerBusy = fmt.Errorf("%w: another reveal of the peer is being checked", ErrPeerBudget)

	// ErrChecksBusy is returned for a remote reveal when every check slot
	// open to peers is taken.
	ErrChecksBusy = errors.New("every reveal check slot open to peers is taken")

	// ErrRootLookup is returned for a remote reveal whose root the tree-root
	// index cannot answer for, an index not ready among others: it is
	// dropped, never checked by a walk of the ancestry.
	ErrRootLookup = errors.New("reveal root cannot be looked up in the tree-root index")

	// ErrRejectedBefore is returned, wrapping the first refusal, for a reveal
	// the pool refused before for a reason that no head can change: it is
	// refused again without any check.
	ErrRejectedBefore = errors.New("reveal refused before")

	// ErrBundleSpent is returned for a bundle every one of whose bundled
	// reveals has a marker spent on the pool's head: applied, it would change
	// nothing. Its root is not verified, and the peer is not counted a failed
	// proof.
	ErrBundleSpent = errors.New("every reveal of the bundle has a spent marker")

	// ErrPublicRootNotPooled is returned for a public root whose checks and
	// proof passed: a root is valid only in a block beside the binding
	// transactions it proves, which no pool takes, so the pool never holds
	// one.
	ErrPublicRootNotPooled = errors.New("public root is not held by the pool: it is valid only in a block beside its binding transactions")
)

// maxRejected is the most hashes of refused reveals the pool remembers; the
// oldest is forgotten first.
const maxRejected = 4096

// rejectedSet is the bounded set of the hashes of refused reveals, each with
// its first refusal, forgetting the oldest when full.
type rejectedSet struct {
	errs map[common.Hash]error
	ring []common.Hash // the remembered hashes, in the order they came
	next int           // the place of ring the next hash takes once full
}

// add remembers hash with its refusal err if err holds whatever the head,
// that is if it comes from the bytes of the transaction alone: its
// decoding, its chain id, the shape of a data reveal, or its proof, which is
// verified last, so a proof refused is refused for good. A refusal that a
// later head, a reorganisation or the pool's own load can lift is not
// remembered: the fee of the window, the root, the marker, the backstop, the
// policy, the slot of an action, its nonce, its debit and its expiry, the
// caps, the budgets and a node without a verifier.
func (s *rejectedSet) add(hash common.Hash, err error) {
	if !permanentRefusal(err) {
		return
	}
	if s.errs == nil {
		s.errs = make(map[common.Hash]error)
	}
	if _, ok := s.errs[hash]; ok {
		return
	}
	if len(s.ring) < maxRejected {
		s.ring = append(s.ring, hash)
	} else {
		delete(s.errs, s.ring[s.next])
		s.ring[s.next] = hash
		s.next = (s.next + 1) % maxRejected
	}
	s.errs[hash] = err
}

// lookup returns the first refusal of a remembered hash, nil for a hash not
// remembered.
func (s *rejectedSet) lookup(hash common.Hash) error {
	return s.errs[hash]
}

// permanentRefusals are the refusals of a transaction that its bytes alone
// decide.
var permanentRefusals = []error{
	ghostpriv.ErrRevealLength, ghostpriv.ErrRevealVersion, ghostpriv.ErrRevealAmount,
	ghostpriv.ErrRevealChainID, ghostpriv.ErrRevealProof,
	ghostpriv.ErrDataRevealLength, ghostpriv.ErrDataRevealVersion, ghostpriv.ErrDataRevealAmount,
	ghostpriv.ErrDataRevealChainID, ghostpriv.ErrDataRevealPurpose, ghostpriv.ErrDataRevealShape,
	ghostpriv.ErrDataRevealProof,
	ghostpriv.ErrPolicyRevealLength, ghostpriv.ErrPolicyRevealVersion, ghostpriv.ErrPolicyRevealAmount,
	ghostpriv.ErrPolicyRevealChainID, ghostpriv.ErrPolicyRevealProof,
	ghostpriv.ErrActionLength, ghostpriv.ErrActionVersion, ghostpriv.ErrActionEncoding,
	ghostpriv.ErrActionChainID, ghostpriv.ErrActionProof,
	ghostpriv.ErrBundleLength, ghostpriv.ErrBundleCount, ghostpriv.ErrBundleVersion,
	ghostpriv.ErrBundleChainID, ghostpriv.ErrBundleBody, ghostpriv.ErrBundleProof,
	// A public root's proof is verified against the bindings it lists, once
	// their key identities are the recorded ones, so its verdict is that of
	// its bytes; and the pool holds no root, whatever the head.
	ghostpriv.ErrPublicRootLength, ghostpriv.ErrPublicRootVersion, ghostpriv.ErrPublicRootChainID,
	ghostpriv.ErrPublicRootProof, ErrPublicRootNotPooled,
}

// permanentRefusal reports whether err is a refusal of a transaction that
// no head can lift.
func permanentRefusal(err error) bool {
	if err == nil || errors.Is(err, ghostpriv.ErrNoVerifier) {
		return false
	}
	for _, target := range permanentRefusals {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

// proofRefusals are the refusals of a proof the verifier rejected, one per
// type, the bundle's root among them.
var proofRefusals = []error{
	ghostpriv.ErrRevealProof, ghostpriv.ErrDataRevealProof,
	ghostpriv.ErrPolicyRevealProof, ghostpriv.ErrActionProof,
	ghostpriv.ErrBundleProof, ghostpriv.ErrPublicRootProof,
}

// failedProof reports whether err is the refusal of a proof the verifier
// checked and rejected. A node without a verifier, or with one that does not
// verify bundle roots (ghostpriv.ErrBundleUnsupported), is not the peer's
// fault.
func failedProof(err error) bool {
	if err == nil || errors.Is(err, ghostpriv.ErrNoVerifier) {
		return false
	}
	for _, target := range proofRefusals {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

// BlockChain is the part of the chain the pool needs. *core.BlockChain
// satisfies it.
type BlockChain interface {
	// Config retrieves the chain's fork configuration.
	Config() ctypes.ChainConfigurator

	// CurrentBlock returns the current head of the chain.
	CurrentBlock() *types.Header

	// GetHeader returns a header by hash and number, for the fee windows and
	// the tree-root index.
	GetHeader(hash common.Hash, number uint64) *types.Header

	// StateAt returns the state with the given root.
	StateAt(root common.Hash) (*state.StateDB, error)

	// Genesis returns the genesis block, the domain of the binding digest.
	Genesis() *types.Block
}

// markerKey identifies a marker: the coin and data marker sets are apart.
type markerKey struct {
	kind   ghosttree.Kind
	marker common.Hash
}

// actionKey identifies the slot nonce a policy action spends: the marker of
// its escrow slot and its nonce.
type actionKey struct {
	marker common.Hash
	nonce  uint64
}

// txClass is the class of a held transaction, which decides its gas, its
// fee and the cap it counts under.
type txClass uint8

const (
	classCoin   txClass = iota // the version 2 coin reveal, G_PRIV
	classCoinV1                // the version 1 coin reveal, its own gas
	classData                  // the data reveal, G_DATA
	classPolicy                // the policy reveal, G_POLICY
	classAction                // the policy action, G_ACTION
	classBundle                // the private bundle, the gas of its count
)

// gas is the gas of a transaction of the class.
func (c txClass) gas() uint64 {
	switch c {
	case classCoinV1:
		return ghostpriv.GasPrivV1
	case classData:
		return ghostpriv.GasData
	case classPolicy:
		return ghostpriv.GasPolicy
	case classAction:
		return ghostpriv.GasAction
	default:
		return ghostpriv.GasPriv
	}
}

// entry is one held transaction.
type entry struct {
	tx      *types.Transaction
	class   txClass
	key     markerKey     // the marker of a reveal
	akey    actionKey     // the slot nonce of an action
	markers []common.Hash // the coin markers of a bundle's reveals, read only
	paid    *uint256.Int  // the fee field of a reveal, the debit of an action
	peer    string        // the peer that first delivered it, empty for a local one
}

// gas is the gas of the held transaction: that of its class, or for a
// bundle that of its count.
func (e *entry) gas() uint64 {
	if e.class == classBundle {
		return e.tx.Gas()
	}
	return e.class.gas()
}

// peerBudget is what one peer has used of its budgets.
type peerBudget struct {
	tokens     int                       // transactions left to take in this head
	announced  map[common.Hash]time.Time // agreed fetches not delivered yet
	held       int                       // transactions held that it delivered first
	validating int                       // transactions it delivered being checked
	failed     int                       // proofs of its transactions failed on this head
}

// Pool is the reveal pool.
//
// The checks run outside the pool's lock, at most maxValidations at a time,
// against a snapshot of the head: they verify the proof, and the lock must
// not be held through that. Their cost is bounded per transaction whatever
// the age of a reveal's root: one lookup in the tree-root index, then the
// other checks, which read at most the headers of the fee window and of the
// window before it, then the proof. A reveal being checked holds its marker
// and a place under the caps, so that the first seen of two competing
// reveals is still the one kept. A policy action being checked holds a
// place under the caps but not its key, which it takes when it is inserted.
//
// The refusals that need neither the proof nor the root run first under the
// lock and charge the peer for every transaction they refuse; one peer holds
// at most one slot at a time; a remote transaction that finds no slot free
// is dropped, never queued; and one slot is kept for the node's own
// transactions.
type Pool struct {
	chain       BlockChain
	verifier    func() ghostpriv.Verifier
	remoteSlots chan struct{} // one per check running, of any transaction
	localSlot   chan struct{} // the slot only local transactions take

	mu           sync.RWMutex
	head         *types.Header
	state        *state.StateDB
	fees         classFeeSet // the fees of each reveal class in the next block
	all          map[common.Hash]*entry
	order        []common.Hash // hashes of the held transactions, first seen first
	markers      map[markerKey]common.Hash
	bytes        uint64                    // envelope bytes of the held reveals
	validating   map[markerKey]common.Hash // reveals being checked, by marker
	locals       int                       // local reveals among those being checked
	actions      map[actionKey]common.Hash // held policy actions, by slot nonce
	actionBytes  uint64                    // envelope bytes of the held actions
	actionChecks map[common.Hash]bool      // actions being checked, true for a local one
	localActions int                       // local actions among those being checked
	bundles      int                       // held bundles
	bundleChecks map[common.Hash]bool      // bundles being checked, true for a local one
	localBundles int                       // local bundles among those being checked
	rootChecks   map[common.Hash]struct{}  // public roots whose proof is being verified
	peers        map[string]*peerBudget
	rejected     rejectedSet // transactions refused for good, refused again unchecked

	feed  event.Feed
	scope event.SubscriptionScope
}

const (
	// maxValidations is the most checks of new transactions that run at
	// the same time. One of them is kept for local transactions.
	maxValidations = 4

	// maxRevalidations is how often a new transaction is checked again when
	// the head moved while it was checked.
	maxRevalidations = 3
)

// errHeadMoving is returned for a reveal whose check could not finish on a
// head that stayed the head.
var errHeadMoving = errors.New("chain head kept moving while the reveal was checked")

// New creates a reveal pool on chain. It checks reveals with the active
// verifier of core/ghostpriv.
func New(chain BlockChain) *Pool {
	return &Pool{
		chain:        chain,
		verifier:     ghostpriv.ActiveVerifier,
		remoteSlots:  make(chan struct{}, maxValidations-1),
		localSlot:    make(chan struct{}, 1),
		all:          make(map[common.Hash]*entry),
		markers:      make(map[markerKey]common.Hash),
		validating:   make(map[markerKey]common.Hash),
		actions:      make(map[actionKey]common.Hash),
		actionChecks: make(map[common.Hash]bool),
		bundleChecks: make(map[common.Hash]bool),
		rootChecks:   make(map[common.Hash]struct{}),
		peers:        make(map[string]*peerBudget),
	}
}

// Filter accepts the coin reveal, the data reveal, the policy reveal, the
// policy action and the private bundle, and the public root, which it checks
// and never holds. The account transaction is the legacy pool's, and the
// direct reveal no pool's yet.
func (p *Pool) Filter(tx *types.Transaction) bool {
	switch tx.Type() {
	case types.GhostBundleTxType, types.GhostPublicRootTxType:
		return true
	}
	return tx.IsGhostReveal()
}

// classFees are the fees of one reveal class the block that would come next
// on the head accepts: that of its fee window and that of the window before
// it, each nil when unknown or, for prev, when there is none.
type classFees struct {
	cur, prev *ghostpriv.Fee
}

// match returns the fee of the two whose total is paid, nil if neither is.
func (c classFees) match(paid *uint256.Int) *ghostpriv.Fee {
	switch {
	case paid == nil:
		return nil
	case c.cur != nil && c.cur.Total.Eq(paid):
		return c.cur
	case c.prev != nil && c.prev.Total.Eq(paid):
		return c.prev
	}
	return nil
}

// classFeeSet are the fees of every reveal class in the next block.
type classFeeSet struct {
	coin, coinV1, data, policy classFees
}

// of returns the fees of the reveal class c.
func (s classFeeSet) of(c txClass) classFees {
	switch c {
	case classCoinV1:
		return s.coinV1
	case classData:
		return s.data
	case classPolicy:
		return s.policy
	default:
		return s.coin
	}
}

// Init sets the head the pool checks against. A reveal has no account, so
// the pool reserves none.
func (p *Pool) Init(gasTip uint64, head *types.Header, reserve txpool.AddressReserver) error {
	st, err := p.chain.StateAt(head.Root)
	if err != nil {
		return err
	}
	fees := p.windowFees(head)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.head, p.state, p.fees = head, st, fees
	return nil
}

// Close ends every subscription.
func (p *Pool) Close() error {
	p.scope.Close()
	return nil
}

// Reset moves the pool to the new head: it refills the peer budgets, starts
// the count of failed proofs again when the head moved, and rechecks every
// held transaction against the block that would come next, dropping each
// that no longer passes, among them every reveal whose marker a block spent
// and every action whose slot closed, whose nonce moved, whose policy a
// reorganisation removed, whose debit no longer pays G_ACTION at the base
// fee or whose expiry passed, and every bundle all of whose markers are
// spent. A held action runs checks 1 to 8 again; its proof, verified once,
// is not verified again, nor is a held bundle's root.
func (p *Pool) Reset(oldHead, newHead *types.Header) {
	st, err := p.chain.StateAt(newHead.Root)
	if err != nil {
		log.Error("Reveal pool cannot reset to the new head", "number", newHead.Number, "hash", newHead.Hash(), "err", err)
		return
	}
	// The recheck runs outside the lock on a state of its own, apart from
	// the one new reveals copy theirs from.
	recheck, err := p.chain.StateAt(newHead.Root)
	if err != nil {
		log.Error("Reveal pool cannot reset to the new head", "number", newHead.Number, "hash", newHead.Hash(), "err", err)
		return
	}
	fees := p.windowFees(newHead)
	p.mu.Lock()
	moved := p.head == nil || p.head.Hash() != newHead.Hash()
	p.head, p.state, p.fees = newHead, st, fees
	now := time.Now()
	for _, b := range p.peers {
		b.tokens = PeerRevealsPerBlock
		if moved {
			b.failed = 0
		}
		for hash, at := range b.announced {
			// A transaction another peer delivered first, or one that never
			// came, no longer holds an in-flight place.
			if _, held := p.all[hash]; held || now.Sub(at) > announceExpiry {
				delete(b.announced, hash)
			}
		}
	}
	held := make([]entry, 0, len(p.order))
	for _, hash := range p.order {
		held = append(held, *p.all[hash])
	}
	p.mu.Unlock()

	var failed []common.Hash
	for _, e := range held {
		var err error
		switch e.class {
		case classAction:
			err = p.actionRules(newHead, recheck.Copy(), e.tx)
		case classBundle:
			// The root verified once; only what the head decides is checked
			// again.
			err = bundleLive(recheck, e.markers)
		default:
			err = p.check(newHead, recheck.Copy(), e.tx, e.peer == "")
		}
		if err != nil {
			log.Debug("Dropped transaction on recheck", "hash", e.tx.Hash(), "type", e.tx.Type(), "err", err)
			failed = append(failed, e.tx.Hash())
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	// A later head runs a recheck of its own; this one only drops what
	// failed on the head that is still the pool's.
	if p.head.Hash() != newHead.Hash() {
		return
	}
	for _, hash := range failed {
		p.remove(hash)
	}
}

// SetGasTip does nothing: a reveal pays the window fee, not a gas price.
func (p *Pool) SetGasTip(tip *big.Int) {}

// Has reports whether the pool holds the reveal with the given hash.
func (p *Pool) Has(hash common.Hash) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	_, ok := p.all[hash]
	return ok
}

// Get returns the held reveal with the given hash, nil if there is none.
func (p *Pool) Get(hash common.Hash) *types.Transaction {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if e, ok := p.all[hash]; ok {
		return e.tx
	}
	return nil
}

// Add adds local reveals, those of the node's own RPC. A remote reveal
// must come through AddFromPeer so that the peer budgets apply: here it is
// already known or refused with ErrNoPeer.
func (p *Pool) Add(txs []*types.Transaction, local bool, sync bool) []error {
	errs := make([]error, len(txs))
	for i, tx := range txs {
		if !local {
			if p.Has(tx.Hash()) {
				errs[i] = txpool.ErrAlreadyKnown
			} else {
				errs[i] = ErrNoPeer
			}
			continue
		}
		errs[i] = p.add(tx, "")
	}
	return errs
}

// AddFromPeer adds transactions delivered by a peer, under that peer's
// budgets. A transaction whose proof failed as the peer's
// PeerMaxFailedProofs-th on this head, and every one after it on the same
// head, is refused with an error wrapping ErrPeerFailLimit: the caller drops
// the peer.
func (p *Pool) AddFromPeer(peer string, txs []*types.Transaction) []error {
	errs := make([]error, len(txs))
	for i, tx := range txs {
		if peer == "" {
			errs[i] = ErrNoPeer
			continue
		}
		errs[i] = p.add(tx, peer)
	}
	return errs
}

// add checks and inserts one transaction, first delivered by peer, empty
// for a local one. The cheap refusals come first, under the lock, and a
// remote transaction takes a check slot there or is dropped; then the
// transaction holds a place under the caps and its slot, and a reveal its
// marker, while its checks run outside the lock, and is inserted when they
// pass on the head that is still the pool's.
func (p *Pool) add(tx *types.Transaction, peer string) error {
	if !p.Filter(tx) {
		return fmt.Errorf("%w: type %#x", core.ErrTxTypeNotSupported, tx.Type())
	}
	hash := tx.Hash()
	p.mu.Lock()
	// A peer at the failed proof limit of this head gets no more checks.
	if b, ok := p.peers[peer]; ok && peer != "" && b.failed >= PeerMaxFailedProofs {
		p.mu.Unlock()
		return fmt.Errorf("%w: peer %s, %d failed proofs", ErrPeerFailLimit, peer, b.failed)
	}
	// A transaction refused for good before is refused again without any
	// check, and charged to the peer as any other.
	if first := p.rejected.lookup(hash); first != nil {
		_, err := p.charge(peer, hash)
		p.mu.Unlock()
		if err != nil {
			return err
		}
		return fmt.Errorf("%w: %w", ErrRejectedBefore, first)
	}
	p.mu.Unlock()
	switch tx.Type() {
	case types.GhostPolicyActionTxType:
		return p.addAction(tx, peer)
	case types.GhostBundleTxType:
		return p.addBundle(tx, peer)
	case types.GhostPublicRootTxType:
		return p.addPublicRoot(tx, peer)
	}
	return p.addReveal(tx, peer)
}

// addPublicRoot checks a public root and refuses it: the pool holds no root.
// Under the lock, the peer is charged first, as for any transaction, then
// come the decoding (the length, the count and the version), the peer's one
// check slot, the chain id, a count no block's gas limit on the head can pay
// for (ghostpriv.ErrPublicRootCount) and the key identities: each binding the root
// lists must name an account whose key identity the head's state records,
// and that identity. None of them verifies anything. Then the root takes a
// check slot, a remote root without waiting, and its proof is verified once,
// outside the lock, with the active verifier against the inputs the pool
// builds from those bindings, this chain's id and its genesis hash. A proof
// refused is ghostpriv.ErrPublicRootProof, counted to the peer as a failed
// proof; a proof accepted is ErrPublicRootNotPooled. Both are remembered by
// the root's hash, so the same root costs no second verification.
func (p *Pool) addPublicRoot(tx *types.Transaction, peer string) error {
	hash := tx.Hash()
	root, decodeErr := ghostpriv.DecodePublicRoot(tx.GhostPublicRootEnvelope())
	p.mu.Lock()
	slot, bindings, err := p.admitPublicRoot(hash, root, decodeErr, peer)
	if err != nil {
		p.rejected.add(hash, err)
		p.mu.Unlock()
		return err
	}
	p.rootChecks[hash] = struct{}{}
	if peer != "" {
		p.peers[peer].validating++
	}
	p.mu.Unlock()

	slot = p.takeSlot(slot)
	in := ghostpriv.NewPublicRootInputs(root.ChainID, p.chain.Genesis().Hash(), bindings)
	err = ghostpriv.VerifyPublicRoot(p.verifier(), in, root.Proof)
	p.mu.Lock()
	<-slot
	delete(p.rootChecks, hash)
	if b, ok := p.peers[peer]; ok && peer != "" && b.validating > 0 {
		b.validating--
	}
	if err == nil {
		err = fmt.Errorf("%w: %x", ErrPublicRootNotPooled, hash)
	}
	err = p.refuse(hash, peer, err)
	p.mu.Unlock()
	return err
}

// admitPublicRoot runs the checks of a public root that verify nothing,
// decoded as root or refused by decodeErr, charging the peer first, and
// returns the check slot of a remote root and the bindings the pool builds
// for the root's proof: for each binding the root lists, its account, the
// key identity recorded for it in the head's state and its transaction
// hash. A binding whose account has no key identity recorded, or another
// one, is ghostpriv.ErrPublicKeyIdentity. The caller holds the lock.
func (p *Pool) admitPublicRoot(hash common.Hash, root *ghostpriv.PublicRoot, decodeErr error, peer string) (chan struct{}, []types.GhostBinding, error) {
	// The same root being verified for another sender is not verified twice.
	if _, ok := p.rootChecks[hash]; ok {
		return nil, nil, txpool.ErrAlreadyKnown
	}
	b, err := p.charge(peer, hash)
	if err != nil {
		return nil, nil, err
	}
	if decodeErr != nil {
		return nil, nil, decodeErr
	}
	if b != nil && b.validating > 0 {
		return nil, nil, fmt.Errorf("%w: peer %s", ErrPeerBusy, peer)
	}
	if id := p.chain.Config().GetChainID(); id == nil || !id.IsUint64() || id.Uint64() != root.ChainID {
		return nil, nil, fmt.Errorf("%w: have %d, chain %v", ghostpriv.ErrPublicRootChainID, root.ChainID, id)
	}
	if p.head == nil || p.state == nil {
		return nil, nil, errors.New("reveal pool not initialised")
	}
	// No block on the head holds more binding transactions than its gas
	// limit pays for at the cheapest binding transaction's intrinsic gas, so
	// a root listing more is refused before any state is read.
	if most := p.head.GasLimit / minBindingTxGas(); uint64(len(root.Bindings)) > most {
		return nil, nil, fmt.Errorf("%w: %d bindings, a block of gas limit %d holds at most %d", ghostpriv.ErrPublicRootCount, len(root.Bindings), p.head.GasLimit, most)
	}
	bindings := make([]types.GhostBinding, len(root.Bindings))
	for i, listed := range root.Bindings {
		node, err := ghostpriv.CheckBinding(p.state, listed, listed.TxHash())
		if err != nil {
			return nil, nil, fmt.Errorf("binding %d: %w", i, err)
		}
		bindings[i] = node
	}
	slot, err := p.remoteSlot(peer)
	if err != nil {
		return nil, nil, err
	}
	return slot, bindings, nil
}

// minBindingTxGas is the least intrinsic gas of a binding transaction: a
// plain transfer of the scheme whose binding transaction is the cheapest.
func minBindingTxGas() uint64 {
	least := uint64(0)
	for _, scheme := range []uint16{types.GhostSchemeMLDSA44, types.GhostSchemeSLHDSA, types.GhostSchemeMLDSA44Rescue, types.GhostSchemeSLHDSARescue} {
		extra, err := core.GhostBindingExtraIntrinsicGas(scheme)
		if err != nil {
			continue
		}
		if gas := vars.TxGas + extra; least == 0 || gas < least {
			least = gas
		}
	}
	if least == 0 {
		return vars.TxGas
	}
	return least
}

// addReveal checks and inserts one reveal, of any of the three reveal
// types.
func (p *Pool) addReveal(tx *types.Transaction, peer string) error {
	hash := tx.Hash()
	// Decoding runs the length, version and amount checks; a peer is charged
	// for a reveal that fails them as for any other.
	fields, decodeErr := decode(tx)
	key := fields.key
	p.mu.Lock()
	slot, err := p.admit(hash, fields, decodeErr, tx.Size(), peer)
	if err != nil {
		p.rejected.add(hash, err)
		p.mu.Unlock()
		return err
	}
	p.validating[key] = hash
	if peer != "" {
		p.peers[peer].validating++
	} else {
		p.locals++
	}
	head, st, err := p.snapshot()
	p.mu.Unlock()

	slot = p.takeSlot(slot)
	err = p.checkUntilSettled(head, st, err, func(head *types.Header, st *state.StateDB) error {
		return p.check(head, st, tx, peer == "")
	})
	// The lock is held from here.
	<-slot
	delete(p.validating, key)
	b, ok := p.peers[peer]
	if peer == "" {
		p.locals--
	} else if ok && b.validating > 0 {
		b.validating--
	}
	// Places a local reveal took while this one was checked are not counted
	// against it at admission, so the caps are checked again here.
	if err == nil && (len(p.markers) >= MaxReveals || p.bytes+tx.Size() > MaxBytes) {
		err = fmt.Errorf("%w: %d reveals, %d bytes", ErrPoolFull, len(p.markers), p.bytes)
	}
	if err != nil {
		err = p.refuse(hash, peer, err)
		p.mu.Unlock()
		return err
	}
	// The reveal held its marker and its place while it was checked, so only
	// a peer that left can have changed what it is entered under.
	if !ok {
		peer = ""
	}
	p.insert(&entry{tx: tx, class: fields.class(), key: key, paid: fields.fee, peer: peer})
	p.markers[key] = hash
	p.bytes += tx.Size()
	p.mu.Unlock()

	p.feed.Send(core.NewTxsEvent{Txs: []*types.Transaction{tx}})
	return nil
}

// addAction checks and inserts one policy action. Checks 1 to 8 run under
// the lock against the pool's head, before any proof; then the action holds
// a check slot and a place under the action caps, but not its key, while its
// proof is verified outside the lock; it takes its key when it is inserted,
// so that of two valid actions for one key the first to finish is kept and
// the other refused with ErrActionPending, which is no failed proof.
func (p *Pool) addAction(tx *types.Transaction, peer string) error {
	hash := tx.Hash()
	envelope := tx.GhostPolicyActionEnvelope()
	a, decodeErr := ghostpriv.DecodeAction(envelope)
	size := tx.Size()
	p.mu.Lock()
	slot, err := p.admitAction(hash, a, decodeErr, envelope, size, peer)
	if err != nil {
		p.rejected.add(hash, err)
		p.mu.Unlock()
		return err
	}
	local := peer == ""
	p.actionChecks[hash] = local
	if local {
		p.localActions++
	} else {
		p.peers[peer].validating++
	}
	head, st, err := p.snapshot()
	p.mu.Unlock()

	slot = p.takeSlot(slot)
	err = p.checkUntilSettled(head, st, err, func(head *types.Header, st *state.StateDB) error {
		_, _, err := ghostpriv.CheckAction(st, p.actionEnv(head), p.verifier(), envelope)
		return err
	})
	// The lock is held from here.
	<-slot
	delete(p.actionChecks, hash)
	b, ok := p.peers[peer]
	if local {
		p.localActions--
	} else if ok && b.validating > 0 {
		b.validating--
	}
	key := actionKey{marker: a.Marker, nonce: a.Nonce}
	// The key is reserved only here, after the proof verified; the caps
	// are checked again, as places local actions took were not counted at
	// admission.
	if err == nil {
		if other, held := p.actions[key]; held {
			err = fmt.Errorf("%w: marker %x nonce %d held by %x", ErrActionPending, key.marker, key.nonce, other)
		} else if len(p.actions) >= MaxActions || p.actionBytes+size > MaxActionBytes {
			err = fmt.Errorf("%w: %d actions, %d bytes", ErrPoolFull, len(p.actions), p.actionBytes)
		}
	}
	if err != nil {
		err = p.refuse(hash, peer, err)
		p.mu.Unlock()
		return err
	}
	if !ok {
		peer = ""
	}
	p.insert(&entry{tx: tx, class: classAction, akey: key, paid: new(uint256.Int).Set(a.Debit), peer: peer})
	p.actions[key] = hash
	p.actionBytes += size
	p.mu.Unlock()

	p.feed.Send(core.NewTxsEvent{Txs: []*types.Transaction{tx}})
	return nil
}

// addBundle checks and inserts one private bundle. The checks its bytes
// alone decide run first, under the lock (admitBundle); then the bundle
// holds a check slot and a place under the bundle cap while, outside the
// lock, the pool checks that some bundled marker is not spent on its head
// and then verifies the root natively, once, last. The root's inputs are
// built from the bundle's bytes, the chain id and the genesis only, so when
// the head moves during the check only the markers are checked again. An
// invalid root is refused with ghostpriv.ErrBundleProof, remembered for
// good, and counted to the peer as a failed proof.
func (p *Pool) addBundle(tx *types.Transaction, peer string) error {
	hash := tx.Hash()
	b, decodeErr := ghostpriv.DecodeBundle(tx.GhostBundleEnvelope())
	size := tx.Size()
	p.mu.Lock()
	slot, err := p.admitBundle(hash, b, decodeErr, size, peer)
	if err != nil {
		p.rejected.add(hash, err)
		p.mu.Unlock()
		return err
	}
	local := peer == ""
	p.bundleChecks[hash] = local
	if local {
		p.localBundles++
	} else {
		p.peers[peer].validating++
	}
	head, st, err := p.snapshot()
	p.mu.Unlock()

	markers := bundleMarkers(b)
	in := b.Inputs(b.ChainID, p.chain.Genesis().Hash())
	verified := false
	slot = p.takeSlot(slot)
	err = p.checkUntilSettled(head, st, err, func(_ *types.Header, st *state.StateDB) error {
		if err := bundleLive(st, markers); err != nil {
			return err
		}
		if verified {
			return nil
		}
		verified = true
		return ghostpriv.VerifyBundleRoot(p.verifier(), in, b.Proof)
	})
	// The lock is held from here.
	<-slot
	delete(p.bundleChecks, hash)
	pb, ok := p.peers[peer]
	if local {
		p.localBundles--
	} else if ok && pb.validating > 0 {
		pb.validating--
	}
	// Places a local bundle took while this one was checked are not counted
	// against it at admission, so the cap is checked again here.
	if err == nil && p.bundles >= MaxBundles {
		err = fmt.Errorf("%w: %d bundles", ErrPoolFull, p.bundles)
	}
	if err != nil {
		err = p.refuse(hash, peer, err)
		p.mu.Unlock()
		return err
	}
	if !ok {
		peer = ""
	}
	p.insert(&entry{tx: tx, class: classBundle, markers: markers, peer: peer})
	p.bundles++
	p.mu.Unlock()

	p.feed.Send(core.NewTxsEvent{Txs: []*types.Transaction{tx}})
	return nil
}

// admitBundle runs the cheap refusals of a new bundle, decoded as b or
// refused by decodeErr, charging the peer first as admit does: the decoding
// (the length, the count, the version and every body a version 2 reveal),
// the peer's one check slot and held cap, the chain id of the bundle and of
// every body, and the bundle cap. None verifies anything. The caller holds
// the lock.
func (p *Pool) admitBundle(hash common.Hash, b *ghostpriv.Bundle, decodeErr error, size uint64, peer string) (chan struct{}, error) {
	if _, ok := p.all[hash]; ok {
		return nil, txpool.ErrAlreadyKnown
	}
	if _, ok := p.bundleChecks[hash]; ok {
		return nil, txpool.ErrAlreadyKnown
	}
	pb, err := p.charge(peer, hash)
	if err != nil {
		return nil, err
	}
	if decodeErr != nil {
		return nil, decodeErr
	}
	if err := p.peerRoom(pb, peer, size); err != nil {
		return nil, err
	}
	if err := bundleChainIDs(b, p.chain.Config().GetChainID()); err != nil {
		return nil, err
	}
	pending := len(p.bundleChecks)
	if peer == "" {
		pending = p.localBundles
	}
	if count := p.bundles + pending; count >= MaxBundles {
		return nil, fmt.Errorf("%w: %d bundles", ErrPoolFull, count)
	}
	return p.remoteSlot(peer)
}

// bundleChainIDs refuses a bundle whose chain id, or the chain id of any of
// whose bodies, is not chainID, as ghostpriv.CheckBundle does.
func bundleChainIDs(b *ghostpriv.Bundle, chainID *big.Int) error {
	if chainID == nil || !chainID.IsUint64() {
		return fmt.Errorf("%w: chain %v", ghostpriv.ErrBundleChainID, chainID)
	}
	id := chainID.Uint64()
	if b.ChainID != id {
		return fmt.Errorf("%w: have %d, chain %d", ghostpriv.ErrBundleChainID, b.ChainID, id)
	}
	for i, r := range b.Reveals {
		if r.ChainID != id {
			return fmt.Errorf("%w: body %d has %d, chain %d", ghostpriv.ErrBundleChainID, i, r.ChainID, id)
		}
	}
	return nil
}

// bundleMarkers returns the coin markers of a bundle's reveals, in order.
func bundleMarkers(b *ghostpriv.Bundle) []common.Hash {
	markers := make([]common.Hash, len(b.Reveals))
	for i, r := range b.Reveals {
		markers[i] = r.Marker
	}
	return markers
}

// bundleLive refuses with ErrBundleSpent a bundle every one of whose coin
// markers is spent in st: applied, each of its reveals would be skipped.
func bundleLive(st *state.StateDB, markers []common.Hash) error {
	for _, m := range markers {
		if !ghosttree.IsSpent(st, ghosttree.Coin, m) {
			return nil
		}
	}
	return fmt.Errorf("%w: %d reveals", ErrBundleSpent, len(markers))
}

// takeSlot returns the check slot of a transaction: slot when admission
// took one for a remote transaction; else, for a local transaction, any
// free one, else the one kept for local transactions, which no peer can
// take, waiting for it.
func (p *Pool) takeSlot(slot chan struct{}) chan struct{} {
	if slot != nil {
		return slot
	}
	select {
	case p.remoteSlots <- struct{}{}:
		return p.remoteSlots
	default:
		select {
		case p.remoteSlots <- struct{}{}:
			return p.remoteSlots
		case p.localSlot <- struct{}{}:
			return p.localSlot
		}
	}
}

// checkUntilSettled runs check on head and st, outside the lock, unless err
// already refuses, and again on the new head while the head moved under it,
// at most maxRevalidations times. It returns holding the lock.
func (p *Pool) checkUntilSettled(head *types.Header, st *state.StateDB, err error, check func(*types.Header, *state.StateDB) error) error {
	for attempt := 0; ; attempt++ {
		if err == nil {
			err = check(head, st)
		}
		p.mu.Lock()
		if err != nil || p.head.Hash() == head.Hash() {
			return err
		}
		// The head moved while the transaction was checked: check it again
		// on the new head.
		if attempt+1 == maxRevalidations {
			return errHeadMoving
		}
		head, st, err = p.snapshot()
		p.mu.Unlock()
	}
}

// refuse records the refusal err of a checked transaction: its hash is
// remembered when no head can lift err, and a failed proof is counted to
// the peer, whose PeerMaxFailedProofs-th on this head turns the refusal into
// one wrapping ErrPeerFailLimit. The remembered refusal is the plain one, so
// that another peer sending the same transaction is not taken for this one.
// The caller holds the lock.
func (p *Pool) refuse(hash common.Hash, peer string, err error) error {
	p.rejected.add(hash, err)
	if peer == "" || !failedProof(err) {
		return err
	}
	b, ok := p.peers[peer]
	if !ok {
		return err
	}
	b.failed++
	if b.failed >= PeerMaxFailedProofs {
		return fmt.Errorf("%w: peer %s, %d failed proofs: %w", ErrPeerFailLimit, peer, b.failed, err)
	}
	return err
}

// insert enters a checked transaction under its hash, first seen last, and
// counts it to the peer that delivered it. The caller holds the lock.
func (p *Pool) insert(e *entry) {
	hash := e.tx.Hash()
	p.all[hash] = e
	p.order = append(p.order, hash)
	if e.peer != "" {
		if b, ok := p.peers[e.peer]; ok {
			b.held++
		}
	}
}

// admit runs the cheap refusals of a new reveal, decoded as fields or
// refused by decodeErr, and charges the peer's budget for it before any
// refusal but that of a reveal held or being checked: so a reveal that
// fails costs the peer as much as one that passes. Then come the decoding,
// the peer's one check slot and held cap, a marker held or being checked
// for another reveal, the chain id, the fee, a spent marker, the policy of a
// policy reveal and the caps. The root and the proof are left to the reveal
// checks, the proof last. A remote reveal takes a check slot last, without
// waiting, and admit returns it; a local reveal takes its slot after the
// lock is let go. The caller holds the lock.
func (p *Pool) admit(hash common.Hash, fields revealFields, decodeErr error, size uint64, peer string) (chan struct{}, error) {
	key := fields.key
	if _, ok := p.all[hash]; ok {
		return nil, txpool.ErrAlreadyKnown
	}
	if decodeErr == nil && p.validating[key] == hash {
		return nil, txpool.ErrAlreadyKnown
	}
	b, err := p.charge(peer, hash)
	if err != nil {
		return nil, err
	}
	if decodeErr != nil {
		return nil, decodeErr
	}
	if err := p.peerRoom(b, peer, size); err != nil {
		return nil, err
	}
	if other, ok := p.validating[key]; ok {
		return nil, fmt.Errorf("%w: marker %x taken by %x", ErrMarkerPending, key.marker, other)
	}
	if other, ok := p.markers[key]; ok {
		return nil, fmt.Errorf("%w: marker %x held by %x", ErrMarkerPending, key.marker, other)
	}
	if err := p.cheapRules(fields); err != nil {
		return nil, err
	}
	// A local reveal is not refused for the places of remote reveals being
	// checked, which may yet fail; the insertion checks the caps again.
	pending := len(p.validating)
	if peer == "" {
		pending = p.locals
	}
	if count := len(p.markers) + pending; count >= MaxReveals || p.bytes+uint64(pending+1)*size > MaxBytes {
		return nil, fmt.Errorf("%w: %d reveals, %d bytes", ErrPoolFull, count, p.bytes)
	}
	return p.remoteSlot(peer)
}

// admitAction runs the cheap refusals of a new policy action, decoded as a
// or refused by decodeErr, charging the peer first as admit does: the
// decoding (checks 1 and 2), the peer's one check slot and held cap, a key
// the pool holds a verified action for, checks 3 to 8 against the pool's
// head, and the action caps. The proof is left to the check after it; the
// action reserves no key here. The caller holds the lock.
func (p *Pool) admitAction(hash common.Hash, a *ghostpriv.Action, decodeErr error, envelope []byte, size uint64, peer string) (chan struct{}, error) {
	if _, ok := p.all[hash]; ok {
		return nil, txpool.ErrAlreadyKnown
	}
	if _, ok := p.actionChecks[hash]; ok {
		return nil, txpool.ErrAlreadyKnown
	}
	b, err := p.charge(peer, hash)
	if err != nil {
		return nil, err
	}
	if decodeErr != nil {
		return nil, decodeErr
	}
	if err := p.peerRoom(b, peer, size); err != nil {
		return nil, err
	}
	key := actionKey{marker: a.Marker, nonce: a.Nonce}
	if other, ok := p.actions[key]; ok {
		return nil, fmt.Errorf("%w: marker %x nonce %d held by %x", ErrActionPending, key.marker, key.nonce, other)
	}
	if p.head == nil || p.state == nil {
		return nil, errors.New("reveal pool not initialised")
	}
	if _, _, err := ghostpriv.CheckAction(p.state, p.actionEnv(p.head), cheapOnly{}, envelope); err != nil {
		return nil, err
	}
	pending := len(p.actionChecks)
	if peer == "" {
		pending = p.localActions
	}
	if count := len(p.actions) + pending; count >= MaxActions || p.actionBytes+uint64(pending+1)*size > MaxActionBytes {
		return nil, fmt.Errorf("%w: %d actions, %d bytes", ErrPoolFull, count, p.actionBytes)
	}
	return p.remoteSlot(peer)
}

// peerRoom refuses a transaction of size bytes from a peer, of budget b,
// that has another transaction being checked or would hold more than its
// held caps. A local transaction, of no budget, is not limited. The caller
// holds the lock.
func (p *Pool) peerRoom(b *peerBudget, peer string, size uint64) error {
	if b == nil {
		return nil
	}
	if b.validating > 0 {
		return fmt.Errorf("%w: peer %s", ErrPeerBusy, peer)
	}
	if n := b.held + b.validating; n >= PeerMaxHeld || uint64(n+1)*size > PeerMaxHeldBytes {
		return fmt.Errorf("%w: peer %s holds %d reveals", ErrPeerBudget, peer, n)
	}
	return nil
}

// remoteSlot takes a check slot open to peers for a remote transaction,
// without waiting, or refuses it with ErrChecksBusy; a local transaction
// takes its slot after the lock is let go. The caller holds the lock.
func (p *Pool) remoteSlot(peer string) (chan struct{}, error) {
	if peer == "" {
		return nil, nil
	}
	select {
	case p.remoteSlots <- struct{}{}:
		return p.remoteSlots, nil
	default:
		return nil, fmt.Errorf("%w: peer %s", ErrChecksBusy, peer)
	}
}

// cheapOnly is the verifier the cheap checks of a policy action run with:
// it accepts every proof, so that ghostpriv.CheckAction runs checks 1 to 8
// alone and verifies no proof.
type cheapOnly struct{}

func (cheapOnly) VerifyReveal(*ghostpriv.VerifyInputs, []byte) error { return nil }

// actionEnv is the environment of a policy action in the block that would
// come next on head.
func (p *Pool) actionEnv(head *types.Header) *ghostpriv.BlockEnv {
	return &ghostpriv.BlockEnv{
		Header:  p.nextHeader(head),
		Chain:   p.chain,
		ChainID: p.chain.Config().GetChainID(),
		Genesis: p.chain.Genesis().Hash(),
	}
}

// actionRules runs checks 1 to 8 of a policy action against st, the state
// after head, for the block that would come next on head: the shape, the
// encoding, the chain id, the expiry, the open slot of a callable policy,
// the nonce, the expected remaining and the debit at the next block's base
// fee. No proof is verified.
func (p *Pool) actionRules(head *types.Header, st *state.StateDB, tx *types.Transaction) error {
	_, _, err := ghostpriv.CheckAction(st, p.actionEnv(head), cheapOnly{}, tx.GhostPolicyActionEnvelope())
	return err
}

// charge takes the transaction with the given hash from the budget of peer
// and returns the budget: nothing for one the peer announced and the node
// agreed to fetch, one of its transactions of this head for any other, and
// a refusal when none is left. A local transaction, of no peer, has no
// budget. The caller holds the lock.
func (p *Pool) charge(peer string, hash common.Hash) (*peerBudget, error) {
	if peer == "" {
		return nil, nil
	}
	b := p.budget(peer)
	if _, ok := b.announced[hash]; ok {
		delete(b.announced, hash)
	} else if b.tokens > 0 {
		b.tokens--
	} else {
		return nil, fmt.Errorf("%w: peer %s, %d reveals per head", ErrPeerBudget, peer, PeerRevealsPerBlock)
	}
	return b, nil
}

// cheapRules runs the reveal checks that read no ancestry against the
// pool's head: the chain id, the fee and the marker against the spent set,
// and for a policy reveal the zero marker and its policy (check 9). The
// caller holds the lock.
func (p *Pool) cheapRules(r revealFields) error {
	coin := r.key.kind == ghosttree.Coin
	errChainID, errFee, errMarker := ghostpriv.ErrRevealChainID, ghostpriv.ErrRevealFee, ghostpriv.ErrRevealMarker
	switch {
	case !coin:
		errChainID, errFee, errMarker = ghostpriv.ErrDataRevealChainID, ghostpriv.ErrDataRevealFee, ghostpriv.ErrDataRevealMarker
	case r.policy:
		errChainID, errFee, errMarker = ghostpriv.ErrPolicyRevealChainID, ghostpriv.ErrPolicyRevealFee, ghostpriv.ErrPolicyRevealMarker
	}
	if id := p.chain.Config().GetChainID(); id == nil || !id.IsUint64() || id.Uint64() != r.chainID {
		return fmt.Errorf("%w: have %d, chain %v", errChainID, r.chainID, id)
	}
	// Each class pays the window fee for its own gas: a version 2 coin
	// reveal that of G_PRIV, a version 1 coin reveal that of its own gas, a
	// data reveal, from its reserve, that of G_DATA, a policy reveal that
	// of G_POLICY.
	fees := p.fees.of(r.class())
	switch {
	case fees.cur != nil && fees.match(r.fee) == nil && fees.prev == nil:
		return fmt.Errorf("%w: have %v, want %v", errFee, r.fee, fees.cur.Total)
	case fees.cur != nil && fees.match(r.fee) == nil:
		return fmt.Errorf("%w: have %v, want %v or %v", errFee, r.fee, fees.cur.Total, fees.prev.Total)
	}
	if r.policy && r.key.marker == (common.Hash{}) {
		return fmt.Errorf("%w: %w", errMarker, ghosttree.ErrZeroMarker)
	}
	if p.state != nil && ghosttree.IsSpent(p.state, r.key.kind, r.key.marker) {
		return fmt.Errorf("%w: %x", errMarker, r.key.marker)
	}
	if r.policy && p.state != nil && p.head != nil {
		next := p.head.Number.Uint64() + 1
		if err := ghostpriv.PolicyRevealAllowed(p.state, r.policyAddr, r.codeHash, next); err != nil {
			return err
		}
	}
	return nil
}

// eligibleRoot answers the root rule for the block that would come next on
// head from the chain's tree-root index: the first canonical height of the
// root, against head. It reads no ancestry: head must be canonical, so that
// the index answers at once, else the lookup is refused as for an index not
// ready. A lookup the index refuses because the chain moved under it is
// tried once more.
func (p *Pool) eligibleRoot(head *types.Header, kind ghosttree.Kind, root common.Hash) (bool, error) {
	chain, ok := p.chain.(ghosttree.HeaderLookup)
	if !ok {
		return false, fmt.Errorf("%w: the chain keeps no root index", ghosttree.ErrIndexNotReady)
	}
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		if chain.GetCanonicalHash(head.Number.Uint64()) != head.Hash() {
			return false, fmt.Errorf("%w: head %d %x is not canonical", ghosttree.ErrIndexNotReady, head.Number, head.Hash())
		}
		var eligible bool
		if eligible, err = ghosttree.EligibleRoot(chain, head, kind, root); err == nil {
			return eligible, nil
		}
	}
	return false, err
}

// windowFees are the fees of each class that the block that would come next
// on head accepts, for the version 2 coin reveal (G_PRIV), the version 1
// coin reveal (its own gas), the data reveal (G_DATA) and the policy reveal
// (G_POLICY): that of its fee window and that of the window before it, nil
// when the window does not exist, for the first window, or an ancestor it
// needs is not available: the reveal checks then refuse the reveal
// themselves. The headers are walked once for all classes, reading at most
// those of the two windows, seven of them.
func (p *Pool) windowFees(head *types.Header) classFeeSet {
	cur, prev := p.windowStarts(head)
	class := func(gas uint64) classFees {
		c := classFees{cur: windowFee(cur, gas)}
		if c.cur != nil {
			c.prev = windowFee(prev, gas)
		}
		return c
	}
	return classFeeSet{
		coin:   class(ghostpriv.GasPriv),
		coinV1: class(ghostpriv.GasPrivV1),
		data:   class(ghostpriv.GasData),
		policy: class(ghostpriv.GasPolicy),
	}
}

// windowStarts returns the first header of the fee window of the block that
// would come next on head and that of the window before it, nil when the
// window does not exist, for the first window, or an ancestor is not
// available.
func (p *Pool) windowStarts(head *types.Header) (cur, prev *types.Header) {
	next := p.nextHeader(head)
	start := ghostpriv.WindowStart(next.Number.Uint64())
	h := next
	if next.Number.Uint64() > start {
		h = p.ancestor(head, start)
	}
	if h == nil || h.BaseFee == nil || start == 0 {
		return h, nil
	}
	from := h
	if h == next {
		from = head
	}
	return h, p.ancestor(from, start-4)
}

// ancestor returns the header at height n of h's ancestry, h itself at its
// own height, by walking the parent links; nil if one is not available.
func (p *Pool) ancestor(h *types.Header, n uint64) *types.Header {
	for h != nil && h.Number.Uint64() > n {
		h = p.chain.GetHeader(h.ParentHash, h.Number.Uint64()-1)
	}
	return h
}

// windowFee is the window fee for gas of a window whose first block is h,
// nil when h or its base fee is missing or cannot be priced.
func windowFee(h *types.Header, gas uint64) *ghostpriv.Fee {
	if h == nil || h.BaseFee == nil {
		return nil
	}
	fee, err := ghostpriv.WindowFeeGas(h.BaseFee, gas)
	if err != nil {
		return nil
	}
	return &fee
}

// remove drops a held transaction. The caller holds the lock.
func (p *Pool) remove(hash common.Hash) {
	e, ok := p.all[hash]
	if !ok {
		return
	}
	delete(p.all, hash)
	switch e.class {
	case classAction:
		delete(p.actions, e.akey)
		p.actionBytes -= e.tx.Size()
	case classBundle:
		p.bundles--
	default:
		delete(p.markers, e.key)
		p.bytes -= e.tx.Size()
	}
	for i, h := range p.order {
		if h == hash {
			p.order = append(p.order[:i], p.order[i+1:]...)
			break
		}
	}
	if b, ok := p.peers[e.peer]; ok && e.peer != "" {
		b.held--
	}
}

// budget returns the budget of a peer, a full one for a peer not seen
// before. The caller holds the lock.
func (p *Pool) budget(peer string) *peerBudget {
	b, ok := p.peers[peer]
	if !ok {
		b = &peerBudget{tokens: PeerRevealsPerBlock, announced: make(map[common.Hash]time.Time)}
		p.peers[peer] = b
	}
	return b
}

// announcedSize reports whether a transaction of type kind announced with
// size is one of the pool's of the size of its envelope, and whether the
// type is one of the pool's at all.
func announcedSize(kind byte, size uint32) (sized, ours bool) {
	switch kind {
	case types.GhostRevealTxType:
		// The version 2 or the version 1 layout.
		return size == types.GhostRevealEnvelopeSize || size == types.GhostRevealV1EnvelopeSize, true
	case types.GhostDataRevealTxType:
		return size == types.GhostDataRevealEnvelopeSize, true
	case types.GhostPolicyRevealTxType:
		return size == types.GhostPolicyRevealEnvelopeSize, true
	case types.GhostPolicyActionTxType:
		return size == types.GhostPolicyActionEnvelopeSize, true
	case types.GhostBundleTxType:
		// The envelope of a count of 1 to GhostBundleMaxReveals bodies.
		fixed := uint32(1 + types.GhostBundleFixedSize)
		if size <= fixed {
			return false, true
		}
		bodies := size - fixed
		count := bodies / types.GhostBundleBodySize
		return bodies%types.GhostBundleBodySize == 0 && count <= types.GhostBundleMaxReveals, true
	}
	return false, false
}

// FilterAnnounced applies a peer's budgets to an announcement of the
// existing announce message and reports for each announced hash whether to
// fetch it. Only the pool's types are limited: the coin, data and policy
// reveals, the policy action and the bundle. One announced with a size other
// than its envelope's, for a bundle that of no count, is never fetched; one the pool holds or already agreed to
// fetch from this peer costs nothing; any other takes one of the peer's
// transactions of this head and one in-flight place, and is not fetched
// when either is used up. Without types, as before the typed announcement,
// nothing is filtered here and the delivery is charged instead.
func (p *Pool) FilterAnnounced(peer string, kinds []byte, sizes []uint32, hashes []common.Hash) []bool {
	keep := make([]bool, len(hashes))
	if kinds == nil || len(kinds) != len(hashes) || len(sizes) != len(hashes) {
		for i := range keep {
			keep[i] = true
		}
		return keep
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	for i, hash := range hashes {
		sized, ours := announcedSize(kinds[i], sizes[i])
		if !ours {
			keep[i] = true
			continue
		}
		if !sized {
			continue
		}
		if _, ok := p.all[hash]; ok {
			keep[i] = true
			continue
		}
		b := p.budget(peer)
		if _, ok := b.announced[hash]; ok {
			keep[i] = true
			continue
		}
		if b.tokens == 0 || len(b.announced) >= PeerMaxInFlight {
			continue
		}
		b.tokens--
		b.announced[hash] = now
		keep[i] = true
	}
	return keep
}

// DropPeer forgets a peer's budgets when it disconnects. The transactions
// it delivered stay in the pool.
func (p *Pool) DropPeer(peer string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.peers, peer)
	for _, e := range p.all {
		if e.peer == peer {
			e.peer = ""
		}
	}
}

// Pending returns nothing: it is grouped by account, and a reveal has none.
// The miner takes reveals from PendingReveals.
func (p *Pool) Pending(filter txpool.PendingFilter) map[common.Address][]*txpool.LazyTransaction {
	return map[common.Address][]*txpool.LazyTransaction{}
}

// PendingReveals returns the held transactions, reveals and policy actions,
// in block order: the highest tip per gas in the block that comes next on
// the pool's head first, then by hash ascending. A reveal's tip is that of
// the cover rule for its class's gas at the next block's base fee, an
// action's its debit less G_ACTION times that base fee, a bundle's zero, its
// fees being those of its bodies; the tips per gas are compared as exact
// fractions. Each passed its checks against the block that comes next on
// the pool's head.
func (p *Pool) PendingReveals() []*types.Transaction {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var baseFee *big.Int
	if p.head != nil {
		baseFee = p.nextHeader(p.head).BaseFee
	}
	type ranked struct {
		tx   *types.Transaction
		hash common.Hash
		tip  *big.Int // the tip of the transaction
		gas  *big.Int // its gas, the denominator of its tip per gas
	}
	list := make([]ranked, 0, len(p.order))
	for _, hash := range p.order {
		e := p.all[hash]
		gas := e.gas()
		list = append(list, ranked{tx: e.tx, hash: hash, tip: p.tip(e, baseFee), gas: new(big.Int).SetUint64(gas)})
	}
	sort.Slice(list, func(i, j int) bool {
		// tip_i / gas_i against tip_j / gas_j, by cross-multiplication.
		left := new(big.Int).Mul(list[i].tip, list[j].gas)
		right := new(big.Int).Mul(list[j].tip, list[i].gas)
		if c := left.Cmp(right); c != 0 {
			return c > 0
		}
		return bytes.Compare(list[i].hash[:], list[j].hash[:]) < 0
	})
	txs := make([]*types.Transaction, len(list))
	for i, r := range list {
		txs[i] = r.tx
	}
	return txs
}

// tip is the tip a held transaction pays in a block with base fee baseFee:
// for a reveal the tip of the cover rule applied to the window fee it pays
// for its class's gas, for an action its debit less G_ACTION times the base
// fee; zero when it cannot be priced. The caller holds the lock.
func (p *Pool) tip(e *entry, baseFee *big.Int) *big.Int {
	if baseFee == nil || e.paid == nil {
		return new(big.Int)
	}
	if e.class == classAction {
		base, overflow := uint256.FromBig(baseFee)
		if overflow {
			return new(big.Int)
		}
		burn, err := ghostpriv.ActionBurn(base)
		if err != nil || burn.Gt(e.paid) {
			return new(big.Int)
		}
		return new(uint256.Int).Sub(e.paid, burn).ToBig()
	}
	fee := p.fees.of(e.class).match(e.paid)
	if fee == nil {
		return new(big.Int)
	}
	split, err := fee.CoverGas(baseFee, e.class.gas())
	if err != nil {
		return new(big.Int)
	}
	return split.Tip.ToBig()
}

// SubscribeTransactions subscribes to new reveals. The pool resurrects no
// reveal on a reorganisation, so the reorgs flag makes no difference.
func (p *Pool) SubscribeTransactions(ch chan<- core.NewTxsEvent, reorgs bool) event.Subscription {
	return p.scope.Track(p.feed.Subscribe(ch))
}

// Nonce returns 0: a reveal has no account.
func (p *Pool) Nonce(addr common.Address) uint64 { return 0 }

// Stats returns the number of held transactions, all of them pending.
func (p *Pool) Stats() (int, int) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.all), 0
}

// Content returns nothing: it is grouped by account.
func (p *Pool) Content() (map[common.Address][]*types.Transaction, map[common.Address][]*types.Transaction) {
	return map[common.Address][]*types.Transaction{}, map[common.Address][]*types.Transaction{}
}

// ContentFrom returns nothing: no reveal has an account.
func (p *Pool) ContentFrom(addr common.Address) ([]*types.Transaction, []*types.Transaction) {
	return []*types.Transaction{}, []*types.Transaction{}
}

// Locals returns nothing: a reveal has no account.
func (p *Pool) Locals() []common.Address { return nil }

// Status returns pending for a held reveal.
func (p *Pool) Status(hash common.Hash) txpool.TxStatus {
	if p.Has(hash) {
		return txpool.TxStatusPending
	}
	return txpool.TxStatusUnknown
}

// snapshot returns the head and a copy of its state for one check outside
// the lock. The caller holds the lock.
func (p *Pool) snapshot() (*types.Header, *state.StateDB, error) {
	if p.head == nil || p.state == nil {
		return nil, nil, errors.New("reveal pool not initialised")
	}
	return p.head, p.state.Copy(), nil
}

// check runs the reveal checks of the transaction's type against st, the
// state after head, for the block that would come next on head, at a cost
// bounded per reveal, cheap first:
//
//  1. the root rule, from the chain's tree-root index for head, with no
//     walk of the ancestry;
//  2. the other checks of core/ghostpriv but the proof, among them the
//     chain id, the fee, the marker and the backstop, on a view of the
//     chain that holds only the headers of the fee window and of the window
//     before it, so that their own root check stops there; a root the index
//     found below those windows is refused by that check, and the checks that come after the root,
//     the marker, the backstop and for a policy reveal its policy and the
//     room for its remainder, are then run here;
//  3. the proof, for the inputs the node computes, last, so that a reveal
//     refused by any other check costs no proof verification.
//
// When the index cannot answer, a remote reveal is refused with
// ErrRootLookup; the node's own reveal is checked by core/ghostpriv on the
// whole chain, as block validation checks it. check reads no pool field, so
// it runs without the lock.
func (p *Pool) check(head *types.Header, st *state.StateDB, tx *types.Transaction, local bool) error {
	genesis := p.chain.Genesis().Hash()
	rv, err := decodeForCheck(tx, genesis)
	if err != nil {
		return err
	}
	if err := p.checkRules(head, st, rv, genesis, local); err != nil {
		return err
	}
	if err := p.verifier().VerifyReveal(rv.in, rv.proof); err != nil {
		return fmt.Errorf("%w: %w", rv.errProof, err)
	}
	return nil
}

// checkRules runs the reveal checks of check but the proof, steps 1 and 2.
// The checks of core/ghostpriv are given pendingProof, which accepts the
// inputs whose proof check verifies after them and no others.
func (p *Pool) checkRules(head *types.Header, st *state.StateDB, rv *checkedReveal, genesis common.Hash, local bool) error {
	next := p.nextHeader(head)
	env := &ghostpriv.BlockEnv{
		Header:  next,
		Chain:   p.chain,
		ChainID: p.chain.Config().GetChainID(),
		Genesis: genesis,
	}
	eligible, err := p.eligibleRoot(head, rv.in.Kind, rv.in.Root)
	if err != nil {
		if !local {
			return fmt.Errorf("%w: %x: %v", ErrRootLookup, rv.in.Root, err)
		}
		return rv.rules(st, env, pendingProof{rv.in})
	}
	if !eligible {
		return fmt.Errorf("%w: %x", rv.errRoot, rv.in.Root)
	}
	env.Chain = windowChain{chain: p.chain, min: feeWindowsStart(next.Number.Uint64())}
	if err = rv.rules(st, env, pendingProof{rv.in}); !errors.Is(err, rv.errRoot) {
		return err
	}
	// Every check before the root passed and the index found the root: what
	// is left is the marker and the backstop: out plus fee for a coin or
	// policy reveal, the reserve for a data reveal; then, for a policy
	// reveal, its policy and the room for its remainder.
	if ghosttree.IsSpent(st, rv.in.Kind, rv.in.Marker) {
		return fmt.Errorf("%w: %x", rv.errMarker, rv.in.Marker)
	}
	hidden, err := ghostpriv.Hidden(st)
	if err != nil {
		return fmt.Errorf("%w: %w", rv.errBackstop, err)
	}
	if rv.in.Kind != ghosttree.Coin {
		if ghostpriv.DataReserve.Gt(hidden) {
			return fmt.Errorf("%w: reserve %v, hidden %v", rv.errBackstop, ghostpriv.DataReserve, hidden)
		}
		return nil
	}
	if need := new(uint256.Int).Add(rv.in.Out, rv.in.Fee); need.Gt(hidden) {
		return fmt.Errorf("%w: out plus fee %v, hidden %v", rv.errBackstop, need, hidden)
	}
	if rv.afterBackstop != nil {
		return rv.afterBackstop(st, next.Number.Uint64())
	}
	return nil
}

// checkedReveal is a reveal decoded for check: the inputs of its proof, the
// proof, the errors of its type and its checks in core/ghostpriv.
type checkedReveal struct {
	in          *ghostpriv.VerifyInputs
	proof       []byte
	errProof    error
	errRoot     error
	errMarker   error
	errBackstop error
	rules       func(st *state.StateDB, env *ghostpriv.BlockEnv, verifier ghostpriv.Verifier) error

	// afterBackstop runs the checks of the type that come after the
	// backstop and before the proof, for a block at height, nil when there
	// are none.
	afterBackstop func(st *state.StateDB, height uint64) error
}

// decodeForCheck decodes a reveal and computes the public inputs of its
// proof as core/ghostpriv does, the binding digest for its own chain id
// over the genesis hash. A chain id other than the chain's makes other
// inputs than the chain rules', and is refused by them in any case.
func decodeForCheck(tx *types.Transaction, genesis common.Hash) (*checkedReveal, error) {
	switch tx.Type() {
	case types.GhostRevealTxType:
		envelope := tx.GhostRevealEnvelope()
		r, err := ghostpriv.DecodeReveal(envelope)
		if err != nil {
			return nil, err
		}
		return &checkedReveal{
			in:          r.VerifyInputs(r.ChainID, genesis),
			proof:       common.CopyBytes(r.Proof),
			errProof:    ghostpriv.ErrRevealProof,
			errRoot:     ghostpriv.ErrRevealRoot,
			errMarker:   ghostpriv.ErrRevealMarker,
			errBackstop: ghostpriv.ErrRevealBackstop,
			rules: func(st *state.StateDB, env *ghostpriv.BlockEnv, verifier ghostpriv.Verifier) error {
				_, _, err := ghostpriv.CheckReveal(st, env, verifier, envelope)
				return err
			},
		}, nil
	case types.GhostDataRevealTxType:
		envelope := tx.GhostDataRevealEnvelope()
		r, err := ghostpriv.DecodeDataReveal(envelope)
		if err != nil {
			return nil, err
		}
		// A purpose field other than reveal or revoke is refused by the
		// chain rules whatever the proof.
		return &checkedReveal{
			in:          r.VerifyInputs(r.Purpose[31], r.ChainID, genesis),
			proof:       common.CopyBytes(r.Proof),
			errProof:    ghostpriv.ErrDataRevealProof,
			errRoot:     ghostpriv.ErrDataRevealRoot,
			errMarker:   ghostpriv.ErrDataRevealMarker,
			errBackstop: ghostpriv.ErrDataRevealBackstop,
			rules: func(st *state.StateDB, env *ghostpriv.BlockEnv, verifier ghostpriv.Verifier) error {
				_, _, err := ghostpriv.CheckDataReveal(st, env, verifier, envelope)
				return err
			},
		}, nil
	case types.GhostPolicyRevealTxType:
		envelope := tx.GhostPolicyRevealEnvelope()
		r, err := ghostpriv.DecodePolicyReveal(envelope)
		if err != nil {
			return nil, err
		}
		return &checkedReveal{
			in:          r.VerifyInputs(r.ChainID, genesis),
			proof:       common.CopyBytes(r.Proof),
			errProof:    ghostpriv.ErrPolicyRevealProof,
			errRoot:     ghostpriv.ErrPolicyRevealRoot,
			errMarker:   ghostpriv.ErrPolicyRevealMarker,
			errBackstop: ghostpriv.ErrPolicyRevealBackstop,
			rules: func(st *state.StateDB, env *ghostpriv.BlockEnv, verifier ghostpriv.Verifier) error {
				_, _, err := ghostpriv.CheckPolicyReveal(st, env, verifier, envelope)
				return err
			},
			afterBackstop: func(st *state.StateDB, height uint64) error {
				if err := ghostpriv.PolicyRevealAllowed(st, r.Policy, r.CodeHash, height); err != nil {
					return err
				}
				return ghostpriv.PolicyRevealTreeRoom(st, height, r.Remainder)
			},
		}, nil
	default:
		return nil, fmt.Errorf("%w: type %#x", core.ErrTxTypeNotSupported, tx.Type())
	}
}

// pendingProof accepts the inputs whose proof check verifies after the
// checks of core/ghostpriv, and refuses any others: those checks then run
// every rule but the proof, and the proof is verified once, last.
type pendingProof struct{ in *ghostpriv.VerifyInputs }

func (v pendingProof) VerifyReveal(in *ghostpriv.VerifyInputs, proof []byte) error {
	errDiffer := errors.New("inputs differ from the verified ones")
	if in == nil || in.Out == nil || in.Fee == nil || !in.Out.Eq(v.in.Out) || !in.Fee.Eq(v.in.Fee) {
		return errDiffer
	}
	// The amounts are equal; the rest of the inputs are compared by value.
	a, b := *in, *v.in
	a.Out, a.Fee, b.Out, b.Fee = nil, nil, nil, nil
	if a != b {
		return errDiffer
	}
	return nil
}

// windowChain is the chain as the checks of core/ghostpriv read it in the
// pool: the headers from height min up, those of the fee window and of the
// window before it, whose fee is accepted too, and none below, so that their
// walk for the fee and the root reads at most the two windows.
type windowChain struct {
	chain ghostpriv.ChainReader
	min   uint64
}

func (c windowChain) GetHeader(hash common.Hash, number uint64) *types.Header {
	if number < c.min {
		return nil
	}
	return c.chain.GetHeader(hash, number)
}

// feeWindowsStart is the height of the first block of the fee window before
// that of a block at height h, or of its own window when it is the first.
func feeWindowsStart(h uint64) uint64 {
	start := ghostpriv.WindowStart(h)
	if start < 4 {
		return 0
	}
	return start - 4
}

// nextHeader is the header of the block that would come next on head, as
// far as the reveal checks read it: the number, the parent and the base fee.
func (p *Pool) nextHeader(head *types.Header) *types.Header {
	config := p.chain.Config()
	h := &types.Header{
		ParentHash: head.Hash(),
		Number:     new(big.Int).Add(head.Number, common.Big1),
		GasLimit:   head.GasLimit,
		Time:       head.Time + 1,
	}
	if config.IsEnabled(config.GetEIP1559Transition, h.Number) {
		h.BaseFee = eip1559.CalcBaseFee(config, head)
	}
	return h
}

// revealFields are the fields of a reveal the cheap refusals read.
type revealFields struct {
	key     markerKey
	chainID uint64
	fee     *uint256.Int
	v1      bool // a version 1 coin reveal, whose fee is priced for its own gas

	// policy marks a policy reveal, a coin marker's reveal into the escrow
	// slot of the policy at policyAddr, of code hash codeHash.
	policy     bool
	policyAddr common.Address
	codeHash   common.Hash
}

// class is the class of the reveal.
func (r revealFields) class() txClass {
	switch {
	case r.key.kind != ghosttree.Coin:
		return classData
	case r.policy:
		return classPolicy
	case r.v1:
		return classCoinV1
	}
	return classCoin
}

// decode decodes a reveal's fields, running the first checks of its type:
// the length, the version and the amount words.
func decode(tx *types.Transaction) (revealFields, error) {
	switch tx.Type() {
	case types.GhostRevealTxType:
		r, err := ghostpriv.DecodeReveal(tx.GhostRevealEnvelope())
		if err != nil {
			return revealFields{}, err
		}
		return revealFields{key: markerKey{kind: ghosttree.Coin, marker: r.Marker}, chainID: r.ChainID, fee: r.Fee, v1: r.IsV1()}, nil
	case types.GhostDataRevealTxType:
		r, err := ghostpriv.DecodeDataReveal(tx.GhostDataRevealEnvelope())
		if err != nil {
			return revealFields{}, err
		}
		return revealFields{key: markerKey{kind: ghosttree.Data, marker: r.Marker}, chainID: r.ChainID, fee: r.Fee}, nil
	case types.GhostPolicyRevealTxType:
		// The policy reveal spends a coin marker: it shares the marker set of
		// the coin reveal.
		r, err := ghostpriv.DecodePolicyReveal(tx.GhostPolicyRevealEnvelope())
		if err != nil {
			return revealFields{}, err
		}
		return revealFields{
			key:        markerKey{kind: ghosttree.Coin, marker: r.Marker},
			chainID:    r.ChainID,
			fee:        r.Fee,
			policy:     true,
			policyAddr: r.Policy,
			codeHash:   r.CodeHash,
		}, nil
	default:
		return revealFields{}, fmt.Errorf("%w: type %#x", core.ErrTxTypeNotSupported, tx.Type())
	}
}
