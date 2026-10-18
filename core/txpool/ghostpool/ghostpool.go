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

// Package ghostpool is the transaction pool of the native reveal
// transactions, the coin reveal (type 0x50) and the data reveal (type 0x51).
// A reveal has no sender account, no nonce and no gas price, so it cannot
// live in the legacy pool, which is ordered per account; it lives here,
// beside the legacy pool, as a subpool of core/txpool.
//
// The pool checks a reveal with the chain rules of core/ghostpriv against
// the block that would come next on the current head: the same checks, the
// same root rule and the active verifier. It holds at most one reveal per
// marker, the first seen: a later reveal of the same marker is refused, and
// a held reveal whose marker another reveal spent in a block is dropped when
// the pool rechecks on the new head.
package ghostpool

import (
	"errors"
	"fmt"
	"math/big"
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
	"github.com/holiman/uint256"
)

// The caps of the pool and the budgets of one peer.
const (
	// MaxReveals is the most reveals the pool holds.
	MaxReveals = 16

	// MaxBytes is the most envelope bytes the pool holds, 16 envelopes.
	MaxBytes = 16_455_856

	// PeerRevealsPerBlock is the number of reveals a peer may have the node
	// fetch or take from it per chain head: each announced reveal the node
	// agrees to fetch, and each reveal delivered without an announcement,
	// takes one. The budget is refilled when the head moves.
	PeerRevealsPerBlock = 4

	// PeerMaxInFlight is the most reveals of one peer that are announced and
	// agreed to be fetched but not delivered yet.
	PeerMaxInFlight = 4

	// PeerMaxHeld is the most reveals the pool holds that one peer was the
	// first to deliver.
	PeerMaxHeld = 4

	// PeerMaxHeldBytes is the most envelope bytes the pool holds that one
	// peer was the first to deliver.
	PeerMaxHeldBytes = PeerMaxHeld * types.GhostRevealEnvelopeSize

	// announceExpiry is how long an agreed fetch counts against a peer's
	// in-flight budget when the reveal never arrives.
	announceExpiry = time.Minute
)

var (
	// ErrPoolFull is returned for a reveal that would take the pool over
	// MaxReveals reveals or MaxBytes bytes.
	ErrPoolFull = errors.New("reveal pool full")

	// ErrMarkerPending is returned for a reveal of a marker the pool already
	// holds a different reveal for. The first seen is kept.
	ErrMarkerPending = errors.New("marker already has a pending reveal")

	// ErrPeerBudget is returned for a reveal from a peer that has used up its
	// budget.
	ErrPeerBudget = errors.New("peer reveal budget used up")

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
)

// BlockChain is the part of the chain the pool needs. *core.BlockChain
// satisfies it.
type BlockChain interface {
	// Config retrieves the chain's fork configuration.
	Config() ctypes.ChainConfigurator

	// CurrentBlock returns the current head of the chain.
	CurrentBlock() *types.Header

	// GetHeader returns a header by hash and number, for the reveal's
	// ancestry walk.
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

// entry is one held reveal.
type entry struct {
	tx   *types.Transaction
	key  markerKey
	peer string // the peer that first delivered it, empty for a local one
}

// peerBudget is what one peer has used of its budgets.
type peerBudget struct {
	tokens     int                       // reveals left to take in this head
	announced  map[common.Hash]time.Time // agreed fetches not delivered yet
	held       int                       // reveals held that it delivered first
	validating int                       // reveals it delivered being checked
}

// Pool is the reveal pool.
//
// The reveal checks run outside the pool's lock, at most maxValidations at
// a time, against a snapshot of the head: the root rule walks the ancestry,
// so a reveal with a root that is no ancestor's costs reads that grow with
// the chain, and the lock must not be held through them. A reveal being
// checked holds its marker and a place under the caps, so that the first
// seen of two competing reveals is still the one kept.
//
// So that peers cannot hold every check slot with reveals that fail, the
// cheap refusals run first under the lock and charge the peer for every
// reveal they refuse; one peer holds at most one slot at a time; a remote
// reveal that finds no slot free is dropped, never queued; and one slot is
// kept for the node's own reveals.
type Pool struct {
	chain       BlockChain
	verifier    func() ghostpriv.Verifier
	remoteSlots chan struct{} // one per check running, of any reveal
	localSlot   chan struct{} // the slot only local reveals take

	mu         sync.RWMutex
	head       *types.Header
	state      *state.StateDB
	fee        *uint256.Int // the coin reveal fee of the next block, nil if unknown
	all        map[common.Hash]*entry
	order      []common.Hash // hashes of the held reveals, first seen first
	markers    map[markerKey]common.Hash
	bytes      uint64
	validating map[markerKey]common.Hash // reveals being checked, by marker
	locals     int                       // local reveals among those being checked
	peers      map[string]*peerBudget

	feed  event.Feed
	scope event.SubscriptionScope
}

const (
	// maxValidations is the most reveal checks of new reveals that run at
	// the same time. One of them is kept for local reveals.
	maxValidations = 4

	// maxRevalidations is how often a new reveal is checked again when the
	// head moved while it was checked.
	maxRevalidations = 3
)

// errHeadMoving is returned for a reveal whose check could not finish on a
// head that stayed the head.
var errHeadMoving = errors.New("chain head kept moving while the reveal was checked")

// New creates a reveal pool on chain. It checks reveals with the active
// verifier of core/ghostpriv.
func New(chain BlockChain) *Pool {
	return &Pool{
		chain:       chain,
		verifier:    ghostpriv.ActiveVerifier,
		remoteSlots: make(chan struct{}, maxValidations-1),
		localSlot:   make(chan struct{}, 1),
		all:         make(map[common.Hash]*entry),
		markers:     make(map[markerKey]common.Hash),
		validating:  make(map[markerKey]common.Hash),
		peers:       make(map[string]*peerBudget),
	}
}

// Filter accepts the coin reveal and the data reveal.
func (p *Pool) Filter(tx *types.Transaction) bool { return tx.IsGhostReveal() }

// Init sets the head the pool checks against. A reveal has no account, so
// the pool reserves none.
func (p *Pool) Init(gasTip uint64, head *types.Header, reserve txpool.AddressReserver) error {
	st, err := p.chain.StateAt(head.Root)
	if err != nil {
		return err
	}
	fee := p.windowFee(head)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.head, p.state, p.fee = head, st, fee
	return nil
}

// Close ends every subscription.
func (p *Pool) Close() error {
	p.scope.Close()
	return nil
}

// Reset moves the pool to the new head: it refills the peer budgets and
// rechecks every held reveal against the block that would come next,
// dropping each that no longer passes, among them every reveal whose marker
// a block spent.
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
	fee := p.windowFee(newHead)
	p.mu.Lock()
	p.head, p.state, p.fee = newHead, st, fee
	now := time.Now()
	for _, b := range p.peers {
		b.tokens = PeerRevealsPerBlock
		for hash, at := range b.announced {
			// A reveal another peer delivered first, or one that never
			// came, no longer holds an in-flight place.
			if _, held := p.all[hash]; held || now.Sub(at) > announceExpiry {
				delete(b.announced, hash)
			}
		}
	}
	held := make([]*types.Transaction, 0, len(p.order))
	for _, hash := range p.order {
		held = append(held, p.all[hash].tx)
	}
	p.mu.Unlock()

	var failed []common.Hash
	for _, tx := range held {
		if err := p.check(newHead, recheck.Copy(), tx); err != nil {
			log.Debug("Dropped reveal on recheck", "hash", tx.Hash(), "err", err)
			failed = append(failed, tx.Hash())
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

// AddFromPeer adds reveals delivered by a peer, under that peer's budgets.
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

// add checks and inserts one reveal, first delivered by peer, empty for a
// local reveal. The cheap refusals come first, under the lock, and a remote
// reveal takes a check slot there or is dropped; then the reveal holds its
// marker, a place under the caps and its slot while the reveal checks run
// outside the lock, and is inserted when they pass on the head that is
// still the pool's.
func (p *Pool) add(tx *types.Transaction, peer string) error {
	if !p.Filter(tx) {
		return fmt.Errorf("%w: type %#x", core.ErrTxTypeNotSupported, tx.Type())
	}
	hash := tx.Hash()
	// Decoding runs the length, version and amount checks; a peer is charged
	// for a reveal that fails them as for any other.
	fields, decodeErr := decode(tx)
	key := fields.key
	p.mu.Lock()
	slot, err := p.admit(hash, fields, decodeErr, tx.Size(), peer)
	if err != nil {
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

	// A local reveal waits for a slot: any free one, else the one kept for
	// local reveals, which no peer can take.
	if slot == nil {
		select {
		case p.remoteSlots <- struct{}{}:
			slot = p.remoteSlots
		default:
			select {
			case p.remoteSlots <- struct{}{}:
				slot = p.remoteSlots
			case p.localSlot <- struct{}{}:
				slot = p.localSlot
			}
		}
	}

	// Each round leaves the loop holding the lock.
	for attempt := 0; ; attempt++ {
		if err == nil {
			err = p.check(head, st, tx)
		}
		p.mu.Lock()
		if err != nil || p.head.Hash() == head.Hash() {
			break
		}
		// The head moved while the reveal was checked: check it again on
		// the new head.
		if attempt+1 == maxRevalidations {
			err = errHeadMoving
			break
		}
		head, st, err = p.snapshot()
		p.mu.Unlock()
	}
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
	if err == nil && (len(p.all) >= MaxReveals || p.bytes+tx.Size() > MaxBytes) {
		err = fmt.Errorf("%w: %d reveals, %d bytes", ErrPoolFull, len(p.all), p.bytes)
	}
	if err != nil {
		p.mu.Unlock()
		return err
	}
	// The reveal held its marker and its place while it was checked, so only
	// a peer that left can have changed what it is entered under.
	if !ok {
		peer = ""
	}
	p.all[hash] = &entry{tx: tx, key: key, peer: peer}
	p.order = append(p.order, hash)
	p.markers[key] = hash
	p.bytes += tx.Size()
	if peer != "" {
		b.held++
	}
	p.mu.Unlock()

	p.feed.Send(core.NewTxsEvent{Txs: []*types.Transaction{tx}})
	return nil
}

// admit runs the cheap refusals of a new reveal, decoded as fields or
// refused by decodeErr, and charges the peer's budget for it before any
// refusal but that of a reveal held or being checked: so a reveal that
// fails costs the peer as much as one that passes. Then come the decoding,
// the peer's one check slot and held cap, a marker held or being checked
// for another reveal, the chain id, the fee, a spent marker and the caps.
// A remote reveal takes a check slot last, without waiting, and admit
// returns it; a local reveal takes its slot after the lock is let go. The
// caller holds the lock.
func (p *Pool) admit(hash common.Hash, fields revealFields, decodeErr error, size uint64, peer string) (chan struct{}, error) {
	key := fields.key
	if _, ok := p.all[hash]; ok {
		return nil, txpool.ErrAlreadyKnown
	}
	if decodeErr == nil && p.validating[key] == hash {
		return nil, txpool.ErrAlreadyKnown
	}
	var b *peerBudget
	if peer != "" {
		b = p.budget(peer)
		if _, ok := b.announced[hash]; ok {
			delete(b.announced, hash)
		} else if b.tokens > 0 {
			b.tokens--
		} else {
			return nil, fmt.Errorf("%w: peer %s, %d reveals per head", ErrPeerBudget, peer, PeerRevealsPerBlock)
		}
	}
	if decodeErr != nil {
		return nil, decodeErr
	}
	if b != nil {
		if b.validating > 0 {
			return nil, fmt.Errorf("%w: peer %s", ErrPeerBusy, peer)
		}
		if n := b.held + b.validating; n >= PeerMaxHeld || uint64(n+1)*size > PeerMaxHeldBytes {
			return nil, fmt.Errorf("%w: peer %s holds %d reveals", ErrPeerBudget, peer, n)
		}
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
	if count := len(p.all) + pending; count >= MaxReveals || p.bytes+uint64(pending+1)*size > MaxBytes {
		return nil, fmt.Errorf("%w: %d reveals, %d bytes", ErrPoolFull, count, p.bytes)
	}
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

// cheapRules runs the reveal checks that read no ancestry against the
// pool's head: the chain id, the fee and the marker against the spent set.
// The caller holds the lock.
func (p *Pool) cheapRules(r revealFields) error {
	coin := r.key.kind == ghosttree.Coin
	if id := p.chain.Config().GetChainID(); id == nil || !id.IsUint64() || id.Uint64() != r.chainID {
		if coin {
			return fmt.Errorf("%w: have %d, chain %v", ghostpriv.ErrRevealChainID, r.chainID, id)
		}
		return fmt.Errorf("%w: have %d, chain %v", ghostpriv.ErrDataRevealChainID, r.chainID, id)
	}
	switch {
	case coin && p.fee != nil && !p.fee.Eq(r.fee):
		return fmt.Errorf("%w: have %v, want %v", ghostpriv.ErrRevealFee, r.fee, p.fee)
	case !coin && !r.fee.IsZero():
		// A data reveal pays no fee or is refused by the chain rules.
		return fmt.Errorf("%w: have %v, want 0", ghostpriv.ErrDataRevealFee, r.fee)
	}
	if p.state != nil && ghosttree.IsSpent(p.state, r.key.kind, r.key.marker) {
		if coin {
			return fmt.Errorf("%w: %x", ghostpriv.ErrRevealMarker, r.key.marker)
		}
		return fmt.Errorf("%w: %x", ghostpriv.ErrDataRevealMarker, r.key.marker)
	}
	return nil
}

// windowFee is the coin reveal fee of the block that would come next on
// head, nil when an ancestor it needs is not available: the reveal checks
// then refuse the reveal themselves. The walk reads at most three headers.
func (p *Pool) windowFee(head *types.Header) *uint256.Int {
	h := p.nextHeader(head)
	start := ghostpriv.WindowStart(h.Number.Uint64())
	if h.Number.Uint64() > start {
		for h = head; h != nil && h.Number.Uint64() > start; {
			h = p.chain.GetHeader(h.ParentHash, h.Number.Uint64()-1)
		}
	}
	if h == nil || h.BaseFee == nil {
		return nil
	}
	fee, err := ghostpriv.WindowFee(h.BaseFee)
	if err != nil {
		return nil
	}
	return fee.Total
}

// remove drops a held reveal. The caller holds the lock.
func (p *Pool) remove(hash common.Hash) {
	e, ok := p.all[hash]
	if !ok {
		return
	}
	delete(p.all, hash)
	delete(p.markers, e.key)
	p.bytes -= e.tx.Size()
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

// FilterAnnounced applies a peer's budgets to an announcement of the
// existing announce message and reports for each announced hash whether to
// fetch it. Only reveals are limited. A reveal announced with a size other
// than the envelope's is never fetched; a reveal the pool holds or already
// agreed to fetch from this peer costs nothing; any other takes one of the
// peer's reveals of this head and one in-flight place, and is not fetched
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
		switch kinds[i] {
		case types.GhostRevealTxType, types.GhostDataRevealTxType:
		default:
			keep[i] = true
			continue
		}
		if sizes[i] != types.GhostRevealEnvelopeSize {
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

// DropPeer forgets a peer's budgets when it disconnects. The reveals it
// delivered stay in the pool.
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

// PendingReveals returns the held reveals, first seen first. Each passed
// the reveal checks against the block that comes next on the pool's head.
func (p *Pool) PendingReveals() []*types.Transaction {
	p.mu.RLock()
	defer p.mu.RUnlock()
	txs := make([]*types.Transaction, 0, len(p.order))
	for _, hash := range p.order {
		txs = append(txs, p.all[hash].tx)
	}
	return txs
}

// SubscribeTransactions subscribes to new reveals. The pool resurrects no
// reveal on a reorganisation, so the reorgs flag makes no difference.
func (p *Pool) SubscribeTransactions(ch chan<- core.NewTxsEvent, reorgs bool) event.Subscription {
	return p.scope.Track(p.feed.Subscribe(ch))
}

// Nonce returns 0: a reveal has no account.
func (p *Pool) Nonce(addr common.Address) uint64 { return 0 }

// Stats returns the number of held reveals, all of them pending.
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
// state after head, for the block that would come next on head. It reads
// no pool field, so it runs without the lock: the root rule walks the
// ancestry, which costs database reads that grow with the chain.
func (p *Pool) check(head *types.Header, st *state.StateDB, tx *types.Transaction) error {
	env := &ghostpriv.BlockEnv{
		Header:  p.nextHeader(head),
		Chain:   p.chain,
		ChainID: p.chain.Config().GetChainID(),
		Genesis: p.chain.Genesis().Hash(),
	}
	var err error
	switch tx.Type() {
	case types.GhostRevealTxType:
		_, _, err = ghostpriv.CheckReveal(st, env, p.verifier(), tx.GhostRevealEnvelope())
	case types.GhostDataRevealTxType:
		_, _, err = ghostpriv.CheckDataReveal(st, env, p.verifier(), tx.GhostDataRevealEnvelope())
	default:
		err = fmt.Errorf("%w: type %#x", core.ErrTxTypeNotSupported, tx.Type())
	}
	return err
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
}

// decode decodes a reveal's fields, running the first three reveal checks
// of its type: the length, the version and the amount words.
func decode(tx *types.Transaction) (revealFields, error) {
	switch tx.Type() {
	case types.GhostRevealTxType:
		r, err := ghostpriv.DecodeReveal(tx.GhostRevealEnvelope())
		if err != nil {
			return revealFields{}, err
		}
		return revealFields{key: markerKey{kind: ghosttree.Coin, marker: r.Marker}, chainID: r.ChainID, fee: r.Fee}, nil
	case types.GhostDataRevealTxType:
		r, err := ghostpriv.DecodeDataReveal(tx.GhostDataRevealEnvelope())
		if err != nil {
			return revealFields{}, err
		}
		return revealFields{key: markerKey{kind: ghosttree.Data, marker: r.Marker}, chainID: r.ChainID, fee: r.Fee}, nil
	default:
		return revealFields{}, fmt.Errorf("%w: type %#x", core.ErrTxTypeNotSupported, tx.Type())
	}
}
