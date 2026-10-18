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

package ghostpool

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghostpriv/ghostprivtest"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/txpool/legacypool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
	"github.com/holiman/uint256"
)

var (
	testKey, _ = crypto.ToECDSA(crypto.Keccak256([]byte("ghost synthetic test account pool")))
	testAddr   = crypto.PubkeyToAddress(testKey.PublicKey)
	oneGhost   = new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
)

// fixture is a chain on the internal network's configuration whose first
// block commits one GHOST, so that reveals have hidden value to take, and
// whose later blocks are built by the test.
type fixture struct {
	t       *testing.T
	gspec   *genesisT.Genesis
	genesis *types.Block
	chain   *core.BlockChain
	blocks  []*types.Block
}

// newFixture generates n blocks, the first with the commit, gen adding to
// any block after it, and imports the first. The stub verifier is active
// for the test.
func newFixture(t *testing.T, n int, gen func(int, *core.BlockGen)) *fixture {
	t.Helper()
	f := newSpec(t)
	f.generate(n, gen)
	return f
}

// newSpec is a fixture with the genesis only, for reveals that a generated
// block must carry.
func newSpec(t *testing.T) *fixture {
	t.Helper()
	t.Cleanup(ghostpriv.SetVerifier(ghostprivtest.Verifier{}))
	gspec := ghost.InternalNetGenesis()
	gspec.Alloc = genesisT.GenesisAlloc{testAddr: {Balance: new(big.Int).Mul(oneGhost, big.NewInt(100))}}
	return &fixture{t: t, gspec: gspec, genesis: core.GenesisToBlock(gspec, nil)}
}

// generate builds the blocks and the chain and imports the first block.
func (f *fixture) generate(n int, gen func(int, *core.BlockGen)) {
	t := f.t
	t.Helper()
	gspec := f.gspec
	signer := types.LatestSigner(gspec.Config)
	commit := commitTx(t, testKey, signer, gspec.Config.GetChainID(), 0, oneGhost)

	engine := ethash.NewFaker()
	_, blocks, _ := core.GenerateChainWithGenesis(gspec, engine, n, func(i int, b *core.BlockGen) {
		b.SetCoinbase(common.Address{0x01})
		if i == 0 {
			b.AddTx(commit)
			return
		}
		if gen != nil {
			gen(i, b)
		}
	})
	chain, err := core.NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, nil, engine, vm.Config{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(chain.Stop)
	if chain.Genesis().Hash() != f.genesis.Hash() {
		t.Fatal("the chain's genesis is not the fixture's")
	}
	f.chain, f.blocks = chain, blocks
	f.insert(1)
}

// insert imports the block of the given height.
func (f *fixture) insert(number int) {
	f.t.Helper()
	if _, err := f.chain.InsertChain(f.blocks[number-1 : number]); err != nil {
		f.t.Fatalf("block %d not imported: %v", number, err)
	}
}

// newPool starts a reveal pool on the chain's head.
func (f *fixture) newPool() *Pool {
	f.t.Helper()
	p := New(f.chain)
	if err := p.Init(0, f.chain.CurrentBlock(), nil); err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { p.Close() })
	return p
}

// reset moves the pool to the chain's head.
func (f *fixture) reset(p *Pool, old *types.Header) {
	p.Reset(old, f.chain.CurrentBlock())
}

func commitTx(t *testing.T, key *ecdsa.PrivateKey, signer types.Signer, chainID *big.Int, nonce uint64, value *big.Int) *types.Transaction {
	t.Helper()
	data, err := ghostpriv.CommitData(ghosttree.K("ghost/test-coin-f", []byte("pool")), make([]byte, ghostpriv.NoteSize))
	if err != nil {
		t.Fatal(err)
	}
	to := ghost.CommitEntryAddress
	return types.MustSignNewTx(key, signer, &types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     nonce,
		GasTipCap: big.NewInt(1_000_000_000),
		GasFeeCap: big.NewInt(100_000_000_000),
		Gas:       60_000,
		To:        &to,
		Value:     value,
		Data:      data,
	})
}

// windowFee is the fee of a reveal in the block at height number: from the
// base fee of the first block of its window, a generated block or the
// genesis, or the base fee the block itself would have when it starts the
// window.
func (f *fixture) windowFee(number int) *uint256.Int {
	f.t.Helper()
	start := ghostpriv.WindowStart(uint64(number))
	var bRef *big.Int
	switch {
	case start == uint64(number):
		bRef = eip1559.CalcBaseFee(f.gspec.Config, f.headerAt(number-1))
	default:
		bRef = f.headerAt(int(start)).BaseFee
	}
	fee, err := ghostpriv.WindowFee(bRef)
	if err != nil {
		f.t.Fatal(err)
	}
	return fee.Total
}

// headerAt is the header at height number, the genesis or a generated block.
func (f *fixture) headerAt(number int) *types.Header {
	if number == 0 {
		return f.genesis.Header()
	}
	return f.blocks[number-1].Header()
}

// reveal is a coin reveal of marker for the block at height number, with
// the genesis coin root, the stub proof and the window fee.
func (f *fixture) reveal(marker common.Hash, recipient common.Address, number int) *types.Transaction {
	f.t.Helper()
	return f.revealWithFee(marker, recipient, f.windowFee(number))
}

func (f *fixture) revealWithFee(marker common.Hash, recipient common.Address, fee *uint256.Int) *types.Transaction {
	f.t.Helper()
	return f.revealWithRoot(marker, recipient, fee, *f.genesis.Header().CoinTreeRoot)
}

func (f *fixture) revealWithRoot(marker common.Hash, recipient common.Address, fee *uint256.Int, root common.Hash) *types.Transaction {
	f.t.Helper()
	genesis := f.genesis
	chainID := f.gspec.Config.GetChainID().Uint64()
	r := &ghostpriv.Reveal{
		Version:   ghostpriv.Version,
		ChainID:   chainID,
		Marker:    marker,
		Root:      root,
		Remainder: ghosttree.K("ghost/test-remainder", marker[:], recipient[:]),
		Recipient: recipient,
		Out:       uint256.NewInt(1000),
		Fee:       new(uint256.Int).Set(fee),
	}
	r.Proof = ghostprivtest.Proof(r.BindingDigest(chainID, genesis.Hash()))
	env, err := r.MarshalBinary()
	if err != nil {
		f.t.Fatal(err)
	}
	tx, err := types.NewGhostRevealTx(env)
	if err != nil {
		f.t.Fatal(err)
	}
	return tx
}

// unproven is a coin reveal of marker with root that takes nothing out and
// carries no proof: a reveal that costs its sender nothing to make.
func (f *fixture) unproven(marker common.Hash, fee *uint256.Int, root common.Hash) *types.Transaction {
	f.t.Helper()
	r := &ghostpriv.Reveal{
		Version: ghostpriv.Version,
		ChainID: f.gspec.Config.GetChainID().Uint64(),
		Marker:  marker,
		Root:    root,
		Out:     new(uint256.Int),
		Fee:     new(uint256.Int).Set(fee),
	}
	env, err := r.MarshalBinary()
	if err != nil {
		f.t.Fatal(err)
	}
	tx, err := types.NewGhostRevealTx(env)
	if err != nil {
		f.t.Fatal(err)
	}
	return tx
}

func testMarker(i int) common.Hash {
	return ghosttree.K("ghost/test-marker", []byte(fmt.Sprintf("synthetic marker %d", i)))
}

func recipient(i int) common.Address {
	return common.BytesToAddress(ghosttree.K("ghost/test-recipient", []byte{byte(i)}).Bytes())
}

func requireErr(t *testing.T, err, want error, what string) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s: error %v, want %v", what, err, want)
	}
}

func hashes(txs []*types.Transaction) []common.Hash {
	out := make([]common.Hash, len(txs))
	for i, tx := range txs {
		out[i] = tx.Hash()
	}
	return out
}

func TestGhostPoolAcceptsRevealWithoutSender(t *testing.T) {
	f := newFixture(t, 1, nil)
	ghostPool := New(f.chain)
	config := legacypool.DefaultConfig
	config.Journal = ""
	legacy := legacypool.New(config, f.chain)
	pool, err := txpool.New(config.PriceLimit, f.chain, []txpool.SubPool{legacy, ghostPool})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	events := make(chan core.NewTxsEvent, 4)
	sub := pool.SubscribeTransactions(events, false)
	defer sub.Unsubscribe()

	tx := f.reveal(testMarker(1), recipient(1), 2)
	if _, err := types.Sender(types.LatestSigner(f.gspec.Config), tx); !errors.Is(err, types.ErrNoSender) {
		t.Fatalf("reveal sender error %v, want %v", err, types.ErrNoSender)
	}
	if errs := pool.Add([]*types.Transaction{tx}, true, true); errs[0] != nil {
		t.Fatalf("reveal refused: %v", errs[0])
	}
	if !pool.Has(tx.Hash()) || pool.Get(tx.Hash()) == nil {
		t.Fatal("pool does not hold the reveal")
	}
	if legacy.Has(tx.Hash()) {
		t.Fatal("the legacy pool holds the reveal")
	}
	if got := pool.Status(tx.Hash()); got != txpool.TxStatusPending {
		t.Fatalf("status %v, want pending", got)
	}
	if got := hashes(pool.PendingReveals()); len(got) != 1 || got[0] != tx.Hash() {
		t.Fatalf("pending reveals %v, want %v", got, tx.Hash())
	}
	if pending := pool.Pending(txpool.PendingFilter{}); len(pending) != 0 {
		t.Fatalf("pending by account holds %d accounts, want none", len(pending))
	}
	if run, queued := ghostPool.Stats(); run != 1 || queued != 0 {
		t.Fatalf("stats %d pending, %d queued, want 1 and 0", run, queued)
	}
	select {
	case ev := <-events:
		if len(ev.Txs) != 1 || ev.Txs[0].Hash() != tx.Hash() {
			t.Fatalf("event for %v, want the reveal", hashes(ev.Txs))
		}
	case <-time.After(time.Second):
		t.Fatal("no event for the new reveal")
	}
	requireErr(t, pool.Add([]*types.Transaction{tx}, true, true)[0], txpool.ErrAlreadyKnown, "the same reveal again")

	// A remote reveal must name its peer.
	other := f.reveal(testMarker(2), recipient(2), 2)
	requireErr(t, pool.Add([]*types.Transaction{other}, false, false)[0], ErrNoPeer, "remote reveal without a peer")
	if errs := ghostPool.AddFromPeer("peer-a", []*types.Transaction{other}); errs[0] != nil {
		t.Fatalf("reveal from a peer refused: %v", errs[0])
	}
	// A remote copy of a held reveal is already known.
	requireErr(t, pool.Add([]*types.Transaction{other}, false, false)[0], txpool.ErrAlreadyKnown, "remote copy of a held reveal")

	// The pool runs the chain rules' checks.
	badFee := f.revealWithFee(testMarker(3), recipient(3), uint256.NewInt(1))
	requireErr(t, pool.Add([]*types.Transaction{badFee}, true, true)[0], ghostpriv.ErrRevealFee, "reveal with a wrong fee")
	restore := ghostpriv.SetVerifier(nil)
	noProof := f.reveal(testMarker(4), recipient(4), 2)
	requireErr(t, pool.Add([]*types.Transaction{noProof}, true, true)[0], ghostpriv.ErrRevealProof, "reveal under the default verifier")
	restore()
	if pool.Has(badFee.Hash()) || pool.Has(noProof.Hash()) {
		t.Fatal("pool holds a refused reveal")
	}
}

func TestGhostPoolCompetingRevealsFirstSeenKept(t *testing.T) {
	f := newFixture(t, 1, nil)
	first := f.reveal(testMarker(1), recipient(1), 2)
	second := f.reveal(testMarker(1), recipient(2), 2)
	if first.Hash() == second.Hash() {
		t.Fatal("the competing reveals are the same")
	}
	for _, order := range [][2]*types.Transaction{{first, second}, {second, first}} {
		p := f.newPool()
		if err := p.AddFromPeer("peer-a", []*types.Transaction{order[0]})[0]; err != nil {
			t.Fatalf("first seen refused: %v", err)
		}
		requireErr(t, p.AddFromPeer("peer-b", []*types.Transaction{order[1]})[0], ErrMarkerPending, "competing reveal from a peer")
		requireErr(t, p.Add([]*types.Transaction{order[1]}, true, true)[0], ErrMarkerPending, "competing reveal over RPC")
		if got := hashes(p.PendingReveals()); len(got) != 1 || got[0] != order[0].Hash() {
			t.Fatalf("pending %v, want only the first seen %v", got, order[0].Hash())
		}
		if p.Has(order[1].Hash()) {
			t.Fatal("pool holds the refused competitor")
		}
	}
}

func TestGhostPoolDropsLoserOnceMarkerSpent(t *testing.T) {
	f := newSpec(t)
	winner := f.reveal(testMarker(1), recipient(1), 2)
	loser := f.reveal(testMarker(1), recipient(2), 2)
	f.generate(2, func(i int, b *core.BlockGen) {
		if i == 1 {
			b.AddTx(winner)
		}
	})

	p := f.newPool()
	if err := p.AddFromPeer("peer-a", []*types.Transaction{loser})[0]; err != nil {
		t.Fatalf("reveal refused: %v", err)
	}
	other := f.reveal(testMarker(2), recipient(3), 2)
	if err := p.Add([]*types.Transaction{other}, true, true)[0]; err != nil {
		t.Fatalf("reveal of another marker refused: %v", err)
	}
	// Another node mined the competing reveal: once its block is the head,
	// the marker is spent and the reveal this pool held is dropped.
	old := f.chain.CurrentBlock()
	f.insert(2)
	f.reset(p, old)
	if p.Has(loser.Hash()) {
		t.Fatal("the losing reveal is still held after its marker was spent")
	}
	if !p.Has(other.Hash()) {
		t.Fatal("the reveal of another marker was dropped")
	}
	requireErr(t, p.Add([]*types.Transaction{loser}, true, true)[0], ghostpriv.ErrRevealMarker, "losing reveal after the marker was spent")
	requireErr(t, p.Add([]*types.Transaction{f.reveal(testMarker(1), recipient(4), 3)}, true, true)[0], ghostpriv.ErrRevealMarker, "new reveal of the spent marker")
	if got := hashes(p.PendingReveals()); len(got) != 1 || got[0] != other.Hash() {
		t.Fatalf("pending %v, want only %v", got, other.Hash())
	}
}

func TestGhostPoolPerPeerBudget(t *testing.T) {
	f := newFixture(t, 2, nil)
	p := f.newPool()

	reveals := make([]*types.Transaction, 16)
	for i := range reveals {
		reveals[i] = f.reveal(testMarker(i), recipient(i), 2)
	}
	revealKinds := func(n int) ([]byte, []uint32) {
		kinds, sizes := make([]byte, n), make([]uint32, n)
		for i := range kinds {
			kinds[i], sizes[i] = types.GhostRevealTxType, types.GhostRevealEnvelopeSize
		}
		return kinds, sizes
	}

	// Announcements: a peer has the node fetch four reveals per head; the
	// rest are not fetched. A reveal announced with another size is never
	// fetched, and other transactions are not limited.
	kinds, sizes := revealKinds(6)
	keep := p.FilterAnnounced("peer-a", kinds, sizes, hashes(reveals[:6]))
	for i, k := range keep {
		if want := i < PeerRevealsPerBlock; k != want {
			t.Fatalf("announced reveal %d: fetch %v, want %v", i, k, want)
		}
	}
	plain := common.Hash{0x01}
	keep = p.FilterAnnounced("peer-c", []byte{types.GhostRevealTxType, types.DynamicFeeTxType}, []uint32{1000, 1000}, []common.Hash{reveals[6].Hash(), plain})
	if keep[0] || !keep[1] {
		t.Fatalf("fetch %v, want a mis-sized reveal dropped and a plain transaction kept", keep)
	}
	// Announcing a reveal already agreed costs nothing.
	keep = p.FilterAnnounced("peer-a", kinds[:1], sizes[:1], hashes(reveals[:1]))
	if !keep[0] {
		t.Fatal("re-announced reveal dropped")
	}

	// Deliveries of the agreed reveals take nothing more.
	for i, err := range p.AddFromPeer("peer-a", reveals[:PeerRevealsPerBlock]) {
		if err != nil {
			t.Fatalf("announced reveal %d refused: %v", i, err)
		}
	}
	// The budget of this head is used up: an unannounced delivery is refused.
	requireErr(t, p.AddFromPeer("peer-a", reveals[6:7])[0], ErrPeerBudget, "delivery over the head's budget")

	// Unannounced deliveries take from the budget too.
	for i, err := range p.AddFromPeer("peer-b", reveals[7:7+PeerRevealsPerBlock]) {
		if err != nil {
			t.Fatalf("delivered reveal %d refused: %v", i, err)
		}
	}
	requireErr(t, p.AddFromPeer("peer-b", reveals[11:12])[0], ErrPeerBudget, "delivery over the head's budget")
	kinds, sizes = revealKinds(1)
	if keep := p.FilterAnnounced("peer-b", kinds, sizes, hashes(reveals[11:12])); keep[0] {
		t.Fatal("announcement over the head's budget kept")
	}

	// A new head refills the budget, but a peer cannot have more than
	// PeerMaxHeld reveals in the pool.
	old := f.chain.CurrentBlock()
	f.insert(2)
	f.reset(p, old)
	if run, _ := p.Stats(); run != 2*PeerMaxHeld {
		t.Fatalf("pool holds %d reveals after the new head, want %d", run, 2*PeerMaxHeld)
	}
	requireErr(t, p.AddFromPeer("peer-a", reveals[11:12])[0], ErrPeerBudget, "delivery over the held cap")

	// A peer that left has no budget left over; one that joins again starts
	// afresh.
	p.DropPeer("peer-a")
	if err := p.AddFromPeer("peer-a", reveals[11:12])[0]; err != nil {
		t.Fatalf("delivery after the peer joined again refused: %v", err)
	}
	// Peers that never delivered still have their budget.
	if err := p.AddFromPeer("peer-c", reveals[12:13])[0]; err != nil {
		t.Fatalf("delivery of a fresh peer refused: %v", err)
	}
	requireErr(t, p.AddFromPeer("", reveals[13:14])[0], ErrNoPeer, "delivery without a peer")
}

func TestGhostPoolCapsAndRecheck(t *testing.T) {
	if MaxBytes != MaxReveals*types.GhostRevealEnvelopeSize {
		t.Fatalf("byte cap %d is not %d envelopes", MaxBytes, MaxReveals)
	}
	f := newFixture(t, 3, nil)
	p := f.newPool()

	reveals := make([]*types.Transaction, MaxReveals+1)
	for i := range reveals {
		reveals[i] = f.reveal(testMarker(i), recipient(i), 2)
	}
	for i, err := range p.Add(reveals[:MaxReveals], true, true) {
		if err != nil {
			t.Fatalf("reveal %d refused: %v", i, err)
		}
	}
	if run, _ := p.Stats(); run != MaxReveals {
		t.Fatalf("pool holds %d reveals, want %d", run, MaxReveals)
	}
	if p.bytes != MaxBytes {
		t.Fatalf("pool holds %d bytes, want %d", p.bytes, MaxBytes)
	}
	requireErr(t, p.Add(reveals[MaxReveals:], true, true)[0], ErrPoolFull, "reveal over the cap")
	requireErr(t, p.AddFromPeer("peer-a", reveals[MaxReveals:])[0], ErrPoolFull, "reveal from a peer over the cap")
	if got := hashes(p.PendingReveals()); len(got) != MaxReveals || got[0] != reveals[0].Hash() || got[MaxReveals-1] != reveals[MaxReveals-1].Hash() {
		t.Fatal("pending reveals are not the held ones, first seen first")
	}

	// A new head in the same fee window: every reveal still passes.
	old := f.chain.CurrentBlock()
	f.insert(2)
	f.reset(p, old)
	if run, _ := p.Stats(); run != MaxReveals {
		t.Fatalf("pool holds %d reveals after a head in the same window, want %d", run, MaxReveals)
	}

	// The next block starts a new fee window with another base fee: the
	// recheck drops every reveal priced for the old one.
	old = f.chain.CurrentBlock()
	f.insert(3)
	if ghostpriv.WindowStart(4) != 4 {
		t.Fatal("block 4 does not start a fee window")
	}
	newFee := f.windowFee(4)
	if oldFee := f.windowFee(2); newFee.Eq(oldFee) {
		t.Fatalf("the fee of the new window equals the old one, %v", newFee)
	}
	f.reset(p, old)
	if run, _ := p.Stats(); run != 0 {
		t.Fatalf("pool holds %d reveals after the window changed, want none", run)
	}
	if p.bytes != 0 || len(p.markers) != 0 || len(p.order) != 0 {
		t.Fatalf("pool keeps %d bytes, %d markers and %d hashes after the recheck", p.bytes, len(p.markers), len(p.order))
	}
	requireErr(t, p.Add(reveals[:1], true, true)[0], ghostpriv.ErrRevealFee, "reveal priced for the old window")
	fresh := f.revealWithFee(testMarker(0), recipient(0), newFee)
	if err := p.Add([]*types.Transaction{fresh}, true, true)[0]; err != nil {
		t.Fatalf("reveal priced for the new window refused: %v", err)
	}
}

// gatedChain is the chain with its first header read above the genesis
// after arming held until the test releases it, standing in for an ancestry
// walk that takes long. The tree-root index reads only the genesis header
// for the genesis root, so the read held is the walk's.
type gatedChain struct {
	*core.BlockChain
	armed   atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func (c *gatedChain) GetHeader(hash common.Hash, number uint64) *types.Header {
	if number > 0 && c.armed.CompareAndSwap(true, false) {
		close(c.entered)
		<-c.release
	}
	return c.BlockChain.GetHeader(hash, number)
}

// stallChain is the chain with the first header reads above the genesis
// after arming, up to stalls of them, held until the test releases them:
// each stands for the long ancestry walk of a reveal down to an old root.
type stallChain struct {
	*core.BlockChain
	stalls  atomic.Int32
	entered chan struct{}
	release chan struct{}
}

func (c *stallChain) GetHeader(hash common.Hash, number uint64) *types.Header {
	if number > 0 && c.stalls.Add(-1) >= 0 {
		c.entered <- struct{}{}
		<-c.release
	}
	return c.BlockChain.GetHeader(hash, number)
}

// countChain is the chain counting its header reads above the genesis, the
// reads of an ancestry walk.
type countChain struct {
	*core.BlockChain
	reads atomic.Int64
}

func (c *countChain) GetHeader(hash common.Hash, number uint64) *types.Header {
	if number > 0 {
		c.reads.Add(1)
	}
	return c.BlockChain.GetHeader(hash, number)
}

// TestGhostPoolAbsentRootsTakeNoCheckSlot floods the pool from several peers
// with reveals that take nothing out, carry no proof and have roots that no
// block carries, and checks that the tree-root index refuses each before it
// takes a check slot or walks the ancestry, that each is charged to its
// peer, and that reveals of other peers delivered during the flood are
// checked and admitted, on this head and the next.
func TestGhostPoolAbsentRootsTakeNoCheckSlot(t *testing.T) {
	f := newFixture(t, 4, nil)
	f.insert(2)
	f.insert(3)
	if ghostpriv.WindowStart(4) != 4 {
		t.Fatal("block 4 does not start a fee window")
	}
	chain := &countChain{BlockChain: f.chain}
	p := New(chain)
	if err := p.Init(0, f.chain.CurrentBlock(), nil); err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	remoteSlots := maxValidations - 1
	// flood has remoteSlots peers deliver their whole budget of reveals at
	// once, for the block at height next, with roots no block carries.
	flood := func(round, next int) <-chan error {
		fee := f.windowFee(next)
		results := make(chan error, remoteSlots*PeerRevealsPerBlock)
		for i := 0; i < remoteSlots; i++ {
			go func(i int) {
				for j := 0; j < PeerRevealsPerBlock; j++ {
					n := 1000*(round+1) + PeerRevealsPerBlock*i + j
					root := ghosttree.K("ghost/test-root", []byte(fmt.Sprintf("synthetic absent root %d", n)))
					tx := f.unproven(testMarker(n), fee, root)
					results <- p.AddFromPeer(fmt.Sprintf("flooder-%d", i), []*types.Transaction{tx})[0]
				}
			}(i)
		}
		return results
	}
	drain := func(results <-chan error) {
		t.Helper()
		for i := 0; i < remoteSlots*PeerRevealsPerBlock; i++ {
			select {
			case err := <-results:
				requireErr(t, err, ghostpriv.ErrRevealRoot, "flooded reveal with a root of no block")
			case <-time.After(10 * time.Second):
				t.Fatal("a flooded reveal was never answered")
			}
		}
	}
	// honest has remoteSlots other peers each deliver a valid reveal for the
	// block at height next, during a flood, and requires every one admitted.
	honest := func(round, next int) {
		t.Helper()
		fee := f.windowFee(next)
		results := flood(round, next)
		admitted := make(chan error, remoteSlots)
		for i := 0; i < remoteSlots; i++ {
			go func(i int) {
				tx := f.revealWithFee(testMarker(100*(round+1)+i), recipient(i), fee)
				admitted <- p.AddFromPeer(fmt.Sprintf("honest-%d-%d", round, i), []*types.Transaction{tx})[0]
			}(i)
		}
		for i := 0; i < remoteSlots; i++ {
			select {
			case err := <-admitted:
				if err != nil {
					t.Fatalf("round %d: reveal of an honest peer refused during the flood: %v", round, err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("a reveal of an honest peer was never answered")
			}
		}
		drain(results)
	}
	charged := func() {
		t.Helper()
		p.mu.RLock()
		defer p.mu.RUnlock()
		for i := 0; i < remoteSlots; i++ {
			if b := p.peers[fmt.Sprintf("flooder-%d", i)]; b == nil || b.tokens != 0 || b.validating != 0 || b.held != 0 {
				t.Fatalf("flooding peer %d: budget %+v, want every reveal charged and none checked or held", i, b)
			}
		}
	}

	// The flood alone reads no header: no reveal of it walks the ancestry,
	// and none takes a check slot.
	drain(flood(0, 4))
	if reads := chain.reads.Load(); reads != 0 {
		t.Fatalf("the flood read %d headers, want none", reads)
	}
	charged()
	if len(p.remoteSlots) != 0 || len(p.validating) != 0 {
		t.Fatal("the flood holds a check slot")
	}

	// A new head refills the flooders' budgets; they flood again while
	// other peers deliver valid reveals, which all find a slot.
	old := f.chain.CurrentBlock()
	f.insert(4)
	f.reset(p, old)
	honest(1, 5)
	charged()
	if len(p.validating) != 0 || len(p.remoteSlots) != 0 {
		t.Fatalf("%d reveals checked and %d slots taken after the flood, want none", len(p.validating), len(p.remoteSlots))
	}
	for i := 0; i < remoteSlots; i++ {
		if tx := f.revealWithFee(testMarker(200+i), recipient(i), f.windowFee(5)); !p.Has(tx.Hash()) {
			t.Fatalf("honest reveal %d not held", i)
		}
	}
}

// TestGhostPoolFloodOfSlowChecksLeavesLocalSlot floods the pool from several
// peers with reveals of an old eligible root and no proof, each check stuck
// in its ancestry walk, and checks that peers hold no more than the slots
// open to them, each at most one, that every refused reveal is charged to
// its peer, and that a local reveal is still checked and admitted.
func TestGhostPoolFloodOfSlowChecksLeavesLocalSlot(t *testing.T) {
	f := newFixture(t, 3, nil)
	f.insert(2)
	f.insert(3)
	// The next block, 4, starts a fee window, so the only header reads are
	// those of the root rule.
	if ghostpriv.WindowStart(4) != 4 {
		t.Fatal("block 4 does not start a fee window")
	}
	remoteSlots := maxValidations - 1
	chain := &stallChain{BlockChain: f.chain, entered: make(chan struct{}, maxValidations), release: make(chan struct{})}
	p := New(chain)
	if err := p.Init(0, f.chain.CurrentBlock(), nil); err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	released := false
	defer func() {
		if !released {
			close(chain.release)
		}
	}()

	fee := f.windowFee(4)
	genesisRoot := *f.genesis.Header().CoinTreeRoot
	slow := func(i int) *types.Transaction {
		return f.unproven(testMarker(100+i), fee, genesisRoot)
	}
	const peers = 8
	chain.stalls.Store(int32(remoteSlots))

	// Every peer sends a reveal at once; those that take a slot are stuck.
	results := make(chan error, peers)
	for i := 0; i < peers; i++ {
		go func(i int) {
			results <- p.AddFromPeer(fmt.Sprintf("peer-%d", i), []*types.Transaction{slow(i)})[0]
		}(i)
	}
	for i := 0; i < remoteSlots; i++ {
		select {
		case <-chain.entered:
		case <-time.After(10 * time.Second):
			t.Fatalf("only %d checks of the flood started, want %d", i, remoteSlots)
		}
	}
	// The peers left without a slot are dropped at once, not queued.
	for i := 0; i < peers-remoteSlots; i++ {
		select {
		case err := <-results:
			requireErr(t, err, ErrChecksBusy, "flooded reveal with every peer slot taken")
		case <-time.After(10 * time.Second):
			t.Fatal("a flooded reveal waits for a slot")
		}
	}
	p.mu.RLock()
	var stuck []string
	for name, b := range p.peers {
		if b.validating > 1 {
			t.Errorf("peer %s holds %d check slots", name, b.validating)
		}
		if b.validating == 1 {
			stuck = append(stuck, name)
		}
		if b.tokens != PeerRevealsPerBlock-1 {
			t.Errorf("peer %s has %d reveals left, want %d: every reveal is charged", name, b.tokens, PeerRevealsPerBlock-1)
		}
	}
	checking := len(p.validating)
	p.mu.RUnlock()
	if len(stuck) != remoteSlots || checking != remoteSlots {
		t.Fatalf("%d peers hold a slot and %d reveals are checked, want %d", len(stuck), checking, remoteSlots)
	}

	// A peer with a reveal being checked cannot take another slot.
	for i, name := range stuck {
		requireErr(t, p.AddFromPeer(name, []*types.Transaction{slow(peers + i)})[0], ErrPeerBusy, "second reveal of a peer being checked")
	}
	// Cheap refusals cost the peer without a slot: a wrong fee, a wrong
	// version and a wrong chain id.
	badFee := f.revealWithFee(testMarker(200), recipient(1), uint256.NewInt(1))
	requireErr(t, p.AddFromPeer("peer-x", []*types.Transaction{badFee})[0], ghostpriv.ErrRevealFee, "reveal with a wrong fee")
	encode := func(r *ghostpriv.Reveal) *types.Transaction {
		env, err := r.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		tx, err := types.NewGhostRevealTx(env)
		if err != nil {
			t.Fatal(err)
		}
		return tx
	}
	chainID := f.gspec.Config.GetChainID().Uint64()
	badVersion := encode(&ghostpriv.Reveal{Version: ghostpriv.Version + 1, ChainID: chainID, Marker: testMarker(201), Fee: fee})
	requireErr(t, p.AddFromPeer("peer-x", []*types.Transaction{badVersion})[0], ghostpriv.ErrRevealVersion, "reveal of another version")
	badChain := encode(&ghostpriv.Reveal{Version: ghostpriv.Version, ChainID: chainID + 1, Marker: testMarker(202), Fee: fee})
	requireErr(t, p.AddFromPeer("peer-x", []*types.Transaction{badChain})[0], ghostpriv.ErrRevealChainID, "reveal of another chain")
	p.mu.RLock()
	tokens := p.peers["peer-x"].tokens
	p.mu.RUnlock()
	if tokens != PeerRevealsPerBlock-3 {
		t.Fatalf("peer with three refused reveals has %d left, want %d", tokens, PeerRevealsPerBlock-3)
	}

	// The node's own reveal still finds its slot and is admitted.
	local := f.revealWithFee(testMarker(1), recipient(1), fee)
	done := make(chan error, 1)
	go func() { done <- p.Add([]*types.Transaction{local}, true, true)[0] }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("local reveal refused during the flood: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("local reveal blocked by the flood")
	}
	if !p.Has(local.Hash()) {
		t.Fatal("pool does not hold the local reveal")
	}

	released = true
	close(chain.release)
	for i := 0; i < remoteSlots; i++ {
		select {
		case err := <-results:
			requireErr(t, err, ghostpriv.ErrRevealProof, "flooded reveal without a proof")
		case <-time.After(10 * time.Second):
			t.Fatal("a stuck check never finished")
		}
	}
	if run, _ := p.Stats(); run != 1 || len(p.validating) != 0 || p.locals != 0 {
		t.Fatalf("pool holds %d reveals and checks %d, want the local one and none", run, len(p.validating))
	}
	if len(p.remoteSlots) != 0 || len(p.localSlot) != 0 {
		t.Fatal("a check slot was not given back")
	}
}

// TestGhostPoolSlowCheckDoesNotBlockPool checks that a peer's reveal of an
// old root without a proof, whose check walks the ancestry, holds no lock
// while it is checked: reads, announcements, a reset and other reveals go
// on, while its marker stays taken for it until the check refuses it.
func TestGhostPoolSlowCheckDoesNotBlockPool(t *testing.T) {
	f := newFixture(t, 3, nil)
	f.insert(2)
	f.insert(3)
	// The next block, 4, starts a fee window, so the fee check reads no
	// header and the first header read is the root rule's ancestry walk.
	if ghostpriv.WindowStart(4) != 4 {
		t.Fatal("block 4 does not start a fee window")
	}
	chain := &gatedChain{BlockChain: f.chain, entered: make(chan struct{}), release: make(chan struct{})}
	p := New(chain)
	head := f.chain.CurrentBlock()
	if err := p.Init(0, head, nil); err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	fee := f.windowFee(4)
	valid := f.revealWithFee(testMarker(1), recipient(1), fee)
	if err := p.Add([]*types.Transaction{valid}, true, true)[0]; err != nil {
		t.Fatalf("valid reveal refused: %v", err)
	}
	bad := f.unproven(testMarker(2), fee, *f.genesis.Header().CoinTreeRoot)

	chain.armed.Store(true)
	done := make(chan error, 1)
	go func() { done <- p.AddFromPeer("peer-a", []*types.Transaction{bad})[0] }()
	select {
	case <-chain.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the bad reveal's check never read a header")
	}

	// The bad reveal's check is stuck in its ancestry walk.
	var (
		other    = f.revealWithFee(testMarker(3), recipient(3), fee)
		rival    = f.revealWithFee(testMarker(2), recipient(4), fee)
		finished = make(chan struct{})
		otherErr error
		rivalErr error
	)
	go func() {
		defer close(finished)
		p.Has(valid.Hash())
		p.Get(valid.Hash())
		p.PendingReveals()
		p.Stats()
		p.Status(valid.Hash())
		p.FilterAnnounced("peer-b", []byte{types.GhostRevealTxType}, []uint32{types.GhostRevealEnvelopeSize}, []common.Hash{other.Hash()})
		p.Reset(head, head)
		otherErr = p.Add([]*types.Transaction{other}, true, true)[0]
		rivalErr = p.Add([]*types.Transaction{rival}, true, true)[0]
	}()
	select {
	case <-finished:
	case <-time.After(10 * time.Second):
		close(chain.release)
		t.Fatal("the pool was blocked while a reveal was checked")
	}
	if otherErr != nil {
		t.Fatalf("reveal of another marker refused while the bad one was checked: %v", otherErr)
	}
	requireErr(t, rivalErr, ErrMarkerPending, "rival of the reveal being checked")
	if !p.Has(valid.Hash()) {
		t.Fatal("the reset dropped the valid reveal")
	}

	close(chain.release)
	select {
	case err := <-done:
		requireErr(t, err, ghostpriv.ErrRevealProof, "reveal without a proof")
	case <-time.After(10 * time.Second):
		t.Fatal("the bad reveal's check never finished")
	}
	if p.Has(bad.Hash()) {
		t.Fatal("pool holds the refused reveal")
	}
	// The refused reveal's marker is free again.
	if err := p.Add([]*types.Transaction{rival}, true, true)[0]; err != nil {
		t.Fatalf("reveal of the freed marker refused: %v", err)
	}
	if run, _ := p.Stats(); run != 3 || len(p.validating) != 0 {
		t.Fatalf("pool holds %d reveals and checks %d, want 3 and none", run, len(p.validating))
	}
}
