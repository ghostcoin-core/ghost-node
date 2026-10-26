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

package eth

// Mining-behaviour tests: several in-process nodes on the internal network's
// genesis, each a BlockChain with its own in-memory database, its own RandomX
// engine and the eth protocol handler on a p2p server listening on loopback.
// Blocks are built and sealed with RandomX by the node that mines them and
// travel between nodes only over the eth protocol, through the full-sync
// downloader. The results the tests log are recorded in
// docs/mining-behaviour.md.

import (
	"bytes"
	"fmt"
	"math/big"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/ghostrules"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/consensus/randomx"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/internal/testlog"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/qsconn"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/holiman/uint256"
)

// The chain is the internal network's genesis and EVM profile with the
// RandomX test engine's consensus values: difficulty 16, so a seal takes a
// few dozen hashes and a wrong nonce fails, ten-second blocks, a key
// interval of 8 blocks and a key delay of 4, so a test chain crosses many
// RandomX keys. At the internal network's own difficulty of 1 every hash
// seals, so no seal check could fail.
const (
	mbEpoch       = 8
	mbKeyLag      = 4
	mbBlockTime   = 10
	mbDifficulty  = 16
	mbFutureDrift = 30

	// mbSealThreads is the number of RandomX threads of a mining node.
	mbSealThreads = 4

	// mbSealTimeout bounds the search for one nonce.
	mbSealTimeout = 2 * time.Minute

	// mbSyncTimeout bounds one node catching up with another.
	mbSyncTimeout = 3 * time.Minute

	// mbLinkTimeout bounds a connection or disconnection between two nodes.
	mbLinkTimeout = 30 * time.Second
)

// Bounds of the header flood. The node must drop a flooding peer within
// floodDropBound of the first message, keep its live heap within
// floodRetainedCap of what it was before the flood once the flood is over,
// keep the peak heap during the flood within floodPeakCap of that, and
// answer every eth_blockNumber call within floodRPCBound. A flooding peer
// that is still connected after floodGiveUp stops by itself, and the test
// fails.
const (
	floodDropBound   = 10 * time.Second
	floodRetainedCap = 32 << 20
	floodPeakCap     = 256 << 20
	floodRPCBound    = time.Second
	floodGiveUp      = 30 * time.Second
	floodRPCInterval = 10 * time.Millisecond
	floodRPCSettle   = 250 * time.Millisecond
)

// miningParams are the consensus constants of the test chain: the internal
// network's half-life and rewards with the RandomX test engine's block
// time, difficulty and future drift.
func miningParams() ghostrules.Params {
	p := ghost.InternalNetParams()
	p.BlockTime = mbBlockTime
	p.StartDifficulty = big.NewInt(mbDifficulty)
	p.MinDifficulty = big.NewInt(mbDifficulty)
	p.FutureDrift = mbFutureDrift
	return p
}

// sealAudit is a RandomX engine that records every header whose seal it
// checked and accepted, so a test can show that a sync verified the seal of
// every block it imported.
type sealAudit struct {
	*randomx.RandomX

	lock   sync.Mutex
	sealed map[common.Hash]int // header hash -> accepted seal checks
}

func (a *sealAudit) record(header *types.Header) {
	a.lock.Lock()
	a.sealed[header.Hash()]++
	a.lock.Unlock()
}

// checked returns how many times the seal of the header with the given hash
// was checked and accepted.
func (a *sealAudit) checked(hash common.Hash) int {
	a.lock.Lock()
	defer a.lock.Unlock()
	return a.sealed[hash]
}

// VerifyHeader implements consensus.Engine. A header the chain already holds
// is accepted by the engine without a check, so it is not recorded.
func (a *sealAudit) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header, seal bool) error {
	known := chain.GetHeader(header.Hash(), header.Number.Uint64()) != nil
	err := a.RandomX.VerifyHeader(chain, header, seal)
	if err == nil && seal && !known {
		a.record(header)
	}
	return err
}

// VerifyHeaders implements consensus.Engine, passing the engine's results on
// in order and recording each header whose seal was checked and accepted.
func (a *sealAudit) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	innerAbort, inner := a.RandomX.VerifyHeaders(chain, headers, seals)
	abort, results := make(chan struct{}), make(chan error, len(headers))
	go func() {
		for i := range headers {
			select {
			case err := <-inner:
				if err == nil && seals[i] {
					a.record(headers[i])
				}
				results <- err
			case <-abort:
				close(innerAbort)
				return
			}
		}
	}()
	return abort, results
}

// miningNode is one in-process node: a chain, its RandomX engine, the eth
// protocol handler and a p2p server listening on loopback.
type miningNode struct {
	t        *testing.T
	name     string
	id       string // the peer ID other nodes know this node by
	coinbase common.Address
	rx       *randomx.RandomX
	audit    *sealAudit // non-nil when the chain verifies through an audit
	chain    *core.BlockChain
	handler  *handler
	srv      *p2p.Server
}

// newMiningNode starts a node on the test chain's genesis. With audit, its
// chain verifies headers through a sealAudit.
func newMiningNode(t *testing.T, name string, index byte, audit bool) *miningNode {
	t.Helper()
	rx, err := randomx.New(randomx.Config{Params: miningParams(), EpochLength: mbEpoch, KeyLag: mbKeyLag})
	if err != nil {
		t.Fatalf("node %s: RandomX engine: %v", name, err)
	}
	rx.SetThreads(mbSealThreads)
	n := &miningNode{t: t, name: name, coinbase: common.Address{0x6d, 0x62, index}, rx: rx}

	var engine consensus.Engine = rx
	if audit {
		n.audit = &sealAudit{RandomX: rx, sealed: make(map[common.Hash]int)}
		engine = n.audit
	}
	gspec := ghost.InternalNetGenesis()
	gspec.Difficulty = big.NewInt(mbDifficulty)
	db := rawdb.NewMemoryDatabase()
	chain, err := core.NewBlockChain(db, nil, gspec, nil, engine, vm.Config{}, nil, nil)
	if err != nil {
		t.Fatalf("node %s: %v", name, err)
	}
	if chain.Genesis().Header().CoinTreeRoot == nil {
		t.Fatalf("node %s: the genesis has no coin tree root", name)
	}
	h, err := newHandler(&handlerConfig{
		Database:   db,
		Chain:      chain,
		TxPool:     newTestTxPool(),
		Merger:     consensus.NewMerger(rawdb.NewMemoryDatabase()),
		Network:    ghost.InternalNetChainID,
		Sync:       downloader.FullSync,
		BloomCache: 1,
	})
	if err != nil {
		t.Fatalf("node %s: handler: %v", name, err)
	}
	h.Start(25)
	t.Cleanup(func() {
		h.Stop()
		chain.Stop()
	})
	n.chain, n.handler = chain, h
	// The server stops before the handler, so every peer is gone by then.
	n.srv, n.id = startMiningServer(t, name, eth.MakeProtocols((*ethHandler)(h), ghost.InternalNetChainID, []uint{eth.ETH68}, nil))
	return n
}

// startMiningServer runs the given protocols on a p2p server with a new
// quantum-safe identity, listening on loopback with discovery off.
func startMiningServer(t *testing.T, name string, protocols []p2p.Protocol) (*p2p.Server, string) {
	t.Helper()
	key, err := qsconn.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	srv := &p2p.Server{Config: p2p.Config{
		Name:        name,
		Identity:    key,
		MaxPeers:    25,
		NoDiscovery: true,
		ListenAddr:  "127.0.0.1:0",
		Protocols:   protocols,
		Logger:      testlog.Logger(t, log.LevelError).New("server", name),
	}}
	if err := srv.Start(); err != nil {
		t.Fatalf("server %s: %v", name, err)
	}
	t.Cleanup(srv.Stop)
	return srv, key.ID().String()
}

func (n *miningNode) head() *types.Header { return n.chain.CurrentBlock() }

func (n *miningNode) td() *big.Int {
	h := n.head()
	return n.chain.GetTd(h.Hash(), h.Number.Uint64())
}

// mine builds, seals and imports count blocks on the node's head, paying the
// rewards to the node's coinbase.
func (n *miningNode) mine(count int) {
	n.t.Helper()
	for i := 0; i < count; i++ {
		block := n.seal(n.build(n.head()))
		if _, err := n.chain.InsertChain(types.Blocks{block}); err != nil {
			n.t.Fatalf("node %s did not import its own block %d: %v", n.name, block.NumberU64(), err)
		}
	}
}

// build assembles an empty block on parent, before the seal.
func (n *miningNode) build(parent *types.Header) *types.Block {
	n.t.Helper()
	header := &types.Header{
		ParentHash: parent.Hash(),
		Number:     new(big.Int).Add(parent.Number, common.Big1),
		GasLimit:   parent.GasLimit,
		Time:       parent.Time + mbBlockTime,
		Coinbase:   n.coinbase,
		BaseFee:    eip1559.CalcBaseFee(n.chain.Config(), parent),
	}
	if err := n.rx.Prepare(n.chain, header); err != nil {
		n.t.Fatalf("node %s: prepare block %d: %v", n.name, header.Number, err)
	}
	st, err := n.chain.StateAt(parent.Root)
	if err != nil {
		n.t.Fatalf("node %s: state of block %d: %v", n.name, parent.Number, err)
	}
	block, err := n.rx.FinalizeAndAssemble(n.chain, header, st, nil, nil, nil, nil)
	if err != nil {
		n.t.Fatalf("node %s: assemble block %d: %v", n.name, header.Number, err)
	}
	return block
}

// seal finds a RandomX nonce for block.
func (n *miningNode) seal(block *types.Block) *types.Block {
	n.t.Helper()
	results, stop := make(chan *types.Block, 1), make(chan struct{})
	defer close(stop)
	if err := n.rx.Seal(n.chain, block, results, stop); err != nil {
		n.t.Fatalf("node %s: seal block %d: %v", n.name, block.Number(), err)
	}
	select {
	case sealed := <-results:
		return sealed
	case <-time.After(mbSealTimeout):
		n.t.Fatalf("node %s: block %d not sealed in %v", n.name, block.Number(), mbSealTimeout)
		return nil
	}
}

// linked reports whether the two nodes hold each other as eth peers.
func linked(a, b *miningNode) (bool, bool) {
	return a.handler.peers.peer(b.id) != nil, b.handler.peers.peer(a.id) != nil
}

// connect makes a dial b and waits for the eth handshake on both sides.
func connect(a, b *miningNode) {
	a.t.Helper()
	a.srv.AddPeer(b.srv.Self())
	waitLink(a, b, true)
}

// disconnect makes a drop b and waits until neither holds the other.
func disconnect(a, b *miningNode) {
	a.t.Helper()
	a.srv.RemovePeer(b.srv.Self())
	waitLink(a, b, false)
}

func waitLink(a, b *miningNode, up bool) {
	a.t.Helper()
	deadline := time.Now().Add(mbLinkTimeout)
	for {
		ab, ba := linked(a, b)
		if ab == up && ba == up {
			return
		}
		if time.Now().After(deadline) {
			a.t.Fatalf("link %s-%s: have %v/%v, want %v", a.name, b.name, ab, ba, up)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// syncFrom runs full syncs of n from src over the eth protocol until n's
// head is src's head, as the node's chain syncer does once src announces a
// heavier head. src must be strictly heavier.
func (n *miningNode) syncFrom(src *miningNode) {
	n.t.Helper()
	deadline := time.Now().Add(mbSyncTimeout)
	for {
		want := src.head()
		if n.head().Hash() == want.Hash() {
			return
		}
		wantTD := src.chain.GetTd(want.Hash(), want.Number.Uint64())
		if n.td().Cmp(wantTD) >= 0 {
			n.t.Fatalf("node %s (td %v) cannot sync from %s (td %v), which is not heavier", n.name, n.td(), src.name, wantTD)
		}
		if time.Now().After(deadline) {
			n.t.Fatalf("node %s at block %d, not synced to %s's block %d in %v", n.name, n.head().Number, src.name, want.Number, mbSyncTimeout)
		}
		p := n.handler.peers.peer(src.id)
		if p == nil {
			n.t.Fatalf("node %s has no peer %s to sync from", n.name, src.name)
		}
		op := &chainSyncOp{mode: downloader.FullSync, peer: p.Peer, td: wantTD, head: want.Hash()}
		if err := n.handler.doSync(op); err != nil {
			// The handler's own chain syncer may be running a cycle.
			time.Sleep(20 * time.Millisecond)
		}
	}
}

// mineInTurn mines count blocks with the nodes of one partition taking
// turns, each block synced to the rest of the partition before the next.
func mineInTurn(count int, partition ...*miningNode) {
	for i := 0; i < count; i++ {
		miner := partition[i%len(partition)]
		miner.mine(1)
		for _, n := range partition {
			if n != miner {
				n.syncFrom(miner)
			}
		}
	}
}

// requireAgreement checks that every node has the same head, that each one
// holds the state of that head with coin and data tree roots matching the
// header, and that every coinbase's balance is the sum of the rewards of
// the canonical blocks it mined. It returns those sums.
func requireAgreement(t *testing.T, nodes ...*miningNode) map[common.Address]*uint256.Int {
	t.Helper()
	params := miningParams()
	want := nodes[0].head()
	var rewards map[common.Address]*uint256.Int
	for _, n := range nodes {
		head := n.head()
		if head.Hash() != want.Hash() {
			t.Fatalf("node %s at block %d %x, node %s at block %d %x", n.name, head.Number, head.Hash(), nodes[0].name, want.Number, want.Hash())
		}
		st, err := n.chain.StateAt(head.Root)
		if err != nil {
			t.Fatalf("node %s: no state for its head: %v", n.name, err)
		}
		coin, err := ghosttree.Root(st, ghosttree.Coin)
		if err != nil {
			t.Fatalf("node %s: coin tree: %v", n.name, err)
		}
		data, err := ghosttree.Root(st, ghosttree.Data)
		if err != nil {
			t.Fatalf("node %s: data tree: %v", n.name, err)
		}
		if head.CoinTreeRoot == nil || coin != *head.CoinTreeRoot {
			t.Fatalf("node %s: coin tree root %x, header has %v", n.name, coin, head.CoinTreeRoot)
		}
		if head.DataTreeRoot == nil || data != *head.DataTreeRoot {
			t.Fatalf("node %s: data tree root %x, header has %v", n.name, data, head.DataTreeRoot)
		}
		if head.DataMarkerRoot == nil || *head.DataMarkerRoot != ghosttree.EmptyMarkerSetRoot {
			t.Fatalf("node %s: header data marker root %v, want %x", n.name, head.DataMarkerRoot, ghosttree.EmptyMarkerSetRoot)
		}
		if root := st.IntermediateRoot(true); root != head.Root {
			t.Fatalf("node %s: state root %x, header has %x", n.name, root, head.Root)
		}
		// The rewards of the node's own canonical chain.
		mined := make(map[common.Address]*uint256.Int)
		for number := uint64(1); number <= head.Number.Uint64(); number++ {
			h := n.chain.GetHeaderByNumber(number)
			if h == nil {
				t.Fatalf("node %s: no canonical header %d", n.name, number)
			}
			if mined[h.Coinbase] == nil {
				mined[h.Coinbase] = new(uint256.Int)
			}
			mined[h.Coinbase].Add(mined[h.Coinbase], params.BlockReward(number))
		}
		for _, m := range nodes {
			want := mined[m.coinbase]
			if want == nil {
				want = new(uint256.Int)
			}
			if have := st.GetBalance(m.coinbase); have.Cmp(want) != 0 {
				t.Fatalf("node %s: balance of %s's coinbase %v, want %v", n.name, m.name, have, want)
			}
		}
		rewards = mined
	}
	return rewards
}

// reward returns the rewards of a coinbase, zero when it has none.
func reward(rewards map[common.Address]*uint256.Int, coinbase common.Address) *uint256.Int {
	if r := rewards[coinbase]; r != nil {
		return r
	}
	return new(uint256.Int)
}

// requireReorged checks that n's canonical chain no longer holds the old
// head and that its fork point with the old head is at forkAt.
func requireReorged(t *testing.T, n *miningNode, old *types.Header, forkAt uint64) {
	t.Helper()
	if n.chain.GetCanonicalHash(old.Number.Uint64()) == old.Hash() {
		t.Fatalf("node %s: old head %d is still canonical", n.name, old.Number)
	}
	// Walk the old branch down to the canonical chain.
	h := old
	for n.chain.GetCanonicalHash(h.Number.Uint64()) != h.Hash() {
		if h = n.chain.GetHeader(h.ParentHash, h.Number.Uint64()-1); h == nil {
			t.Fatalf("node %s: the old branch is missing a block", n.name)
		}
	}
	if h.Number.Uint64() != forkAt {
		t.Fatalf("node %s: the old branch leaves the canonical chain at %d, want %d", n.name, h.Number, forkAt)
	}
}

// memory returns the Go heap in use and the resident set of the process, in
// MiB. The RandomX caches are allocated outside the Go heap, so only the
// resident set includes them. The resident set is zero where /proc is
// missing.
func memory() (heap, rss, peakRSS float64) {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	heap = float64(ms.HeapAlloc) / (1 << 20)
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return heap, 0, 0
	}
	field := func(name string) float64 {
		for _, line := range strings.Split(string(status), "\n") {
			if rest, ok := strings.CutPrefix(line, name+":"); ok {
				kb, _ := strconv.ParseFloat(strings.TrimSuffix(strings.TrimSpace(rest), " kB"), 64)
				return kb / 1024
			}
		}
		return 0
	}
	return heap, field("VmRSS"), field("VmHWM")
}

// logResult logs one measurement in the form docs/mining-behaviour.md
// records.
func logResult(t *testing.T, format string, args ...any) {
	t.Helper()
	heap, rss, peak := memory()
	t.Logf("result: %s (Go heap %.0f MiB, RSS %.0f MiB, peak RSS %.0f MiB)", fmt.Sprintf(format, args...), heap, rss, peak)
}

// TestMiningDeepReorg splits four nodes into two partitions of two after a
// common prefix. Both partitions mine apart, the second further, and when
// the partitions rejoin the first reorganises across many RandomX keys onto
// the heavier chain: every node ends on the same head with the same state,
// coin tree and rewards, and the first partition's rewards are gone.
func TestMiningDeepReorg(t *testing.T) {
	const (
		prefix  = 6
		lighter = 24
		heavier = 40
	)
	start := time.Now()
	a1 := newMiningNode(t, "a1", 1, false)
	a2 := newMiningNode(t, "a2", 2, false)
	b1 := newMiningNode(t, "b1", 3, false)
	b2 := newMiningNode(t, "b2", 4, false)
	connect(a1, a2)
	connect(b1, b2)
	connect(a1, b1)

	// A common prefix, mined by a1, reaches every node over the network.
	a1.mine(prefix)
	a2.syncFrom(a1)
	b1.syncFrom(a1)
	b2.syncFrom(b1)
	requireAgreement(t, a1, a2, b1, b2)
	fork := a1.head()

	// Split, and mine apart.
	disconnect(a1, b1)
	mineStart := time.Now()
	mineInTurn(lighter, a1, a2)
	mineInTurn(heavier, b1, b2)
	mined := time.Since(mineStart)
	requireAgreement(t, a1, a2)
	requireAgreement(t, b1, b2)
	oldHead := a1.head()
	if a1.head().Hash() == b1.head().Hash() {
		t.Fatal("the partitions mined the same chain")
	}
	if a1.td().Cmp(b1.td()) >= 0 {
		t.Fatalf("partition a (td %v) is not lighter than partition b (td %v)", a1.td(), b1.td())
	}
	heaviest := b1.head()

	// Rejoin, dialled from the other side, and sync.
	healStart := time.Now()
	connect(b1, a1)
	a1.syncFrom(b1)
	a2.syncFrom(a1)
	healed := time.Since(healStart)

	rewards := requireAgreement(t, a1, a2, b1, b2)
	if a1.head().Hash() != heaviest.Hash() {
		t.Fatalf("the network ended on block %d, not on the heaviest head %d", a1.head().Number, heaviest.Number)
	}
	for _, n := range []*miningNode{a1, a2} {
		requireReorged(t, n, oldHead, fork.Number.Uint64())
	}
	// Only the prefix of a1's work survives; a2 mined only on the lost branch.
	params := miningParams()
	prefixReward := new(uint256.Int)
	for number := uint64(1); number <= prefix; number++ {
		prefixReward.Add(prefixReward, params.BlockReward(number))
	}
	if have := reward(rewards, a1.coinbase); have.Cmp(prefixReward) != 0 {
		t.Fatalf("a1's rewards after the reorg %v, want the prefix's %v", have, prefixReward)
	}
	if have := reward(rewards, a2.coinbase); !have.IsZero() {
		t.Fatalf("a2's rewards after the reorg %v, want none", have)
	}
	logResult(t, "deep reorg: %d-block common prefix, partitions mined %d and %d blocks in %v, rejoined and reorganised %d blocks deep in %v, total %v",
		prefix, lighter, heavier, mined.Round(time.Millisecond), lighter, healed.Round(time.Millisecond), time.Since(start).Round(time.Second))
}

// TestMiningSplitHeal splits three nodes into a majority of two holding
// three quarters of the hashrate and a minority of one holding a quarter.
// The partitions mine in rounds in proportion to their hashrate. When the
// network heals, the minority node drops its branch for the majority's,
// the majority's heads do not move, and the network then mines on one
// chain again.
func TestMiningSplitHeal(t *testing.T) {
	const (
		prefix   = 4
		rounds   = 10
		majority = 3 // blocks per round
		minority = 1
		after    = 4
	)
	start := time.Now()
	m1 := newMiningNode(t, "m1", 1, false)
	m2 := newMiningNode(t, "m2", 2, false)
	n1 := newMiningNode(t, "n1", 3, false)
	connect(m1, m2)
	connect(m1, n1)
	connect(m2, n1)

	// The minority node mines the common prefix, so its prefix rewards must
	// survive the heal.
	n1.mine(prefix)
	m1.syncFrom(n1)
	m2.syncFrom(m1)
	requireAgreement(t, m1, m2, n1)
	fork := n1.head()

	disconnect(m1, n1)
	disconnect(m2, n1)
	splitStart := time.Now()
	for round := 0; round < rounds; round++ {
		mineInTurn(majority, m1, m2)
		mineInTurn(minority, n1)
	}
	split := time.Since(splitStart)
	requireAgreement(t, m1, m2)
	minorityHead, majorityHead := n1.head(), m1.head()
	if minorityHead.Number.Uint64() != prefix+rounds*minority || majorityHead.Number.Uint64() != prefix+rounds*majority {
		t.Fatalf("heads at %d and %d after the split", minorityHead.Number, majorityHead.Number)
	}

	// Heal, dialled by the minority node.
	healStart := time.Now()
	connect(n1, m1)
	connect(n1, m2)
	n1.syncFrom(m1)
	healed := time.Since(healStart)
	rewards := requireAgreement(t, m1, m2, n1)
	if m1.head().Hash() != majorityHead.Hash() {
		t.Fatal("the majority's head moved when the network healed")
	}
	requireReorged(t, n1, minorityHead, fork.Number.Uint64())

	params := miningParams()
	prefixReward := new(uint256.Int)
	for number := uint64(1); number <= prefix; number++ {
		prefixReward.Add(prefixReward, params.BlockReward(number))
	}
	if have := reward(rewards, n1.coinbase); have.Cmp(prefixReward) != 0 {
		t.Fatalf("the minority's rewards after the heal %v, want the prefix's %v", have, prefixReward)
	}

	// The healed network mines on one chain: the minority node extends the
	// majority's chain and the majority follows.
	n1.mine(after)
	m1.syncFrom(n1)
	m2.syncFrom(n1)
	requireAgreement(t, m1, m2, n1)
	if n1.chain.GetCanonicalHash(majorityHead.Number.Uint64()) != majorityHead.Hash() {
		t.Fatal("the minority's new blocks are not on the majority's chain")
	}
	logResult(t, "split and heal: hashrate 3:1, %d rounds mined %d and %d blocks apart in %v, minority reorganised %d blocks deep in %v, total %v",
		rounds, rounds*majority, rounds*minority, split.Round(time.Millisecond), rounds*minority, healed.Round(time.Millisecond), time.Since(start).Round(time.Second))
}

// floodPeer is a minimal eth/68 peer: it answers the status handshake with
// the remote's own genesis and fork ID and a total difficulty of one, then,
// once started, writes the same messages over and over until the remote
// drops it or floodGiveUp passes. It reads and discards what it is sent.
type floodPeer struct {
	code     uint64
	payloads [][]byte

	ready chan struct{}    // closed after the handshake
	start chan struct{}    // closed by the test to begin the flood
	quit  chan struct{}    // closed when the test ends
	done  chan floodResult // the outcome, sent once
}

type floodResult struct {
	sent    int           // messages written before the flood ended
	err     error         // the write error that ended it, nil if it gave up
	elapsed time.Duration // from the first message to the end
}

func newFloodPeer(code uint64, payloads [][]byte) *floodPeer {
	return &floodPeer{
		code:     code,
		payloads: payloads,
		ready:    make(chan struct{}),
		start:    make(chan struct{}),
		quit:     make(chan struct{}),
		done:     make(chan floodResult, 1),
	}
}

func (f *floodPeer) protocol() p2p.Protocol {
	// 17 is the eth/68 message count the eth package registers.
	return p2p.Protocol{Name: eth.ProtocolName, Version: eth.ETH68, Length: 17, Run: f.run}
}

func (f *floodPeer) run(peer *p2p.Peer, rw p2p.MsgReadWriter) error {
	msg, err := rw.ReadMsg()
	if err != nil {
		f.done <- floodResult{err: fmt.Errorf("handshake: %w", err)}
		return err
	}
	var status eth.StatusPacket
	err = msg.Decode(&status)
	msg.Discard()
	if err != nil {
		f.done <- floodResult{err: fmt.Errorf("handshake: %w", err)}
		return err
	}
	if err := p2p.Send(rw, eth.StatusMsg, &eth.StatusPacket{
		ProtocolVersion: status.ProtocolVersion,
		NetworkID:       status.NetworkID,
		TD:              big.NewInt(1),
		Head:            status.Genesis,
		Genesis:         status.Genesis,
		ForkID:          status.ForkID,
	}); err != nil {
		f.done <- floodResult{err: fmt.Errorf("handshake: %w", err)}
		return err
	}
	go func() {
		for {
			msg, err := rw.ReadMsg()
			if err != nil {
				return
			}
			msg.Discard()
		}
	}()
	close(f.ready)
	select {
	case <-f.start:
	case <-f.quit:
		return nil
	}
	begin := time.Now()
	for i := 0; ; i++ {
		if time.Since(begin) > floodGiveUp {
			f.done <- floodResult{sent: i, elapsed: time.Since(begin)}
			return nil
		}
		payload := f.payloads[i%len(f.payloads)]
		if err := rw.WriteMsg(p2p.Msg{Code: f.code, Size: uint32(len(payload)), Payload: bytes.NewReader(payload)}); err != nil {
			f.done <- floodResult{sent: i, err: err, elapsed: time.Since(begin)}
			return err
		}
	}
}

// rpcProbe calls eth_blockNumber on a node in a loop and records the
// slowest answer.
type rpcProbe struct {
	client *rpc.Client
	stop   chan struct{}
	done   chan struct{}

	calls   int
	slowest time.Duration
	err     error
	last    uint64
}

func startRPCProbe(client *rpc.Client) *rpcProbe {
	p := &rpcProbe{client: client, stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(p.done)
		for {
			begin := time.Now()
			var number hexutil.Uint64
			if err := p.client.Call(&number, "eth_blockNumber"); err != nil && p.err == nil {
				p.err = err
			}
			p.calls++
			p.last = uint64(number)
			p.slowest = max(p.slowest, time.Since(begin))
			select {
			case <-p.stop:
				return
			case <-time.After(floodRPCInterval):
			}
		}
	}()
	return p
}

func (p *rpcProbe) finish() {
	close(p.stop)
	<-p.done
}

// heapWatch samples the Go heap in a loop and records the peak.
type heapWatch struct {
	stop chan struct{}
	done chan struct{}
	peak uint64
}

func startHeapWatch() *heapWatch {
	w := &heapWatch{stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(w.done)
		var ms runtime.MemStats
		for {
			runtime.ReadMemStats(&ms)
			w.peak = max(w.peak, ms.HeapAlloc)
			select {
			case <-w.stop:
				return
			case <-time.After(5 * time.Millisecond):
			}
		}
	}()
	return w
}

func (w *heapWatch) finish() uint64 {
	close(w.stop)
	<-w.done
	return w.peak
}

func liveHeap() uint64 {
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapAlloc
}

func mustRLP(t *testing.T, v any) []byte {
	t.Helper()
	b, err := rlp.EncodeToBytes(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestMiningHeaderFlood connects peers that flood a mining node with
// invalid or low-work headers: unsolicited header responses carrying a
// thousand low-work headers each, blocks on the node's head below the
// required difficulty, and blocks on the head with the right difficulty
// and a nonce that fails the RandomX seal. For each flood the node must
// drop the flooding peer within floodDropBound, keep its heap within
// floodPeakCap during the flood and floodRetainedCap after it, answer
// eth_blockNumber within floodRPCBound throughout, keep its head and its
// honest peer, and afterwards still sync a new block from that peer.
func TestMiningHeaderFlood(t *testing.T) {
	const prefix = 8
	target := newMiningNode(t, "target", 1, false)
	honest := newMiningNode(t, "honest", 2, false)
	connect(honest, target)
	honest.mine(prefix)
	target.syncFrom(honest)

	server := rpc.NewServer()
	t.Cleanup(server.Stop)
	backend := &EthAPIBackend{eth: &Ethereum{blockchain: target.chain, handler: target.handler}}
	if err := server.RegisterName("eth", ethapi.NewBlockChainAPI(backend)); err != nil {
		t.Fatal(err)
	}
	client := rpc.DialInProc(server)
	t.Cleanup(client.Close)

	head := target.head()
	headTD := target.td()
	config := target.chain.Config()

	// A thousand low-work headers, unsolicited: no request asked for them.
	lowWork := make([]*types.Header, 1024)
	for i := range lowWork {
		h := types.CopyHeader(head)
		h.ParentHash = common.Hash{0xf1, byte(i >> 8), byte(i)}
		h.Number = new(big.Int).SetUint64(head.Number.Uint64() + 1 + uint64(i))
		h.Time = head.Time + mbBlockTime*uint64(i+1)
		h.Difficulty = big.NewInt(1)
		lowWork[i] = h
	}
	unsolicited := mustRLP(t, &struct {
		RequestId uint64
		Headers   []*types.Header
	}{RequestId: 0xf100d, Headers: lowWork})

	// A block on the head with every field right but the seal, with the
	// given difficulty and nonce, and an extra field that makes it unique.
	onHead := func(difficulty int64, nonce uint64, extra int) *types.Block {
		h := &types.Header{
			ParentHash:     head.Hash(),
			Coinbase:       common.Address{0xf1},
			Number:         new(big.Int).Add(head.Number, common.Big1),
			GasLimit:       head.GasLimit,
			Time:           head.Time + mbBlockTime,
			Extra:          []byte(fmt.Sprintf("flood %d", extra)),
			BaseFee:        eip1559.CalcBaseFee(config, head),
			Difficulty:     big.NewInt(difficulty),
			Nonce:          types.EncodeNonce(nonce),
			Root:           head.Root,
			CoinTreeRoot:   head.CoinTreeRoot,
			DataTreeRoot:   head.DataTreeRoot,
			DataMarkerRoot: head.DataMarkerRoot,
		}
		return types.NewBlock(h, nil, nil, nil, trie.NewStackTrie(nil))
	}
	var lowDifficulty [][]byte
	for i := 0; i < 256; i++ {
		block := onHead(1, 0, i)
		if err := target.rx.VerifyHeader(target.chain, block.Header(), false); err == nil || !strings.Contains(err.Error(), "invalid difficulty") {
			t.Fatalf("low-difficulty flood block: verification %v, want an invalid difficulty", err)
		}
		lowDifficulty = append(lowDifficulty, mustRLP(t, &eth.NewBlockPacket{Block: block, TD: headTD}))
	}
	// Blocks valid but for the seal: the header passes every check without
	// the seal and fails the RandomX check with it.
	var badSeal [][]byte
	for nonce := uint64(0); len(badSeal) < 32; nonce++ {
		block := onHead(mbDifficulty, nonce, len(badSeal))
		if err := target.rx.VerifyHeader(target.chain, block.Header(), false); err != nil {
			t.Fatalf("bad-seal flood block fails before the seal: %v", err)
		}
		err := target.rx.VerifyHeader(target.chain, block.Header(), true)
		if err == nil {
			continue // this nonce happens to seal the block
		}
		if !strings.Contains(err.Error(), "invalid proof-of-work") {
			t.Fatalf("bad-seal flood block: verification %v, want an invalid proof-of-work", err)
		}
		badSeal = append(badSeal, mustRLP(t, &eth.NewBlockPacket{Block: block, TD: headTD}))
	}

	floods := []struct {
		name     string
		code     uint64
		payloads [][]byte
	}{
		{"unsolicited low-work headers", eth.BlockHeadersMsg, [][]byte{unsolicited}},
		{"blocks below the difficulty", eth.NewBlockMsg, lowDifficulty},
		{"blocks with a bad seal", eth.NewBlockMsg, badSeal},
	}
	for _, flood := range floods {
		t.Run(flood.name, func(t *testing.T) {
			f := newFloodPeer(flood.code, flood.payloads)
			srv, id := startMiningServer(t, "flood", []p2p.Protocol{f.protocol()})
			t.Cleanup(func() { close(f.quit) })
			srv.AddPeer(target.srv.Self())

			select {
			case <-f.ready:
			case res := <-f.done:
				t.Fatalf("flood peer did not connect: %v", res.err)
			case <-time.After(mbLinkTimeout):
				t.Fatal("flood peer did not connect")
			}
			deadline := time.Now().Add(mbLinkTimeout)
			for target.handler.peers.peer(id) == nil {
				if time.Now().After(deadline) {
					t.Fatal("the target did not register the flood peer")
				}
				time.Sleep(10 * time.Millisecond)
			}

			baseline := liveHeap()
			watch := startHeapWatch()
			probe := startRPCProbe(client)
			close(f.start)

			var res floodResult
			select {
			case res = <-f.done:
			case <-time.After(floodGiveUp + mbLinkTimeout):
				t.Fatal("the flood peer neither finished nor was dropped")
			}
			deadline = time.Now().Add(floodDropBound)
			for target.handler.peers.peer(id) != nil {
				if time.Now().After(deadline) {
					t.Fatal("the target still holds the flood peer")
				}
				time.Sleep(10 * time.Millisecond)
			}
			// Keep calling while the node tears the connection down.
			time.Sleep(floodRPCSettle)
			probe.finish()
			peak := watch.finish()
			retained := int64(liveHeap()) - int64(baseline)

			if res.err == nil {
				t.Fatalf("the flood peer was not dropped: it wrote %d messages in %v", res.sent, res.elapsed)
			}
			if res.elapsed > floodDropBound {
				t.Fatalf("the flood peer was dropped after %v, bound %v", res.elapsed, floodDropBound)
			}
			if growth := int64(peak) - int64(baseline); growth > floodPeakCap {
				t.Fatalf("heap grew by %d MiB during the flood, cap %d MiB", growth>>20, floodPeakCap>>20)
			}
			if retained > floodRetainedCap {
				t.Fatalf("the flood left %d MiB on the heap, cap %d MiB", retained>>20, floodRetainedCap>>20)
			}
			if probe.err != nil {
				t.Fatalf("eth_blockNumber failed during the flood: %v", probe.err)
			}
			if probe.slowest > floodRPCBound {
				t.Fatalf("eth_blockNumber took %v during the flood, bound %v", probe.slowest, floodRPCBound)
			}
			if probe.last != head.Number.Uint64() || target.head().Hash() != head.Hash() {
				t.Fatalf("the target's head moved during the flood to block %d", target.head().Number)
			}
			if target.handler.peers.peer(honest.id) == nil {
				t.Fatal("the target dropped its honest peer")
			}
			logResult(t, "header flood, %s: dropped after %d messages in %v, peak heap growth %.1f MiB, retained %.1f MiB, %d eth_blockNumber calls, slowest %v",
				flood.name, res.sent, res.elapsed.Round(time.Microsecond), float64(int64(peak)-int64(baseline))/(1<<20), float64(retained)/(1<<20), probe.calls, probe.slowest.Round(time.Microsecond))
		})
	}

	// The node still follows its honest peer.
	honest.mine(1)
	target.syncFrom(honest)
	requireAgreement(t, target, honest)
}

// TestMiningFullSealSync mines a chain across many RandomX keys on one node
// and syncs it over the eth protocol to a fresh node whose engine records
// every seal it checks. Every block of the synced chain must have had its
// RandomX seal checked and accepted on the fresh node, and that node's
// engine must refuse the head with any nonce that does not seal it.
func TestMiningFullSealSync(t *testing.T) {
	if testing.Short() {
		t.Skip("mines and verifies a chain with RandomX")
	}
	const blocks = 160 // 20 RandomX keys at the test key interval
	source := newMiningNode(t, "source", 1, false)
	fresh := newMiningNode(t, "fresh", 2, true)

	mineStart := time.Now()
	source.mine(blocks)
	mined := time.Since(mineStart)
	logResult(t, "full-seal sync: mined %d blocks in %v (%v a block)", blocks, mined.Round(time.Millisecond), (mined / blocks).Round(time.Millisecond))

	heapBefore, _, _ := memory()
	connect(fresh, source)
	syncStart := time.Now()
	fresh.syncFrom(source)
	synced := time.Since(syncStart)
	requireAgreement(t, source, fresh)

	for number := uint64(1); number <= blocks; number++ {
		hash := fresh.chain.GetCanonicalHash(number)
		if fresh.audit.checked(hash) == 0 {
			t.Fatalf("the fresh node imported block %d without checking its RandomX seal", number)
		}
	}
	// The seal check is a real one: the head with another nonce fails it.
	tip := types.CopyHeader(fresh.head())
	parent := fresh.chain.GetHeaderByHash(tip.ParentHash)
	refused := 0
	for nonce := tip.Nonce.Uint64() + 1; refused < 4; nonce++ {
		tip.Nonce = types.EncodeNonce(nonce)
		if err := fresh.rx.VerifyHeader(fresh.chain, tip, false); err != nil {
			t.Fatalf("the head with nonce %d fails before the seal (parent %d): %v", nonce, parent.Number, err)
		}
		if err := fresh.rx.VerifyHeader(fresh.chain, tip, true); err != nil {
			if !strings.Contains(err.Error(), "invalid proof-of-work") {
				t.Fatalf("the head with nonce %d: %v, want an invalid proof-of-work", nonce, err)
			}
			refused++
		}
	}
	heapAfter, _, _ := memory()
	logResult(t, "full-seal sync: fresh node synced and verified %d seals in %v (%v a block), Go heap %.0f to %.0f MiB",
		blocks, synced.Round(time.Millisecond), (synced / blocks).Round(time.Millisecond), heapBefore, heapAfter)
}
