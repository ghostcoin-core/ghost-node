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

package ghostpriv_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghostpriv/ghostprivtest"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
	"github.com/holiman/uint256"
)

var stub = ghostprivtest.Verifier{}

// scenario is a chain whose block 1 commits one GHOST from account A, with
// empty blocks after it, all imported.
type scenario struct {
	f      *fixture
	chain  *core.BlockChain
	blocks []*types.Block
	c      coin
}

func newScenario(t *testing.T, n int) *scenario {
	t.Helper()
	f := newFixture(t, ghost.InternalNetGasLimit, nil)
	c := testCoin("scenario", oneGhost)
	blocks, _ := f.generate(n, func(i int, b *core.BlockGen) {
		if i == 0 {
			b.AddTx(f.commitTx(keyA, 0, c))
		}
	})
	chain := f.newChain()
	f.insert(chain, blocks)
	return &scenario{f: f, chain: chain, blocks: blocks, c: c}
}

// root is the coin root of block 1, which holds the coin.
func (s *scenario) root() common.Hash { return *s.blocks[0].Header().CoinTreeRoot }

// reveal is a reveal of the scenario's coin in the block of env with the
// given marker, out and fee, the rest going to the remainder.
func (s *scenario) reveal(t *testing.T, marker string, out, fee *uint256.Int) *ghostpriv.Reveal {
	t.Helper()
	rest := new(uint256.Int)
	if spent := new(uint256.Int).Add(out, fee); !spent.Gt(s.c.value) {
		rest.Sub(s.c.value, spent)
	}
	return s.f.newReveal(s.root(), testMarker(marker), testCoin("rest of "+marker, rest.ToBig()), addrB, out, fee)
}

func clone(r *ghostpriv.Reveal) *ghostpriv.Reveal {
	cp := *r
	cp.Out = new(uint256.Int).Set(r.Out)
	cp.Fee = new(uint256.Int).Set(r.Fee)
	cp.Proof = common.CopyBytes(r.Proof)
	return &cp
}

// revealLog is the receipt log a reveal writes.
func revealLog(index, position uint32, remainder coin, recipient common.Address, out *uint256.Int) []byte {
	leaf := remainder.commitment()
	word := out.Bytes32()
	data := binary.BigEndian.AppendUint32(nil, index)
	data = binary.BigEndian.AppendUint32(data, position)
	data = append(data, leaf[:]...)
	data = append(data, remainder.note...)
	data = append(data, recipient[:]...)
	return append(data, word[:]...)
}

// TestRevealMintsAndAppendsRemainder runs a commit and two reveals end to
// end on the internal network: the second reveal spends the first one's
// remainder and pays a contract, which is credited without running its
// code. It checks the minted balances, the tips, the burned base parts, the
// spent markers, the coin tree and its header root, the receipts and the
// totals.
func TestRevealMintsAndAppendsRemainder(t *testing.T) {
	useStub(t)
	trap := common.Address{0x7a, 0x9}
	f := newFixture(t, ghost.InternalNetGasLimit, genesisT.GenesisAlloc{
		trap: {Code: []byte{0xfe}, Balance: new(big.Int)}, // INVALID: any run of it fails
	})
	var (
		minerA, minerB = common.Address{0xcb, 1}, common.Address{0xcb, 2}
		recipient      = common.Address{0x9e, 0xc1}
		c              = testCoin("mint", oneGhost)
		markers        = []common.Hash{testMarker("mint one"), testMarker("mint two")}
		outs           = []*uint256.Int{u256(ghostAmount(3, 10)), u256(ghostAmount(1, 10))}
		fees           []ghostpriv.Fee
		rests          []coin
		txs            []*types.Transaction
	)
	blocks, _ := f.generate(6, func(i int, b *core.BlockGen) {
		switch i {
		case 0:
			b.AddTx(f.commitTx(keyA, 0, c))
		case 4, 5:
			k := i - 4
			b.SetCoinbase([]common.Address{minerA, minerB}[k])
			fee := genWindowFee(t, b)
			spend := c.value
			if k == 1 {
				spend = rests[0].value
			}
			rest := new(uint256.Int).Sub(spend, outs[k])
			rest.Sub(rest, fee.Total)
			rc := testCoin([]string{"mint rest one", "mint rest two"}[k], rest.ToBig())
			to := []common.Address{recipient, trap}[k]
			tx := revealTx(t, f.newReveal(genParentRoot(b), markers[k], rc, to, outs[k], fee.Total))
			b.AddTx(tx)
			fees, rests, txs = append(fees, fee), append(rests, rc), append(txs, tx)
		}
	})
	chain := f.newChain()
	f.insert(chain, blocks)
	st, err := chain.StateAt(blocks[5].Root())
	if err != nil {
		t.Fatal(err)
	}

	// Minted by plain credit, to an account and to a contract whose code
	// would fail if it ran.
	if got := st.GetBalance(recipient); !got.Eq(outs[0]) {
		t.Errorf("recipient %v, want %v", got, outs[0])
	}
	if got := st.GetBalance(trap); !got.Eq(outs[1]) {
		t.Errorf("contract recipient %v, want %v", got, outs[1])
	}
	if !bytes.Equal(st.GetCode(trap), []byte{0xfe}) || st.GetNonce(recipient) != 0 {
		t.Error("a reveal changed a recipient's code or nonce")
	}
	// The tips went to the coinbases; the base parts to nobody.
	for k, miner := range []common.Address{minerA, minerB} {
		height := blocks[4+k].NumberU64()
		want := new(uint256.Int).Add(f.engine.params.BlockReward(height), fees[k].Tip)
		if got := st.GetBalance(miner); !got.Eq(want) {
			t.Errorf("coinbase %d: %v, want reward and tip %v", k, got, want)
		}
		if want := new(uint256.Int).Add(fees[k].BasePart, fees[k].Tip); !want.Eq(fees[k].Total) {
			t.Errorf("fee %d does not split into base part and tip", k)
		}
	}
	// The markers are spent.
	for k, m := range markers {
		if !ghosttree.IsSpent(st, ghosttree.Coin, m) {
			t.Errorf("marker %d not spent", k)
		}
	}
	// The tree holds the commitment and both remainders, under the root.
	leaves := []common.Hash{c.commitment(), rests[0].commitment(), rests[1].commitment()}
	if n := coinLeafCount(st); n != 3 {
		t.Fatalf("coin tree has %d leaves", n)
	}
	wantRoot := ghosttree.RootFromPageRoots(ghosttree.Coin, []common.Hash{ghosttree.PageRoot(ghosttree.Coin, leaves)})
	if got := *blocks[5].Header().CoinTreeRoot; got != wantRoot {
		t.Fatalf("header coin root %x, want %x", got, wantRoot)
	}
	// Totals: one GHOST in; both outs and fees out; the last remainder is
	// what stays hidden.
	in, out := totals(st)
	wantOut := new(uint256.Int).Add(outs[0], outs[1])
	wantOut.Add(wantOut, fees[0].Total)
	wantOut.Add(wantOut, fees[1].Total)
	if in.Cmp(oneGhost) != 0 || out.Cmp(wantOut.ToBig()) != 0 {
		t.Errorf("totals in %v out %v, want %v and %v", in, out, oneGhost, wantOut)
	}
	if hidden, err := ghostpriv.Hidden(st); err != nil || !hidden.Eq(rests[1].value) {
		t.Errorf("hidden %v (%v), want %v", hidden, err, rests[1].value)
	}
	// Receipts: typed 0x50, status 1, exactly G_PRIV gas, one log.
	for k := range markers {
		block := blocks[4+k]
		if block.GasUsed() != ghostpriv.GasPriv {
			t.Errorf("block %d gas used %d", block.NumberU64(), block.GasUsed())
		}
		stored := chain.GetBlockByNumber(block.NumberU64()).Transactions()
		if len(stored) != 1 || stored[0].Hash() != txs[k].Hash() || stored[0].Type() != types.GhostRevealTxType {
			t.Fatalf("block %d does not carry the reveal", block.NumberU64())
		}
		if _, err := types.Sender(f.signer, stored[0]); !errors.Is(err, types.ErrNoSender) {
			t.Errorf("reveal %d has a sender: %v", k, err)
		}
		rs := chain.GetReceiptsByHash(block.Hash())
		r := rs[0]
		if r.Type != types.GhostRevealTxType || r.Status != types.ReceiptStatusSuccessful || r.GasUsed != ghostpriv.GasPriv || r.CumulativeGasUsed != ghostpriv.GasPriv || r.TxHash != txs[k].Hash() {
			t.Errorf("receipt %d: %+v", k, r)
		}
		if len(r.Logs) != 1 {
			t.Fatalf("receipt %d has %d logs", k, len(r.Logs))
		}
		l := r.Logs[0]
		if l.Address != ghosttree.TreeAccount(ghosttree.Coin) || len(l.Topics) != 2 || l.Topics[0] != ghosttree.K("ghost/reveal-receipt/v1") || l.Topics[1] != markers[k] {
			t.Errorf("log %d: address %x topics %x", k, l.Address, l.Topics)
		}
		to := []common.Address{recipient, trap}[k]
		position := uint32(k) + 1 // the commitment is at 0
		if want := revealLog(0, position, rests[k], to, outs[k]); !bytes.Equal(l.Data, want) {
			t.Errorf("log %d data\n%x\nwant\n%x", k, l.Data, want)
		}
		if len(l.Data) != 4+4+32+156+20+32 {
			t.Errorf("log %d data has %d bytes", k, len(l.Data))
		}
	}
}

// TestRevealCheckOrder gives the block after a commit a reveal that fails
// each check in turn, and where it can a later one too, and checks that the
// first failing check is the one reported; a reveal that passes every check
// up to the tree and then finds it full changes nothing.
func TestRevealCheckOrder(t *testing.T) {
	useStub(t)
	s := newScenario(t, 5)
	miner := common.Address{0xcb}
	env, st := nextEnv(t, s.chain, s.blocks[4].Header(), miner) // block 6, window from block 4
	fee := chainWindowFee(t, s.chain, env.Header).Total
	base := s.reveal(t, "order", u256(ghostAmount(1, 2)), fee)
	hidden, err := ghostpriv.Hidden(st)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ghostpriv.CheckReveal(st.Copy(), env, stub, envelope(t, base)); err != nil {
		t.Fatalf("the base reveal is rejected: %v", err)
	}
	one := uint256.NewInt(1)
	edit := func(change func(e []byte) []byte) []byte { return change(envelope(t, base)) }
	with := func(change func(r *ghostpriv.Reveal)) []byte {
		r := clone(base)
		change(r)
		return envelope(t, r)
	}
	spend := func(st *state.StateDB) {
		if err := ghosttree.MarkSpent(st, ghosttree.Coin, base.Marker); err != nil {
			t.Fatal(err)
		}
	}
	fill := func(st *state.StateDB) { fillCoinTree(st, env.Header.Number.Uint64()) }
	otherGenesis := ghostprivtest.Proof(base.BindingDigest(s.f.chainID, common.Hash{3}))
	otherChain := ghostprivtest.Proof(base.BindingDigest(s.f.chainID+1, s.f.genesis.Hash()))
	tests := []struct {
		name string
		env  []byte
		prep func(*state.StateDB)
		want error
	}{
		{"1: short, version 2", edit(func(e []byte) []byte { e[2] = 2; return e[:len(e)-1] }), nil, ghostpriv.ErrRevealLength},
		{"1: long", edit(func(e []byte) []byte { return append(e, 0) }), nil, ghostpriv.ErrRevealLength},
		{"1: type 0x02", edit(func(e []byte) []byte { e[0] = types.DynamicFeeTxType; return e }), nil, ghostpriv.ErrRevealLength},
		{"2: version 2, out not below 2^96", edit(func(e []byte) []byte { e[2] = 2; e[1+126] = 1; return e }), nil, ghostpriv.ErrRevealVersion},
		{"2: version 0", edit(func(e []byte) []byte { e[2] = 0; return e }), nil, ghostpriv.ErrRevealVersion},
		{"3: out not below 2^96, wrong chain", edit(func(e []byte) []byte { e[1+126+19] = 1; e[1+9] ^= 1; return e }), nil, ghostpriv.ErrRevealAmount},
		{"3: fee not below 2^96", edit(func(e []byte) []byte { e[1+158] = 1; return e }), nil, ghostpriv.ErrRevealAmount},
		{"4: wrong chain, wrong fee", with(func(r *ghostpriv.Reveal) { r.ChainID++; r.Fee.Add(r.Fee, one) }), nil, ghostpriv.ErrRevealChainID},
		{"5: fee one wei high, unknown root", with(func(r *ghostpriv.Reveal) { r.Fee.Add(r.Fee, one); r.Root = common.Hash{1} }), nil, ghostpriv.ErrRevealFee},
		{"5: fee one wei low", with(func(r *ghostpriv.Reveal) { r.Fee.Sub(r.Fee, one); s.f.prove(r) }), nil, ghostpriv.ErrRevealFee},
		{"7: unknown root, marker spent", with(func(r *ghostpriv.Reveal) { r.Root = common.Hash{1}; s.f.prove(r) }), spend, ghostpriv.ErrRevealRoot},
		{"8: marker spent, overdraw", with(func(r *ghostpriv.Reveal) { r.Out = new(uint256.Int).Set(hidden); s.f.prove(r) }), spend, ghostpriv.ErrRevealMarker},
		{"9: overdraw, stale proof", with(func(r *ghostpriv.Reveal) { r.Out = new(uint256.Int).Sub(hidden, r.Fee); r.Out.Add(r.Out, one) }), nil, ghostpriv.ErrRevealBackstop},
		{"10: proof of another digest, full tree", with(func(r *ghostpriv.Reveal) { r.Proof = ghostprivtest.Proof(common.Hash{2}) }), fill, ghostpriv.ErrRevealProof},
		{"10: proof bound to another genesis", with(func(r *ghostpriv.Reveal) { r.Proof = otherGenesis }), nil, ghostpriv.ErrRevealProof},
		{"10: proof bound to another chain id", with(func(r *ghostpriv.Reveal) { r.Proof = otherChain }), nil, ghostpriv.ErrRevealProof},
		{"10: no proof", with(func(r *ghostpriv.Reveal) { r.Proof = nil }), nil, ghostpriv.ErrRevealProof},
		{"12: full tree", envelope(t, base), fill, ghostpriv.ErrRevealTree},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cp := st.Copy()
			if tt.prep != nil {
				tt.prep(cp)
			}
			before := snapshotReveal(cp, miner)
			err := ghostpriv.ApplyReveal(cp, env, stub, tt.env)
			if !errors.Is(err, tt.want) {
				t.Fatalf("error %v, want %v", err, tt.want)
			}
			if tt.want == ghostpriv.ErrRevealTree && !errors.Is(err, ghosttree.ErrFillingBlock) {
				t.Fatalf("full tree: %v, want %v", err, ghosttree.ErrFillingBlock)
			}
			if after := snapshotReveal(cp, miner); after != before {
				t.Fatalf("a rejected reveal changed the state:\n%+v\n%+v", before, after)
			}
		})
	}

	// The base reveal applies.
	cp := st.Copy()
	if err := ghostpriv.ApplyReveal(cp, env, stub, envelope(t, base)); err != nil {
		t.Fatal(err)
	}
	if after := snapshotReveal(cp, miner); after == snapshotReveal(st, miner) {
		t.Fatal("the base reveal changed nothing")
	}
}

// revealSnapshot is what a reveal changes.
type revealSnapshot struct {
	spent              bool
	in, out            string
	recipient, miner   string
	leaves             uint64
	totalsNonce, logNo int
}

func snapshotReveal(st *state.StateDB, miner common.Address) revealSnapshot {
	in, out := totals(st)
	return revealSnapshot{
		spent:       ghosttree.IsSpent(st, ghosttree.Coin, testMarker("order")),
		in:          in.String(),
		out:         out.String(),
		recipient:   st.GetBalance(addrB).String(),
		miner:       st.GetBalance(miner).String(),
		leaves:      coinLeafCount(st),
		totalsNonce: int(st.GetNonce(ghost.PrivTotalsAccount)),
		logNo:       len(st.Logs()),
	}
}

// TestSecondRevealRejected reveals a coin and then tries the same marker
// again in a later block, with another remainder, recipient and a proof
// valid for its own fields: the check and the block are rejected.
func TestSecondRevealRejected(t *testing.T) {
	useStub(t)
	f := newFixture(t, ghost.InternalNetGasLimit, nil)
	var (
		c      = testCoin("second", oneGhost)
		marker = testMarker("second")
		again  *types.Transaction
	)
	gen := func(i int, b *core.BlockGen) {
		switch i {
		case 0:
			b.AddTx(f.commitTx(keyA, 0, c))
		case 4:
			fee := genWindowFee(t, b).Total
			out := u256(ghostAmount(1, 4))
			rest := new(uint256.Int).Sub(c.value, out)
			rest.Sub(rest, fee)
			b.AddTx(revealTx(t, f.newReveal(genParentRoot(b), marker, testCoin("second rest", rest.ToBig()), addrB, out, fee)))
		case 6:
			b.AddUncheckedTx(again)
		}
	}
	blocks, _ := f.generate(6, gen)
	chain := f.newChain()
	f.insert(chain, blocks)

	env, st := nextEnv(t, chain, blocks[5].Header(), common.Address{0xcb})
	fee := chainWindowFee(t, chain, env.Header).Total
	r := f.newReveal(*blocks[0].Header().CoinTreeRoot, marker, testCoin("second rest again", big.NewInt(1)), addrC, uint256.NewInt(1), fee)
	if _, _, err := ghostpriv.CheckReveal(st.Copy(), env, stub, envelope(t, r)); !errors.Is(err, ghostpriv.ErrRevealMarker) {
		t.Fatalf("second reveal: %v, want %v", err, ghostpriv.ErrRevealMarker)
	}
	// With a fresh marker the same reveal would pass: the marker is the
	// reason.
	fresh := clone(r)
	fresh.Marker = testMarker("second, fresh")
	f.prove(fresh)
	if _, _, err := ghostpriv.CheckReveal(st.Copy(), env, stub, envelope(t, fresh)); err != nil {
		t.Fatalf("control reveal: %v", err)
	}

	// A block carrying the second reveal is invalid.
	again = revealTx(t, r)
	longer, _ := f.generate(7, gen)
	if longer[5].Hash() != blocks[5].Hash() {
		t.Fatal("the chain did not rebuild identically")
	}
	if _, err := chain.InsertChain(longer[6:]); !errors.Is(err, ghostpriv.ErrRevealMarker) {
		t.Fatalf("block with the second reveal: %v, want %v", err, ghostpriv.ErrRevealMarker)
	}
	if chain.CurrentBlock().Hash() != blocks[5].Hash() {
		t.Fatal("the head moved")
	}
	head, err := chain.State()
	if err != nil {
		t.Fatal(err)
	}
	if head.GetBalance(addrC).ToBig().Cmp(startBal) != 0 {
		t.Fatal("the second reveal paid out")
	}
}

// TestBlockWithTwoRevealsOfOneMarkerIsInvalid puts two reveals of one marker
// into one block, with enough gas and hidden value for both: the block is
// rejected and nothing of it stays. The same block with two markers imports.
func TestBlockWithTwoRevealsOfOneMarkerIsInvalid(t *testing.T) {
	useStub(t)
	f := newFixture(t, 40_000_000, nil)
	var (
		c1, c2         = testCoin("twice one", oneGhost), testCoin("twice two", oneGhost)
		marker         = testMarker("twice")
		out            = u256(ghostAmount(1, 4))
		toOne, toOther = common.Address{0x9e, 1}, common.Address{0x9e, 2}
	)
	build := func(secondMarker common.Hash, unchecked bool) []*types.Block {
		blocks, _ := f.generate(5, func(i int, b *core.BlockGen) {
			switch i {
			case 0:
				b.AddTx(f.commitTx(keyA, 0, c1))
				b.AddTx(f.commitTx(keyB, 0, c2))
			case 4:
				fee := genWindowFee(t, b).Total
				rest := new(uint256.Int).Sub(c1.value, out)
				rest.Sub(rest, fee)
				root := genParentRoot(b)
				first := revealTx(t, f.newReveal(root, marker, testCoin("twice rest one", rest.ToBig()), toOne, out, fee))
				second := revealTx(t, f.newReveal(root, secondMarker, testCoin("twice rest two", rest.ToBig()), toOther, out, fee))
				b.AddTx(first)
				if unchecked {
					b.AddUncheckedTx(second)
				} else {
					b.AddTx(second)
				}
			}
		})
		return blocks
	}
	bad := build(marker, true)
	chain := f.newChain()
	f.insert(chain, bad[:4])
	if len(bad[4].Transactions()) != 2 {
		t.Fatal("the block does not carry both reveals")
	}
	if _, err := chain.InsertChain(bad[4:]); !errors.Is(err, ghostpriv.ErrRevealMarker) {
		t.Fatalf("block with two reveals of one marker: %v, want %v", err, ghostpriv.ErrRevealMarker)
	}
	if chain.CurrentBlock().Hash() != bad[3].Hash() {
		t.Fatal("the head moved")
	}
	st, err := chain.State()
	if err != nil {
		t.Fatal(err)
	}
	if ghosttree.IsSpent(st, ghosttree.Coin, marker) || !st.GetBalance(toOne).IsZero() || !st.GetBalance(toOther).IsZero() {
		t.Fatal("something of the invalid block stayed")
	}
	if _, totalOut := totals(st); totalOut.Sign() != 0 {
		t.Fatalf("total out %v after the invalid block", totalOut)
	}

	// Two markers in one block: valid, two reveals' gas.
	good := build(testMarker("twice, other"), false)
	if good[3].Hash() != bad[3].Hash() {
		t.Fatal("the chain did not rebuild identically")
	}
	f.insert(chain, good[4:])
	if chain.CurrentBlock().Hash() != good[4].Hash() || good[4].GasUsed() != 2*ghostpriv.GasPriv {
		t.Fatal("the block with two markers was not imported")
	}
}

// TestDefaultVerifierRejectsEveryReveal checks that the verifier a node runs
// with until a real one is linked rejects every proof, the stub's included,
// and that a chain built with the stub cannot be imported by such a node.
func TestDefaultVerifierRejectsEveryReveal(t *testing.T) {
	useDefault(t)
	def := ghostpriv.DefaultVerifier()
	in := &ghostpriv.VerifyInputs{Binding: common.Hash{1}, Out: new(uint256.Int), Fee: new(uint256.Int)}
	for name, proof := range map[string][]byte{
		"stub proof": ghostprivtest.Proof(in.Binding),
		"zero proof": make([]byte, ghostpriv.ProofSize),
		"empty":      nil,
	} {
		if err := def.VerifyReveal(in, proof); !errors.Is(err, ghostpriv.ErrNoVerifier) {
			t.Errorf("%s: %v", name, err)
		}
		if err := def.VerifyReveal(nil, proof); !errors.Is(err, ghostpriv.ErrNoVerifier) {
			t.Errorf("%s without inputs: %v", name, err)
		}
		if err := ghostpriv.ActiveVerifier().VerifyReveal(in, proof); !errors.Is(err, ghostpriv.ErrNoVerifier) {
			t.Errorf("%s with the active verifier: %v", name, err)
		}
	}

	f := newFixture(t, ghost.InternalNetGasLimit, nil)
	c := testCoin("default", oneGhost)
	restore := ghostpriv.SetVerifier(stub)
	blocks, _ := f.generate(5, func(i int, b *core.BlockGen) {
		switch i {
		case 0:
			b.AddTx(f.commitTx(keyA, 0, c))
		case 4:
			fee := genWindowFee(t, b).Total
			out := u256(ghostAmount(1, 2))
			rest := new(uint256.Int).Sub(c.value, out)
			rest.Sub(rest, fee)
			b.AddTx(revealTx(t, f.newReveal(genParentRoot(b), testMarker("default"), testCoin("default rest", rest.ToBig()), addrB, out, fee)))
		}
	})
	restore()

	chain := f.newChain()
	n, err := chain.InsertChain(blocks)
	if !errors.Is(err, ghostpriv.ErrRevealProof) || !errors.Is(err, ghostpriv.ErrNoVerifier) {
		t.Fatalf("import with the default verifier: %v", err)
	}
	if n != 4 || chain.CurrentBlock().Number.Uint64() != 4 {
		t.Fatalf("imported up to block %d", chain.CurrentBlock().Number)
	}
	// The same reveal, checked directly with the active verifier.
	env, st := nextEnv(t, chain, chain.CurrentBlock(), common.Address{0xcb})
	tx := blocks[4].Transactions()[0]
	if _, _, err := ghostpriv.CheckReveal(st, env, ghostpriv.ActiveVerifier(), tx.GhostRevealEnvelope()); !errors.Is(err, ghostpriv.ErrNoVerifier) {
		t.Fatalf("check with the active verifier: %v", err)
	}
	if _, _, err := ghostpriv.CheckReveal(st, env, nil, tx.GhostRevealEnvelope()); !errors.Is(err, ghostpriv.ErrNoVerifier) {
		t.Fatalf("check with no verifier: %v", err)
	}
	if _, _, err := ghostpriv.CheckReveal(st, env, stub, tx.GhostRevealEnvelope()); err != nil {
		t.Fatalf("the reveal is otherwise valid: %v", err)
	}
}

// TestRevealFeeMustEqualWindowFee checks the fee formula's known answers and
// that a reveal must pay exactly the fee of its window, priced from the
// base fee of the window's first block: the including block itself when it
// starts the window, an ancestor otherwise, never the parent as such.
func TestRevealFeeMustEqualWindowFee(t *testing.T) {
	type answer struct {
		bRef                       int64
		price, base, tip, totalFee string
	}
	for _, tt := range []answer{
		{1_000_000_000, "1424017979", "23594776040855724", "2359477604085573", "25954253644941297"},
		{1_100_000_000, "1566419776", "25954253630029056", "2595425363002906", "28549678993031962"},
	} {
		fee, err := ghostpriv.WindowFee(big.NewInt(tt.bRef))
		if err != nil {
			t.Fatal(err)
		}
		if fee.Price.Dec() != tt.price || fee.BasePart.Dec() != tt.base || fee.Tip.Dec() != tt.tip || fee.Total.Dec() != tt.totalFee {
			t.Errorf("b_ref %d: price %v base %v tip %v fee %v", tt.bRef, fee.Price, fee.BasePart, fee.Tip, fee.Total)
		}
	}
	for _, bad := range []*big.Int{nil, big.NewInt(-1), new(big.Int).Lsh(big.NewInt(1), 256)} {
		if _, err := ghostpriv.WindowFee(bad); !errors.Is(err, ghostpriv.ErrBaseFee) {
			t.Errorf("base fee %v: %v", bad, err)
		}
	}
	for h, want := range []uint64{0, 0, 0, 0, 4, 4, 4, 4, 8, 8} {
		if got := ghostpriv.WindowStart(uint64(h)); got != want {
			t.Errorf("window start of %d: %d, want %d", h, got, want)
		}
	}

	useStub(t)
	s := newScenario(t, 7)
	price := func(bRef *big.Int) *uint256.Int {
		fee, err := ghostpriv.WindowFee(bRef)
		if err != nil {
			t.Fatal(err)
		}
		return fee.Total
	}
	check := func(env *ghostpriv.BlockEnv, st *state.StateDB, fee *uint256.Int) error {
		_, _, err := ghostpriv.CheckReveal(st.Copy(), env, stub, envelope(t, s.reveal(t, "fee", u256(ghostAmount(1, 10)), fee)))
		return err
	}
	one := uint256.NewInt(1)

	// Block 8 starts its window: its own base fee prices it.
	env8, st8 := nextEnv(t, s.chain, s.blocks[6].Header(), common.Address{0xcb})
	if env8.Header.BaseFee.Cmp(s.blocks[6].BaseFee()) == 0 {
		t.Fatal("blocks 7 and 8 have the same base fee")
	}
	ownFee, err := ghostpriv.WindowFee(env8.Header.BaseFee)
	if err != nil {
		t.Fatal(err)
	}
	own := ownFee.Total
	if err := check(env8, st8, own); err != nil {
		t.Fatalf("block 8 at its own window fee: %v", err)
	}
	wrong := map[string]*uint256.Int{
		"the parent's": price(s.blocks[6].BaseFee()),
		"one wei more": new(uint256.Int).Add(own, one),
		"one wei less": new(uint256.Int).Sub(own, one),
		"no tip":       ownFee.BasePart,
		"zero":         new(uint256.Int),
	}
	for name, fee := range wrong {
		if err := check(env8, st8, fee); !errors.Is(err, ghostpriv.ErrRevealFee) {
			t.Errorf("block 8 at %s fee: %v", name, err)
		}
	}

	// Block 7 is in the window of block 4.
	env7, st7 := nextEnv(t, s.chain, s.blocks[5].Header(), common.Address{0xcb})
	if err := check(env7, st7, price(s.blocks[3].BaseFee())); err != nil {
		t.Fatalf("block 7 at block 4's fee: %v", err)
	}
	others := map[string]*big.Int{
		"its own base fee": env7.Header.BaseFee,
		"its parent's":     s.blocks[5].BaseFee(),
		"block 5's":        s.blocks[4].BaseFee(),
		"block 3's":        s.blocks[2].BaseFee(),
	}
	for name, bRef := range others {
		if err := check(env7, st7, price(bRef)); !errors.Is(err, ghostpriv.ErrRevealFee) {
			t.Errorf("block 7 at %s fee: %v", name, err)
		}
	}
}

// headerReader is a ChainReader for tests: hiding hides every header below
// a height, and byNumber answers with the canonical header of the number
// whatever hash is asked for.
type headerReader struct {
	chain    *core.BlockChain
	below    uint64
	byNumber bool
}

func (r headerReader) GetHeader(hash common.Hash, number uint64) *types.Header {
	if number < r.below {
		return nil
	}
	if r.byNumber {
		return r.chain.GetHeaderByNumber(number)
	}
	return r.chain.GetHeader(hash, number)
}

// TestRevealRootMustBeAncestorCoinRoot checks which roots a reveal may use:
// the coin root of any block of its own ancestry strictly below it, the
// genesis included; not its own block's root, not the root of a side block
// the node stores, not one it cannot confirm.
func TestRevealRootMustBeAncestorCoinRoot(t *testing.T) {
	useStub(t)
	f := newFixture(t, ghost.InternalNetGasLimit, nil)
	var (
		miner      = common.Address{0xcb}
		c1, c2, c3 = testCoin("root one", oneGhost), testCoin("root side", oneGhost), testCoin("root two", oneGhost)
	)
	main, _ := f.generate(3, func(i int, b *core.BlockGen) {
		switch i {
		case 0:
			b.AddTx(f.commitTx(keyA, 0, c1))
		case 1:
			b.AddTx(f.commitTx(keyA, 1, c3))
		}
	})
	side, _ := f.generate(3, func(i int, b *core.BlockGen) {
		b.SetCoinbase(common.Address{0x5e})
		if i == 0 {
			b.AddTx(f.commitTx(keyB, 0, c2))
		}
	})
	chain := f.newChain()
	f.insert(chain, main)
	f.insert(chain, side[:1])
	if chain.CurrentBlock().Hash() != main[2].Hash() {
		t.Fatal("the side block became the head")
	}
	if chain.GetHeader(side[0].Hash(), 1) == nil {
		t.Fatal("the side block is not stored")
	}
	var (
		genesisRoot = *f.genesis.Header().CoinTreeRoot
		r1, r2      = *main[0].Header().CoinTreeRoot, *main[1].Header().CoinTreeRoot
		rSide       = *side[0].Header().CoinTreeRoot
	)
	if r1 == r2 || r1 == rSide || r1 == genesisRoot {
		t.Fatal("roots are not distinct")
	}
	check := func(env *ghostpriv.BlockEnv, st *state.StateDB, root common.Hash) error {
		fee := chainWindowFee(t, chain, env.Header).Total
		r := f.newReveal(root, testMarker("root"), testCoin("root rest", ghostAmount(1, 2)), addrB, u256(ghostAmount(1, 4)), fee)
		_, _, err := ghostpriv.CheckReveal(st.Copy(), env, stub, envelope(t, r))
		return err
	}

	// Block 4 on the main chain, which starts its fee window.
	env, st := nextEnv(t, chain, main[2].Header(), miner)
	for name, root := range map[string]common.Hash{"block 1": r1, "block 2": r2, "the genesis": genesisRoot} {
		if err := check(env, st, root); err != nil {
			t.Errorf("root of %s: %v", name, err)
		}
	}
	coinState, err := ghosttree.Root(st, ghosttree.Coin)
	if err != nil {
		t.Fatal(err)
	}
	for name, root := range map[string]common.Hash{
		"the stored side block": rSide,
		"no block":              common.Hash{0x0b},
		"the zero hash":         {},
		"the data tree":         *main[2].Header().DataTreeRoot,
		"a node of the tree":    ghosttree.K(ghosttree.TagCoinNode, []byte{0}, c1.commitment().Bytes(), c3.commitment().Bytes()),
	} {
		if err := check(env, st, root); !errors.Is(err, ghostpriv.ErrRevealRoot) {
			t.Errorf("root of %s: %v, want %v", name, err, ghostpriv.ErrRevealRoot)
		}
	}
	if coinState != r2 {
		t.Fatal("the coin root of the state is not the head's")
	}

	// The including block's own root is not below it: block 2 carries r2.
	st1, err := chain.StateAt(main[0].Root())
	if err != nil {
		t.Fatal(err)
	}
	self := &ghostpriv.BlockEnv{Header: main[1].Header(), Chain: chain, ChainID: chain.Config().GetChainID(), Genesis: chain.Genesis().Hash()}
	if err := check(self, st1, r2); !errors.Is(err, ghostpriv.ErrRevealRoot) {
		t.Errorf("the including block's own root: %v", err)
	}
	if err := check(self, st1, r1); err != nil {
		t.Errorf("the parent's root from block 2: %v", err)
	}

	// An ancestor the chain cannot give is not confirmed.
	hidden := *env
	hidden.Chain = headerReader{chain: chain, below: 2}
	if err := check(&hidden, st, r1); !errors.Is(err, ghostpriv.ErrRevealRoot) {
		t.Errorf("root of a missing ancestor: %v", err)
	}
	if err := check(&hidden, st, r2); err != nil {
		t.Errorf("root of a present ancestor: %v", err)
	}

	// On the side branch, its own root is eligible and the main chain's is
	// not, even from a reader that answers by number with main headers.
	// Block 4 of the side branch starts its fee window, so only the root
	// needs its ancestry.
	sideChain := f.newChain()
	f.insert(sideChain, side)
	envSide, stSide := nextEnv(t, sideChain, side[2].Header(), miner)
	if err := check(envSide, stSide, rSide); err != nil {
		t.Errorf("side root on the side branch: %v", err)
	}
	byNumber := *envSide
	byNumber.Chain = headerReader{chain: chain, byNumber: true}
	if err := check(&byNumber, stSide, r1); !errors.Is(err, ghostpriv.ErrRevealRoot) {
		t.Errorf("main root through a by-number reader: %v", err)
	}
}

// TestBackstopRejectsOverdraw checks that no reveal takes out more than the
// totals say is hidden, even with a proof the verifier accepts.
func TestBackstopRejectsOverdraw(t *testing.T) {
	useStub(t)
	s := newScenario(t, 4)
	env, st := nextEnv(t, s.chain, s.blocks[3].Header(), common.Address{0xcb})
	fee := chainWindowFee(t, s.chain, env.Header).Total
	hidden, err := ghostpriv.Hidden(st)
	if err != nil || !hidden.Eq(s.c.value) {
		t.Fatalf("hidden %v (%v), want the commit", hidden, err)
	}
	all := new(uint256.Int).Sub(hidden, fee)
	more := new(uint256.Int).AddUint64(all, 1)
	if _, _, err := ghostpriv.CheckReveal(st.Copy(), env, stub, envelope(t, s.reveal(t, "backstop", more, fee))); !errors.Is(err, ghostpriv.ErrRevealBackstop) {
		t.Fatalf("one wei over: %v", err)
	}
	if _, _, err := ghostpriv.CheckReveal(st.Copy(), env, stub, envelope(t, s.reveal(t, "backstop", all, fee))); err != nil {
		t.Fatalf("exactly the hidden value: %v", err)
	}

	// After a reveal takes half, the rest bounds the next one, whatever its
	// root and proof.
	cp := st.Copy()
	half := u256(ghostAmount(1, 2))
	if err := ghostpriv.ApplyReveal(cp, env, stub, envelope(t, s.reveal(t, "backstop half", half, fee))); err != nil {
		t.Fatal(err)
	}
	left := new(uint256.Int).Sub(hidden, half)
	left.Sub(left, fee)
	if h, _ := ghostpriv.Hidden(cp); !h.Eq(left) {
		t.Fatalf("hidden after half %v, want %v", h, left)
	}
	rest := new(uint256.Int).Sub(left, fee)
	if err := ghostpriv.ApplyReveal(cp.Copy(), env, stub, envelope(t, s.reveal(t, "backstop rest", new(uint256.Int).AddUint64(rest, 1), fee))); !errors.Is(err, ghostpriv.ErrRevealBackstop) {
		t.Fatalf("second reveal one wei over: %v", err)
	}
	if err := ghostpriv.ApplyReveal(cp, env, stub, envelope(t, s.reveal(t, "backstop rest", rest, fee))); err != nil {
		t.Fatalf("second reveal of the rest: %v", err)
	}
	if h, _ := ghostpriv.Hidden(cp); !h.IsZero() {
		t.Fatalf("hidden %v after taking everything", h)
	}

	// Totals that say more left than entered reject every reveal.
	bad := st.Copy()
	bad.SetState(ghost.PrivTotalsAccount, ghosttree.Slot(ghostpriv.SlotTotalOut), common.BigToHash(new(big.Int).Mul(big.NewInt(2), oneGhost)))
	if _, _, err := ghostpriv.CheckReveal(bad, env, stub, envelope(t, s.reveal(t, "backstop", uint256.NewInt(0), fee))); !errors.Is(err, ghostpriv.ErrRevealBackstop) || !errors.Is(err, ghostpriv.ErrTotals) {
		t.Fatalf("corrupt totals: %v", err)
	}
}

// accountsSnapshot reads what a reveal and its block change.
func accountsSnapshot(t *testing.T, chain *core.BlockChain, root common.Hash, addrs []common.Address, markers []common.Hash) map[string]string {
	t.Helper()
	st, err := chain.StateAt(root)
	if err != nil {
		t.Fatal(err)
	}
	snap := make(map[string]string)
	for _, a := range addrs {
		snap["balance "+a.Hex()] = st.GetBalance(a).String()
		snap["nonce "+a.Hex()] = big.NewInt(int64(st.GetNonce(a))).String()
	}
	for _, m := range markers {
		snap["marker "+m.Hex()] = st.GetState(ghosttree.MarkerAccount(ghosttree.Coin), m).Hex()
	}
	for i := uint64(0); i < ghosttree.SlotFrontier+ghosttree.MaxDepth; i++ {
		snap["coin slot "+big.NewInt(int64(i)).String()] = st.GetState(ghosttree.TreeAccount(ghosttree.Coin), ghosttree.Slot(i)).Hex()
	}
	in, out := totals(st)
	snap["total in"], snap["total out"] = in.String(), out.String()
	for _, a := range []common.Address{ghost.PrivTotalsAccount, ghosttree.TreeAccount(ghosttree.Coin), ghosttree.MarkerAccount(ghosttree.Coin)} {
		snap["nonce "+a.Hex()] = big.NewInt(int64(st.GetNonce(a))).String()
	}
	return snap
}

// TestReorgRevertsRevealAtomically imports a branch with a reveal and then a
// heavier branch without it: the node ends with exactly the state of a node
// that only saw the heavier branch, the marker unspent, and the reveal can
// then be included on the new branch.
func TestReorgRevertsRevealAtomically(t *testing.T) {
	useStub(t)
	f := newFixture(t, ghost.InternalNetGasLimit, nil)
	var (
		c         = testCoin("reorg", oneGhost)
		marker    = testMarker("reorg")
		recipient = common.Address{0x9e, 0x0a}
		minerA    = common.Address{0xa0}
		minerB    = common.Address{0xb0}
		out       = u256(ghostAmount(2, 5))
	)
	reveal := func(b *core.BlockGen) {
		fee := genWindowFee(t, b).Total
		rest := new(uint256.Int).Sub(c.value, out)
		rest.Sub(rest, fee)
		b.AddTx(revealTx(t, f.newReveal(genParentRoot(b), marker, testCoin("reorg rest", rest.ToBig()), recipient, out, fee)))
	}
	branch := func(n int, revealAt int) []*types.Block {
		blocks, _ := f.generate(n, func(i int, b *core.BlockGen) {
			switch {
			case i == 0:
				b.AddTx(f.commitTx(keyA, 0, c))
			case i >= 4 && revealAt == 4:
				b.SetCoinbase(minerA)
				if i == revealAt {
					reveal(b)
				}
			case i >= 4:
				b.SetCoinbase(minerB)
				if i == revealAt {
					reveal(b)
				}
			}
		})
		return blocks
	}
	a := branch(5, 4)  // the reveal in block 5
	b := branch(7, -1) // blocks 5 to 7 without it
	if a[3].Hash() != b[3].Hash() || a[4].Hash() == b[4].Hash() {
		t.Fatal("the branches do not fork after block 4")
	}
	addrs := []common.Address{addrA, addrB, recipient, minerA, minerB}
	markers := []common.Hash{marker}

	reorged := f.newChain()
	f.insert(reorged, a)
	st, err := reorged.State()
	if err != nil {
		t.Fatal(err)
	}
	if !ghosttree.IsSpent(st, ghosttree.Coin, marker) || !st.GetBalance(recipient).Eq(out) {
		t.Fatal("branch A did not reveal")
	}
	atFork := accountsSnapshot(t, reorged, a[3].Root(), addrs, markers)
	if len(diffMaps(atFork, accountsSnapshot(t, reorged, a[4].Root(), addrs, markers))) == 0 {
		t.Fatal("the reveal changed nothing")
	}

	f.insert(reorged, b)
	if reorged.CurrentBlock().Hash() != b[6].Hash() {
		t.Fatal("the node did not reorganise to branch B")
	}
	onlyB := f.newChain()
	f.insert(onlyB, b)
	after := accountsSnapshot(t, reorged, reorged.CurrentBlock().Root, addrs, markers)
	for _, d := range diffMaps(after, accountsSnapshot(t, onlyB, onlyB.CurrentBlock().Root, addrs, markers)) {
		t.Errorf("against the node that saw only B: %s", d)
	}
	st, err = reorged.State()
	if err != nil {
		t.Fatal(err)
	}
	if ghosttree.IsSpent(st, ghosttree.Coin, marker) || !st.GetBalance(recipient).IsZero() {
		t.Fatal("the reveal survived the reorganisation")
	}
	if _, o := totals(st); o.Sign() != 0 {
		t.Fatalf("total out %v after the reorganisation", o)
	}

	// The coin is still there to reveal on branch B.
	longer := branch(8, 7)
	if longer[6].Hash() != b[6].Hash() {
		t.Fatal("branch B did not rebuild identically")
	}
	f.insert(reorged, longer[7:])
	st, err = reorged.State()
	if err != nil {
		t.Fatal(err)
	}
	if !ghosttree.IsSpent(st, ghosttree.Coin, marker) || !st.GetBalance(recipient).Eq(out) {
		t.Fatal("the reveal did not apply on branch B")
	}
}

func diffMaps(a, b map[string]string) []string {
	var diffs []string
	for k, v := range a {
		if b[k] != v {
			diffs = append(diffs, k+": "+v+" vs "+b[k])
		}
	}
	return diffs
}
