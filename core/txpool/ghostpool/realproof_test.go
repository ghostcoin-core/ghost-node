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

//go:build cgo && ghostproofs && (linux || darwin)

package ghostpool

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/holiman/uint256"
)

// realProofRequestEnv names the file the real-proof tests write their
// request to, for ghostverifier/examples/revealfixture.rs, instead of
// running.
const realProofRequestEnv = "GHOST_REAL_PROOF_REQUEST"

// realProofFixture is the committed output of revealfixture.rs.
var realProofFixture = filepath.Join("testdata", "real_reveal.bin.gz")

const realProofRegenerate = `regenerate the fixture: GHOST_REAL_PROOF_REQUEST=/tmp/real_reveal.req CGO_ENABLED=1 go test -tags ghostproofs -run '^TestRealProofRevealPoolAndBlock$' ./core/txpool/ghostpool/, then cargo run --release --locked --manifest-path ghostverifier/Cargo.toml --example revealfixture -- /tmp/real_reveal.req real_reveal.bin and gzip -n -9 real_reveal.bin into core/txpool/ghostpool/testdata/ (see ghostverifier/examples/revealfixture.rs)`

// Lengths of the request and of the parts of the fixture after it, in the
// layout of revealfixture.rs and ghost_proofs.h.
const (
	realChainParamsBytes = 42
	realRequestBytes     = realChainParamsBytes + 4 + 32*32 + 32 + 20 + 32 + 32
	realStatementBytes   = 368
)

var (
	// realRecipient is paid by the real-proof reveal.
	realRecipient = common.Address{0x9e, 0x11}
	// realOut is what the real-proof reveal pays out: 0.4 GHOST.
	realOut = new(big.Int).Div(new(big.Int).Mul(oneGhost, big.NewInt(4)), big.NewInt(10))
)

// realProof is a fixture chain of the pool tests, the internal network's
// genesis with the pool tests' account's alloc, whose block 1 commits one
// GHOST to the fingerprint the pinned prover chose, and the honest reveal of
// that coin in block 2 as the prover made it.
type realProof struct {
	*fixture
	commitF common.Hash
	reveal  *ghostpriv.Reveal
	fee     ghostpriv.Fee
	// commitTx is block 1's commit once signed: ML-DSA signatures are
	// randomized, so signing again would give another block 1.
	commitTx *types.Transaction
}

// newRealProof loads the fixture for the chain of the pool tests. It fails
// with how to regenerate it when the chain no longer matches. With
// GHOST_REAL_PROOF_REQUEST set it writes the request there and skips.
func newRealProof(t *testing.T) *realProof {
	t.Helper()
	gspec := ghost.InternalNetGenesis()
	gspec.Alloc = genesisT.GenesisAlloc{poolAddr: {Balance: new(big.Int).Mul(oneGhost, big.NewInt(100))}}
	f := &fixture{t: t, gspec: gspec, genesis: core.GenesisToBlock(gspec, nil)}
	if v := ghostpriv.ActiveVerifier(); v != ghostpriv.DefaultVerifier() {
		t.Fatalf("active verifier %T, want the default", v)
	}

	// The reveal is in block 2, whose fee window starts at the genesis.
	if start := ghostpriv.WindowStart(2); start != 0 {
		t.Fatalf("block 2 is in the window of block %d", start)
	}
	fee, err := ghostpriv.WindowFee(f.genesis.BaseFee())
	if err != nil {
		t.Fatal(err)
	}
	request := realRequest(t, f, fee.Total)
	if path := os.Getenv(realProofRequestEnv); path != "" {
		if err := os.WriteFile(path, request, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Skipf("wrote the request to %s; now run ghostverifier/examples/revealfixture.rs", path)
	}

	raw := readRealFixture(t)
	if len(raw) <= realRequestBytes+32+realStatementBytes {
		t.Fatalf("fixture of %d bytes; %s", len(raw), realProofRegenerate)
	}
	if !bytes.Equal(raw[:realRequestBytes], request) {
		t.Fatalf("the fixture was made for another chain or fee; %s", realProofRegenerate)
	}
	rest := raw[realRequestBytes:]
	commitF := common.BytesToHash(rest[:32])
	s := rest[32 : 32+realStatementBytes]
	r := &ghostpriv.Reveal{
		Version:   ghostpriv.Version,
		ChainID:   gspec.Config.GetChainID().Uint64(),
		Root:      common.BytesToHash(s[0:32]),
		Marker:    common.BytesToHash(s[32:64]),
		Remainder: common.BytesToHash(s[64:96]),
		Recipient: common.BytesToAddress(s[252:272]),
		Out:       new(uint256.Int).SetBytes(s[272:304]),
		Fee:       new(uint256.Int).SetBytes(s[304:336]),
		Proof:     common.CopyBytes(rest[32+realStatementBytes:]),
	}
	copy(r.Note[:], s[96:252])
	if r.Recipient != realRecipient || r.Out.ToBig().Cmp(realOut) != 0 || !r.Fee.Eq(fee.Total) {
		t.Fatalf("fixture statement does not match its request; %s", realProofRegenerate)
	}
	if !bytes.Equal(s[336:368], make([]byte, 32)) {
		t.Fatalf("fixture rule %x, want the empty rule", s[336:368])
	}
	if len(r.Proof) > ghostpriv.ProofSize {
		t.Fatalf("proof of %d bytes, the field holds %d", len(r.Proof), ghostpriv.ProofSize)
	}
	return &realProof{fixture: f, commitF: commitF, reveal: r, fee: fee}
}

// realRequest is the request of revealfixture.rs for the chain: the chain
// parameters, the position and path of the commitment block 1 makes, its
// value, the recipient, out and fee.
func realRequest(t *testing.T, f *fixture, fee *uint256.Int) []byte {
	t.Helper()
	// The genesis coin tree is empty, so the commitment is at position 0
	// with siblings that do not depend on it.
	if root := f.genesis.Header().CoinTreeRoot; root == nil || *root != ghosttree.EmptyRoot(ghosttree.Coin) {
		t.Fatalf("genesis coin tree is not empty; %s", realProofRegenerate)
	}
	page := []common.Hash{{0x01}}
	path, err := ghosttree.Witness(ghosttree.Coin, 0, page, []common.Hash{ghosttree.PageRoot(ghosttree.Coin, page)})
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 0, realRequestBytes)
	b = binary.BigEndian.AppendUint64(b, f.gspec.Config.GetChainID().Uint64())
	b = binary.BigEndian.AppendUint16(b, ghostpriv.Version)
	b = append(b, f.genesis.Hash().Bytes()...)
	b = binary.BigEndian.AppendUint32(b, 0)
	for _, sibling := range path {
		b = append(b, sibling[:]...)
	}
	value := uint256.MustFromBig(oneGhost).Bytes32()
	b = append(b, value[:]...)
	b = append(b, realRecipient[:]...)
	out := uint256.MustFromBig(realOut).Bytes32()
	b = append(b, out[:]...)
	feeWord := fee.Bytes32()
	return append(b, feeWord[:]...)
}

// readRealFixture reads the uncompressed fixture.
func readRealFixture(t *testing.T) []byte {
	t.Helper()
	file, err := os.Open(realProofFixture)
	if err != nil {
		t.Fatalf("%v; %s", err, realProofRegenerate)
	}
	defer file.Close()
	zr, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// commit is block 1's commit of one GHOST to the fixture's fingerprint, an
// account transaction of the pool tests' account, signed on first use.
func (rp *realProof) commit() *types.Transaction {
	rp.t.Helper()
	if rp.commitTx != nil {
		return rp.commitTx
	}
	data, err := ghostpriv.CommitData(rp.commitF, make([]byte, ghostpriv.NoteSize))
	if err != nil {
		rp.t.Fatal(err)
	}
	to := ghost.CommitEntryAddress
	signer := types.NewGhostAccountSigner(types.LatestSigner(rp.gspec.Config), rp.genesis.Hash())
	rp.commitTx = signAccountTransfer(signer, poolKey, 0, &to, oneGhost, big.NewInt(1_000_000_000), big.NewInt(100_000_000_000), 60_000+accountTxExtraGas, data)
	return rp.commitTx
}

// revealTx is the envelope of r as a transaction.
func (rp *realProof) revealTx(r *ghostpriv.Reveal) *types.Transaction {
	rp.t.Helper()
	env, err := r.MarshalBinary()
	if err != nil {
		rp.t.Fatal(err)
	}
	tx, err := types.NewGhostRevealTx(env)
	if err != nil {
		rp.t.Fatal(err)
	}
	return tx
}

// treeRootEngine is the fake ethash engine that also writes the coin and
// data tree roots into the header, as the network's engine does, so that
// block 1's coin root is one a reveal can prove against.
type treeRootEngine struct {
	*ethash.Ethash
}

func (e treeRootEngine) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header, st *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt, withdrawals []*types.Withdrawal) (*types.Block, error) {
	e.Finalize(chain, header, st, txs, uncles, withdrawals)
	coin, err := ghosttree.Root(st, ghosttree.Coin)
	if err != nil {
		return nil, err
	}
	data, err := ghosttree.Root(st, ghosttree.Data)
	if err != nil {
		return nil, err
	}
	header.CoinTreeRoot, header.DataTreeRoot = &coin, &data
	header.Root = st.IntermediateRoot(true)
	return types.NewBlock(header, txs, uncles, receipts, trie.NewStackTrie(nil)), nil
}

// makeBlocks makes block 1 with the commit and block 2 with the given
// reveals, under whatever verifier is active. Block 1 is the same every
// time.
func (rp *realProof) makeBlocks(reveals ...*types.Transaction) []*types.Block {
	rp.t.Helper()
	commit := rp.commit()
	_, blocks, _ := core.GenerateChainWithGenesis(rp.gspec, treeRootEngine{ethash.NewFaker()}, 2, func(i int, b *core.BlockGen) {
		b.SetCoinbase(common.Address{0x01})
		switch i {
		case 0:
			b.AddTx(commit)
		case 1:
			for _, tx := range reveals {
				b.AddTx(tx)
			}
		}
	})
	return blocks
}

// newChain starts a chain of the blocks and imports block 1, whose coin
// root must be the one the proof is for.
func (rp *realProof) newChain(blocks []*types.Block) {
	t := rp.t
	t.Helper()
	chain, err := core.NewBlockChain(rawdb.NewMemoryDatabase(), nil, rp.gspec, nil, treeRootEngine{ethash.NewFaker()}, vm.Config{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(chain.Stop)
	if chain.Genesis().Hash() != rp.genesis.Hash() {
		t.Fatal("the chain's genesis is not the fixture's")
	}
	rp.chain, rp.blocks = chain, blocks
	rp.insert(1)
	if root := blocks[0].Header().CoinTreeRoot; root == nil || *root != rp.reveal.Root {
		t.Fatalf("block 1 coin root %v, the proof's %x; %s", root, rp.reveal.Root, realProofRegenerate)
	}
}

func cloneReveal(r *ghostpriv.Reveal) *ghostpriv.Reveal {
	cp := *r
	cp.Out = new(uint256.Int).Set(r.Out)
	cp.Fee = new(uint256.Int).Set(r.Fee)
	cp.Proof = common.CopyBytes(r.Proof)
	return &cp
}

// tamperedReveals are the fixture's reveal with one proof byte flipped and
// with out changed by one.
func (rp *realProof) tamperedReveals() map[string]*ghostpriv.Reveal {
	flipped := cloneReveal(rp.reveal)
	flipped.Proof[len(flipped.Proof)/2] ^= 0x01
	changedOut := cloneReveal(rp.reveal)
	changedOut.Out.AddUint64(changedOut.Out, 1)
	return map[string]*ghostpriv.Reveal{"flipped proof byte": flipped, "changed out": changedOut}
}

// acceptAll is a test-only verifier that accepts every proof, to have the
// chain maker build a block the default verifier refuses.
type acceptAll struct{}

func (acceptAll) VerifyReveal(*ghostpriv.VerifyInputs, []byte) error { return nil }

// TestRealProofRevealPoolAndBlock takes a reveal carrying a real proof of
// the pinned prover through the default verifier end to end: the pool
// admits it, a generated block includes it, and that block imports with the
// reveal's receipt and state change.
func TestRealProofRevealPoolAndBlock(t *testing.T) {
	rp := newRealProof(t)
	tx := rp.revealTx(rp.reveal)
	if tx.Size() != types.GhostRevealEnvelopeSize {
		t.Fatalf("reveal of %d bytes", tx.Size())
	}

	// The pool on block 1 admits the reveal for block 2.
	rp.newChain(rp.makeBlocks())
	p := rp.newPool()
	if err := p.Add([]*types.Transaction{tx}, true, true)[0]; err != nil {
		t.Fatalf("pool refused the real reveal: %v", err)
	}
	pending := p.PendingReveals()
	if got := hashes(pending); len(got) != 1 || got[0] != tx.Hash() {
		t.Fatalf("pending reveals %v, want %v", got, tx.Hash())
	}
	requireErr(t, p.Add([]*types.Transaction{tx}, true, true)[0], txpool.ErrAlreadyKnown, "the same reveal again")

	// Block 2, generated with the pool's pending reveal, imports under the
	// default verifier.
	blocks := rp.makeBlocks(pending...)
	if blocks[0].Hash() != rp.blocks[0].Hash() {
		t.Fatal("block 1 generated again differs")
	}
	rp.blocks = blocks
	block := blocks[1]
	if txs := block.Transactions(); len(txs) != 1 || txs[0].Hash() != tx.Hash() {
		t.Fatal("block 2 does not carry the reveal")
	}
	old := rp.chain.CurrentBlock()
	rp.insert(2)
	if head := rp.chain.CurrentBlock(); head.Hash() != block.Hash() {
		t.Fatalf("head %d %x, want block 2", head.Number, head.Hash())
	}
	rp.reset(p, old)
	if p.Has(tx.Hash()) {
		t.Fatal("pool still holds the included reveal")
	}

	// The receipt: typed 0x50, status 1, exactly G_PRIV gas, one log.
	if block.GasUsed() != ghostpriv.GasPriv {
		t.Errorf("block 2 gas used %d, want %d", block.GasUsed(), ghostpriv.GasPriv)
	}
	rs := rp.chain.GetReceiptsByHash(block.Hash())
	if len(rs) != 1 {
		t.Fatalf("%d receipts", len(rs))
	}
	r := rs[0]
	if r.Type != types.GhostRevealTxType || r.Status != types.ReceiptStatusSuccessful || r.GasUsed != ghostpriv.GasPriv || r.TxHash != tx.Hash() {
		t.Errorf("receipt: %+v", r)
	}
	if len(r.Logs) != 1 {
		t.Fatalf("receipt has %d logs", len(r.Logs))
	}
	l := r.Logs[0]
	if l.Address != ghosttree.TreeAccount(ghosttree.Coin) || len(l.Topics) != 2 || l.Topics[0] != ghosttree.K(ghostpriv.TagRevealReceipt) || l.Topics[1] != rp.reveal.Marker {
		t.Errorf("log: address %x topics %x", l.Address, l.Topics)
	}
	wantData := binary.BigEndian.AppendUint32(nil, 0)
	wantData = binary.BigEndian.AppendUint32(wantData, 1) // the commitment is at 0
	wantData = append(wantData, rp.reveal.Remainder[:]...)
	wantData = append(wantData, rp.reveal.Note[:]...)
	wantData = append(wantData, realRecipient[:]...)
	outWord := rp.reveal.Out.Bytes32()
	wantData = append(wantData, outWord[:]...)
	if !bytes.Equal(l.Data, wantData) {
		t.Errorf("log data\n%x\nwant\n%x", l.Data, wantData)
	}

	// The state: out minted to the recipient, the marker spent, the
	// remainder in the coin tree under the header root, the rest hidden.
	st, err := rp.chain.StateAt(block.Root())
	if err != nil {
		t.Fatal(err)
	}
	if got := st.GetBalance(realRecipient); got.ToBig().Cmp(realOut) != 0 {
		t.Errorf("recipient %v, want %v", got, realOut)
	}
	if !ghosttree.IsSpent(st, ghosttree.Coin, rp.reveal.Marker) {
		t.Error("marker not spent")
	}
	commitment := ghostpriv.Commitment(rp.commitF, uint256.MustFromBig(oneGhost))
	wantRoot := ghosttree.RootFromPageRoots(ghosttree.Coin, []common.Hash{
		ghosttree.PageRoot(ghosttree.Coin, []common.Hash{commitment, rp.reveal.Remainder}),
	})
	if got := block.Header().CoinTreeRoot; got == nil || *got != wantRoot {
		t.Errorf("header coin root %v, want %x", got, wantRoot)
	}
	wantHidden := uint256.MustFromBig(oneGhost)
	wantHidden.Sub(wantHidden, rp.reveal.Out)
	wantHidden.Sub(wantHidden, rp.fee.Total)
	if hidden, err := ghostpriv.Hidden(st); err != nil || !hidden.Eq(wantHidden) {
		t.Errorf("hidden %v (%v), want %v", hidden, err, wantHidden)
	}

	// The spent marker cannot be revealed again.
	requireErr(t, p.Add([]*types.Transaction{tx}, true, true)[0], ghostpriv.ErrRevealMarker, "the reveal again after its block")
}

// TestRealProofTamperedRevealRejected changes the real reveal by one proof
// byte and by one unit of out: the pool refuses each with ErrRevealProof, and
// a block carrying one, made while a test-only verifier accepted it, is
// refused on import with ErrRevealProof and leaves the head where it was.
func TestRealProofTamperedRevealRejected(t *testing.T) {
	rp := newRealProof(t)
	for name, r := range rp.tamperedReveals() {
		t.Run(name, func(t *testing.T) {
			rp := &realProof{fixture: &fixture{t: t, gspec: rp.gspec, genesis: rp.genesis}, commitF: rp.commitF, reveal: rp.reveal, fee: rp.fee}
			tx := rp.revealTx(r)

			// The pool on block 1 refuses it.
			rp.newChain(rp.makeBlocks())
			p := rp.newPool()
			requireErr(t, p.Add([]*types.Transaction{tx}, true, true)[0], ghostpriv.ErrRevealProof, "tampered reveal over RPC")
			requireErr(t, p.AddFromPeer("peer-a", []*types.Transaction{tx})[0], ghostpriv.ErrRevealProof, "tampered reveal from a peer")
			if p.Has(tx.Hash()) || len(p.PendingReveals()) != 0 {
				t.Fatal("pool holds the tampered reveal")
			}

			// A block carrying it, made under a verifier that accepts every
			// proof, is refused under the default one.
			restore := ghostpriv.SetVerifier(acceptAll{})
			blocks := rp.makeBlocks(tx)
			restore()
			if v := ghostpriv.ActiveVerifier(); v != ghostpriv.DefaultVerifier() {
				t.Fatalf("active verifier %T, want the default", v)
			}
			if blocks[0].Hash() != rp.blocks[0].Hash() {
				t.Fatal("block 1 generated again differs")
			}
			if txs := blocks[1].Transactions(); len(txs) != 1 || txs[0].Hash() != tx.Hash() {
				t.Fatal("block 2 does not carry the tampered reveal")
			}
			head := rp.chain.CurrentBlock()
			if _, err := rp.chain.InsertChain(blocks[1:]); !errors.Is(err, ghostpriv.ErrRevealProof) {
				t.Fatalf("block with the tampered reveal: %v, want %v", err, ghostpriv.ErrRevealProof)
			}
			if now := rp.chain.CurrentBlock(); now.Hash() != head.Hash() || now.Number.Uint64() != 1 {
				t.Fatalf("head moved to %d %x", now.Number, now.Hash())
			}
		})
	}
}
