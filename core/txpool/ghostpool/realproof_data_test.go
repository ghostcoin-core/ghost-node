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
	"io"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
	"github.com/holiman/uint256"
)

// realDataFixture is the committed output of
// ghostverifier/examples/datalifecyclefixture.rs.
var realDataFixture = filepath.Join("testdata", "real_data_lifecycle.bin.gz")

const realDataRegenerate = `regenerate the fixture: GHOST_REAL_PROOF_REQUEST=/tmp/real_data.req CGO_ENABLED=1 go test -tags ghostproofs -run '^TestRealProofDataLifecycle$' ./core/txpool/ghostpool/, then cargo run --release --locked --features unsettled-points-test --manifest-path ghostverifier/Cargo.toml --example datalifecyclefixture -- /tmp/real_data.req real_data_lifecycle.bin and gzip -n -9 real_data_lifecycle.bin into core/txpool/ghostpool/testdata/ (see ghostverifier/examples/datalifecyclefixture.rs)`

// Lengths of the request and of the parts of the fixture, in the layout of
// datalifecyclefixture.rs, ghost_data.h and ghost_hold.h.
const (
	realDataRequestBytes   = realChainParamsBytes + 32
	realDataStatementBytes = 193
	realHoldContextBytes   = 162
)

// The fixed content of the two commitments and the tag of their content
// fingerprints, as datalifecyclefixture.rs has them.
var (
	realContentA = []byte("synthetic data lifecycle content A, example only")
	realContentB = []byte("synthetic data lifecycle content B, example only")
)

const tagRealContentFingerprint = "ghost/test-data-lifecycle/content-fingerprint/v1"

// realReveal is the reveal verifier of A, as datalifecyclefixture.rs has it.
var realReveal = common.Address{0x9d, 0x9d, 0x9d, 0x9d, 0x9d, 0x9d, 0x9d, 0x9d, 0x9d, 0x9d, 0x9d, 0x9d, 0x9d, 0x9d, 0x9d, 0x9d, 0x9d, 0x9d, 0x9d, 0x9d}

// realContentFingerprint is the content fingerprint of content.
func realContentFingerprint(content []byte) common.Hash {
	return ghosttree.K(tagRealContentFingerprint, binary.BigEndian.AppendUint64(nil, uint64(len(content))), content)
}

// realData is the data lifecycle fixture: block 1 commits A and B, block 2
// reveals A, block 3 revokes B, each spend carrying a real proof of the
// pinned prover, and a real proof of holding of B made after block 2.
type realData struct {
	*fixture
	fA, fB       common.Hash
	saltA, saltB []byte
	reveal       *ghostpriv.DataReveal // A, to realReveal
	revoke       *ghostpriv.DataReveal // B
	hold         ghostpriv.HoldInputs  // B, after block 2
	holdProof    []byte
	markersAfter common.Hash // the marker-set root after block 3
	commits      []*types.Transaction
}

// newRealData loads the fixture for the chain of the pool tests. It fails
// with how to regenerate it when the chain no longer matches. With
// GHOST_REAL_PROOF_REQUEST set it writes the request there and skips.
func newRealData(t *testing.T) *realData {
	t.Helper()
	gspec := ghost.InternalNetGenesis()
	gspec.Alloc = genesisT.GenesisAlloc{poolAddr: {Balance: new(big.Int).Mul(oneGhost, big.NewInt(100))}}
	f := &fixture{t: t, gspec: gspec, genesis: core.GenesisToBlock(gspec, nil)}
	if v := ghostpriv.ActiveVerifier(); v != ghostpriv.DefaultVerifier() {
		t.Fatalf("active verifier %T, want the default", v)
	}
	// The spends are in blocks 2 and 3, whose fee window starts at the genesis.
	if ghostpriv.WindowStart(2) != 0 || ghostpriv.WindowStart(3) != 0 {
		t.Fatal("blocks 2 and 3 are not in the genesis window")
	}
	if root := f.genesis.Header().DataTreeRoot; root == nil || *root != ghosttree.EmptyRoot(ghosttree.Data) {
		t.Fatalf("genesis data tree is not empty; %s", realDataRegenerate)
	}
	if root := f.genesis.Header().DataMarkerRoot; root == nil || *root != ghosttree.EmptyMarkerSetRoot {
		t.Fatalf("genesis data marker set is not empty; %s", realDataRegenerate)
	}
	fee, err := ghostpriv.WindowFee(f.genesis.BaseFee())
	if err != nil {
		t.Fatal(err)
	}
	chainID := gspec.Config.GetChainID().Uint64()
	request := binary.BigEndian.AppendUint64(nil, chainID)
	request = binary.BigEndian.AppendUint16(request, ghostpriv.Version)
	request = append(request, f.genesis.Hash().Bytes()...)
	feeWord := fee.Total.Bytes32()
	request = append(request, feeWord[:]...)
	if path := os.Getenv(realProofRequestEnv); path != "" {
		if err := os.WriteFile(path, request, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Skipf("wrote the request to %s; now run ghostverifier/examples/datalifecyclefixture.rs", path)
	}

	raw := readGzip(t, realDataFixture, realDataRegenerate)
	rest := raw
	take := func(n int) []byte {
		if len(rest) < n {
			t.Fatalf("fixture of %d bytes is short; %s", len(raw), realDataRegenerate)
		}
		b := rest[:n]
		rest = rest[n:]
		return b
	}
	if !bytes.Equal(take(realDataRequestBytes), request) {
		t.Fatalf("the fixture was made for another chain or fee; %s", realDataRegenerate)
	}
	d := &realData{fixture: f}
	d.fA, d.saltA = common.BytesToHash(take(32)), common.CopyBytes(take(ghostpriv.SaltSize))
	d.fB, d.saltB = common.BytesToHash(take(32)), common.CopyBytes(take(ghostpriv.SaltSize))
	d.reveal = realDataReveal(t, chainID, take(realDataStatementBytes), ghostpriv.PurposeReveal)
	d.revoke = realDataReveal(t, chainID, take(realDataStatementBytes), ghostpriv.PurposeRevoke)
	ctx := take(realHoldContextBytes)
	if ctx[0] != ghostpriv.DataV2[0] || ctx[1] != ghostpriv.DataV2[1] {
		t.Fatalf("hold context type %x", ctx[:2])
	}
	d.hold = ghostpriv.HoldInputs{
		ChainID:       chainID,
		Domain:        f.genesis.Hash(),
		Root:          common.BytesToHash(ctx[2:34]),
		MarkerSetRoot: common.BytesToHash(ctx[34:66]),
		Verifier:      common.BytesToHash(ctx[66:98]),
		Challenge:     common.BytesToHash(ctx[98:130]),
		Cf:            common.BytesToHash(ctx[130:162]),
	}
	d.markersAfter = common.BytesToHash(take(32))
	proof := func() []byte { return common.CopyBytes(take(int(binary.BigEndian.Uint32(take(4))))) }
	d.reveal.Proof, d.revoke.Proof, d.holdProof = proof(), proof(), proof()
	if len(rest) != 0 {
		t.Fatalf("fixture has %d bytes left over; %s", len(rest), realDataRegenerate)
	}

	// What the fixture says matches what the test asked for.
	if !d.reveal.Fee.Eq(fee.Total) || !d.revoke.Fee.Eq(fee.Total) {
		t.Fatalf("fixture fees %v and %v, want %v; %s", d.reveal.Fee, d.revoke.Fee, fee.Total, realDataRegenerate)
	}
	if d.reveal.Verifier != realReveal || d.revoke.Verifier != (common.Address{}) {
		t.Fatalf("fixture parties %x and %x", d.reveal.Verifier, d.revoke.Verifier)
	}
	if d.reveal.Root != d.revoke.Root || d.hold.Root != d.reveal.Root {
		t.Fatal("the fixture's spends and proof of holding are not for one data root")
	}
	for _, p := range [][]byte{d.reveal.Proof, d.revoke.Proof} {
		if len(p) > ghostpriv.ProofSize {
			t.Fatalf("proof of %d bytes, the field holds %d", len(p), ghostpriv.ProofSize)
		}
	}
	return d
}

// realDataReveal decodes a data reveal statement of ghost_data.h into the
// data reveal of the node with the given purpose.
func realDataReveal(t *testing.T, chainID uint64, s []byte, purpose byte) *ghostpriv.DataReveal {
	t.Helper()
	// ghost_data.h's purpose codes are the node's plus one.
	if s[0] != purpose+1 {
		t.Fatalf("statement purpose %#x, want the code of %#x", s[0], purpose)
	}
	if !bytes.Equal(s[1+4*32:1+5*32], make([]byte, 32)) {
		t.Fatal("fixture rule is not the empty rule")
	}
	if !bytes.Equal(s[1+2*32:1+2*32+12], make([]byte, 12)) {
		t.Fatal("fixture party is not a padded address")
	}
	return &ghostpriv.DataReveal{
		Version:  ghostpriv.Version,
		ChainID:  chainID,
		Root:     common.BytesToHash(s[1:33]),
		Marker:   common.BytesToHash(s[33:65]),
		Purpose:  ghostpriv.PurposeField(purpose),
		Verifier: common.BytesToAddress(s[65:97]),
		Out:      new(uint256.Int),
		Fee:      new(uint256.Int).SetBytes(s[97:129]),
		Cf:       common.BytesToHash(s[161:193]),
	}
}

// readGzip reads an uncompressed gzip fixture.
func readGzip(t *testing.T, name, regenerate string) []byte {
	t.Helper()
	file, err := os.Open(name)
	if err != nil {
		t.Fatalf("%v; %s", err, regenerate)
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

// dataTx is the envelope of r as a transaction.
func (d *realData) dataTx(r *ghostpriv.DataReveal) *types.Transaction {
	d.t.Helper()
	env, err := r.MarshalBinary()
	if err != nil {
		d.t.Fatal(err)
	}
	tx, err := types.NewGhostDataRevealTx(env)
	if err != nil {
		d.t.Fatal(err)
	}
	return tx
}

// commitTxs are block 1's data commits of A and B, account transactions of
// the pool tests' account, signed on first use: ML-DSA signatures are
// randomized, so signing again would give another block 1.
func (d *realData) commitTxs() []*types.Transaction {
	d.t.Helper()
	if d.commits != nil {
		return d.commits
	}
	to := ghost.DataCommitEntryAddress
	signer := types.NewGhostAccountSigner(types.LatestSigner(d.gspec.Config), d.genesis.Hash())
	for i, c := range []struct {
		f    common.Hash
		salt []byte
	}{{d.fA, d.saltA}, {d.fB, d.saltB}} {
		data, err := ghostpriv.SaltedCommitData(c.f, c.salt, make([]byte, ghostpriv.NoteSize))
		if err != nil {
			d.t.Fatal(err)
		}
		d.commits = append(d.commits, signAccountTransfer(signer, poolKey, uint64(i), &to, ghostpriv.DataReserve.ToBig(), big.NewInt(1_000_000_000), big.NewInt(100_000_000_000), 60_000+accountTxExtraGas, data))
	}
	return d.commits
}

// makeBlocks makes block 1 with the commits and blocks 2 and 3 with the given
// transactions. Block 1 is the same every time.
func (d *realData) makeBlocks(block2, block3 []*types.Transaction) []*types.Block {
	d.t.Helper()
	commits := d.commitTxs()
	_, blocks, _ := core.GenerateChainWithGenesis(d.gspec, treeRootEngine{ethash.NewFaker()}, 3, func(i int, b *core.BlockGen) {
		b.SetCoinbase(common.Address{0x01})
		for _, tx := range [][]*types.Transaction{commits, block2, block3}[i] {
			b.AddTx(tx)
		}
	})
	return blocks
}

// header is the canonical header at height number.
func (d *realData) header(number uint64) *types.Header {
	d.t.Helper()
	h := d.chain.GetHeaderByNumber(number)
	if h == nil || h.DataTreeRoot == nil || h.DataMarkerRoot == nil {
		d.t.Fatalf("block %d missing or without data roots", number)
	}
	return h
}

// holdAt is the proof of holding's inputs with the roots of the headers at
// the given heights, as a holding verifier that accepts them takes them.
func (d *realData) holdAt(rootAt, markersAt uint64) *ghostpriv.HoldInputs {
	in := d.hold
	in.Root = *d.header(rootAt).DataTreeRoot
	in.MarkerSetRoot = *d.header(markersAt).DataMarkerRoot
	return &in
}

// TestRealProofDataLifecycle runs the data lifecycle on a node with the
// default verifiers and no test-only switch, every proof a real one of the
// pinned prover: two data commits; a proof of holding of B; a reveal of A to
// a verifier, whose content fingerprint the proof binds and a reader checks
// against the content; the revoke of B; and the proof of holding of B
// refused against the marker-set root after the revoke. Neither spend can be
// made twice.
func TestRealProofDataLifecycle(t *testing.T) {
	d := newRealData(t)
	revealTx, revokeTx := d.dataTx(d.reveal), d.dataTx(d.revoke)
	if revealTx.Size() != types.GhostDataRevealEnvelopeSize {
		t.Fatalf("data reveal of %d bytes", revealTx.Size())
	}

	// Block 1: the two commits, at positions 0 and 1 under the fixture's root.
	chain, err := core.NewBlockChain(rawdb.NewMemoryDatabase(), nil, d.gspec, nil, treeRootEngine{ethash.NewFaker()}, vm.Config{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(chain.Stop)
	d.chain, d.blocks = chain, d.makeBlocks(nil, nil)
	d.insert(1)
	if got := *d.header(1).DataTreeRoot; got != d.reveal.Root {
		t.Fatalf("block 1 data root %x, the proofs' %x; %s", got, d.reveal.Root, realDataRegenerate)
	}
	wantRoot := ghosttree.RootFromPageRoots(ghosttree.Data, []common.Hash{ghosttree.PageRoot(ghosttree.Data, []common.Hash{
		ghostpriv.DataCommitmentVersion(ghostpriv.SaltedCommitVersion, d.fA),
		ghostpriv.DataCommitmentVersion(ghostpriv.SaltedCommitVersion, d.fB),
	})})
	if wantRoot != d.reveal.Root {
		t.Fatalf("data root of the commitments %x, the proofs' %x", wantRoot, d.reveal.Root)
	}

	// The content fingerprints are the contents': the reveal's cf is what a
	// reader of the revealed bytes checks, and the hold asks about B's.
	if d.reveal.Cf != realContentFingerprint(realContentA) || d.reveal.Cf == realContentFingerprint(realContentB) {
		t.Fatalf("the reveal's cf %x is not content A's", d.reveal.Cf)
	}
	if d.hold.Cf != realContentFingerprint(realContentB) {
		t.Fatalf("the hold's cf %x is not content B's", d.hold.Cf)
	}

	// The pool on block 1 admits the reveal and the revoke, and refuses the
	// reveal with another content fingerprint at the proof.
	p := d.newPool()
	otherCf := *d.reveal
	otherCf.Cf = realContentFingerprint(realContentB)
	requireErr(t, p.Add([]*types.Transaction{d.dataTx(&otherCf)}, true, true)[0], ghostpriv.ErrDataRevealProof, "the reveal with B's content fingerprint")
	if err := p.Add([]*types.Transaction{revealTx}, true, true)[0]; err != nil {
		t.Fatalf("pool refused the real data reveal: %v", err)
	}
	requireErr(t, p.Add([]*types.Transaction{revealTx}, true, true)[0], txpool.ErrAlreadyKnown, "the same data reveal again")
	if got := hashes(p.PendingReveals()); len(got) != 1 || got[0] != revealTx.Hash() {
		t.Fatalf("pending reveals %v, want the data reveal", got)
	}

	// Block 2, with the pool's pending reveal, imports under the default
	// verifier and spends A's marker.
	blocks := d.makeBlocks(p.PendingReveals(), nil)
	if blocks[0].Hash() != d.blocks[0].Hash() {
		t.Fatal("block 1 generated again differs")
	}
	d.blocks = blocks
	old := d.chain.CurrentBlock()
	d.insert(2)
	d.reset(p, old)
	if p.Has(revealTx.Hash()) {
		t.Fatal("pool still holds the included data reveal")
	}
	d.requireSpend(2, revealTx, d.reveal, ghostpriv.PurposeReveal)
	requireErr(t, p.Add([]*types.Transaction{revealTx}, true, true)[0], ghostpriv.ErrDataRevealMarker, "the data reveal again after its block")

	// Proof of holding of B, against block 1's data root and block 2's
	// marker-set root, which holds A's marker and not B's.
	if got := *d.header(2).DataMarkerRoot; got != d.hold.MarkerSetRoot {
		t.Fatalf("block 2 marker-set root %x, the hold's %x; %s", got, d.hold.MarkerSetRoot, realDataRegenerate)
	}
	if err := ghostpriv.VerifyHold(d.holdAt(1, 2), d.holdProof); err != nil {
		t.Fatalf("the real proof of holding of B: %v", err)
	}
	for name, change := range map[string]func(*ghostpriv.HoldInputs){
		"A's content fingerprint": func(in *ghostpriv.HoldInputs) { in.Cf = realContentFingerprint(realContentA) },
		"another verifier":        func(in *ghostpriv.HoldInputs) { in.Verifier[0] ^= 1 },
		"another challenge":       func(in *ghostpriv.HoldInputs) { in.Challenge[0] ^= 1 },
		"the genesis marker set":  func(in *ghostpriv.HoldInputs) { in.MarkerSetRoot = ghosttree.EmptyMarkerSetRoot },
	} {
		in := d.holdAt(1, 2)
		change(in)
		requireErr(t, ghostpriv.VerifyHold(in, d.holdProof), ghostpriv.ErrProofRejected, "the proof of holding with "+name)
	}

	// Block 3: the revoke of B.
	if err := p.Add([]*types.Transaction{revokeTx}, true, true)[0]; err != nil {
		t.Fatalf("pool refused the real data revoke: %v", err)
	}
	blocks = d.makeBlocks(blocks[1].Transactions(), p.PendingReveals())
	if blocks[1].Hash() != d.blocks[1].Hash() {
		t.Fatal("block 2 generated again differs")
	}
	d.blocks = blocks
	old = d.chain.CurrentBlock()
	d.insert(3)
	d.reset(p, old)
	d.requireSpend(3, revokeTx, d.revoke, ghostpriv.PurposeRevoke)
	requireErr(t, p.Add([]*types.Transaction{revokeTx}, true, true)[0], ghostpriv.ErrDataRevealMarker, "the revoke again after its block")
	if got := *d.header(3).DataMarkerRoot; got != d.markersAfter {
		t.Fatalf("block 3 marker-set root %x, the fixture's %x; %s", got, d.markersAfter, realDataRegenerate)
	}

	// After the revoke, a verifier taking the current marker-set root
	// refuses the proof of holding of B. The fixture's generator checked
	// that no honest proof against that root can be made.
	requireErr(t, ghostpriv.VerifyHold(d.holdAt(1, 3), d.holdProof), ghostpriv.ErrProofRejected, "the proof of holding of B after the revoke")
	requireErr(t, ghostpriv.VerifyHold(d.holdAt(3, 3), d.holdProof), ghostpriv.ErrProofRejected, "the proof of holding of B at block 3's roots")
}

// requireSpend checks the block at height number carries tx alone and that
// it spent r's marker under the default verifier: the receipt, the marker in
// the set and the reserve settled.
func (d *realData) requireSpend(number uint64, tx *types.Transaction, r *ghostpriv.DataReveal, purpose byte) {
	t := d.t
	t.Helper()
	if v := ghostpriv.ActiveVerifier(); v != ghostpriv.DefaultVerifier() {
		t.Fatalf("active verifier %T, want the default", v)
	}
	block := d.chain.GetBlockByNumber(number)
	if head := d.chain.CurrentBlock(); head.Hash() != block.Hash() {
		t.Fatalf("head %d, want block %d", head.Number, number)
	}
	if txs := block.Transactions(); len(txs) != 1 || txs[0].Hash() != tx.Hash() {
		t.Fatalf("block %d does not carry the spend alone", number)
	}
	rs := d.chain.GetReceiptsByHash(block.Hash())
	if len(rs) != 1 || rs[0].Status != types.ReceiptStatusSuccessful || len(rs[0].Logs) != 1 {
		t.Fatalf("block %d receipts: %+v", number, rs)
	}
	l := rs[0].Logs[0]
	if l.Address != ghosttree.TreeAccount(ghosttree.Data) || len(l.Topics) != 2 || l.Topics[0] != ghosttree.K(ghostpriv.TagDataRevealReceipt) || l.Topics[1] != r.Marker {
		t.Errorf("block %d log: address %x topics %x", number, l.Address, l.Topics)
	}
	if want := append([]byte{purpose}, r.Verifier[:]...); !bytes.Equal(l.Data, want) {
		t.Errorf("block %d log data %x, want %x", number, l.Data, want)
	}
	st, err := d.chain.StateAt(block.Root())
	if err != nil {
		t.Fatal(err)
	}
	if !ghosttree.IsSpent(st, ghosttree.Data, r.Marker) {
		t.Errorf("block %d: marker not spent", number)
	}
	if root, err := ghosttree.DataMarkerRoot(st); err != nil || block.Header().DataMarkerRoot == nil || root != *block.Header().DataMarkerRoot {
		t.Errorf("block %d: state marker-set root %x (%v), header %v", number, root, err, block.Header().DataMarkerRoot)
	}
	if _, out := ghostpriv.Totals(st); !out.Eq(new(uint256.Int).Mul(ghostpriv.DataReserve, uint256.NewInt(number-1))) {
		t.Errorf("block %d: total out %v, want %d reserves", number, out, number-1)
	}
}
