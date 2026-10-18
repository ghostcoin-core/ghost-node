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
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
	"github.com/holiman/uint256"
)

// useZeroDataFee turns the test-only zero data reveal fee on for the test.
func useZeroDataFee(t *testing.T) {
	restore := ghostpriv.SetDataRevealZeroFee(true)
	t.Cleanup(restore)
}

func testDataMarker(name string) common.Hash {
	return ghosttree.K(ghostpriv.TagDataMarker, []byte("synthetic data marker "+name))
}

// newDataReveal is a data reveal of the given fields, zero fee, with the stub
// proof of its binding digest on this chain.
func (f *fixture) newDataReveal(root, marker common.Hash, purpose byte, verifier common.Address) *ghostpriv.DataReveal {
	r := &ghostpriv.DataReveal{
		Version:  ghostpriv.Version,
		ChainID:  f.chainID,
		Marker:   marker,
		Root:     root,
		Purpose:  ghostpriv.PurposeField(purpose),
		Verifier: verifier,
		Out:      new(uint256.Int),
		Fee:      new(uint256.Int),
	}
	f.proveData(r)
	return r
}

// proveData sets the stub proof of the data reveal's binding digest.
func (f *fixture) proveData(r *ghostpriv.DataReveal) {
	r.Proof = ghostprivtest.Proof(r.BindingDigest(f.chainID, f.genesis.Hash()))
}

func cloneData(r *ghostpriv.DataReveal) *ghostpriv.DataReveal {
	cp := *r
	cp.Out = new(uint256.Int).Set(r.Out)
	cp.Fee = new(uint256.Int).Set(r.Fee)
	cp.Proof = common.CopyBytes(r.Proof)
	return &cp
}

func dataEnvelope(t *testing.T, r *ghostpriv.DataReveal) []byte {
	t.Helper()
	env, err := r.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func dataRevealTx(t *testing.T, r *ghostpriv.DataReveal) *types.Transaction {
	t.Helper()
	tx, err := types.NewGhostDataRevealTx(dataEnvelope(t, r))
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

// genParentDataRoot is the data root of the parent of the block being
// generated.
func genParentDataRoot(b *core.BlockGen) common.Hash {
	return *b.PrevBlock(int(b.Number().Uint64()) - 2).Header().DataTreeRoot
}

// dataRevealLog is the receipt log data a data reveal writes.
func dataRevealLog(purpose byte, verifier common.Address) []byte {
	return append([]byte{purpose}, verifier[:]...)
}

// countingVerifier counts the proofs it is asked to verify and hands them
// to the stub.
type countingVerifier struct {
	calls int
	last  ghostpriv.VerifyInputs
}

func (v *countingVerifier) VerifyReveal(in *ghostpriv.VerifyInputs, proof []byte) error {
	v.calls++
	v.last = *in
	return ghostprivtest.Verifier{}.VerifyReveal(in, proof)
}

// checkDataReceipt checks a data reveal's receipt: type 0x51, status 1,
// G_PRIV gas and one log with the marker, the purpose and the
// verifier-or-recipient field.
func checkDataReceipt(t *testing.T, r *types.Receipt, tx *types.Transaction, marker common.Hash, purpose byte, verifier common.Address) {
	t.Helper()
	if r.Type != types.GhostDataRevealTxType || r.Status != types.ReceiptStatusSuccessful || r.GasUsed != ghostpriv.GasPriv || r.TxHash != tx.Hash() {
		t.Fatalf("receipt: type %#x status %d gas %d", r.Type, r.Status, r.GasUsed)
	}
	if len(r.Logs) != 1 {
		t.Fatalf("%d logs", len(r.Logs))
	}
	l := r.Logs[0]
	if l.Address != ghosttree.TreeAccount(ghosttree.Data) {
		t.Errorf("log address %x", l.Address)
	}
	if len(l.Topics) != 2 || l.Topics[0] != ghosttree.K("ghost/data-reveal-receipt/v1") || l.Topics[1] != marker {
		t.Errorf("log topics %x", l.Topics)
	}
	if want := dataRevealLog(purpose, verifier); !bytes.Equal(l.Data, want) {
		t.Errorf("log data %x, want %x", l.Data, want)
	}
}

// dataSnapshot reads everything a data reveal must not change, and the
// marker sets it may.
func dataSnapshot(t *testing.T, chain *core.BlockChain, root common.Hash, addrs []common.Address, markers []common.Hash) map[string]string {
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
		snap["data marker "+m.Hex()] = st.GetState(ghosttree.MarkerAccount(ghosttree.Data), m).Hex()
		snap["coin marker "+m.Hex()] = st.GetState(ghosttree.MarkerAccount(ghosttree.Coin), m).Hex()
	}
	for _, kind := range []ghosttree.Kind{ghosttree.Coin, ghosttree.Data} {
		for i := uint64(0); i < ghosttree.SlotFrontier+ghosttree.MaxDepth; i++ {
			snap[kind.String()+" slot "+big.NewInt(int64(i)).String()] = st.GetState(ghosttree.TreeAccount(kind), ghosttree.Slot(i)).Hex()
		}
	}
	in, out := totals(st)
	snap["total in"], snap["total out"] = in.String(), out.String()
	return snap
}

// noProofVerified fails the test if the counting verifier was asked for a
// proof.
func noProofVerified(t *testing.T, v *countingVerifier, what string) {
	t.Helper()
	if v.calls != 0 {
		t.Errorf("%s: %d proofs verified", what, v.calls)
	}
	v.calls = 0
}

// checkDataBindingLayout checks the 164 bytes of the data binding digest
// field by field, its tag, that the node supplies the chain id, version,
// domain and type, that every field it covers changes it, and that it never
// equals the coin digest of the same fields.
func checkDataBindingLayout(t *testing.T) {
	t.Helper()
	layout := func() *ghostpriv.DataReveal {
		return &ghostpriv.DataReveal{
			Version:  ghostpriv.Version,
			ChainID:  0x0102030405060708,
			Marker:   filled(0x11),
			Root:     filled(0x22),
			Purpose:  ghostpriv.PurposeField(ghostpriv.PurposeRevoke),
			Verifier: common.BytesToAddress(bytes.Repeat([]byte{0x44}, 20)),
			Out:      new(uint256.Int),
			Fee:      uint256.NewInt(0x6666),
			Proof:    bytes.Repeat([]byte{0x99}, 100),
		}
	}
	r := layout()
	const chainID = 6_777_971
	genesis := filled(0x88)
	in := r.BindingInput(chainID, genesis)
	if len(in) != 164 || ghostpriv.DataBindingSize != 164 {
		t.Fatalf("data binding input of %d bytes", len(in))
	}
	var want []byte
	want = binary.BigEndian.AppendUint64(want, chainID)
	want = append(want, 0x00, 0x01)
	want = append(want, genesis[:]...)
	want = append(want, 0x51)       // the transaction type
	want = append(want, 0x02, 0x01) // statement and statement version
	want = append(want, 0x02, 0x01) // DATA
	want = append(want, 0x02)       // purpose: revoke
	want = append(want, r.Verifier[:]...)
	want = append(want, r.Root[:]...)
	want = append(want, r.Marker[:]...)
	want = append(want, word(0x6666)...)
	if !bytes.Equal(in, want) {
		t.Fatalf("data binding input\n%x\nwant\n%x", in, want)
	}
	tag := "ghost/data-reveal-binding/v1"
	digest := r.BindingDigest(chainID, genesis)
	if raw := crypto.Keccak256Hash([]byte{byte(len(tag))}, []byte(tag), in); digest != raw {
		t.Fatalf("digest %x, want %x", digest, raw)
	}

	// The node supplies the chain id and the version; the proof is not
	// covered.
	other := layout()
	other.ChainID, other.Version, other.Proof = 1, 9, nil
	if other.BindingDigest(chainID, genesis) != digest {
		t.Fatal("the payload's chain id, version or proof entered the digest")
	}
	for name, change := range map[string]func(r *ghostpriv.DataReveal){
		"marker":   func(r *ghostpriv.DataReveal) { r.Marker[0] ^= 1 },
		"root":     func(r *ghostpriv.DataReveal) { r.Root[31] ^= 1 },
		"purpose":  func(r *ghostpriv.DataReveal) { r.Purpose = ghostpriv.PurposeField(ghostpriv.PurposeReveal) },
		"verifier": func(r *ghostpriv.DataReveal) { r.Verifier[19] ^= 1 },
		"fee":      func(r *ghostpriv.DataReveal) { r.Fee.AddUint64(r.Fee, 1) },
	} {
		m := layout()
		change(m)
		if m.BindingDigest(chainID, genesis) == digest {
			t.Errorf("changing the %s leaves the digest", name)
		}
	}
	if r.BindingDigest(chainID+1, genesis) == digest || r.BindingDigest(chainID, filled(0x89)) == digest {
		t.Error("the chain id or domain does not enter the digest")
	}

	// The coin digest of the same fields is another value, and its stub
	// proof does not verify the data reveal.
	for _, p := range []byte{ghostpriv.PurposeReveal, ghostpriv.PurposeRevoke} {
		d := layout()
		d.Purpose = ghostpriv.PurposeField(p)
		coin := &ghostpriv.Reveal{
			Version: ghostpriv.Version, ChainID: d.ChainID, Marker: d.Marker, Root: d.Root,
			Remainder: d.Purpose, Recipient: d.Verifier, Out: new(uint256.Int), Fee: d.Fee.Clone(),
		}
		coinDigest, dataDigest := coin.BindingDigest(chainID, genesis), d.BindingDigest(chainID, genesis)
		if coinDigest == dataDigest {
			t.Fatalf("purpose %d: the data digest equals the coin digest", p)
		}
		in := &ghostpriv.VerifyInputs{Kind: ghosttree.Data, Purpose: p, Binding: dataDigest}
		if err := (ghostprivtest.Verifier{}).VerifyReveal(in, ghostprivtest.Proof(coinDigest)); err == nil {
			t.Fatalf("purpose %d: the stub proof of the coin digest verified a data reveal", p)
		}
		if err := (ghostprivtest.Verifier{}).VerifyReveal(in, ghostprivtest.Proof(dataDigest)); err != nil {
			t.Fatalf("purpose %d: the stub proof of the data digest: %v", p, err)
		}
	}
}

// checkDataEnvelopeLayout checks that a data reveal envelope has the coin
// reveal's size and offsets under its own type byte, and that each decoder
// takes only its own type.
func checkDataEnvelopeLayout(t *testing.T) {
	t.Helper()
	r := &ghostpriv.DataReveal{
		Version:  ghostpriv.Version,
		ChainID:  0x0102030405060708,
		Marker:   filled(0x11),
		Root:     filled(0x22),
		Purpose:  ghostpriv.PurposeField(ghostpriv.PurposeReveal),
		Verifier: common.BytesToAddress(bytes.Repeat([]byte{0x44}, 20)),
		Proof:    bytes.Repeat([]byte{0x99}, 100),
	}
	env := dataEnvelope(t, r)
	if types.GhostDataRevealEnvelopeSize != ghostpriv.EnvelopeSize {
		t.Fatalf("data reveal envelope size %d, coin reveal %d", types.GhostDataRevealEnvelopeSize, ghostpriv.EnvelopeSize)
	}
	if len(env) != ghostpriv.EnvelopeSize || env[0] != 0x51 {
		t.Fatalf("data reveal envelope of %d bytes, type %#x", len(env), env[0])
	}
	p := env[1:]
	for _, f := range []struct {
		name     string
		from, to int
		want     []byte
	}{
		{"version", 0, 2, []byte{0, 1}},
		{"chain_id", 2, 10, []byte{1, 2, 3, 4, 5, 6, 7, 8}},
		{"marker", 10, 42, r.Marker[:]},
		{"root", 42, 74, r.Root[:]},
		{"purpose", 74, 106, append(make([]byte, 31), 0x01)},
		{"verifier-or-recipient", 106, 126, r.Verifier[:]},
		{"out", 126, 158, make([]byte, 32)},
		{"fee", 158, 190, make([]byte, 32)},
		{"proof", 190, 290, r.Proof},
		{"proof padding and note", 290, 1_311_066, make([]byte, 1_311_066-290)},
	} {
		if !bytes.Equal(p[f.from:f.to], f.want) {
			t.Errorf("payload field %s at %d to %d", f.name, f.from, f.to)
		}
	}
	dec, err := ghostpriv.DecodeDataReveal(env)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := dec.MarshalBinary(); err != nil || !bytes.Equal(again, env) {
		t.Fatal("re-encoding differs")
	}
	if _, err := ghostpriv.DecodeReveal(env); !errors.Is(err, ghostpriv.ErrRevealLength) {
		t.Fatalf("a data reveal decoded as a coin reveal: %v", err)
	}
	coin, err := ghostpriv.DecodeDataReveal(append([]byte{types.GhostRevealTxType}, env[1:]...))
	if !errors.Is(err, ghostpriv.ErrDataRevealLength) || coin != nil {
		t.Fatalf("a coin reveal envelope decoded as a data reveal: %v", err)
	}
	for name, bad := range map[string][]byte{
		"one byte short": env[:len(env)-1],
		"one byte long":  append(append([]byte{}, env...), 0),
		"empty":          nil,
	} {
		if _, err := ghostpriv.DecodeDataReveal(bad); !errors.Is(err, ghostpriv.ErrDataRevealLength) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestDataRevealOnceThenSecondRejected reveals a file once on the internal
// network, then tries its marker again in a later block and twice in one
// block: each second use is rejected and the block carrying it is invalid.
func TestDataRevealOnceThenSecondRejected(t *testing.T) {
	useStub(t)
	useZeroDataFee(t)
	f := newFixture(t, 50_000_000, nil)
	var (
		file     = testDataFile("once")
		marker   = testDataMarker("once")
		verifier = common.Address{0x7e, 0x01}
		first    *types.Transaction
		again    *types.Transaction
	)
	gen := func(i int, b *core.BlockGen) {
		switch i {
		case 0:
			b.AddTx(f.dataCommitTx(keyA, 0, file, new(big.Int)))
		case 2:
			first = dataRevealTx(t, f.newDataReveal(genParentDataRoot(b), marker, ghostpriv.PurposeReveal, verifier))
			b.AddTx(first)
		case 4:
			b.AddUncheckedTx(again)
		}
	}
	blocks, _ := f.generate(4, gen)
	chain := f.newChain()
	f.insert(chain, blocks)

	// The reveal: one marker in the data set, its receipt, its gas.
	stored := chain.GetBlockByHash(blocks[2].Hash()).Transactions()
	if len(stored) != 1 || stored[0].Type() != types.GhostDataRevealTxType || stored[0].Hash() != first.Hash() {
		t.Fatal("the block does not carry the data reveal")
	}
	receipts := chain.GetReceiptsByHash(blocks[2].Hash())
	if len(receipts) != 1 || blocks[2].GasUsed() != ghostpriv.GasPriv {
		t.Fatalf("%d receipts, gas used %d", len(receipts), blocks[2].GasUsed())
	}
	checkDataReceipt(t, receipts[0], first, marker, ghostpriv.PurposeReveal, verifier)
	st, err := chain.StateAt(blocks[2].Root())
	if err != nil {
		t.Fatal(err)
	}
	if !ghosttree.IsSpent(st, ghosttree.Data, marker) || ghosttree.IsSpent(st, ghosttree.Coin, marker) {
		t.Fatal("the marker is not in the data set alone")
	}
	if st.GetNonce(ghosttree.MarkerAccount(ghosttree.Data)) != 1 {
		t.Fatal("the data marker account has no nonce")
	}
	before, err := chain.StateAt(blocks[1].Root())
	if err != nil {
		t.Fatal(err)
	}
	if ghosttree.IsSpent(before, ghosttree.Data, marker) {
		t.Fatal("the marker was spent before the reveal")
	}

	// A second reveal of the marker in a later block, to another verifier
	// with a proof valid for its own fields, is rejected.
	env, stHead := nextEnv(t, chain, blocks[3].Header(), common.Address{0xcb})
	root := *blocks[0].Header().DataTreeRoot
	r := f.newDataReveal(root, marker, ghostpriv.PurposeReveal, common.Address{0x7e, 0x02})
	if _, _, err := ghostpriv.CheckDataReveal(stHead.Copy(), env, stub, dataEnvelope(t, r)); !errors.Is(err, ghostpriv.ErrDataRevealMarker) {
		t.Fatalf("second reveal: %v, want %v", err, ghostpriv.ErrDataRevealMarker)
	}
	// With a fresh marker the same reveal passes: the marker is the reason.
	fresh := cloneData(r)
	fresh.Marker = testDataMarker("once, fresh")
	f.proveData(fresh)
	if _, _, err := ghostpriv.CheckDataReveal(stHead.Copy(), env, stub, dataEnvelope(t, fresh)); err != nil {
		t.Fatalf("control reveal: %v", err)
	}

	// A block carrying the second reveal is invalid.
	again = dataRevealTx(t, r)
	longer, _ := f.generate(5, gen)
	if longer[3].Hash() != blocks[3].Hash() {
		t.Fatal("the chain did not rebuild identically")
	}
	if _, err := chain.InsertChain(longer[4:]); !errors.Is(err, ghostpriv.ErrDataRevealMarker) {
		t.Fatalf("block with the second reveal: %v, want %v", err, ghostpriv.ErrDataRevealMarker)
	}
	if chain.CurrentBlock().Hash() != blocks[3].Hash() {
		t.Fatal("the head moved")
	}

	// Two reveals of one marker in one block: the block is invalid and
	// nothing of it stays. Two markers in one block import.
	build := func(second common.Hash, unchecked bool) []*types.Block {
		blocks, _ := f.generate(3, func(i int, b *core.BlockGen) {
			switch i {
			case 0:
				b.AddTx(f.dataCommitTx(keyA, 0, file, new(big.Int)))
			case 2:
				root := genParentDataRoot(b)
				b.AddTx(dataRevealTx(t, f.newDataReveal(root, marker, ghostpriv.PurposeReveal, verifier)))
				tx := dataRevealTx(t, f.newDataReveal(root, second, ghostpriv.PurposeReveal, common.Address{0x7e, 0x03}))
				if unchecked {
					b.AddUncheckedTx(tx)
				} else {
					b.AddTx(tx)
				}
			}
		})
		return blocks
	}
	twice := f.newChain()
	bad := build(marker, true)
	f.insert(twice, bad[:2])
	if len(bad[2].Transactions()) != 2 {
		t.Fatal("the block does not carry both reveals")
	}
	if _, err := twice.InsertChain(bad[2:]); !errors.Is(err, ghostpriv.ErrDataRevealMarker) {
		t.Fatalf("block with two reveals of one marker: %v, want %v", err, ghostpriv.ErrDataRevealMarker)
	}
	if twice.CurrentBlock().Hash() != bad[1].Hash() {
		t.Fatal("the head moved")
	}
	stTwice, err := twice.State()
	if err != nil {
		t.Fatal(err)
	}
	if ghosttree.IsSpent(stTwice, ghosttree.Data, marker) {
		t.Fatal("something of the invalid block stayed")
	}
	good := build(testDataMarker("once, other"), false)
	if good[1].Hash() != bad[1].Hash() {
		t.Fatal("the chain did not rebuild identically")
	}
	f.insert(twice, good[2:])
	if twice.CurrentBlock().Hash() != good[2].Hash() || good[2].GasUsed() != 2*ghostpriv.GasPriv {
		t.Fatal("the block with two markers was not imported")
	}
}

// TestDataRevealRevokePurposeSeparate checks that the purpose is part of the
// binding digest: a revoke presented as a reveal, or a reveal as a revoke,
// fails at the proof check, and an unknown purpose fails at the purpose
// check with no proof verified. After a revoke the marker is spent, so any
// later reveal or second revoke of it is rejected and the block carrying it
// is invalid. It also checks the layout of the digest.
func TestDataRevealRevokePurposeSeparate(t *testing.T) {
	checkDataBindingLayout(t)
	useStub(t)
	useZeroDataFee(t)
	f := newFixture(t, ghost.InternalNetGasLimit, nil)
	var (
		file     = testDataFile("purpose")
		marker   = testDataMarker("purpose")
		verifier = common.Address{0x7e, 0x0f}
		later    *types.Transaction
		revokeTx *types.Transaction
	)
	gen := func(i int, b *core.BlockGen) {
		switch i {
		case 0:
			b.AddTx(f.dataCommitTx(keyA, 0, file, new(big.Int)))
		case 3:
			revokeTx = dataRevealTx(t, f.newDataReveal(genParentDataRoot(b), marker, ghostpriv.PurposeRevoke, verifier))
			b.AddTx(revokeTx)
		case 4:
			b.AddUncheckedTx(later)
		}
	}
	blocks, _ := f.generate(3, gen)
	chain := f.newChain()
	f.insert(chain, blocks)
	env, st := nextEnv(t, chain, blocks[2].Header(), common.Address{0xcb})
	root := *blocks[0].Header().DataTreeRoot
	counter := &countingVerifier{}
	check := func(r *ghostpriv.DataReveal) error {
		_, _, err := ghostpriv.CheckDataReveal(st.Copy(), env, counter, dataEnvelope(t, r))
		return err
	}

	reveal := f.newDataReveal(root, marker, ghostpriv.PurposeReveal, verifier)
	revoke := f.newDataReveal(root, marker, ghostpriv.PurposeRevoke, verifier)
	if reveal.BindingDigest(f.chainID, f.genesis.Hash()) == revoke.BindingDigest(f.chainID, f.genesis.Hash()) {
		t.Fatal("a reveal and a revoke share a binding digest")
	}
	for name, r := range map[string]*ghostpriv.DataReveal{"reveal": reveal, "revoke": revoke} {
		counter.calls = 0
		if err := check(r); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want := ghostpriv.PurposeReveal
		if name == "revoke" {
			want = ghostpriv.PurposeRevoke
		}
		if counter.calls != 1 || counter.last.Kind != ghosttree.Data || counter.last.Purpose != want || counter.last.Recipient != verifier {
			t.Fatalf("%s: verifier saw kind %v purpose %d, %d calls", name, counter.last.Kind, counter.last.Purpose, counter.calls)
		}
		if counter.last.Binding != r.BindingDigest(f.chainID, f.genesis.Hash()) || counter.last.Marker != marker || counter.last.Root != root {
			t.Fatalf("%s: verifier inputs are not the node's", name)
		}
	}

	// A revoke presented as a reveal, and a reveal as a revoke: the proof
	// was made for the other purpose and fails.
	asReveal := cloneData(revoke)
	asReveal.Purpose = ghostpriv.PurposeField(ghostpriv.PurposeReveal)
	asRevoke := cloneData(reveal)
	asRevoke.Purpose = ghostpriv.PurposeField(ghostpriv.PurposeRevoke)
	for name, r := range map[string]*ghostpriv.DataReveal{"revoke as reveal": asReveal, "reveal as revoke": asRevoke} {
		if err := check(r); !errors.Is(err, ghostpriv.ErrDataRevealProof) || !errors.Is(err, ghostprivtest.ErrStubProof) {
			t.Errorf("%s: %v, want %v", name, err, ghostpriv.ErrDataRevealProof)
		}
	}

	// Unknown purposes, each with a proof made for its own fields, fail at
	// the purpose check: no proof is verified.
	counter.calls = 0
	for name, field := range map[string]common.Hash{
		"zero":                   {},
		"0x03":                   ghostpriv.PurposeField(0x03),
		"0xff":                   ghostpriv.PurposeField(0xff),
		"reveal in the first":    {0: 0x01},
		"a leading byte":         {0: 0x01, 31: 0x01},
		"a middle byte":          {15: 0x80, 31: 0x02},
		"a remainder commitment": testCoin("purpose rest", oneGhost).commitment(),
	} {
		r := cloneData(reveal)
		r.Purpose = field
		f.proveData(r)
		if err := check(r); !errors.Is(err, ghostpriv.ErrDataRevealPurpose) {
			t.Errorf("purpose %s: %v, want %v", name, err, ghostpriv.ErrDataRevealPurpose)
		}
	}
	noProofVerified(t, counter, "unknown purposes")

	// Out, or a note, on a data reveal: there is no value and no remainder.
	withOut := cloneData(reveal)
	withOut.Out = uint256.NewInt(1)
	f.proveData(withOut)
	withNote := cloneData(reveal)
	withNote.Note[0] = 1
	f.proveData(withNote)
	for name, r := range map[string]*ghostpriv.DataReveal{"out": withOut, "note": withNote} {
		if err := check(r); !errors.Is(err, ghostpriv.ErrDataRevealShape) {
			t.Errorf("%s: %v, want %v", name, err, ghostpriv.ErrDataRevealShape)
		}
	}
	noProofVerified(t, counter, "out or note")

	// The revoke, in block 4.
	withRevoke, _ := f.generate(4, gen)
	if withRevoke[2].Hash() != blocks[2].Hash() {
		t.Fatal("the chain did not rebuild identically")
	}
	f.insert(chain, withRevoke[3:])
	checkDataReceipt(t, chain.GetReceiptsByHash(withRevoke[3].Hash())[0], revokeTx, marker, ghostpriv.PurposeRevoke, verifier)
	env5, st5 := nextEnv(t, chain, withRevoke[3].Header(), common.Address{0xcb})
	if !ghosttree.IsSpent(st5, ghosttree.Data, marker) {
		t.Fatal("the revoke did not spend the marker")
	}
	// Any later reveal, or a second revoke, of the marker is rejected.
	for _, p := range []byte{ghostpriv.PurposeReveal, ghostpriv.PurposeRevoke} {
		r := f.newDataReveal(root, marker, p, common.Address{0x7e, p})
		if _, _, err := ghostpriv.CheckDataReveal(st5.Copy(), env5, stub, dataEnvelope(t, r)); !errors.Is(err, ghostpriv.ErrDataRevealMarker) {
			t.Errorf("purpose %d after the revoke: %v, want %v", p, err, ghostpriv.ErrDataRevealMarker)
		}
	}
	// A block carrying the later reveal is invalid.
	later = dataRevealTx(t, f.newDataReveal(root, marker, ghostpriv.PurposeReveal, verifier))
	withLater, _ := f.generate(5, gen)
	if withLater[3].Hash() != withRevoke[3].Hash() {
		t.Fatal("the chain did not rebuild identically")
	}
	if _, err := chain.InsertChain(withLater[4:]); !errors.Is(err, ghostpriv.ErrDataRevealMarker) {
		t.Fatalf("block with a reveal after the revoke: %v, want %v", err, ghostpriv.ErrDataRevealMarker)
	}
	if chain.CurrentBlock().Hash() != withRevoke[3].Hash() {
		t.Fatal("the head moved")
	}
}

// TestDataRevealRejectedByDefaultFee checks that while the data reveal fee
// is not settled every data reveal is rejected at the fee check, with no
// proof verified and nothing changed, and a block carrying one is invalid;
// that the test-only switch settles it as zero, rejecting any other fee;
// and that the default verifier still rejects every data reveal.
func TestDataRevealRejectedByDefaultFee(t *testing.T) {
	useStub(t)
	f := newFixture(t, ghost.InternalNetGasLimit, nil)
	var (
		file   = testDataFile("fee")
		marker = testDataMarker("fee")
		bad    *types.Transaction
	)
	gen := func(i int, b *core.BlockGen) {
		switch i {
		case 0:
			b.AddTx(f.dataCommitTx(keyA, 0, file, new(big.Int)))
		case 3:
			b.AddUncheckedTx(bad)
		}
	}
	blocks, _ := f.generate(3, gen)
	chain := f.newChain()
	f.insert(chain, blocks)
	env, st := nextEnv(t, chain, blocks[2].Header(), common.Address{0xcb})
	root := *blocks[0].Header().DataTreeRoot
	counter := &countingVerifier{}
	reveal := f.newDataReveal(root, marker, ghostpriv.PurposeReveal, addrC)
	revoke := f.newDataReveal(root, marker, ghostpriv.PurposeRevoke, addrC)
	windowFee := cloneData(reveal)
	windowFee.Fee = chainWindowFee(t, chain, env.Header).Total
	f.proveData(windowFee)

	// The default: every data reveal, whatever its fee, is rejected.
	for name, r := range map[string]*ghostpriv.DataReveal{"reveal": reveal, "revoke": revoke, "window fee": windowFee} {
		cp := st.Copy()
		rootBefore := cp.IntermediateRoot(true)
		_, _, err := ghostpriv.CheckDataReveal(cp, env, counter, dataEnvelope(t, r))
		if !errors.Is(err, ghostpriv.ErrDataRevealFee) || !errors.Is(err, ghostpriv.ErrDataRevealFeeUnsettled) {
			t.Fatalf("%s by default: %v, want %v", name, err, ghostpriv.ErrDataRevealFeeUnsettled)
		}
		if err := ghostpriv.ApplyDataReveal(cp, env, counter, dataEnvelope(t, r)); !errors.Is(err, ghostpriv.ErrDataRevealFee) {
			t.Fatalf("%s applied by default: %v", name, err)
		}
		if cp.IntermediateRoot(true) != rootBefore || ghosttree.IsSpent(cp, ghosttree.Data, marker) || len(cp.Logs()) != 0 {
			t.Fatalf("%s: a rejected data reveal changed the state", name)
		}
	}
	noProofVerified(t, counter, "the default fee")

	// A block carrying a data reveal is invalid by default.
	bad = dataRevealTx(t, reveal)
	withBad, _ := f.generate(4, gen)
	if withBad[2].Hash() != blocks[2].Hash() {
		t.Fatal("the chain did not rebuild identically")
	}
	if _, err := chain.InsertChain(withBad[3:]); !errors.Is(err, ghostpriv.ErrDataRevealFeeUnsettled) {
		t.Fatalf("block with a data reveal by default: %v, want %v", err, ghostpriv.ErrDataRevealFeeUnsettled)
	}
	if chain.CurrentBlock().Hash() != blocks[2].Hash() {
		t.Fatal("the head moved")
	}

	// With the test-only switch the fee is zero: a zero fee passes and any
	// other is rejected at the fee check, with no proof verified.
	restore := ghostpriv.SetDataRevealZeroFee(true)
	for name, r := range map[string]*ghostpriv.DataReveal{"reveal": reveal, "revoke": revoke} {
		if _, _, err := ghostpriv.CheckDataReveal(st.Copy(), env, stub, dataEnvelope(t, r)); err != nil {
			t.Fatalf("%s with the zero fee: %v", name, err)
		}
	}
	oneWei := cloneData(reveal)
	oneWei.Fee = uint256.NewInt(1)
	f.proveData(oneWei)
	counter.calls = 0
	for name, r := range map[string]*ghostpriv.DataReveal{"one wei": oneWei, "window fee": windowFee} {
		_, _, err := ghostpriv.CheckDataReveal(st.Copy(), env, counter, dataEnvelope(t, r))
		if !errors.Is(err, ghostpriv.ErrDataRevealFee) || errors.Is(err, ghostpriv.ErrDataRevealFeeUnsettled) {
			t.Errorf("fee of %s with the zero fee: %v, want %v", name, err, ghostpriv.ErrDataRevealFee)
		}
	}
	noProofVerified(t, counter, "a non-zero fee")

	// The default verifier rejects every data reveal, the stub's included:
	// the reject-all one, or the linked proof verifier, which verifies only
	// coin reveals.
	if _, _, err := ghostpriv.CheckDataReveal(st.Copy(), env, ghostpriv.DefaultVerifier(), dataEnvelope(t, reveal)); !errors.Is(err, errDefaultDataVerifier) {
		t.Fatalf("default verifier: %v, want %v", err, errDefaultDataVerifier)
	}
	if _, _, err := ghostpriv.CheckDataReveal(st.Copy(), env, nil, dataEnvelope(t, revoke)); !errors.Is(err, errDefaultDataVerifier) {
		t.Fatalf("nil verifier: %v, want %v", err, errDefaultDataVerifier)
	}

	// Turned off again, the default holds.
	restore()
	if _, _, err := ghostpriv.CheckDataReveal(st.Copy(), env, stub, dataEnvelope(t, reveal)); !errors.Is(err, ghostpriv.ErrDataRevealFeeUnsettled) {
		t.Fatalf("after the switch: %v, want %v", err, ghostpriv.ErrDataRevealFeeUnsettled)
	}
}

// TestDataRevealNeverMintsOrTouchesCoinSets reveals and revokes in one block
// next to a coin commit and checks that nothing but the data marker set
// changes: no balance, no total, neither tree, no coin marker. A data reveal
// relabelled as a coin reveal and a coin reveal relabelled as a data reveal
// are rejected with no proof verified, and a coin tree root, the root of
// another kind or one seen only on a side branch is no data reveal's root.
func TestDataRevealNeverMintsOrTouchesCoinSets(t *testing.T) {
	checkDataEnvelopeLayout(t)
	useStub(t)
	useZeroDataFee(t)
	trap := common.Address{0x7a, 0x0d}
	f := newFixture(t, 50_000_000, genesisT.GenesisAlloc{
		trap: {Code: []byte{0xfe}, Balance: new(big.Int)}, // INVALID: any run of it fails
	})
	var (
		c       = testCoin("data never mints", oneGhost)
		file    = testDataFile("never mints")
		mReveal = testDataMarker("never mints")
		mRevoke = testDataMarker("never mints, revoked")
		miner   = common.Address{0xcb, 0x0d}
		extra   *types.Transaction
	)
	gen := func(i int, b *core.BlockGen) {
		switch i {
		case 0:
			b.AddTx(f.commitTx(keyA, 0, c))
			b.AddTx(f.dataCommitTx(keyB, 0, file, new(big.Int)))
		case 3:
			b.SetCoinbase(miner)
			root := genParentDataRoot(b)
			b.AddTx(dataRevealTx(t, f.newDataReveal(root, mReveal, ghostpriv.PurposeReveal, addrC)))
			b.AddTx(dataRevealTx(t, f.newDataReveal(root, mRevoke, ghostpriv.PurposeRevoke, trap)))
		case 4:
			b.AddUncheckedTx(extra)
		}
	}
	blocks, _ := f.generate(4, gen)
	chain := f.newChain()
	f.insert(chain, blocks)
	parent, block := blocks[2], blocks[3]

	// Nothing but the data marker set changed.
	addrs := []common.Address{
		addrA, addrB, addrC, trap, ghost.CommitEntryAddress, ghost.DataCommitEntryAddress, ghost.PrivTotalsAccount,
		ghosttree.TreeAccount(ghosttree.Coin), ghosttree.TreeAccount(ghosttree.Data), ghosttree.MarkerAccount(ghosttree.Coin),
	}
	markers := []common.Hash{mReveal, mRevoke}
	before := dataSnapshot(t, chain, parent.Root(), addrs, markers)
	after := dataSnapshot(t, chain, block.Root(), addrs, markers)
	for k, v := range before {
		if k == "data marker "+mReveal.Hex() || k == "data marker "+mRevoke.Hex() {
			if v != (common.Hash{}).Hex() || after[k] != (common.Hash{31: 1}).Hex() {
				t.Errorf("%s: %s then %s", k, v, after[k])
			}
			continue
		}
		if after[k] != v {
			t.Errorf("%s: %s then %s", k, v, after[k])
		}
	}
	st, err := chain.StateAt(block.Root())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := st.GetBalance(miner), f.engine.params.BlockReward(4); !got.Eq(want) {
		t.Errorf("coinbase %v, want the block reward %v alone", got, want)
	}
	if len(st.GetCode(trap)) != 1 || !st.GetBalance(trap).IsZero() {
		t.Error("the revoke's verifier field was paid or run")
	}
	if *block.Header().CoinTreeRoot != *parent.Header().CoinTreeRoot || *block.Header().DataTreeRoot != *parent.Header().DataTreeRoot {
		t.Error("a data reveal changed a tree root")
	}
	if st.Exist(ghosttree.MarkerAccount(ghosttree.Coin)) {
		t.Error("a data reveal wrote to the coin marker account")
	}
	if block.GasUsed() != 2*ghostpriv.GasPriv {
		t.Errorf("gas used %d", block.GasUsed())
	}
	receipts := chain.GetReceiptsByHash(block.Hash())
	checkDataReceipt(t, receipts[0], block.Transactions()[0], mReveal, ghostpriv.PurposeReveal, addrC)
	checkDataReceipt(t, receipts[1], block.Transactions()[1], mRevoke, ghostpriv.PurposeRevoke, trap)
	if receipts[1].CumulativeGasUsed != 2*ghostpriv.GasPriv {
		t.Errorf("cumulative gas %d", receipts[1].CumulativeGasUsed)
	}

	// The coin set is its own: the data marker, used as a coin marker, still
	// passes the coin reveal checks.
	env, stHead := nextEnv(t, chain, block.Header(), miner)
	coinRoot, dataRoot := *blocks[0].Header().CoinTreeRoot, *blocks[0].Header().DataTreeRoot
	fee := chainWindowFee(t, chain, env.Header).Total
	out := u256(ghostAmount(1, 4))
	rest := new(uint256.Int).Sub(c.value, out)
	rest.Sub(rest, fee)
	coinReveal := f.newReveal(coinRoot, mReveal, testCoin("never mints rest", rest.ToBig()), addrC, out, fee)
	if _, _, err := ghostpriv.CheckReveal(stHead.Copy(), env, stub, envelope(t, coinReveal)); err != nil {
		t.Fatalf("coin reveal with a spent data marker: %v", err)
	}

	// A data reveal relabelled 0x50 fails the coin checks: its zero fee is
	// not the window fee, and with the window fee its data root is no coin
	// root. A coin reveal relabelled 0x51 fails the data checks: its fee is
	// not zero, and with a zero fee its remainder is no purpose. No proof is
	// verified and nothing changes.
	counter := &countingVerifier{}
	dataReveal := f.newDataReveal(dataRoot, testDataMarker("relabelled"), ghostpriv.PurposeReveal, addrC)
	dataWithFee := cloneData(dataReveal)
	dataWithFee.Fee = fee.Clone()
	f.proveData(dataWithFee)
	coinNoFee := f.newReveal(coinRoot, testMarker("relabelled"), testCoin("relabelled rest", oneGhost), addrC, new(uint256.Int), new(uint256.Int))
	relabel := func(env []byte, typ byte) []byte { return append([]byte{typ}, env[1:]...) }
	asCoin := map[string][]byte{
		"data reveal":                 relabel(dataEnvelope(t, dataReveal), types.GhostRevealTxType),
		"data reveal with window fee": relabel(dataEnvelope(t, dataWithFee), types.GhostRevealTxType),
	}
	asData := map[string][]byte{
		"coin reveal":            relabel(envelope(t, coinReveal), types.GhostDataRevealTxType),
		"coin reveal of nothing": relabel(envelope(t, coinNoFee), types.GhostDataRevealTxType),
	}
	wantCoin := map[string]error{"data reveal": ghostpriv.ErrRevealFee, "data reveal with window fee": ghostpriv.ErrRevealRoot}
	wantData := map[string]error{"coin reveal": ghostpriv.ErrDataRevealFee, "coin reveal of nothing": ghostpriv.ErrDataRevealPurpose}
	rootBefore := stHead.Copy().IntermediateRoot(true)
	for name, e := range asCoin {
		cp := stHead.Copy()
		if err := ghostpriv.ApplyReveal(cp, env, counter, e); !errors.Is(err, wantCoin[name]) {
			t.Errorf("%s as type 0x50: %v, want %v", name, err, wantCoin[name])
		}
		if cp.IntermediateRoot(true) != rootBefore {
			t.Errorf("%s as type 0x50 changed the state", name)
		}
		if err := ghostpriv.ApplyDataReveal(stHead.Copy(), env, counter, e); !errors.Is(err, ghostpriv.ErrDataRevealLength) {
			t.Errorf("%s as type 0x50 through the data checks: %v", name, err)
		}
	}
	for name, e := range asData {
		cp := stHead.Copy()
		if err := ghostpriv.ApplyDataReveal(cp, env, counter, e); !errors.Is(err, wantData[name]) {
			t.Errorf("%s as type 0x51: %v, want %v", name, err, wantData[name])
		}
		if cp.IntermediateRoot(true) != rootBefore {
			t.Errorf("%s as type 0x51 changed the state", name)
		}
		if err := ghostpriv.ApplyReveal(stHead.Copy(), env, counter, e); !errors.Is(err, ghostpriv.ErrRevealLength) {
			t.Errorf("%s as type 0x51 through the coin checks: %v", name, err)
		}
	}
	noProofVerified(t, counter, "relabelled reveals")

	// A block carrying a relabelled reveal is invalid and pays nothing.
	relabelledTxs := map[string]*types.Transaction{}
	for name, e := range asCoin {
		tx, err := types.NewGhostRevealTx(e)
		if err != nil {
			t.Fatal(err)
		}
		relabelledTxs[name] = tx
	}
	for name, e := range asData {
		tx, err := types.NewGhostDataRevealTx(e)
		if err != nil {
			t.Fatal(err)
		}
		relabelledTxs[name] = tx
	}
	for name, tx := range relabelledTxs {
		extra = tx
		longer, _ := f.generate(5, gen)
		if longer[3].Hash() != block.Hash() {
			t.Fatal("the chain did not rebuild identically")
		}
		if _, err := chain.InsertChain(longer[4:]); err == nil {
			t.Errorf("block with the %s relabelled was imported", name)
		}
		if chain.CurrentBlock().Hash() != block.Hash() {
			t.Fatalf("%s: the head moved", name)
		}
	}
	stAfter, err := chain.State()
	if err != nil {
		t.Fatal(err)
	}
	if stAfter.GetBalance(addrC).ToBig().Cmp(startBal) != 0 {
		t.Fatal("a relabelled reveal paid out")
	}

	// The data reveal's root: a data tree root of the ancestry, the
	// genesis's included; never a coin tree root, a root of another kind or
	// a root seen only on a side branch.
	check := func(root common.Hash) error {
		r := f.newDataReveal(root, testDataMarker("roots"), ghostpriv.PurposeReveal, addrC)
		_, _, err := ghostpriv.CheckDataReveal(stHead.Copy(), env, stub, dataEnvelope(t, r))
		return err
	}
	for name, root := range map[string]common.Hash{"block 1": dataRoot, "the genesis": *f.genesis.Header().DataTreeRoot} {
		if err := check(root); err != nil {
			t.Errorf("data root of %s: %v", name, err)
		}
	}
	side, _ := f.generate(1, func(i int, b *core.BlockGen) {
		b.SetCoinbase(common.Address{0x5e})
		b.AddTx(f.dataCommitTx(keyC, 0, testDataFile("side only"), new(big.Int)))
	})
	f.insert(chain, side)
	if chain.CurrentBlock().Hash() != block.Hash() || chain.GetHeader(side[0].Hash(), 1) == nil {
		t.Fatal("the side block is not a stored side block")
	}
	for name, root := range map[string]common.Hash{
		"block 1's coin tree":     coinRoot,
		"the genesis's coin tree": *f.genesis.Header().CoinTreeRoot,
		"the stored side block":   *side[0].Header().DataTreeRoot,
		"no block":                {0x0b},
		"the zero hash":           {},
		"a node of the data tree": ghosttree.K(ghosttree.TagDataNode, []byte{0}, file.commitment().Bytes(), common.Hash{}.Bytes()),
		"the data commitment":     file.commitment(),
		"the coin commitment":     c.commitment(),
		"the empty coin tree":     ghosttree.EmptyRoot(ghosttree.Coin),
	} {
		if err := check(root); !errors.Is(err, ghostpriv.ErrDataRevealRoot) {
			t.Errorf("root of %s: %v, want %v", name, err, ghostpriv.ErrDataRevealRoot)
		}
	}
	// The including block's own data root is not below it: block 1 carries
	// the data commit and its root.
	st0, err := chain.StateAt(f.genesis.Root())
	if err != nil {
		t.Fatal(err)
	}
	self := &ghostpriv.BlockEnv{Header: blocks[0].Header(), Chain: chain, ChainID: chain.Config().GetChainID(), Genesis: chain.Genesis().Hash()}
	selfReveal := f.newDataReveal(dataRoot, testDataMarker("self"), ghostpriv.PurposeReveal, addrC)
	if _, _, err := ghostpriv.CheckDataReveal(st0.Copy(), self, stub, dataEnvelope(t, selfReveal)); !errors.Is(err, ghostpriv.ErrDataRevealRoot) {
		t.Errorf("the including block's own data root: %v", err)
	}
	parentReveal := f.newDataReveal(*f.genesis.Header().DataTreeRoot, testDataMarker("self"), ghostpriv.PurposeReveal, addrC)
	if _, _, err := ghostpriv.CheckDataReveal(st0.Copy(), self, stub, dataEnvelope(t, parentReveal)); err != nil {
		t.Errorf("the parent's data root from block 1: %v", err)
	}
}

// TestDataRevealReorgRestoresMarker imports a branch with a reveal and a
// revoke, and a data commit only that branch has, then a heavier branch
// without them: the node ends with the state of a node that only saw the
// heavier branch, both markers unspent and the side branch's data root no
// longer eligible, and the reveal and the revoke can be included again on
// the new branch.
func TestDataRevealReorgRestoresMarker(t *testing.T) {
	useStub(t)
	useZeroDataFee(t)
	f := newFixture(t, 50_000_000, nil)
	var (
		file     = testDataFile("reorg")
		extra    = testDataFile("reorg, branch A only")
		mReveal  = testDataMarker("reorg")
		mRevoke  = testDataMarker("reorg, revoked")
		verifier = common.Address{0x9e, 0x0d}
		minerA   = common.Address{0xa0}
		minerB   = common.Address{0xb0}
	)
	spend := func(b *core.BlockGen) {
		root := genParentDataRoot(b)
		b.AddTx(dataRevealTx(t, f.newDataReveal(root, mReveal, ghostpriv.PurposeReveal, verifier)))
		b.AddTx(dataRevealTx(t, f.newDataReveal(root, mRevoke, ghostpriv.PurposeRevoke, verifier)))
	}
	branch := func(n int, spendAt int) []*types.Block {
		blocks, _ := f.generate(n, func(i int, b *core.BlockGen) {
			switch {
			case i == 0:
				b.AddTx(f.dataCommitTx(keyA, 0, file, new(big.Int)))
			case i >= 4 && spendAt == 4:
				b.SetCoinbase(minerA)
				if i == spendAt {
					spend(b)
					b.AddTx(f.dataCommitTx(keyC, 0, extra, new(big.Int)))
				}
			case i >= 4:
				b.SetCoinbase(minerB)
				if i == spendAt {
					spend(b)
				}
			}
		})
		return blocks
	}
	a := branch(5, 4)  // the reveal and the revoke in block 5
	b := branch(7, -1) // blocks 5 to 7 without them
	if a[3].Hash() != b[3].Hash() || a[4].Hash() == b[4].Hash() {
		t.Fatal("the branches do not fork after block 4")
	}
	addrs := []common.Address{addrA, addrB, addrC, verifier, minerA, minerB}
	markers := []common.Hash{mReveal, mRevoke}

	reorged := f.newChain()
	f.insert(reorged, a)
	st, err := reorged.State()
	if err != nil {
		t.Fatal(err)
	}
	if !ghosttree.IsSpent(st, ghosttree.Data, mReveal) || !ghosttree.IsSpent(st, ghosttree.Data, mRevoke) {
		t.Fatal("branch A did not spend the markers")
	}
	if len(diffMaps(dataSnapshot(t, reorged, a[3].Root(), addrs, markers), dataSnapshot(t, reorged, a[4].Root(), addrs, markers))) == 0 {
		t.Fatal("branch A's block 5 changed nothing")
	}
	onlyA := *a[4].Header().DataTreeRoot

	f.insert(reorged, b)
	if reorged.CurrentBlock().Hash() != b[6].Hash() {
		t.Fatal("the node did not reorganise to branch B")
	}
	onlyB := f.newChain()
	f.insert(onlyB, b)
	after := dataSnapshot(t, reorged, reorged.CurrentBlock().Root, addrs, markers)
	for _, d := range diffMaps(after, dataSnapshot(t, onlyB, onlyB.CurrentBlock().Root, addrs, markers)) {
		t.Errorf("against the node that saw only B: %s", d)
	}
	st, err = reorged.State()
	if err != nil {
		t.Fatal(err)
	}
	if ghosttree.IsSpent(st, ghosttree.Data, mReveal) || ghosttree.IsSpent(st, ghosttree.Data, mRevoke) {
		t.Fatal("a marker stayed spent after the reorganisation")
	}
	if n := dataLeafCount(st); n != 1 {
		t.Fatalf("data tree has %d leaves after the reorganisation", n)
	}

	// On branch B the reveal passes again, and the data root seen only on
	// branch A is not eligible.
	env, stB := nextEnv(t, reorged, b[6].Header(), minerB)
	root := *b[0].Header().DataTreeRoot
	for _, p := range []byte{ghostpriv.PurposeReveal, ghostpriv.PurposeRevoke} {
		marker := map[byte]common.Hash{ghostpriv.PurposeReveal: mReveal, ghostpriv.PurposeRevoke: mRevoke}[p]
		r := f.newDataReveal(root, marker, p, verifier)
		if _, _, err := ghostpriv.CheckDataReveal(stB.Copy(), env, stub, dataEnvelope(t, r)); err != nil {
			t.Errorf("purpose %d on branch B: %v", p, err)
		}
		r = f.newDataReveal(onlyA, marker, p, verifier)
		if _, _, err := ghostpriv.CheckDataReveal(stB.Copy(), env, stub, dataEnvelope(t, r)); !errors.Is(err, ghostpriv.ErrDataRevealRoot) {
			t.Errorf("purpose %d against branch A's data root: %v, want %v", p, err, ghostpriv.ErrDataRevealRoot)
		}
	}

	// The reveal and the revoke are included on branch B.
	longer := branch(8, 7)
	if longer[6].Hash() != b[6].Hash() {
		t.Fatal("branch B did not rebuild identically")
	}
	f.insert(reorged, longer[7:])
	st, err = reorged.State()
	if err != nil {
		t.Fatal(err)
	}
	if !ghosttree.IsSpent(st, ghosttree.Data, mReveal) || !ghosttree.IsSpent(st, ghosttree.Data, mRevoke) {
		t.Fatal("the reveal and the revoke did not apply on branch B")
	}
	receipts := reorged.GetReceiptsByHash(longer[7].Hash())
	if len(receipts) != 2 {
		t.Fatalf("%d receipts on branch B", len(receipts))
	}
	checkDataReceipt(t, receipts[0], longer[7].Transactions()[0], mReveal, ghostpriv.PurposeReveal, verifier)
	checkDataReceipt(t, receipts[1], longer[7].Transactions()[1], mRevoke, ghostpriv.PurposeRevoke, verifier)
	if !st.GetBalance(verifier).IsZero() {
		t.Fatal("the verifier field was paid")
	}
}
