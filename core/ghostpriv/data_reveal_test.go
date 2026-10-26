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
	"reflect"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghostpriv/ghostprivtest"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
	"github.com/holiman/uint256"
)

func testDataMarker(name string) common.Hash {
	return ghosttree.K(ghostpriv.TagDataMarker, []byte("synthetic data marker "+name))
}

// newDataReveal is a data reveal of the given fields and fee, with the stub
// proof of its binding digest on this chain.
func (f *fixture) newDataReveal(root, marker common.Hash, purpose byte, verifier common.Address, fee *uint256.Int) *ghostpriv.DataReveal {
	r := &ghostpriv.DataReveal{
		Version:  ghostpriv.Version,
		ChainID:  f.chainID,
		Marker:   marker,
		Root:     root,
		Purpose:  ghostpriv.PurposeField(purpose),
		Verifier: verifier,
		Out:      new(uint256.Int),
		Fee:      new(uint256.Int).Set(fee),
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

// checkDataBindingLayout checks the 196 bytes of the data binding digest
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
			Cf:       filled(0xcf),
		}
	}
	r := layout()
	const chainID = 6_777_971
	genesis := filled(0x88)
	in := r.BindingInput(chainID, genesis)
	if len(in) != 196 || ghostpriv.DataBindingSize != 196 {
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
	want = append(want, r.Cf[:]...)
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
		"cf":       func(r *ghostpriv.DataReveal) { r.Cf[31] ^= 1 },
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
// reveal's size and offsets under its own type byte, with cf in the first 32
// bytes of the note slot, and that each decoder takes only its own type.
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
		Cf:       filled(0xcf),
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
		{"proof padding", 290, 1_310_910, make([]byte, 1_310_910-290)},
		{"cf", 1_310_910, 1_310_942, r.Cf[:]},
		{"rest of the note slot", 1_310_942, 1_311_066, make([]byte, 124)},
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

// testCf is a synthetic content fingerprint: the node checks none against
// anything, so any 32 bytes do.
func testCf(name string) common.Hash {
	return crypto.Keccak256Hash([]byte("synthetic content fingerprint " + name))
}

// dataRevealChain builds three blocks on the internal network, the first with
// a data commit, and returns the fixture, the environment and state of the
// next block, the data root of block 1 and the window fee of the next block.
func dataRevealChain(t *testing.T, name string) (*fixture, *ghostpriv.BlockEnv, *state.StateDB, common.Hash, *uint256.Int) {
	t.Helper()
	f := newFixture(t, ghost.InternalNetGasLimit, nil)
	blocks, _ := f.generate(3, func(i int, b *core.BlockGen) {
		if i == 0 {
			b.AddTx(f.dataCommitTx(keyA, 0, testDataFile(name), reserve()))
		}
	})
	chain := f.newChain()
	f.insert(chain, blocks)
	env, st := nextEnv(t, chain, blocks[2].Header(), common.Address{0xcb})
	return f, env, st, *blocks[0].Header().DataTreeRoot, chainWindowFee(t, chain, env.Header).Total
}

// genDataFee is the window fee of a data reveal in the block being
// generated.
func genDataFee(t *testing.T, b *core.BlockGen) *uint256.Int {
	t.Helper()
	return genWindowFee(t, b).Total
}

// TestDataRevealCarriesFingerprint checks that cf rides in the first 32 bytes
// of the note slot, at payload offset 190 + 1,310,720, round-trips through
// MarshalBinary and DecodeDataReveal and leaves the envelope at 1,311,067
// bytes, and that a non-zero byte in the other 124 bytes of the slot fails
// check 7 with ErrDataRevealShape before any proof is verified.
func TestDataRevealCarriesFingerprint(t *testing.T) {
	checkDataEnvelopeLayout(t)
	useStub(t)
	f, env, st, root, fee := dataRevealChain(t, "fingerprint")
	cf := testCf("carried")
	r := f.newDataReveal(root, testDataMarker("fingerprint"), ghostpriv.PurposeReveal, common.Address{0x7e, 0xcf}, fee)
	r.Cf = cf
	f.proveData(r)

	enc := dataEnvelope(t, r)
	if len(enc) != 1_311_067 || types.GhostDataRevealEnvelopeSize != 1_311_067 {
		t.Fatalf("data reveal envelope of %d bytes", len(enc))
	}
	const slot = 190 + 1_310_720
	p := enc[1:]
	if !bytes.Equal(p[slot:slot+32], cf[:]) {
		t.Fatalf("note slot starts %x, want cf %x", p[slot:slot+32], cf)
	}
	if !bytes.Equal(p[slot+32:], make([]byte, 124)) || len(p[slot+32:]) != 124 {
		t.Fatal("the rest of the note slot is not 124 zero bytes")
	}
	dec, err := ghostpriv.DecodeDataReveal(enc)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Cf != cf || dec.Note != ([ghostpriv.NoteSize - 32]byte{}) {
		t.Fatalf("decoded cf %x, note %x", dec.Cf, dec.Note)
	}
	if again, err := dec.MarshalBinary(); err != nil || !bytes.Equal(again, enc) {
		t.Fatal("re-encoding differs")
	}
	counter := &countingVerifier{}
	if _, _, err := ghostpriv.CheckDataReveal(st.Copy(), env, counter, enc); err != nil || counter.calls != 1 {
		t.Fatalf("data reveal with cf: %v, %d proofs verified", err, counter.calls)
	}

	// Any non-zero byte after cf is a remainder the data reveal cannot have.
	counter.calls = 0
	for _, at := range []int{32, 33, 64, 100, 155} {
		bad := common.CopyBytes(enc)
		bad[1+slot+at] = 0x01
		if dec, err := ghostpriv.DecodeDataReveal(bad); err != nil || dec.Cf != cf || dec.Note[at-32] != 0x01 {
			t.Fatalf("note slot byte %d: decoded %v", at, err)
		}
		if _, _, err := ghostpriv.CheckDataReveal(st.Copy(), env, counter, bad); !errors.Is(err, ghostpriv.ErrDataRevealShape) {
			t.Errorf("note slot byte %d: %v, want %v", at, err, ghostpriv.ErrDataRevealShape)
		}
	}
	noProofVerified(t, counter, "a note after cf")
}

// TestDataRevealBindsFingerprint checks that cf enters the binding digest: a
// changed cf changes the digest, and a stub proof made for another cf is
// refused at the proof check.
func TestDataRevealBindsFingerprint(t *testing.T) {
	useStub(t)
	f, env, st, root, fee := dataRevealChain(t, "binds")
	for _, purpose := range []byte{ghostpriv.PurposeReveal, ghostpriv.PurposeRevoke} {
		r := f.newDataReveal(root, testDataMarker("binds"), purpose, common.Address{0x7e, 0xb1}, fee)
		r.Cf = testCf("bound")
		f.proveData(r)
		other := cloneData(r)
		other.Cf = testCf("other")
		zero := cloneData(r)
		zero.Cf = common.Hash{}
		digest := r.BindingDigest(f.chainID, f.genesis.Hash())
		if other.BindingDigest(f.chainID, f.genesis.Hash()) == digest || zero.BindingDigest(f.chainID, f.genesis.Hash()) == digest {
			t.Fatalf("purpose %d: changing cf leaves the binding digest", purpose)
		}
		if _, _, err := ghostpriv.CheckDataReveal(st.Copy(), env, stub, dataEnvelope(t, r)); err != nil {
			t.Fatalf("purpose %d with its own cf: %v", purpose, err)
		}
		for name, m := range map[string]*ghostpriv.DataReveal{"another cf": other, "a zero cf": zero} {
			_, _, err := ghostpriv.CheckDataReveal(st.Copy(), env, stub, dataEnvelope(t, m))
			if !errors.Is(err, ghostpriv.ErrDataRevealProof) || !errors.Is(err, ghostprivtest.ErrStubProof) {
				t.Errorf("purpose %d, proof for %s: %v, want %v", purpose, name, err, ghostpriv.ErrDataRevealProof)
			}
		}
		// Proved for its own cf, the other reveal passes: cf is the reason.
		f.proveData(other)
		if _, _, err := ghostpriv.CheckDataReveal(st.Copy(), env, stub, dataEnvelope(t, other)); err != nil {
			t.Fatalf("purpose %d, another cf proved anew: %v", purpose, err)
		}
	}
}

// TestDataRevealVerifyInputsCarryFingerprint checks that the inputs the
// verifier receives from CheckDataReveal carry the reveal's cf, and that
// DataReveal.VerifyInputs, which the pool uses too, gives the same inputs.
func TestDataRevealVerifyInputsCarryFingerprint(t *testing.T) {
	useStub(t)
	f, env, st, root, fee := dataRevealChain(t, "inputs")
	for _, purpose := range []byte{ghostpriv.PurposeReveal, ghostpriv.PurposeRevoke} {
		for _, cf := range []common.Hash{testCf("inputs one"), testCf("inputs two")} {
			r := f.newDataReveal(root, testDataMarker("inputs"), purpose, common.Address{0x7e, 0x1f}, fee)
			r.Cf = cf
			f.proveData(r)
			counter := &countingVerifier{}
			if _, _, err := ghostpriv.CheckDataReveal(st.Copy(), env, counter, dataEnvelope(t, r)); err != nil || counter.calls != 1 {
				t.Fatalf("purpose %d: %v, %d proofs verified", purpose, err, counter.calls)
			}
			if counter.last.Cf != cf {
				t.Errorf("purpose %d: the verifier saw cf %x, want %x", purpose, counter.last.Cf, cf)
			}
			want := r.VerifyInputs(purpose, f.chainID, f.genesis.Hash())
			if want.Cf != cf || want.Binding != r.BindingDigest(f.chainID, f.genesis.Hash()) {
				t.Errorf("purpose %d: VerifyInputs carries cf %x", purpose, want.Cf)
			}
			if !reflect.DeepEqual(*want, counter.last) {
				t.Errorf("purpose %d: the checks gave\n%+v\nVerifyInputs gives\n%+v", purpose, counter.last, *want)
			}
		}
	}
}

// TestDataRevealOnceThenSecondRejected reveals a file once on the internal
// network, then tries its marker again in a later block and twice in one
// block: each second use is rejected and the block carrying it is invalid.
func TestDataRevealOnceThenSecondRejected(t *testing.T) {
	useStub(t)
	f := newFixture(t, 50_000_000, nil)
	var (
		file     = testDataFile("once")
		other    = testDataFile("once, other")
		marker   = testDataMarker("once")
		verifier = common.Address{0x7e, 0x01}
		first    *types.Transaction
		again    *types.Transaction
	)
	// Two data commits, so that the hidden set holds a reserve for a second
	// data reveal.
	gen := func(i int, b *core.BlockGen) {
		switch i {
		case 0:
			b.AddTx(f.dataCommitTx(keyA, 0, file, reserve()))
			b.AddTx(f.dataCommitTx(keyB, 0, other, reserve()))
		case 2:
			first = dataRevealTx(t, f.newDataReveal(genParentDataRoot(b), marker, ghostpriv.PurposeReveal, verifier, genDataFee(t, b)))
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
	r := f.newDataReveal(root, marker, ghostpriv.PurposeReveal, common.Address{0x7e, 0x02}, chainWindowFee(t, chain, env.Header).Total)
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
				b.AddTx(f.dataCommitTx(keyA, 0, file, reserve()))
				b.AddTx(f.dataCommitTx(keyB, 0, other, reserve()))
			case 2:
				root, fee := genParentDataRoot(b), genDataFee(t, b)
				b.AddTx(dataRevealTx(t, f.newDataReveal(root, marker, ghostpriv.PurposeReveal, verifier, fee)))
				tx := dataRevealTx(t, f.newDataReveal(root, second, ghostpriv.PurposeReveal, common.Address{0x7e, 0x03}, fee))
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
	f := newFixture(t, ghost.InternalNetGasLimit, nil)
	var (
		file     = testDataFile("purpose")
		other    = testDataFile("purpose, other")
		marker   = testDataMarker("purpose")
		verifier = common.Address{0x7e, 0x0f}
		later    *types.Transaction
		revokeTx *types.Transaction
	)
	// Two data commits, so that after the revoke the hidden set still holds
	// a reserve and a later reveal fails at the marker.
	gen := func(i int, b *core.BlockGen) {
		switch i {
		case 0:
			b.AddTx(f.dataCommitTx(keyA, 0, file, reserve()))
			b.AddTx(f.dataCommitTx(keyB, 0, other, reserve()))
		case 3:
			revokeTx = dataRevealTx(t, f.newDataReveal(genParentDataRoot(b), marker, ghostpriv.PurposeRevoke, verifier, genDataFee(t, b)))
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

	fee := chainWindowFee(t, chain, env.Header).Total
	reveal := f.newDataReveal(root, marker, ghostpriv.PurposeReveal, verifier, fee)
	revoke := f.newDataReveal(root, marker, ghostpriv.PurposeRevoke, verifier, fee)
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
		r := f.newDataReveal(root, marker, p, common.Address{0x7e, p}, chainWindowFee(t, chain, env5.Header).Total)
		if _, _, err := ghostpriv.CheckDataReveal(st5.Copy(), env5, stub, dataEnvelope(t, r)); !errors.Is(err, ghostpriv.ErrDataRevealMarker) {
			t.Errorf("purpose %d after the revoke: %v, want %v", p, err, ghostpriv.ErrDataRevealMarker)
		}
	}
	// A block carrying the later reveal is invalid.
	later = dataRevealTx(t, f.newDataReveal(root, marker, ghostpriv.PurposeReveal, verifier, chainWindowFee(t, chain, env5.Header).Total))
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

// TestDataRevealSettlesWindowFeeFromReserve includes a data reveal and a data
// revoke paying the window fee, as a coin reveal does, on the internal
// network with no test-only switch: both are accepted, the coinbase gains
// their tips, and the total out grows by a reserve each. A fee of zero, or of
// the window fee plus one, is rejected at the fee check with no proof
// verified and nothing changed, and a block carrying one is invalid. The
// default verifier still rejects every data reveal.
func TestDataRevealSettlesWindowFeeFromReserve(t *testing.T) {
	useStub(t)
	f := newFixture(t, 50_000_000, nil)
	var (
		fileA    = testDataFile("settles A")
		fileB    = testDataFile("settles B")
		mReveal  = testDataMarker("settles")
		mRevoke  = testDataMarker("settles, revoked")
		miner    = common.Address{0xcb, 0x5e}
		verifier = common.Address{0x7e, 0x5e}
		fee      ghostpriv.Fee
		bad      *types.Transaction
	)
	gen := func(i int, b *core.BlockGen) {
		switch i {
		case 0:
			b.AddTx(f.dataCommitTx(keyA, 0, fileA, reserve()))
			b.AddTx(f.dataCommitTx(keyB, 0, fileB, reserve()))
		case 2:
			if bad != nil {
				b.AddUncheckedTx(bad)
				return
			}
			b.SetCoinbase(miner)
			fee = genWindowFee(t, b)
			root := genParentDataRoot(b)
			b.AddTx(dataRevealTx(t, f.newDataReveal(root, mReveal, ghostpriv.PurposeReveal, verifier, fee.Total)))
			b.AddTx(dataRevealTx(t, f.newDataReveal(root, mRevoke, ghostpriv.PurposeRevoke, verifier, fee.Total)))
		}
	}
	blocks, _ := f.generate(3, gen)
	chain := f.newChain()
	f.insert(chain, blocks[:2])

	// The rejections, against the state before the reveals.
	env, st := nextEnv(t, chain, blocks[1].Header(), miner)
	if want := chainWindowFee(t, chain, env.Header); !want.Total.Eq(fee.Total) {
		t.Fatalf("window fee %v, the generated block's %v", want.Total, fee.Total)
	}
	root := *blocks[0].Header().DataTreeRoot
	counter := &countingVerifier{}
	for _, p := range []byte{ghostpriv.PurposeReveal, ghostpriv.PurposeRevoke} {
		for name, paid := range map[string]*uint256.Int{
			"zero":              new(uint256.Int),
			"window fee plus 1": new(uint256.Int).AddUint64(fee.Total, 1),
			"window fee less 1": new(uint256.Int).SubUint64(fee.Total, 1),
		} {
			r := f.newDataReveal(root, mReveal, p, verifier, paid)
			cp := st.Copy()
			rootBefore := cp.IntermediateRoot(true)
			if _, _, err := ghostpriv.CheckDataReveal(cp, env, counter, dataEnvelope(t, r)); !errors.Is(err, ghostpriv.ErrDataRevealFee) {
				t.Errorf("purpose %d, fee %s: %v, want %v", p, name, err, ghostpriv.ErrDataRevealFee)
			}
			if err := ghostpriv.ApplyDataReveal(cp, env, counter, dataEnvelope(t, r)); !errors.Is(err, ghostpriv.ErrDataRevealFee) {
				t.Errorf("purpose %d, fee %s applied: %v, want %v", p, name, err, ghostpriv.ErrDataRevealFee)
			}
			if cp.IntermediateRoot(true) != rootBefore || len(cp.Logs()) != 0 {
				t.Errorf("purpose %d, fee %s: a rejected data reveal changed the state", p, name)
			}
		}
	}
	noProofVerified(t, counter, "a fee other than the window fee")

	// The default verifier rejects every data reveal with the window fee: the
	// reject-all one, or the linked proof verifier, which verifies only coin
	// reveals.
	reveal := f.newDataReveal(root, mReveal, ghostpriv.PurposeReveal, verifier, fee.Total)
	revoke := f.newDataReveal(root, mRevoke, ghostpriv.PurposeRevoke, verifier, fee.Total)
	if _, _, err := ghostpriv.CheckDataReveal(st.Copy(), env, ghostpriv.DefaultVerifier(), dataEnvelope(t, reveal)); !errors.Is(err, errDefaultDataVerifier) {
		t.Fatalf("default verifier: %v, want %v", err, errDefaultDataVerifier)
	}
	if _, _, err := ghostpriv.CheckDataReveal(st.Copy(), env, nil, dataEnvelope(t, revoke)); !errors.Is(err, errDefaultDataVerifier) {
		t.Fatalf("nil verifier: %v, want %v", err, errDefaultDataVerifier)
	}

	// A block carrying a zero-fee data reveal is invalid.
	bad = dataRevealTx(t, f.newDataReveal(root, mReveal, ghostpriv.PurposeReveal, verifier, new(uint256.Int)))
	withBad, _ := f.generate(3, gen)
	if withBad[1].Hash() != blocks[1].Hash() {
		t.Fatal("the chain did not rebuild identically")
	}
	if _, err := chain.InsertChain(withBad[2:]); !errors.Is(err, ghostpriv.ErrDataRevealFee) {
		t.Fatalf("block with a zero-fee data reveal: %v, want %v", err, ghostpriv.ErrDataRevealFee)
	}
	if chain.CurrentBlock().Hash() != blocks[1].Hash() {
		t.Fatal("the head moved")
	}

	// The reveal and the revoke with the window fee are included.
	bad = nil
	f.insert(chain, blocks[2:])
	receipts := chain.GetReceiptsByHash(blocks[2].Hash())
	if len(receipts) != 2 {
		t.Fatalf("%d receipts", len(receipts))
	}
	checkDataReceipt(t, receipts[0], blocks[2].Transactions()[0], mReveal, ghostpriv.PurposeReveal, verifier)
	checkDataReceipt(t, receipts[1], blocks[2].Transactions()[1], mRevoke, ghostpriv.PurposeRevoke, verifier)
	after, err := chain.StateAt(blocks[2].Root())
	if err != nil {
		t.Fatal(err)
	}
	if !ghosttree.IsSpent(after, ghosttree.Data, mReveal) || !ghosttree.IsSpent(after, ghosttree.Data, mRevoke) {
		t.Fatal("the markers are not spent")
	}
	reserves := new(big.Int).Mul(reserve(), big.NewInt(2))
	if in, out := totals(after); in.Cmp(reserves) != 0 || out.Cmp(reserves) != 0 {
		t.Errorf("totals in %v out %v, want %v each", in, out, reserves)
	}
	wantMiner := new(big.Int).Add(f.engine.params.BlockReward(3).ToBig(), new(big.Int).Mul(fee.Tip.ToBig(), big.NewInt(2)))
	if got := after.GetBalance(miner).ToBig(); got.Cmp(wantMiner) != 0 {
		t.Errorf("coinbase %v, want the reward and two tips %v", got, wantMiner)
	}
	if !after.GetBalance(verifier).IsZero() {
		t.Error("the verifier field was paid")
	}
}

// headerChain is a ChainReader of the given headers, by hash.
type headerChain map[common.Hash]*types.Header

func (c headerChain) GetHeader(hash common.Hash, number uint64) *types.Header {
	if h := c[hash]; h != nil && h.Number.Uint64() == number {
		return h
	}
	return nil
}

// TestDataRevealFeeAboveReserveRejectedBeforeProof checks a data reveal in a
// block whose window fee is above the reserve: it is rejected with
// ErrDataRevealFeeAboveReserve before any proof is verified, and nothing
// changes. The fee rule gives no window fee of exactly the reserve, so the
// boundary is the reference base fee whose window fee is the largest not
// above it: that one is accepted, the reserve pays it and forfeits less than
// one step of the fee, and one wei of reference base fee more is refused.
func TestDataRevealFeeAboveReserveRejectedBeforeProof(t *testing.T) {
	useStub(t)
	f, env, st, root, _ := dataRevealChain(t, "above")
	windowFee := func(bRef *big.Int) ghostpriv.Fee {
		fee, err := ghostpriv.WindowFee(bRef)
		if err != nil {
			t.Fatal(err)
		}
		return fee
	}
	// The largest reference base fee whose window fee the reserve pays.
	lo, hi := big.NewInt(1), big.NewInt(1_000_000_000_000)
	for new(big.Int).Sub(hi, lo).Cmp(common.Big1) > 0 {
		mid := new(big.Int).Rsh(new(big.Int).Add(lo, hi), 1)
		if windowFee(mid).Total.Gt(ghostpriv.DataReserve) {
			hi = mid
		} else {
			lo = mid
		}
	}
	at, above := windowFee(lo), windowFee(hi)
	if at.Total.Gt(ghostpriv.DataReserve) || !above.Total.Gt(ghostpriv.DataReserve) {
		t.Fatalf("window fees %v and %v around the reserve", at.Total, above.Total)
	}

	// A chain of the real headers of blocks 0 to 2 but with the given
	// reference base fee, the base fee of each.
	chain := env.Chain.(*core.BlockChain)
	envAt := func(bRef *big.Int) *ghostpriv.BlockEnv {
		hc := headerChain{}
		var parent *types.Header
		for n := uint64(0); n < 3; n++ {
			h := types.CopyHeader(chain.GetHeaderByNumber(n))
			h.BaseFee = new(big.Int).Set(bRef)
			if parent != nil {
				h.ParentHash = parent.Hash()
			}
			hc[h.Hash()] = h
			parent = h
		}
		header := types.CopyHeader(env.Header)
		header.Number = big.NewInt(3)
		header.ParentHash = parent.Hash()
		header.BaseFee = new(big.Int).Set(bRef)
		return &ghostpriv.BlockEnv{Header: header, Chain: hc, ChainID: env.ChainID, Genesis: env.Genesis}
	}

	counter := &countingVerifier{}
	marker := testDataMarker("above")
	for _, p := range []byte{ghostpriv.PurposeReveal, ghostpriv.PurposeRevoke} {
		r := f.newDataReveal(root, marker, p, common.Address{0x7e, 0xab}, above.Total)
		cp := st.Copy()
		rootBefore := cp.IntermediateRoot(true)
		e := envAt(hi)
		_, _, err := ghostpriv.CheckDataReveal(cp, e, counter, dataEnvelope(t, r))
		if !errors.Is(err, ghostpriv.ErrDataRevealFeeAboveReserve) || !errors.Is(err, ghostpriv.ErrDataRevealFee) {
			t.Fatalf("purpose %d, fee %v above the reserve: %v, want %v", p, above.Total, err, ghostpriv.ErrDataRevealFeeAboveReserve)
		}
		if err := ghostpriv.ApplyDataReveal(cp, e, counter, dataEnvelope(t, r)); !errors.Is(err, ghostpriv.ErrDataRevealFeeAboveReserve) {
			t.Fatalf("purpose %d applied: %v, want %v", p, err, ghostpriv.ErrDataRevealFeeAboveReserve)
		}
		if cp.IntermediateRoot(true) != rootBefore || len(cp.Logs()) != 0 || ghosttree.IsSpent(cp, ghosttree.Data, marker) {
			t.Fatalf("purpose %d: a rejected data reveal changed the state", p)
		}
	}
	noProofVerified(t, counter, "a fee above the reserve")

	// The largest window fee the reserve pays is accepted.
	for _, p := range []byte{ghostpriv.PurposeReveal, ghostpriv.PurposeRevoke} {
		r := f.newDataReveal(root, marker, p, common.Address{0x7e, 0xab}, at.Total)
		e := envAt(lo)
		cp := st.Copy()
		if err := ghostpriv.ApplyDataReveal(cp, e, counter, dataEnvelope(t, r)); err != nil || counter.calls != 1 {
			t.Fatalf("purpose %d, fee %v: %v, %d proofs verified", p, at.Total, err, counter.calls)
		}
		counter.calls = 0
		if got := cp.GetBalance(e.Header.Coinbase); !got.Eq(at.Tip) {
			t.Errorf("purpose %d: coinbase %v, want the tip %v", p, got, at.Tip)
		}
		if _, out := totals(cp); out.Cmp(reserve()) != 0 {
			t.Errorf("purpose %d: total out %v, want the reserve", p, out)
		}
		forfeited := new(uint256.Int).Sub(ghostpriv.DataReserve, at.Total)
		if step := new(uint256.Int).Sub(above.Total, at.Total); !forfeited.Lt(step) {
			t.Errorf("purpose %d: %v forfeited, a fee step is %v", p, forfeited, step)
		}
	}
}

// TestDataRevealAccountingMatchesWorkedExample follows the worked example of
// spec 04, section 6: two data commits, A and B, then a reveal of A in the
// first fee window and a revoke of B in the next. The totals after each step,
// and the fee, burn and tip of the first window at its reference base fee of
// 1,000,000,000 wei, are the spec's; each coinbase gains exactly the tip,
// nobody else gains, and the burn, the tip and the forfeited rest make up the
// reserve.
func TestDataRevealAccountingMatchesWorkedExample(t *testing.T) {
	useStub(t)
	f := newFixture(t, ghost.InternalNetGasLimit, nil)
	if bRef := f.genesis.BaseFee(); bRef == nil || bRef.Cmp(gwei) != 0 {
		t.Fatalf("genesis base fee %v, the worked example's is 1,000,000,000", bRef)
	}
	var (
		fileA    = testDataFile("worked example A")
		fileB    = testDataFile("worked example B")
		mA       = testDataMarker("worked example A")
		mB       = testDataMarker("worked example B")
		verifier = common.Address{0x7e, 0x04}
		miner2   = common.Address{0xcb, 0x02}
		miner5   = common.Address{0xcb, 0x05}
		fees     = map[int]ghostpriv.Fee{}
	)
	blocks, _ := f.generate(5, func(i int, b *core.BlockGen) {
		switch i {
		case 0:
			b.AddTx(f.dataCommitTx(keyA, 0, fileA, reserve()))
			b.AddTx(f.dataCommitTx(keyB, 0, fileB, reserve()))
		case 1:
			// Block 2, in the window that starts at the genesis.
			b.SetCoinbase(miner2)
			fees[2] = genWindowFee(t, b)
			b.AddTx(dataRevealTx(t, f.newDataReveal(genParentDataRoot(b), mA, ghostpriv.PurposeReveal, verifier, fees[2].Total)))
		case 4:
			// Block 5, in the window that starts at block 4.
			b.SetCoinbase(miner5)
			fees[5] = genWindowFee(t, b)
			b.AddTx(dataRevealTx(t, f.newDataReveal(*b.PrevBlock(0).Header().DataTreeRoot, mB, ghostpriv.PurposeRevoke, verifier, fees[5].Total)))
		}
	})
	chain := f.newChain()
	f.insert(chain, blocks)
	stateAt := func(n int) *state.StateDB {
		st, err := chain.StateAt(blocks[n-1].Root())
		if err != nil {
			t.Fatal(err)
		}
		return st
	}

	// The spec's numbers for the first window.
	want := ghostpriv.Fee{
		Total: uint256.MustFromDecimal("26100495343659410"),
		Burn:  uint256.MustFromDecimal("23727723039690372"),
		Tip:   uint256.MustFromDecimal("2372772303969038"),
	}
	if got := fees[2]; !got.Total.Eq(want.Total) || !got.Burn.Eq(want.Burn) || !got.Tip.Eq(want.Tip) {
		t.Fatalf("fee of the first window: total %v burn %v tip %v, want %v %v %v", got.Total, got.Burn, got.Tip, want.Total, want.Burn, want.Tip)
	}

	// The totals after each step.
	half := reserve()
	whole := new(big.Int).Mul(half, big.NewInt(2))
	for _, step := range []struct {
		block   int
		in, out *big.Int
	}{
		{1, whole, new(big.Int)},
		{2, whole, half},
		{4, whole, half},
		{5, whole, whole},
	} {
		if in, out := totals(stateAt(step.block)); in.Cmp(step.in) != 0 || out.Cmp(step.out) != 0 {
			t.Errorf("after block %d: totals in %v out %v, want %v and %v", step.block, in, out, step.in, step.out)
		}
	}
	if in, _ := totals(stateAt(1)); in.Cmp(uint256.MustFromDecimal("500000000000000000").ToBig()) != 0 {
		t.Errorf("total in %v", in)
	}

	// Each spend: the coinbase gains its reward and exactly the tip, nobody
	// else gains, and the burn, the tip and the forfeited rest are the
	// reserve.
	accounts := []common.Address{addrA, addrB, addrC, verifier, miner2, miner5, ghost.PrivTotalsAccount,
		ghost.DataCommitEntryAddress, ghosttree.TreeAccount(ghosttree.Data), ghosttree.MarkerAccount(ghosttree.Data)}
	for _, spend := range []struct {
		block int
		miner common.Address
	}{{2, miner2}, {5, miner5}} {
		before, after := stateAt(spend.block-1), stateAt(spend.block)
		fee := fees[spend.block]
		reward := f.engine.params.BlockReward(uint64(spend.block))
		for _, a := range accounts {
			gain := new(big.Int).Sub(after.GetBalance(a).ToBig(), before.GetBalance(a).ToBig())
			wantGain := new(big.Int)
			if a == spend.miner {
				wantGain.Add(reward.ToBig(), fee.Tip.ToBig())
			}
			if gain.Cmp(wantGain) != 0 {
				t.Errorf("block %d: %x gained %v, want %v", spend.block, a, gain, wantGain)
			}
		}
		forfeited := new(uint256.Int).Sub(ghostpriv.DataReserve, fee.Total)
		sum := new(uint256.Int).Add(fee.Burn, fee.Tip)
		if sum.Add(sum, forfeited); !sum.Eq(ghostpriv.DataReserve) {
			t.Errorf("block %d: burn %v, tip %v and forfeited %v make %v", spend.block, fee.Burn, fee.Tip, forfeited, sum)
		}
		if !fee.Burn.Eq(new(uint256.Int).Mul(uint256.NewInt(ghostpriv.GasPriv), fee.Price)) {
			t.Errorf("block %d: burn %v is not G_PRIV times the price %v", spend.block, fee.Burn, fee.Price)
		}
	}
}

// TestDataRevealBackstopReserve checks that a data reveal whose reserve is
// more than the hidden set holds is rejected with ErrDataRevealBackstop
// before its proof is verified, and that one with the hidden set holding
// exactly the reserve passes.
func TestDataRevealBackstopReserve(t *testing.T) {
	useStub(t)
	// Block 1 commits a file, block 2 reveals it, emptying the hidden set,
	// and block 3 commits a coin of the given value.
	build := func(coinValue *big.Int) (*fixture, *ghostpriv.BlockEnv, *state.StateDB, common.Hash) {
		f := newFixture(t, ghost.InternalNetGasLimit, nil)
		var root common.Hash
		blocks, _ := f.generate(3, func(i int, b *core.BlockGen) {
			switch i {
			case 0:
				b.AddTx(f.dataCommitTx(keyA, 0, testDataFile("backstop"), reserve()))
			case 1:
				root = genParentDataRoot(b)
				b.AddTx(dataRevealTx(t, f.newDataReveal(root, testDataMarker("backstop, spent"), ghostpriv.PurposeReveal, addrC, genDataFee(t, b))))
			case 2:
				b.AddTx(f.commitTx(keyB, 0, testCoin("backstop coin", coinValue)))
			}
		})
		chain := f.newChain()
		f.insert(chain, blocks)
		env, st := nextEnv(t, chain, blocks[2].Header(), common.Address{0xcb})
		return f, env, st, root
	}
	below := new(big.Int).Sub(reserve(), common.Big1)
	for _, tt := range []struct {
		name  string
		coin  *big.Int
		want  error
		calls int
	}{
		{"hidden one wei below the reserve", below, ghostpriv.ErrDataRevealBackstop, 0},
		{"hidden exactly the reserve", reserve(), nil, 1},
	} {
		f, env, st, root := build(tt.coin)
		if hidden, err := ghostpriv.Hidden(st); err != nil || hidden.ToBig().Cmp(tt.coin) != 0 {
			t.Fatalf("%s: hidden %v, %v", tt.name, hidden, err)
		}
		fee := chainWindowFee(t, env.Chain.(*core.BlockChain), env.Header).Total
		counter := &countingVerifier{}
		for _, p := range []byte{ghostpriv.PurposeReveal, ghostpriv.PurposeRevoke} {
			r := f.newDataReveal(root, testDataMarker("backstop, fresh"), p, addrC, fee)
			cp := st.Copy()
			rootBefore := cp.IntermediateRoot(true)
			err := ghostpriv.ApplyDataReveal(cp, env, counter, dataEnvelope(t, r))
			if !errors.Is(err, tt.want) || (tt.want == nil) != (err == nil) {
				t.Fatalf("%s, purpose %d: %v, want %v", tt.name, p, err, tt.want)
			}
			if counter.calls != tt.calls {
				t.Errorf("%s, purpose %d: %d proofs verified, want %d", tt.name, p, counter.calls, tt.calls)
			}
			counter.calls = 0
			if tt.want != nil && cp.IntermediateRoot(true) != rootBefore {
				t.Errorf("%s, purpose %d: a rejected data reveal changed the state", tt.name, p)
			}
		}
	}
}

// TestDataRevealNeverMintsOrTouchesCoinSets reveals and revokes in one block
// next to a coin commit and checks that nothing but the data marker set, the
// total out and the coinbase changes: no other balance, neither tree, no coin
// marker. A data reveal
// relabelled as a coin reveal and a coin reveal relabelled as a data reveal
// are rejected with no proof verified, and a coin tree root, the root of
// another kind or one seen only on a side branch is no data reveal's root.
func TestDataRevealNeverMintsOrTouchesCoinSets(t *testing.T) {
	checkDataEnvelopeLayout(t)
	useStub(t)
	trap := common.Address{0x7a, 0x0d}
	f := newFixture(t, 50_000_000, genesisT.GenesisAlloc{
		trap: {Code: []byte{0xfe}, Balance: new(big.Int)}, // INVALID: any run of it fails
	})
	var (
		c       = testCoin("data never mints", oneGhost)
		file    = testDataFile("never mints")
		file2   = testDataFile("never mints, second")
		mReveal = testDataMarker("never mints")
		mRevoke = testDataMarker("never mints, revoked")
		miner   = common.Address{0xcb, 0x0d}
		extra   *types.Transaction
		spent   ghostpriv.Fee
	)
	gen := func(i int, b *core.BlockGen) {
		switch i {
		case 0:
			b.AddTx(f.commitTx(keyA, 0, c))
			b.AddTx(f.dataCommitTx(keyB, 0, file, reserve()))
			b.AddTx(f.dataCommitTx(keyC, 0, file2, reserve()))
		case 3:
			b.SetCoinbase(miner)
			root := genParentDataRoot(b)
			spent = genWindowFee(t, b)
			b.AddTx(dataRevealTx(t, f.newDataReveal(root, mReveal, ghostpriv.PurposeReveal, addrC, spent.Total)))
			b.AddTx(dataRevealTx(t, f.newDataReveal(root, mRevoke, ghostpriv.PurposeRevoke, trap, spent.Total)))
		case 4:
			b.AddUncheckedTx(extra)
		}
	}
	blocks, _ := f.generate(4, gen)
	chain := f.newChain()
	f.insert(chain, blocks)
	parent, block := blocks[2], blocks[3]

	// Nothing but the data marker set and the total out changed: the two
	// reserves left the hidden set, and only the coinbase was paid.
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
		if k == "total out" {
			out, _ := new(big.Int).SetString(v, 10)
			if want := out.Add(out, new(big.Int).Mul(reserve(), big.NewInt(2))); after[k] != want.String() {
				t.Errorf("total out %s then %s, want %v", v, after[k], want)
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
	tips := new(uint256.Int).Mul(spent.Tip, uint256.NewInt(2))
	if got, want := st.GetBalance(miner), new(uint256.Int).Add(f.engine.params.BlockReward(4), tips); !got.Eq(want) {
		t.Errorf("coinbase %v, want the block reward and the two tips %v", got, want)
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
	// root. A coin reveal relabelled 0x51 fails the data checks: with the
	// window fee its remainder is no purpose, and with a zero fee its fee is
	// not the window fee. No proof is verified and nothing changes.
	counter := &countingVerifier{}
	dataReveal := f.newDataReveal(dataRoot, testDataMarker("relabelled"), ghostpriv.PurposeReveal, addrC, new(uint256.Int))
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
	wantData := map[string]error{"coin reveal": ghostpriv.ErrDataRevealPurpose, "coin reveal of nothing": ghostpriv.ErrDataRevealFee}
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
	if !stAfter.GetBalance(addrC).Eq(st.GetBalance(addrC)) {
		t.Fatal("a relabelled reveal paid out")
	}

	// The data reveal's root: a data tree root of the ancestry, the
	// genesis's included; never a coin tree root, a root of another kind or
	// a root seen only on a side branch.
	check := func(root common.Hash) error {
		r := f.newDataReveal(root, testDataMarker("roots"), ghostpriv.PurposeReveal, addrC, fee)
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
		b.AddTx(f.dataCommitTx(keyC, 0, testDataFile("side only"), reserve()))
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
	// the data commit and its root. The state is the head's, whose hidden
	// set holds a reserve: only the root is in question.
	self := &ghostpriv.BlockEnv{Header: blocks[0].Header(), Chain: chain, ChainID: chain.Config().GetChainID(), Genesis: chain.Genesis().Hash()}
	selfFee := chainWindowFee(t, chain, self.Header).Total
	selfReveal := f.newDataReveal(dataRoot, testDataMarker("self"), ghostpriv.PurposeReveal, addrC, selfFee)
	if _, _, err := ghostpriv.CheckDataReveal(stHead.Copy(), self, stub, dataEnvelope(t, selfReveal)); !errors.Is(err, ghostpriv.ErrDataRevealRoot) {
		t.Errorf("the including block's own data root: %v", err)
	}
	parentReveal := f.newDataReveal(*f.genesis.Header().DataTreeRoot, testDataMarker("self"), ghostpriv.PurposeReveal, addrC, selfFee)
	if _, _, err := ghostpriv.CheckDataReveal(stHead.Copy(), self, stub, dataEnvelope(t, parentReveal)); err != nil {
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
	f := newFixture(t, 50_000_000, nil)
	var (
		file     = testDataFile("reorg")
		second   = testDataFile("reorg, second")
		extra    = testDataFile("reorg, branch A only")
		mReveal  = testDataMarker("reorg")
		mRevoke  = testDataMarker("reorg, revoked")
		verifier = common.Address{0x9e, 0x0d}
		minerA   = common.Address{0xa0}
		minerB   = common.Address{0xb0}
	)
	spend := func(b *core.BlockGen) {
		root, fee := genParentDataRoot(b), genDataFee(t, b)
		b.AddTx(dataRevealTx(t, f.newDataReveal(root, mReveal, ghostpriv.PurposeReveal, verifier, fee)))
		b.AddTx(dataRevealTx(t, f.newDataReveal(root, mRevoke, ghostpriv.PurposeRevoke, verifier, fee)))
	}
	branch := func(n int, spendAt int) []*types.Block {
		blocks, _ := f.generate(n, func(i int, b *core.BlockGen) {
			switch {
			case i == 0:
				b.AddTx(f.dataCommitTx(keyA, 0, file, reserve()))
				b.AddTx(f.dataCommitTx(keyB, 0, second, reserve()))
			case i >= 4 && spendAt == 4:
				b.SetCoinbase(minerA)
				if i == spendAt {
					spend(b)
					b.AddTx(f.dataCommitTx(keyC, 0, extra, reserve()))
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
	if n := dataLeafCount(st); n != 2 {
		t.Fatalf("data tree has %d leaves after the reorganisation", n)
	}

	// On branch B the reveal passes again, and the data root seen only on
	// branch A is not eligible.
	env, stB := nextEnv(t, reorged, b[6].Header(), minerB)
	root := *b[0].Header().DataTreeRoot
	fee := chainWindowFee(t, reorged, env.Header).Total
	for _, p := range []byte{ghostpriv.PurposeReveal, ghostpriv.PurposeRevoke} {
		marker := map[byte]common.Hash{ghostpriv.PurposeReveal: mReveal, ghostpriv.PurposeRevoke: mRevoke}[p]
		r := f.newDataReveal(root, marker, p, verifier, fee)
		if _, _, err := ghostpriv.CheckDataReveal(stB.Copy(), env, stub, dataEnvelope(t, r)); err != nil {
			t.Errorf("purpose %d on branch B: %v", p, err)
		}
		r = f.newDataReveal(onlyA, marker, p, verifier, fee)
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
