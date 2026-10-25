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

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghostpriv/ghostprivtest"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
	"github.com/holiman/uint256"
)

// applyTx applies tx to st as the first transaction of the block of header.
func applyTx(chain *core.BlockChain, st *state.StateDB, header *types.Header, tx *types.Transaction) (*types.Receipt, error) {
	gp := new(core.GasPool).AddGas(header.GasLimit)
	var used uint64
	st.SetTxContext(tx.Hash(), 0)
	return core.ApplyTransaction(chain.Config(), chain, &header.Coinbase, gp, st, header, tx, &used, vm.Config{})
}

// commitLog is the receipt log of a commit of c with the zero salt the
// test commits send.
func commitLog(index, position uint32, c coin) []byte {
	return append(commitLogOf(index, position, c.commitment(), c), make([]byte, ghostpriv.SaltSize)...)
}

// saltedCommitment is the version 2 commitment of c, the leaf of a commit of
// c with salted data.
func saltedCommitment(c coin) common.Hash {
	return ghostpriv.CommitmentVersion(ghostpriv.SaltedCommitVersion, c.f, c.value)
}

// commitLogOf is the receipt log of a commit of c recorded under leaf,
// without the salt a salted commit's log carries after the note.
func commitLogOf(index, position uint32, leaf common.Hash, c coin) []byte {
	word := c.value.Bytes32()
	data := binary.BigEndian.AppendUint32(nil, index)
	data = binary.BigEndian.AppendUint32(data, position)
	data = append(data, leaf[:]...)
	data = append(data, word[:]...)
	return append(data, c.note...)
}

// TestCommitBurnsAndRecordsCommitment commits from two account transactions,
// of two accounts with two tips, in one block on the internal network and checks that each
// sender paid exactly its value and its gas, that nobody received the value,
// that the coin tree holds the commitments the node computed under the
// header's root, the receipt logs, and the total in.
func TestCommitBurnsAndRecordsCommitment(t *testing.T) {
	// The known answer of the version 1 commitment, which the leaf of a
	// salted commit of the same F and value is not.
	known := common.HexToHash("b44338ab6f6dcb3d63772c457737afd38a841207725e1440d235c4f6be0c4d8b")
	if got, want := ghostpriv.Commitment(known, uint256.NewInt(1_000_000_000_000_000_000)), common.HexToHash("562d92a92bb8f2b3b772b55220a5ee26f189bedc0f4bfa513205df1545029458"); got != want {
		t.Fatalf("commitment %x, want %x", got, want)
	}

	f := newFixture(t, ghost.InternalNetGasLimit, nil)
	var (
		miner  = common.Address{0xcb}
		first  = coin{f: known, value: uint256.NewInt(1_000_000_000_000_000_000), note: testNote(7)}
		second = testCoin("second", ghostAmount(1, 4))
		txs    []*types.Transaction
	)
	blocks, _ := f.generate(1, func(i int, b *core.BlockGen) {
		b.SetCoinbase(miner)
		txs = append(txs, f.commitTx(keyA, 0, first))
		// A second account commits in the same block, with its tip at the
		// fee cap: the gas price is the fee cap, as a legacy price was.
		data, err := ghostpriv.SaltedCommitData(second.f, make([]byte, ghostpriv.SaltSize), second.note)
		if err != nil {
			t.Fatal(err)
		}
		txs = append(txs, f.signAccountTx(keyB, &types.GhostAccountTx{
			ChainID:   new(big.Int).SetUint64(f.chainID),
			Nonce:     0,
			GasTipCap: new(big.Int).Mul(gwei, big.NewInt(100)),
			GasFeeCap: new(big.Int).Mul(gwei, big.NewInt(100)),
			Gas:       60_000 + accountExtraGas,
			To:        &ghost.CommitEntryAddress,
			Value:     second.value.ToBig(),
			Data:      data,
		}))
		for _, tx := range txs {
			b.AddTx(tx)
		}
	})
	chain := f.newChain()
	f.insert(chain, blocks)
	block := blocks[0]
	st, err := chain.StateAt(block.Root())
	if err != nil {
		t.Fatal(err)
	}
	receipts := chain.GetReceiptsByHash(block.Hash())
	if len(receipts) != 2 {
		t.Fatalf("%d receipts", len(receipts))
	}

	// Each sender paid its value and its gas, nothing more.
	tips := new(big.Int)
	for i, sender := range []common.Address{addrA, addrB} {
		r := receipts[i]
		if r.Status != types.ReceiptStatusSuccessful {
			t.Fatalf("commit %d failed", i)
		}
		gasCost := new(big.Int).Mul(new(big.Int).SetUint64(r.GasUsed), r.EffectiveGasPrice)
		value := []coin{first, second}[i].value.ToBig()
		want := new(big.Int).Sub(startBal, value)
		want.Sub(want, gasCost)
		if got := st.GetBalance(sender).ToBig(); got.Cmp(want) != 0 {
			t.Errorf("sender %d balance %v, want %v", i, got, want)
		}
		if st.GetNonce(sender) != 1 {
			t.Errorf("sender %d nonce %d", i, st.GetNonce(sender))
		}
		tip := new(big.Int).Sub(r.EffectiveGasPrice, block.BaseFee())
		tips.Add(tips, tip.Mul(tip, new(big.Int).SetUint64(r.GasUsed)))
	}
	// Nobody received the value: not the entry address, not the coinbase.
	if st.Exist(ghost.CommitEntryAddress) || !st.GetBalance(ghost.CommitEntryAddress).IsZero() {
		t.Error("the commit entry address holds an account")
	}
	wantMiner := new(big.Int).Add(f.engine.params.BlockReward(1).ToBig(), tips)
	if got := st.GetBalance(miner).ToBig(); got.Cmp(wantMiner) != 0 {
		t.Errorf("coinbase %v, want reward and tips %v", got, wantMiner)
	}
	for _, acc := range []common.Address{ghost.PrivTotalsAccount, ghosttree.TreeAccount(ghosttree.Coin)} {
		if !st.GetBalance(acc).IsZero() {
			t.Errorf("reserved account %x holds a balance", acc)
		}
	}

	// The tree holds the node's commitments, under the header root.
	leaves := []common.Hash{first.commitment(), second.commitment()}
	if leaves[0] == common.HexToHash("562d92a92bb8f2b3b772b55220a5ee26f189bedc0f4bfa513205df1545029458") {
		t.Fatal("the first leaf is the version 1 commitment")
	}
	if n := coinLeafCount(st); n != 2 {
		t.Fatalf("coin tree has %d leaves", n)
	}
	wantRoot := ghosttree.RootFromPageRoots(ghosttree.Coin, []common.Hash{ghosttree.PageRoot(ghosttree.Coin, leaves)})
	if root := block.Header().CoinTreeRoot; root == nil || *root != wantRoot {
		t.Fatalf("header coin root %v, want %x", root, wantRoot)
	}

	// One log each, on the coin tree account.
	for i, r := range receipts {
		if len(r.Logs) != 1 {
			t.Fatalf("commit %d has %d logs", i, len(r.Logs))
		}
		l := r.Logs[0]
		if l.Address != ghosttree.TreeAccount(ghosttree.Coin) {
			t.Errorf("log %d address %x", i, l.Address)
		}
		if len(l.Topics) != 1 || l.Topics[0] != ghosttree.K("ghost/commit-receipt/v1") {
			t.Errorf("log %d topics %x", i, l.Topics)
		}
		if want := commitLog(0, uint32(i), []coin{first, second}[i]); !bytes.Equal(l.Data, want) {
			t.Errorf("log %d data\n%x\nwant\n%x", i, l.Data, want)
		}
		if len(l.Data) != 4+4+32+32+156+16 {
			t.Errorf("log %d data has %d bytes", i, len(l.Data))
		}
	}

	// The value entered the hidden set's accounting.
	in, out := totals(st)
	wantIn := new(big.Int).Add(first.value.ToBig(), second.value.ToBig())
	if in.Cmp(wantIn) != 0 || out.Sign() != 0 {
		t.Errorf("totals in %v out %v, want in %v out 0", in, out, wantIn)
	}
	if st.GetNonce(ghost.PrivTotalsAccount) != 1 {
		t.Errorf("totals account nonce %d, want 1", st.GetNonce(ghost.PrivTotalsAccount))
	}
}

// TestCommitClaimingMoreThanBurnedIsRejected shows that a commitment can
// only ever be worth what was burned: the data has no room for a claimed
// amount, a value beyond the sender's funds is refused, the node records the
// commitment of the burned value whatever the wallet intended, and a reveal
// against it cannot take more than entered the hidden set.
func TestCommitClaimingMoreThanBurnedIsRejected(t *testing.T) {
	useStub(t)
	f := newFixture(t, ghost.InternalNetGasLimit, nil)
	chain := f.newChain()
	env, st := nextEnv(t, chain, chain.CurrentBlock(), common.Address{0xcb})

	claimed := testCoin("claimed", new(big.Int).Mul(big.NewInt(5), oneGhost))

	// A claimed amount after the note: 222 bytes, refused.
	data, err := ghostpriv.SaltedCommitData(claimed.f, make([]byte, ghostpriv.SaltSize), claimed.note)
	if err != nil {
		t.Fatal(err)
	}
	word := claimed.value.Bytes32()
	extra := append(append([]byte{}, data...), word[:]...)
	tx := f.callTx(keyA, 0, ghost.CommitEntryAddress, oneGhost, extra, 60_000)
	if _, err := applyTx(chain, st.Copy(), env.Header, tx); !errors.Is(err, ghostpriv.ErrCommitData) {
		t.Fatalf("commit with a claimed amount: %v, want %v", err, ghostpriv.ErrCommitData)
	}
	// A block carrying it is invalid.
	bad, _ := f.generate(1, func(i int, b *core.BlockGen) { b.AddUncheckedTx(tx) })
	if _, err := chain.InsertChain(bad); !errors.Is(err, ghostpriv.ErrCommitData) {
		t.Fatalf("block with a claiming commit: %v", err)
	}

	// A value beyond the sender's funds is refused, and nothing is recorded.
	rich := testCoin("beyond funds", new(big.Int).Add(startBal, big.NewInt(1)))
	cp := st.Copy()
	if _, err := applyTx(chain, cp, env.Header, f.commitTx(keyA, 0, rich)); !errors.Is(err, core.ErrInsufficientFunds) {
		t.Fatalf("commit beyond funds: %v, want %v", err, core.ErrInsufficientFunds)
	}
	if n := coinLeafCount(cp); n != 0 {
		t.Fatalf("a refused commit appended %d leaves", n)
	}

	// The wallet meant five GHOST but burned one wei: the node records the
	// commitment of one wei.
	tiny := coin{f: claimed.f, value: uint256.NewInt(1), note: claimed.note}
	blocks, _ := f.generate(4, func(i int, b *core.BlockGen) {
		if i == 0 {
			b.AddTx(f.commitTx(keyA, 0, tiny))
		}
	})
	f.insert(chain, blocks)
	head := chain.CurrentBlock()
	stHead, err := chain.StateAt(head.Root)
	if err != nil {
		t.Fatal(err)
	}
	logs := chain.GetReceiptsByHash(blocks[0].Hash())[0].Logs
	leaf := common.BytesToHash(logs[0].Data[8:40])
	if leaf != tiny.commitment() || leaf == claimed.commitment() {
		t.Fatalf("recorded leaf %x, want the commitment of the burned value %x", leaf, tiny.commitment())
	}
	if in, _ := totals(stHead); in.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("total in %v, want 1 wei", in)
	}

	// A reveal of the claimed five GHOST, or even of nothing, finds one wei
	// in the hidden set and is rejected.
	env5, st5 := nextEnv(t, chain, head, common.Address{0xcb})
	fee := chainWindowFee(t, chain, env5.Header).Total
	root := *blocks[0].Header().CoinTreeRoot
	for _, out := range []*uint256.Int{claimed.value, new(uint256.Int)} {
		r := f.newReveal(root, testMarker("claimed"), testCoin("claimed rest", big.NewInt(0)), addrB, out, fee)
		if _, _, err := ghostpriv.CheckReveal(st5.Copy(), env5, ghostprivtest.Verifier{}, envelope(t, r)); !errors.Is(err, ghostpriv.ErrRevealBackstop) {
			t.Errorf("reveal of %v against one wei: %v, want %v", out, err, ghostpriv.ErrRevealBackstop)
		}
	}
}

// TestCommitRejections runs each commit check, in order, against a commit
// that fails it, and where it can also a later one, so that the first
// failing check is the one reported.
func TestCommitRejections(t *testing.T) {
	f := newFixture(t, ghost.InternalNetGasLimit, nil)
	chain := f.newChain()
	env, st := nextEnv(t, chain, chain.CurrentBlock(), common.Address{0xcb})
	good := testCoin("rejections", oneGhost)
	goodData, err := ghostpriv.SaltedCommitData(good.f, make([]byte, ghostpriv.SaltSize), good.note)
	if err != nil {
		t.Fatal(err)
	}
	withData := func(change func([]byte) []byte) []byte {
		return change(append([]byte{}, goodData...))
	}
	vmax := ghostpriv.VMax.ToBig()
	over := new(big.Int).Add(vmax, big.NewInt(1))
	zeroF := withData(func(d []byte) []byte { copy(d[2:34], make([]byte, 32)); return d })

	tests := []struct {
		name  string
		tx    *types.Transaction
		fill  bool // the coin tree filled in this block
		want  error
		wantB error // a second error the result must also match
	}{
		{"nonce too high, bad data", f.callTx(keyA, 5, ghost.CommitEntryAddress, oneGhost, nil, 60_000), false, core.ErrNonceTooHigh, nil},
		{"intrinsic gas, bad data", f.callTx(keyA, 0, ghost.CommitEntryAddress, oneGhost, goodData[:100], 21_000), false, core.ErrIntrinsicGas, nil},
		{"empty data", f.callTx(keyA, 0, ghost.CommitEntryAddress, oneGhost, nil, 60_000), false, ghostpriv.ErrCommitData, nil},
		{"205 bytes", f.callTx(keyA, 0, ghost.CommitEntryAddress, oneGhost, goodData[:205], 60_000), false, ghostpriv.ErrCommitData, nil},
		{"207 bytes, an extra field", f.callTx(keyA, 0, ghost.CommitEntryAddress, oneGhost, append(append([]byte{}, goodData...), 1), 60_000), false, ghostpriv.ErrCommitData, nil},
		{"190 bytes of version 1", f.callTx(keyA, 0, ghost.CommitEntryAddress, oneGhost, versionOneCommitData(good.f, good.note), 60_000), false, ghostpriv.ErrCommitData, nil},
		{"206 bytes of version 1", f.callTx(keyA, 0, ghost.CommitEntryAddress, oneGhost, withData(func(d []byte) []byte { d[1] = 1; return d }), 60_000), false, ghostpriv.ErrCommitData, nil},
		{"version 0", f.callTx(keyA, 0, ghost.CommitEntryAddress, oneGhost, withData(func(d []byte) []byte { d[1] = 0; return d }), 60_000), false, ghostpriv.ErrCommitData, nil},
		{"zero F, zero value", f.callTx(keyA, 0, ghost.CommitEntryAddress, new(big.Int), zeroF, 60_000), false, ghostpriv.ErrCommitZeroF, nil},
		{"zero value", f.callTx(keyA, 0, ghost.CommitEntryAddress, new(big.Int), goodData, 60_000), false, ghostpriv.ErrCommitAmount, nil},
		{"2^96, beyond funds", f.callTx(keyA, 0, ghost.CommitEntryAddress, over, goodData, 60_000), false, ghostpriv.ErrCommitAmount, nil},
		{"V_MAX, beyond funds", f.callTx(keyA, 0, ghost.CommitEntryAddress, vmax, goodData, 60_000), false, core.ErrInsufficientFunds, nil},
		{"whole balance, no gas left", f.callTx(keyA, 0, ghost.CommitEntryAddress, startBal, goodData, 60_000), true, core.ErrInsufficientFunds, nil},
		{"tree filled in this block", f.commitTx(keyA, 0, good), true, ghostpriv.ErrCommitTree, ghosttree.ErrFillingBlock},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cp := st.Copy()
			if tt.fill {
				fillCoinTree(cp, env.Header.Number.Uint64())
			}
			_, err := applyTx(chain, cp, env.Header, tt.tx)
			if !errors.Is(err, tt.want) || (tt.wantB != nil && !errors.Is(err, tt.wantB)) {
				t.Fatalf("error %v, want %v", err, tt.want)
			}
			if in, _ := totals(cp); in.Sign() != 0 {
				t.Errorf("a rejected commit added %v to the total in", in)
			}
		})
	}

	// The smallest commit, one wei, is accepted; data to any other address
	// is an ordinary transfer and records nothing.
	cp := st.Copy()
	one := coin{f: good.f, value: uint256.NewInt(1), note: good.note}
	if r, err := applyTx(chain, cp, env.Header, f.commitTx(keyA, 0, one)); err != nil || r.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("one-wei commit: %v", err)
	}
	if n := coinLeafCount(cp); n != 1 {
		t.Fatalf("one-wei commit appended %d leaves", n)
	}
	cp = st.Copy()
	other := common.Address{0x67, 0x68}
	if _, err := applyTx(chain, cp, env.Header, f.callTx(keyA, 0, other, oneGhost, goodData, 60_000)); err != nil {
		t.Fatal(err)
	}
	if n := coinLeafCount(cp); n != 0 || cp.GetBalance(other).ToBig().Cmp(oneGhost) != 0 {
		t.Fatal("a transfer to another address committed")
	}
}

// testSalt is a synthetic per-coin salt.
// versionOneCommitData is the old 190-byte version 1 layout, the version, F
// and the note, which the node refuses.
func versionOneCommitData(f common.Hash, note []byte) []byte {
	data := binary.BigEndian.AppendUint16(nil, ghostpriv.Version)
	return append(append(data, f[:]...), note...)
}

func testSalt(seed byte) []byte {
	salt := make([]byte, ghostpriv.SaltSize)
	for i := range salt {
		salt[i] = seed ^ byte(0xa0+i)
	}
	return salt
}

// saltedCommitTx is a commit of c with salted commit data, from key.
func (f *fixture) saltedCommitTx(key *mldsa44.PrivateKey, nonce uint64, c coin, salt []byte) *types.Transaction {
	f.t.Helper()
	data, err := ghostpriv.SaltedCommitData(c.f, salt, c.note)
	if err != nil {
		f.t.Fatal(err)
	}
	return f.callTx(key, nonce, ghost.CommitEntryAddress, c.value.ToBig(), data, 60_000)
}

// historyChain is a chain of the fixture that keeps the tree history in its
// own database, as a node does.
func (f *fixture) historyChain() (*core.BlockChain, *ghosttree.History) {
	f.t.Helper()
	db := rawdb.NewMemoryDatabase()
	chain, err := core.NewBlockChain(db, nil, f.gspec, nil, f.engine, vm.Config{}, nil, nil)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(chain.Stop)
	history := ghosttree.NewHistory(db)
	if err := chain.SetTreeHistory(history); err != nil {
		f.t.Fatal(err)
	}
	return chain, history
}

// checkSalt fails unless got is the salt want, or nil for want nil.
func checkSalt(t *testing.T, what string, got *[ghostpriv.SaltSize]byte, want []byte) {
	t.Helper()
	switch {
	case want == nil && got != nil:
		t.Errorf("%s: salt %x, want none", what, got[:])
	case want != nil && got == nil:
		t.Errorf("%s: no salt, want %x", what, want)
	case want != nil && !bytes.Equal(got[:], want):
		t.Errorf("%s: salt %x, want %x", what, got[:], want)
	}
}

// TestSaltedCommitCarriesSaltToHistory commits one coin with a zero salt
// and one with a drawn salt in a block: both are recorded under the version 2
// commitment of F and the value, each receipt log carries its salt after the
// note (244 bytes), and the tree history returns each salt with its leaf and
// note.
func TestSaltedCommitCarriesSaltToHistory(t *testing.T) {
	f := newFixture(t, ghost.InternalNetGasLimit, nil)
	var (
		plain  = testCoin("plain", oneGhost)
		salted = testCoin("salted", ghostAmount(3, 2))
		salt   = testSalt(0x11)
	)
	blocks, _ := f.generate(1, func(i int, b *core.BlockGen) {
		b.AddTx(f.commitTx(keyA, 0, plain))
		b.AddTx(f.saltedCommitTx(keyB, 0, salted, salt))
	})
	chain, history := f.historyChain()
	f.insert(chain, blocks)
	block := blocks[0]
	st, err := chain.StateAt(block.Root())
	if err != nil {
		t.Fatal(err)
	}
	receipts := chain.GetReceiptsByHash(block.Hash())
	if len(receipts) != 2 {
		t.Fatalf("%d receipts", len(receipts))
	}
	for i, r := range receipts {
		if r.Status != types.ReceiptStatusSuccessful || len(r.Logs) != 1 {
			t.Fatalf("commit %d: status %d, %d logs", i, r.Status, len(r.Logs))
		}
	}

	// The salted commit burned its value and is recorded under the version 2
	// commitment of F and the value: the salt is no input of it.
	gasCost := new(big.Int).Mul(new(big.Int).SetUint64(receipts[1].GasUsed), receipts[1].EffectiveGasPrice)
	if got, want := st.GetBalance(addrB).ToBig(), new(big.Int).Sub(new(big.Int).Sub(startBal, salted.value.ToBig()), gasCost); got.Cmp(want) != 0 {
		t.Errorf("salted sender balance %v, want %v", got, want)
	}
	leaves := []common.Hash{plain.commitment(), saltedCommitment(salted)}
	wantRoot := ghosttree.RootFromPageRoots(ghosttree.Coin, []common.Hash{ghosttree.PageRoot(ghosttree.Coin, leaves)})
	if root := block.Header().CoinTreeRoot; root == nil || *root != wantRoot {
		t.Fatalf("header coin root %v, want %x", root, wantRoot)
	}
	if in, _ := totals(st); in.Cmp(new(big.Int).Add(plain.value.ToBig(), salted.value.ToBig())) != 0 {
		t.Errorf("total in %v", in)
	}

	// The logs: each with its salt after the note.
	if got, want := receipts[0].Logs[0].Data, commitLog(0, 0, plain); !bytes.Equal(got, want) || len(got) != 244 {
		t.Errorf("zero-salt log of %d bytes\n%x\nwant\n%x", len(got), got, want)
	}
	if got, want := receipts[1].Logs[0].Data, append(commitLogOf(0, 1, leaves[1], salted), salt...); !bytes.Equal(got, want) || len(got) != 244 {
		t.Errorf("salted log of %d bytes\n%x\nwant\n%x", len(got), got, want)
	}
	if got := common.BytesToHash(receipts[1].Logs[0].Data[8:40]); got != leaves[1] {
		t.Errorf("salted leaf %x, want %x", got, leaves[1])
	}

	// The history records and the page carry the salt with the leaf and note.
	records, err := ghostpriv.HistoryRecords(receipts)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].Leaf != leaves[0] || records[1].Leaf != leaves[1] {
		t.Fatalf("history records %+v", records)
	}
	checkSalt(t, "zero-salt record", records[0].Salt, make([]byte, ghostpriv.SaltSize))
	checkSalt(t, "salted record", records[1].Salt, salt)
	if !bytes.Equal(records[1].Note[:], salted.note) {
		t.Errorf("salted record note %x", records[1].Note[:])
	}
	page, err := history.Page(ghosttree.Coin, 0, 0, block.Hash())
	if err != nil {
		t.Fatal(err)
	}
	if page.Filled != 2 {
		t.Fatalf("page of %d entries", page.Filled)
	}
	for i, c := range []coin{plain, salted} {
		if e := page.Entries[i]; e.Leaf != leaves[i] || !bytes.Equal(e.Note[:], c.note) {
			t.Errorf("entry %d: leaf %x note %x", i, e.Leaf, e.Note[:])
		}
	}
	checkSalt(t, "zero-salt entry", page.Entries[0].Salt, make([]byte, ghostpriv.SaltSize))
	checkSalt(t, "salted entry", page.Entries[1].Salt, salt)
}

// TestSaltedCommitDataLengthIsExact builds salted commit data, checks its
// layout, and sends salted data of every wrong length and version to the
// commit entry address: only exactly 206 bytes of version 2 are accepted, and
// anything else, the 190 bytes of version 1 included, is ErrCommitData.
func TestSaltedCommitDataLengthIsExact(t *testing.T) {
	good := testCoin("exact", oneGhost)
	salt := testSalt(0x22)
	data, err := ghostpriv.SaltedCommitData(good.f, salt, good.note)
	if err != nil {
		t.Fatal(err)
	}
	if ghostpriv.SaltedCommitDataSize != 206 || ghostpriv.CommitDataSize != 190 || ghostpriv.SaltedCommitVersion != 2 || ghostpriv.Version != 1 {
		t.Fatalf("sizes %d and %d, versions %d and %d", ghostpriv.SaltedCommitDataSize, ghostpriv.CommitDataSize, ghostpriv.SaltedCommitVersion, ghostpriv.Version)
	}
	want := append(append(append([]byte{0x00, 0x02}, good.f[:]...), salt...), good.note...)
	if !bytes.Equal(data, want) {
		t.Fatalf("salted commit data\n%x\nwant\n%x", data, want)
	}
	for _, bad := range []struct {
		name       string
		salt, note []byte
	}{
		{"15-byte salt", salt[:15], good.note},
		{"17-byte salt", append(append([]byte{}, salt...), 0), good.note},
		{"no salt", nil, good.note},
		{"short note", salt, good.note[:155]},
		{"long note", salt, append(append([]byte{}, good.note...), 0)},
	} {
		if d, err := ghostpriv.SaltedCommitData(good.f, bad.salt, bad.note); err == nil {
			t.Errorf("%s: built %d bytes", bad.name, len(d))
		}
	}

	// Parsed, the salt and note come apart and the commitment is the version
	// 2 commitment of F and the value.
	c, err := ghostpriv.ParseCommit(data, oneGhost)
	if err != nil {
		t.Fatal(err)
	}
	if c.F != good.f || !bytes.Equal(c.Note[:], good.note) || c.Commitment() != saltedCommitment(good) {
		t.Fatalf("parsed salted commit %+v", c)
	}
	checkSalt(t, "parsed salted commit", c.Salt, salt)
	dc, err := ghostpriv.ParseDataCommit(data, new(big.Int))
	if err != nil {
		t.Fatal(err)
	}
	if dc.F != good.f || !bytes.Equal(dc.Note[:], good.note) || dc.Commitment() != ghostpriv.DataCommitmentVersion(ghostpriv.SaltedCommitVersion, good.f) {
		t.Fatalf("parsed salted data commit %+v", dc)
	}
	checkSalt(t, "parsed salted data commit", dc.Salt, salt)
	v1 := versionOneCommitData(good.f, good.note)

	with := func(change func([]byte) []byte) []byte { return change(append([]byte{}, data...)) }
	wrong := []struct {
		name string
		data []byte
	}{
		{"205 bytes", data[:205]},
		{"207 bytes", with(func(d []byte) []byte { return append(d, 0) })},
		{"222 bytes, the salt twice", with(func(d []byte) []byte { return append(d, salt...) })},
		{"206 bytes of version 1", with(func(d []byte) []byte { d[1] = 1; return d })},
		{"206 bytes of version 3", with(func(d []byte) []byte { d[1] = 3; return d })},
		{"206 bytes of version 0x0102", with(func(d []byte) []byte { d[0] = 1; return d })},
		{"190 bytes of version 2", func() []byte { d := append([]byte{}, v1...); d[1] = 2; return d }()},
		{"version 2 without the note", data[:2+32+16]},
		{"version 2 header only", data[:2]},
		{"190 bytes of version 1", v1},
	}
	for _, w := range wrong {
		if _, err := ghostpriv.ParseCommit(w.data, oneGhost); !errors.Is(err, ghostpriv.ErrCommitData) {
			t.Errorf("%s: commit %v, want %v", w.name, err, ghostpriv.ErrCommitData)
		}
		if _, err := ghostpriv.ParseDataCommit(w.data, new(big.Int)); !errors.Is(err, ghostpriv.ErrCommitData) {
			t.Errorf("%s: data commit %v, want %v", w.name, err, ghostpriv.ErrCommitData)
		}
	}

	// On the chain: each wrong length is refused and appends nothing; the
	// exact 206 bytes are accepted.
	f := newFixture(t, ghost.InternalNetGasLimit, nil)
	chain := f.newChain()
	env, st := nextEnv(t, chain, chain.CurrentBlock(), common.Address{0xcb})
	for _, w := range wrong {
		cp := st.Copy()
		tx := f.callTx(keyA, 0, ghost.CommitEntryAddress, oneGhost, w.data, 60_000)
		if _, err := applyTx(chain, cp, env.Header, tx); !errors.Is(err, ghostpriv.ErrCommitData) {
			t.Errorf("%s on the chain: %v, want %v", w.name, err, ghostpriv.ErrCommitData)
		}
		if n := coinLeafCount(cp); n != 0 {
			t.Errorf("%s appended %d leaves", w.name, n)
		}
		if in, _ := totals(cp); in.Sign() != 0 {
			t.Errorf("%s added %v to the total in", w.name, in)
		}
	}
	cp := st.Copy()
	r, err := applyTx(chain, cp, env.Header, f.saltedCommitTx(keyA, 0, good, salt))
	if err != nil || r.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("206-byte salted commit: %v", err)
	}
	if n := coinLeafCount(cp); n != 1 || len(r.Logs) != 1 || len(r.Logs[0].Data) != 244 {
		t.Fatalf("salted commit: %d leaves, logs %v", n, r.Logs)
	}
}

// callerCode is a contract that calls the commit entry address with the
// given call opcode, one wei for the kinds that carry a value, and stores
// the call's result plus one in slot 0.
func callerCode(op vm.OpCode, target common.Address) []byte {
	code := []byte{
		byte(vm.PUSH1), 0, // return size
		byte(vm.PUSH1), 0, // return offset
		byte(vm.PUSH1), 0, // argument size
		byte(vm.PUSH1), 0, // argument offset
	}
	if op == vm.CALL || op == vm.CALLCODE {
		code = append(code, byte(vm.PUSH1), 1) // value
	}
	code = append(code, byte(vm.PUSH20))
	code = append(code, target[:]...)
	code = append(code, byte(vm.PUSH3), 0x01, 0x86, 0xa0) // 100,000 gas
	code = append(code, byte(op))
	code = append(code, byte(vm.PUSH1), 1, byte(vm.ADD))
	code = append(code, byte(vm.PUSH1), 0, byte(vm.SSTORE), byte(vm.STOP))
	return code
}

// TestCommitEntryNotCallableFromContract calls the commit entry address
// from contracts with CALL, CALLCODE, DELEGATECALL and STATICCALL: every
// call fails, nothing reaches the entry address and nothing is committed,
// while the same CALL to an ordinary address succeeds.
func TestCommitEntryNotCallableFromContract(t *testing.T) {
	var (
		ordinary = common.Address{0x0e, 0x0e}
		callers  = map[common.Address][]byte{
			{0xc1}: callerCode(vm.CALL, ghost.CommitEntryAddress),
			{0xc2}: callerCode(vm.CALLCODE, ghost.CommitEntryAddress),
			{0xc4}: callerCode(vm.DELEGATECALL, ghost.CommitEntryAddress),
			{0xca}: callerCode(vm.STATICCALL, ghost.CommitEntryAddress),
			{0xc0}: callerCode(vm.CALL, ordinary),
		}
		alloc = genesisT.GenesisAlloc{}
	)
	for addr, code := range callers {
		alloc[addr] = genesisT.GenesisAccount{Code: code, Balance: new(big.Int).Set(oneGhost)}
	}
	f := newFixture(t, ghost.InternalNetGasLimit, alloc)
	order := []common.Address{{0xc1}, {0xc2}, {0xc4}, {0xca}, {0xc0}}
	blocks, _ := f.generate(1, func(i int, b *core.BlockGen) {
		for n, addr := range order {
			b.AddTx(f.callTx(keyA, uint64(n), addr, new(big.Int), nil, 1_000_000))
		}
	})
	chain := f.newChain()
	f.insert(chain, blocks)
	st, err := chain.StateAt(blocks[0].Root())
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range order {
		want := common.Hash{31: 1} // the call failed
		if addr == (common.Address{0xc0}) {
			want = common.Hash{31: 2} // the call succeeded
		}
		if got := st.GetState(addr, common.Hash{}); got != want {
			t.Errorf("caller %x stored %x, want %x", addr, got, want)
		}
	}
	if st.Exist(ghost.CommitEntryAddress) || !st.GetBalance(ghost.CommitEntryAddress).IsZero() {
		t.Error("a contract reached the commit entry address")
	}
	if st.GetBalance(ordinary).Uint64() != 1 {
		t.Error("the control call did not transfer")
	}
	if in, _ := totals(st); in.Sign() != 0 {
		t.Errorf("total in %v after contract calls", in)
	}
	if n := coinLeafCount(st); n != 0 {
		t.Errorf("contract calls appended %d leaves", n)
	}
	for i, r := range chain.GetReceiptsByHash(blocks[0].Hash()) {
		if r.Status != types.ReceiptStatusSuccessful || len(r.Logs) != 0 {
			t.Errorf("transaction %d: status %d, %d logs", i, r.Status, len(r.Logs))
		}
	}
}

// logState is a state that keeps the logs the coin and data rules write.
type logState struct {
	*state.StateDB
	logs []*types.Log
}

func (s *logState) AddLog(l *types.Log) { s.logs = append(s.logs, l) }

// TestCommitLeafTagFollowsVersion sends 206 bytes of salted version 2 data through ParseCommit and ApplyCommit, and
// through ParseDataCommit and ApplyDataCommit, and checks that the leaf the
// tree takes and the receipt log carries has the type of the data's version:
// K(tag, 0x01 0x01, F, v) and K(tag, 0x02 0x01, F, v) for a coin,
// K(tag, 0x01 0x02, F_d) and K(tag, 0x02 0x02, F_d) for data (spec 01).
func TestCommitLeafTagFollowsVersion(t *testing.T) {
	if ghostpriv.Coin != [2]byte{0x01, 0x01} || ghostpriv.CoinV2 != [2]byte{0x02, 0x01} ||
		ghostpriv.Data != [2]byte{0x01, 0x02} || ghostpriv.DataV2 != [2]byte{0x02, 0x02} {
		t.Fatalf("types COIN %x and %x, DATA %x and %x", ghostpriv.Coin, ghostpriv.CoinV2, ghostpriv.Data, ghostpriv.DataV2)
	}
	f := newFixture(t, ghost.InternalNetGasLimit, nil)
	chain := f.newChain()
	env, st := nextEnv(t, chain, chain.CurrentBlock(), common.Address{0xcb})
	height := env.Header.Number.Uint64()

	c := testCoin("tagged", oneGhost)
	v2, err := ghostpriv.SaltedCommitData(c.f, testSalt(0x44), c.note)
	if err != nil {
		t.Fatal(err)
	}
	word := c.value.Bytes32()
	for _, tc := range []struct {
		name     string
		data     []byte
		version  uint16
		coinLeaf common.Hash
		dataLeaf common.Hash
	}{
		{"206 bytes, version 2", v2, ghostpriv.SaltedCommitVersion,
			ghosttree.K("ghost/coin-commitment/v1", []byte{0x02, 0x01}, c.f[:], word[:]),
			ghosttree.K("ghost/data-commitment/v1", []byte{0x02, 0x02}, c.f[:])},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The coin commit.
			cc, err := ghostpriv.ParseCommit(tc.data, oneGhost)
			if err != nil {
				t.Fatal(err)
			}
			if cc.CommitVersion() != tc.version {
				t.Fatalf("commit version %d, want %d", cc.CommitVersion(), tc.version)
			}
			ls := &logState{StateDB: st.Copy()}
			if err := ghostpriv.ApplyCommit(ls, height, addrA, cc); err != nil {
				t.Fatal(err)
			}
			checkAppended(t, "coin", ls, ghosttree.Coin, tc.coinLeaf)

			// The data commit of the same data.
			dc, err := ghostpriv.ParseDataCommit(tc.data, new(big.Int))
			if err != nil {
				t.Fatal(err)
			}
			if dc.CommitVersion() != tc.version {
				t.Fatalf("data commit version %d, want %d", dc.CommitVersion(), tc.version)
			}
			ls = &logState{StateDB: st.Copy()}
			if err := ghostpriv.ApplyDataCommit(ls, height, dc); err != nil {
				t.Fatal(err)
			}
			checkAppended(t, "data", ls, ghosttree.Data, tc.dataLeaf)
		})
	}
}

// checkAppended checks that the only leaf of the tree of kind in ls is want,
// and that the one receipt log carries it.
func checkAppended(t *testing.T, name string, ls *logState, kind ghosttree.Kind, want common.Hash) {
	t.Helper()
	root, err := ghosttree.Root(ls, kind)
	if err != nil {
		t.Fatal(err)
	}
	if wantRoot := ghosttree.RootFromPageRoots(kind, []common.Hash{ghosttree.PageRoot(kind, []common.Hash{want})}); root != wantRoot {
		t.Errorf("%s tree root %x, want the root of the one leaf %x", name, root, want)
	}
	if len(ls.logs) != 1 || len(ls.logs[0].Data) < 40 {
		t.Fatalf("%s: logs %v", name, ls.logs)
	}
	if got := common.BytesToHash(ls.logs[0].Data[8:40]); got != want {
		t.Errorf("%s leaf %x, want %x", name, got, want)
	}
}

// TestLeafMatchesProofCrateVectors checks the leaves the node computes for
// fixed F, v and version against the commitment vectors of spec 01, the
// values the ghost proofs crate computes and scripts/check_commitment_vectors.py
// recomputes with its own Keccak in the ghost repository. A salted vector
// goes through salted commit data, so the leaf is the one the node records.
func TestLeafMatchesProofCrateVectors(t *testing.T) {
	var (
		commit    = uint256.NewInt(1_000_000_000_000_000_000)
		remainder = uint256.NewInt(700_000_000_000_000_000)
	)
	coins := []struct {
		name    string
		version uint16
		f       string
		v       *uint256.Int
		want    string
	}{
		{"coin-commit", 1, "b44338ab6f6dcb3d63772c457737afd38a841207725e1440d235c4f6be0c4d8b", commit, "562d92a92bb8f2b3b772b55220a5ee26f189bedc0f4bfa513205df1545029458"},
		{"coin-remainder", 1, "06917a6f382fb7dabd47f6461319883f17f2bf3a8ebc1f00cbb1183b168389be", remainder, "93312061656298f41cd5a9f116d070b38b0acf5f8d968c58e32170f70e7aed15"},
		{"coin-commit-salted", 2, "6f7edf086ae8451b86811fcc222a6c3b77e1010705b57d64fd336a9f114c11a3", commit, "72ab16e25e13d2101dbfad21972605641aa4f2ea369b7173edd4d3ba2678689d"},
		{"coin-commit-salted-other", 2, "03c501af5675709301cff4e93da4140792f4ccfff3b2b2a16ff55b2bf1ecc5ab", commit, "be9a0db30dbd08f5af50b766ceafd3c15f3f843d9cf5122682e002448380bd74"},
		{"coin-remainder-salted", 2, "8d8f86ffe5d0c251cfe7d8cfa9e49287e8e83fc6cb3dd3345213c812d67cf81a", remainder, "7b2269649fa191df18cf80dde1e81f5cf61bb00a7faf17f58aafc197251393ab"},
		{"coin-remainder-salted-other", 2, "bdd18c032eef7bfc6aec7268f7fe4446beafefd12a6808c1b6e24687eee0acac", remainder, "c07b2ff99412387057a171046120ac0d57f63d9516a0bc612089a7cdf0200bf2"},
	}
	datas := []struct {
		name    string
		version uint16
		f       string
		want    string
	}{
		{"data-commit", 1, "a7450331b78ed2a6cf4864e6fdf58c1147e0cb4c8608e0dc0b37ec94f67e5b41", "39c4e1e8edca6f366db5125e1bc9484063fa9f35da539638207f03732d913b06"},
		{"data-commit-salted", 2, "c5248f5ae13e74d2ecd2ee324068ae947012a76b5a44d66bf6f59830a366a7e2", "324c90dbad0fbecfd82331d087ea216b525e68b8dcb64891aa59322565ebb8b5"},
		{"data-commit-salted-other", 2, "72ac806d9e8c49284e2cc0e10fff283fadeff8d0345954770960f68b1d0df358", "91e0e4460c6ffd42b5efcbd8a94e4fa91eb6a5e4aa17b1e8faf8eb38c6779f2f"},
	}
	// commitData is commit data of F at a version, as a wallet sends it. The
	// node refuses version 1 data, so a version 1 vector stops at the
	// commitment.
	commitData := func(t *testing.T, version uint16, f common.Hash) []byte {
		t.Helper()
		note := testNote(0x5a)
		if version != ghostpriv.SaltedCommitVersion {
			return versionOneCommitData(f, note)
		}
		data, err := ghostpriv.SaltedCommitData(f, testSalt(0x66), note)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	for _, v := range coins {
		f, want := common.HexToHash(v.f), common.HexToHash(v.want)
		if got := ghostpriv.CommitmentVersion(v.version, f, v.v); got != want {
			t.Errorf("%s: commitment %x, want %x", v.name, got, want)
		}
		c, err := ghostpriv.ParseCommit(commitData(t, v.version, f), v.v.ToBig())
		if v.version != ghostpriv.SaltedCommitVersion {
			if !errors.Is(err, ghostpriv.ErrCommitData) {
				t.Errorf("%s: version 1 commit %v, want %v", v.name, err, ghostpriv.ErrCommitData)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", v.name, err)
		}
		if got := c.Commitment(); got != want {
			t.Errorf("%s: commit leaf %x, want %x", v.name, got, want)
		}
	}
	for _, v := range datas {
		f, want := common.HexToHash(v.f), common.HexToHash(v.want)
		if got := ghostpriv.DataCommitmentVersion(v.version, f); got != want {
			t.Errorf("%s: data commitment %x, want %x", v.name, got, want)
		}
		c, err := ghostpriv.ParseDataCommit(commitData(t, v.version, f), new(big.Int))
		if v.version != ghostpriv.SaltedCommitVersion {
			if !errors.Is(err, ghostpriv.ErrCommitData) {
				t.Errorf("%s: version 1 data commit %v, want %v", v.name, err, ghostpriv.ErrCommitData)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", v.name, err)
		}
		if got := c.Commitment(); got != want {
			t.Errorf("%s: data commit leaf %x, want %x", v.name, got, want)
		}
	}
}

// TestVersionOneCommitDataRefused sends the old 190 bytes of version 1 data
// as a coin commit and as a data commit on a new chain: the node refuses both
// with ErrCommitData and neither tree takes a leaf. Two version 1 commits to
// one key would share a marker, so the second coin could never be revealed.
func TestVersionOneCommitDataRefused(t *testing.T) {
	f := newFixture(t, ghost.InternalNetGasLimit, nil)
	chain := f.newChain()
	env, st := nextEnv(t, chain, chain.CurrentBlock(), common.Address{0xcb})
	c := testCoin("version 1", oneGhost)
	v1 := versionOneCommitData(c.f, c.note)
	if len(v1) != ghostpriv.CommitDataSize {
		t.Fatalf("version 1 data of %d bytes", len(v1))
	}
	if _, err := ghostpriv.ParseCommit(v1, oneGhost); !errors.Is(err, ghostpriv.ErrCommitData) {
		t.Errorf("parse commit: %v, want %v", err, ghostpriv.ErrCommitData)
	}
	if _, err := ghostpriv.ParseDataCommit(v1, new(big.Int)); !errors.Is(err, ghostpriv.ErrCommitData) {
		t.Errorf("parse data commit: %v, want %v", err, ghostpriv.ErrCommitData)
	}
	for _, tc := range []struct {
		name  string
		to    common.Address
		value *big.Int
	}{
		{"coin commit", ghost.CommitEntryAddress, oneGhost},
		{"data commit", ghost.DataCommitEntryAddress, new(big.Int)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cp := st.Copy()
			if _, err := applyTx(chain, cp, env.Header, f.callTx(keyA, 0, tc.to, tc.value, v1, 60_000)); !errors.Is(err, ghostpriv.ErrCommitData) {
				t.Fatalf("error %v, want %v", err, ghostpriv.ErrCommitData)
			}
			if n := coinLeafCount(cp); n != 0 {
				t.Errorf("coin tree took %d leaves", n)
			}
			if n := dataLeafCount(cp); n != 0 {
				t.Errorf("data tree took %d leaves", n)
			}
		})
	}
}
