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
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
	"github.com/holiman/uint256"
)

// dataFile is what a wallet keeps of a data commitment it made: F_d and the
// note, and the commitment format version of the data it was committed with
// (0 for the zero salt the test data commits send, also version 2). The
// node never sees the file itself.
type dataFile struct {
	f       common.Hash
	note    []byte
	version uint16
}

func (d dataFile) commitment() common.Hash {
	if d.version == 0 {
		return ghostpriv.DataCommitmentVersion(ghostpriv.SaltedCommitVersion, d.f)
	}
	return ghostpriv.DataCommitmentVersion(d.version, d.f)
}

// reserve is DATA_RESERVE, the value of every data commit, as a big.Int.
func reserve() *big.Int { return ghostpriv.DataReserve.ToBig() }

func testDataFile(name string) dataFile {
	return dataFile{
		f:    ghosttree.K("ghost/test-data-f", []byte(name)),
		note: testNote(byte(0x40 + len(name))),
	}
}

// dataCommitTx is a data commit of d from key with the given value, an
// account transaction to the data commit entry address. A valid data commit
// sends reserve().
func (f *fixture) dataCommitTx(key *mldsa44.PrivateKey, nonce uint64, d dataFile, value *big.Int) *types.Transaction {
	f.t.Helper()
	data, err := ghostpriv.SaltedCommitData(d.f, make([]byte, ghostpriv.SaltSize), d.note)
	if err != nil {
		f.t.Fatal(err)
	}
	return f.callTx(key, nonce, ghost.DataCommitEntryAddress, value, data, 60_000)
}

// dataCommitLog is the receipt log a data commit writes, without the salt
// after the note.
func dataCommitLog(index, position uint32, d dataFile) []byte {
	leaf := d.commitment()
	data := binary.BigEndian.AppendUint32(nil, index)
	data = binary.BigEndian.AppendUint32(data, position)
	data = append(data, leaf[:]...)
	return append(data, d.note...)
}

// zeroSaltDataCommitLog is the receipt log of a data commit of d with the
// zero salt the test data commits send.
func zeroSaltDataCommitLog(index, position uint32, d dataFile) []byte {
	return append(dataCommitLog(index, position, d), make([]byte, ghostpriv.SaltSize)...)
}

func dataLeafCount(st *state.StateDB) uint64 {
	return st.GetState(ghosttree.TreeAccount(ghosttree.Data), ghosttree.Slot(ghosttree.SlotLeafCount)).Big().Uint64()
}

// TestDataCommitAppendsToDataTree commits two files, from two account
// transactions of two accounts, in one block on the internal network and checks that
// the data tree holds the commitments the node computed under the header's
// data root, the receipt logs with leaf, tree index, position and note, that
// the coin tree is as it was, that each sender paid the reserve and its gas
// and nobody received the reserve, and that the total in grew by the
// reserves.
func TestDataCommitAppendsToDataTree(t *testing.T) {
	// The commitment is K over DATA at version 2, the reserve and F_d, and
	// never a coin commitment.
	known := testDataFile("known")
	want := ghosttree.K("ghost/data-commitment/v1", []byte{0x02, 0x02}, common.BigToHash(reserve()).Bytes(), known.f[:])
	if known.commitment() != want {
		t.Fatalf("data commitment %x, want %x", known.commitment(), want)
	}
	for _, v := range []uint64{0, 1} {
		if known.commitment() == ghostpriv.Commitment(known.f, uint256.NewInt(v)) {
			t.Fatalf("the data commitment equals the coin commitment of value %d", v)
		}
	}
	if ghostpriv.Data == ghostpriv.Coin {
		t.Fatal("DATA and COIN are one type")
	}

	f := newFixture(t, ghost.InternalNetGasLimit, nil)
	var (
		miner  = common.Address{0xcb}
		first  = known
		second = testDataFile("second")
		txs    []*types.Transaction
	)
	blocks, _ := f.generate(1, func(i int, b *core.BlockGen) {
		b.SetCoinbase(miner)
		txs = append(txs, f.dataCommitTx(keyA, 0, first, reserve()))
		data, err := ghostpriv.SaltedCommitData(second.f, make([]byte, ghostpriv.SaltSize), second.note)
		if err != nil {
			t.Fatal(err)
		}
		// A second account, with its tip at the fee cap.
		txs = append(txs, f.signAccountTx(keyB, &types.GhostAccountTx{
			ChainID:   new(big.Int).SetUint64(f.chainID),
			Nonce:     0,
			GasTipCap: new(big.Int).Mul(gwei, big.NewInt(100)),
			GasFeeCap: new(big.Int).Mul(gwei, big.NewInt(100)),
			Gas:       60_000 + accountExtraGas,
			To:        &ghost.DataCommitEntryAddress,
			Value:     reserve(),
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

	// Each sender paid the reserve and its gas; the coinbase got the reward
	// and the tips.
	tips := new(big.Int)
	for i, sender := range []common.Address{addrA, addrB} {
		r := receipts[i]
		if r.Status != types.ReceiptStatusSuccessful {
			t.Fatalf("data commit %d failed", i)
		}
		gasCost := new(big.Int).Mul(new(big.Int).SetUint64(r.GasUsed), r.EffectiveGasPrice)
		if got, want := st.GetBalance(sender).ToBig(), new(big.Int).Sub(startBal, gasCost.Add(gasCost, reserve())); got.Cmp(want) != 0 {
			t.Errorf("sender %d balance %v, want %v", i, got, want)
		}
		if st.GetNonce(sender) != 1 {
			t.Errorf("sender %d nonce %d", i, st.GetNonce(sender))
		}
		tip := new(big.Int).Sub(r.EffectiveGasPrice, block.BaseFee())
		tips.Add(tips, tip.Mul(tip, new(big.Int).SetUint64(r.GasUsed)))
	}
	if got := st.GetBalance(addrC).ToBig(); got.Cmp(startBal) != 0 {
		t.Errorf("bystander balance %v", got)
	}
	wantMiner := new(big.Int).Add(f.engine.params.BlockReward(1).ToBig(), tips)
	if got := st.GetBalance(miner).ToBig(); got.Cmp(wantMiner) != 0 {
		t.Errorf("coinbase %v, want reward and tips %v", got, wantMiner)
	}
	if st.Exist(ghost.DataCommitEntryAddress) || st.Exist(ghost.CommitEntryAddress) {
		t.Error("a commit entry address holds an account")
	}
	for _, acc := range []common.Address{ghost.PrivTotalsAccount, ghosttree.TreeAccount(ghosttree.Data), ghosttree.TreeAccount(ghosttree.Coin)} {
		if !st.GetBalance(acc).IsZero() {
			t.Errorf("reserved account %x holds a balance", acc)
		}
	}

	// The data tree holds the node's commitments, under the header's data
	// root; the coin tree and its root are those of the genesis.
	leaves := []common.Hash{first.commitment(), second.commitment()}
	if n := dataLeafCount(st); n != 2 {
		t.Fatalf("data tree has %d leaves", n)
	}
	wantRoot := ghosttree.RootFromPageRoots(ghosttree.Data, []common.Hash{ghosttree.PageRoot(ghosttree.Data, leaves)})
	if root := block.Header().DataTreeRoot; root == nil || *root != wantRoot {
		t.Fatalf("header data root %v, want %x", root, wantRoot)
	}
	if n := coinLeafCount(st); n != 0 {
		t.Fatalf("a data commit appended %d coin leaves", n)
	}
	if root := block.Header().CoinTreeRoot; root == nil || *root != *f.genesis.Header().CoinTreeRoot {
		t.Fatal("a data commit changed the coin tree root")
	}

	// One log each, on the data tree account.
	for i, r := range receipts {
		if len(r.Logs) != 1 {
			t.Fatalf("data commit %d has %d logs", i, len(r.Logs))
		}
		l := r.Logs[0]
		if l.Address != ghosttree.TreeAccount(ghosttree.Data) {
			t.Errorf("log %d address %x", i, l.Address)
		}
		if len(l.Topics) != 1 || l.Topics[0] != ghosttree.K("ghost/data-commit-receipt/v1") {
			t.Errorf("log %d topics %x", i, l.Topics)
		}
		if want := zeroSaltDataCommitLog(0, uint32(i), []dataFile{first, second}[i]); !bytes.Equal(l.Data, want) {
			t.Errorf("log %d data\n%x\nwant\n%x", i, l.Data, want)
		}
		if len(l.Data) != 4+4+32+156+16 {
			t.Errorf("log %d data has %d bytes", i, len(l.Data))
		}
	}

	// The two reserves entered the hidden set and none left it.
	if in, out := totals(st); in.Cmp(new(big.Int).Mul(reserve(), big.NewInt(2))) != 0 || out.Sign() != 0 {
		t.Errorf("totals in %v out %v after data commits", in, out)
	}

	// A later block appends after them.
	third := testDataFile("third")
	more, _ := f.generate(2, func(i int, b *core.BlockGen) {
		if i == 0 {
			b.SetCoinbase(miner)
			for _, tx := range txs {
				b.AddTx(tx)
			}
		} else {
			b.AddTx(f.dataCommitTx(keyA, 1, third, reserve()))
		}
	})
	if more[0].Hash() != block.Hash() {
		t.Fatal("the chain did not rebuild identically")
	}
	f.insert(chain, more[1:])
	r := chain.GetReceiptsByHash(more[1].Hash())[0]
	if len(r.Logs) != 1 || !bytes.Equal(r.Logs[0].Data, zeroSaltDataCommitLog(0, 2, third)) {
		t.Fatal("the third data commit is not at position 2")
	}
}

// TestSaltedDataCommitCarriesSaltToHistory data commits one file with a
// zero salt and one with a drawn salt in a block: both are recorded under the
// version 2 data commitment of F_d, each receipt log carries its salt after
// the note (212 bytes), and the tree history returns each salt with its leaf
// and note. Salted data with a value is still refused.
func TestSaltedDataCommitCarriesSaltToHistory(t *testing.T) {
	f := newFixture(t, ghost.InternalNetGasLimit, nil)
	var (
		plain  = testDataFile("plain")
		salted = testDataFile("salted")
		salt   = testSalt(0x33)
	)
	salted.version = ghostpriv.SaltedCommitVersion
	saltedData, err := ghostpriv.SaltedCommitData(salted.f, salt, salted.note)
	if err != nil {
		t.Fatal(err)
	}
	saltedTx := f.callTx(keyB, 0, ghost.DataCommitEntryAddress, reserve(), saltedData, 60_000)
	blocks, _ := f.generate(1, func(i int, b *core.BlockGen) {
		b.AddTx(f.dataCommitTx(keyA, 0, plain, reserve()))
		b.AddTx(saltedTx)
	})
	chain, history := f.historyChain()

	// With a value other than the reserve the salted data commit is refused
	// like any other.
	env, st := nextEnv(t, chain, chain.CurrentBlock(), common.Address{0xcb})
	valued := f.callTx(keyB, 0, ghost.DataCommitEntryAddress, big.NewInt(1), saltedData, 60_000)
	if _, err := applyTx(chain, st.Copy(), env.Header, valued); !errors.Is(err, ghostpriv.ErrDataCommitValue) {
		t.Fatalf("salted data commit with a value: %v, want %v", err, ghostpriv.ErrDataCommitValue)
	}

	f.insert(chain, blocks)
	block := blocks[0]
	receipts := chain.GetReceiptsByHash(block.Hash())
	if len(receipts) != 2 {
		t.Fatalf("%d receipts", len(receipts))
	}
	for i, r := range receipts {
		if r.Status != types.ReceiptStatusSuccessful || len(r.Logs) != 1 {
			t.Fatalf("data commit %d: status %d, %d logs", i, r.Status, len(r.Logs))
		}
	}
	leaves := []common.Hash{plain.commitment(), salted.commitment()}
	wantRoot := ghosttree.RootFromPageRoots(ghosttree.Data, []common.Hash{ghosttree.PageRoot(ghosttree.Data, leaves)})
	if root := block.Header().DataTreeRoot; root == nil || *root != wantRoot {
		t.Fatalf("header data root %v, want %x", root, wantRoot)
	}
	if root := block.Header().CoinTreeRoot; root == nil || *root != *f.genesis.Header().CoinTreeRoot {
		t.Fatal("a salted data commit changed the coin tree root")
	}

	// The logs: each with its salt after the note.
	if got, want := receipts[0].Logs[0].Data, zeroSaltDataCommitLog(0, 0, plain); !bytes.Equal(got, want) || len(got) != 212 {
		t.Errorf("zero-salt log of %d bytes\n%x\nwant\n%x", len(got), got, want)
	}
	if got, want := receipts[1].Logs[0].Data, append(dataCommitLog(0, 1, salted), salt...); !bytes.Equal(got, want) || len(got) != 212 {
		t.Errorf("salted log of %d bytes\n%x\nwant\n%x", len(got), got, want)
	}

	// The history records and the page carry the salt with the leaf and note.
	records, err := ghostpriv.HistoryRecords(receipts)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].Kind != ghosttree.Data || records[1].Kind != ghosttree.Data || records[1].Leaf != leaves[1] {
		t.Fatalf("history records %+v", records)
	}
	checkSalt(t, "zero-salt record", records[0].Salt, make([]byte, ghostpriv.SaltSize))
	checkSalt(t, "salted record", records[1].Salt, salt)
	page, err := history.Page(ghosttree.Data, 0, 0, block.Hash())
	if err != nil {
		t.Fatal(err)
	}
	if page.Filled != 2 {
		t.Fatalf("page of %d entries", page.Filled)
	}
	for i, d := range []dataFile{plain, salted} {
		if e := page.Entries[i]; e.Leaf != d.commitment() || !bytes.Equal(e.Note[:], d.note) {
			t.Errorf("entry %d: leaf %x note %x", i, e.Leaf, e.Note[:])
		}
	}
	checkSalt(t, "zero-salt entry", page.Entries[0].Salt, make([]byte, ghostpriv.SaltSize))
	checkSalt(t, "salted entry", page.Entries[1].Salt, salt)
	if coin, err := history.Page(ghosttree.Coin, 0, 0, block.Hash()); err != nil || coin.Filled != 0 {
		t.Errorf("coin page after data commits: %+v, %v", coin, err)
	}
}

// TestDataCommitRejectsValueAndWrongLength sends data commits with a value
// other than the reserve, with data of every wrong length and version and with a zero F, and calls
// the data commit entry address from contracts: each is rejected and nothing
// changes. A block carrying a rejected data commit is invalid.
func TestDataCommitRejectsValueAndWrongLength(t *testing.T) {
	f := newFixture(t, ghost.InternalNetGasLimit, nil)
	chain := f.newChain()
	env, st := nextEnv(t, chain, chain.CurrentBlock(), common.Address{0xcb})
	good := testDataFile("rejections")
	goodData, err := ghostpriv.SaltedCommitData(good.f, make([]byte, ghostpriv.SaltSize), good.note)
	if err != nil {
		t.Fatal(err)
	}
	withData := func(change func([]byte) []byte) []byte {
		return change(append([]byte{}, goodData...))
	}
	zeroF := withData(func(d []byte) []byte { copy(d[2:34], make([]byte, 32)); return d })
	to := ghost.DataCommitEntryAddress
	zero := new(big.Int)

	tests := []struct {
		name string
		tx   *types.Transaction
		want error
	}{
		{"zero", f.callTx(keyA, 0, to, zero, goodData, 60_000), ghostpriv.ErrDataCommitValue},
		{"one wei", f.callTx(keyA, 0, to, big.NewInt(1), goodData, 60_000), ghostpriv.ErrDataCommitValue},
		{"one GHOST", f.callTx(keyA, 0, to, oneGhost, goodData, 60_000), ghostpriv.ErrDataCommitValue},
		{"V_MAX", f.callTx(keyA, 0, to, ghostpriv.VMax.ToBig(), goodData, 60_000), ghostpriv.ErrDataCommitValue},
		{"empty data", f.callTx(keyA, 0, to, zero, nil, 60_000), ghostpriv.ErrCommitData},
		{"one byte", f.callTx(keyA, 0, to, zero, goodData[:1], 60_000), ghostpriv.ErrCommitData},
		{"34 bytes, no note", f.callTx(keyA, 0, to, zero, goodData[:34], 60_000), ghostpriv.ErrCommitData},
		{"205 bytes", f.callTx(keyA, 0, to, zero, goodData[:205], 60_000), ghostpriv.ErrCommitData},
		{"207 bytes, a storage location", f.callTx(keyA, 0, to, zero, append(append([]byte{}, goodData...), 1), 60_000), ghostpriv.ErrCommitData},
		{"238 bytes, a fingerprint", f.callTx(keyA, 0, to, zero, append(append([]byte{}, goodData...), make([]byte, 32)...), 60_000), ghostpriv.ErrCommitData},
		{"version 0", f.callTx(keyA, 0, to, zero, withData(func(d []byte) []byte { d[1] = 0; return d }), 60_000), ghostpriv.ErrCommitData},
		{"190 bytes of version 1", f.callTx(keyA, 0, to, zero, versionOneCommitData(good.f, good.note), 60_000), ghostpriv.ErrCommitData},
		{"206 bytes of version 1", f.callTx(keyA, 0, to, zero, withData(func(d []byte) []byte { d[1] = 1; return d }), 60_000), ghostpriv.ErrCommitData},
		{"zero F", f.callTx(keyA, 0, to, zero, zeroF, 60_000), ghostpriv.ErrCommitZeroF},
		{"zero F, with a value", f.callTx(keyA, 0, to, oneGhost, zeroF, 60_000), ghostpriv.ErrCommitZeroF},
		{"intrinsic gas", f.callTx(keyA, 0, to, zero, goodData, 21_000), core.ErrIntrinsicGas},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cp := st.Copy()
			if _, err := applyTx(chain, cp, env.Header, tt.tx); !errors.Is(err, tt.want) {
				t.Fatalf("error %v, want %v", err, tt.want)
			}
			if n := dataLeafCount(cp); n != 0 {
				t.Errorf("a rejected data commit appended %d leaves", n)
			}
			if n := coinLeafCount(cp); n != 0 {
				t.Errorf("a rejected data commit appended %d coin leaves", n)
			}
			if in, out := totals(cp); in.Sign() != 0 || out.Sign() != 0 {
				t.Errorf("a rejected data commit changed the totals to %v and %v", in, out)
			}
			if cp.GetBalance(addrA).ToBig().Cmp(startBal) != 0 || cp.GetNonce(addrA) != 0 {
				t.Errorf("a rejected data commit charged the sender")
			}
		})
	}

	// A block carrying a data commit with a value is invalid, and the head
	// stays.
	bad, _ := f.generate(1, func(i int, b *core.BlockGen) {
		b.AddUncheckedTx(f.callTx(keyA, 0, to, big.NewInt(1), goodData, 60_000))
	})
	if _, err := chain.InsertChain(bad); !errors.Is(err, ghostpriv.ErrDataCommitValue) {
		t.Fatalf("block with a valued data commit: %v, want %v", err, ghostpriv.ErrDataCommitValue)
	}
	if chain.CurrentBlock().Hash() != f.genesis.Hash() {
		t.Fatal("the head moved")
	}

	// The control: the reserve and the exact 206 bytes are accepted. The
	// same data with value 0 to the coin commit entry is a coin commit of
	// nothing, rejected as before.
	cp := st.Copy()
	if r, err := applyTx(chain, cp, env.Header, f.dataCommitTx(keyA, 0, good, reserve())); err != nil || r.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("data commit: %v", err)
	}
	if n := dataLeafCount(cp); n != 1 {
		t.Fatalf("data commit appended %d leaves", n)
	}
	if _, err := applyTx(chain, st.Copy(), env.Header, f.callTx(keyA, 0, ghost.CommitEntryAddress, zero, goodData, 60_000)); !errors.Is(err, ghostpriv.ErrCommitAmount) {
		t.Fatalf("zero-value coin commit: %v, want %v", err, ghostpriv.ErrCommitAmount)
	}

	// Calls from inside the EVM: every kind fails and nothing is committed,
	// while the same CALL to an ordinary address succeeds.
	var (
		ordinary = common.Address{0x0e, 0x0d}
		callers  = map[common.Address][]byte{
			{0xd1}: callerCode(vm.CALL, to),
			{0xd2}: callerCode(vm.CALLCODE, to),
			{0xd4}: callerCode(vm.DELEGATECALL, to),
			{0xda}: callerCode(vm.STATICCALL, to),
			{0xd0}: callerCode(vm.CALL, ordinary),
		}
		alloc = genesisT.GenesisAlloc{}
	)
	for addr, code := range callers {
		alloc[addr] = genesisT.GenesisAccount{Code: code, Balance: new(big.Int).Set(oneGhost)}
	}
	fc := newFixture(t, ghost.InternalNetGasLimit, alloc)
	order := []common.Address{{0xd1}, {0xd2}, {0xd4}, {0xda}, {0xd0}}
	blocks, _ := fc.generate(1, func(i int, b *core.BlockGen) {
		for n, addr := range order {
			b.AddTx(fc.callTx(keyA, uint64(n), addr, new(big.Int), nil, 1_000_000))
		}
	})
	callChain := fc.newChain()
	fc.insert(callChain, blocks)
	stc, err := callChain.StateAt(blocks[0].Root())
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range order {
		want := common.Hash{31: 1} // the call failed
		if addr == (common.Address{0xd0}) {
			want = common.Hash{31: 2} // the call succeeded
		}
		if got := stc.GetState(addr, common.Hash{}); got != want {
			t.Errorf("caller %x stored %x, want %x", addr, got, want)
		}
	}
	if stc.Exist(to) || !stc.GetBalance(to).IsZero() {
		t.Error("a contract reached the data commit entry address")
	}
	if n := dataLeafCount(stc); n != 0 {
		t.Errorf("contract calls appended %d data leaves", n)
	}
	if root := blocks[0].Header().DataTreeRoot; root == nil || *root != *fc.genesis.Header().DataTreeRoot {
		t.Error("contract calls changed the data tree root")
	}
	for i, r := range callChain.GetReceiptsByHash(blocks[0].Hash()) {
		if r.Status != types.ReceiptStatusSuccessful || len(r.Logs) != 0 {
			t.Errorf("transaction %d: status %d, %d logs", i, r.Status, len(r.Logs))
		}
	}
}

// TestDataCommitValueMustBeTheReserve checks that a data commit's value is
// exactly DATA_RESERVE, 2.5 x 10^17 wei: 0, one wei less or more and one
// GHOST are each ErrDataCommitValue, through ParseDataCommit and in a block,
// which is then invalid; the reserve itself is accepted both ways.
func TestDataCommitValueMustBeTheReserve(t *testing.T) {
	if want, _ := new(big.Int).SetString("250000000000000000", 10); reserve().Cmp(want) != 0 {
		t.Fatalf("DATA_RESERVE %v, want %v", reserve(), want)
	}
	if got := common.BigToHash(reserve()); got != common.HexToHash("0x3782dace9d90000") {
		t.Fatalf("DATA_RESERVE word %x", got)
	}
	file := testDataFile("reserve value")
	data, err := ghostpriv.SaltedCommitData(file.f, make([]byte, ghostpriv.SaltSize), file.note)
	if err != nil {
		t.Fatal(err)
	}
	one := big.NewInt(1)
	for name, value := range map[string]*big.Int{
		"zero":               new(big.Int),
		"the reserve less 1": new(big.Int).Sub(reserve(), one),
		"the reserve plus 1": new(big.Int).Add(reserve(), one),
		"one GHOST":          new(big.Int).Set(oneGhost),
	} {
		if _, err := ghostpriv.ParseDataCommit(data, value); !errors.Is(err, ghostpriv.ErrDataCommitValue) {
			t.Errorf("%s: %v, want %v", name, err, ghostpriv.ErrDataCommitValue)
		}
		f := newFixture(t, ghost.InternalNetGasLimit, nil)
		chain := f.newChain()
		bad, _ := f.generate(1, func(i int, b *core.BlockGen) {
			b.AddUncheckedTx(f.dataCommitTx(keyA, 0, file, value))
		})
		if _, err := chain.InsertChain(bad); !errors.Is(err, ghostpriv.ErrDataCommitValue) {
			t.Errorf("block with a data commit of %s: %v, want %v", name, err, ghostpriv.ErrDataCommitValue)
		}
		if chain.CurrentBlock().Hash() != f.genesis.Hash() {
			t.Errorf("%s: the head moved", name)
		}
	}
	if _, err := ghostpriv.ParseDataCommit(data, nil); !errors.Is(err, ghostpriv.ErrDataCommitValue) {
		t.Errorf("no value: %v, want %v", err, ghostpriv.ErrDataCommitValue)
	}

	// Exactly the reserve.
	dc, err := ghostpriv.ParseDataCommit(data, reserve())
	if err != nil || dc.F != file.f {
		t.Fatalf("data commit of the reserve: %v", err)
	}
	f := newFixture(t, ghost.InternalNetGasLimit, nil)
	chain := f.newChain()
	good, _ := f.generate(1, func(i int, b *core.BlockGen) {
		b.AddTx(f.dataCommitTx(keyA, 0, file, reserve()))
	})
	f.insert(chain, good)
	if r := chain.GetReceiptsByHash(good[0].Hash()); len(r) != 1 || r[0].Status != types.ReceiptStatusSuccessful {
		t.Fatal("the data commit of the reserve did not apply")
	}
}

// TestDataCommitBurnsTheReserve checks that a data commit debits the sender
// the reserve and its gas, credits the reserve to nobody, adds it to the
// total in and records the leaf K(tag, DATA version 2, the reserve, F_d),
// recomputed here, which is not the leaf without the reserve. A sender
// holding less than the reserve is refused and nothing changes.
func TestDataCommitBurnsTheReserve(t *testing.T) {
	poorKey, _, poor := testAccount(0xd5)
	poorBal := new(big.Int).Sub(reserve(), common.Big1)
	f := newFixture(t, ghost.InternalNetGasLimit, genesisT.GenesisAlloc{poor: {Balance: poorBal}})
	chain := f.newChain()
	env, st := nextEnv(t, chain, chain.CurrentBlock(), common.Address{0xcb})
	file := testDataFile("burns the reserve")

	cp := st.Copy()
	tx := f.dataCommitTx(keyA, 0, file, reserve())
	r, err := applyTx(chain, cp, env.Header, tx)
	if err != nil || r.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("data commit: %v", err)
	}
	price := new(big.Int).Add(tx.GasTipCap(), env.Header.BaseFee)
	if price.Cmp(tx.GasFeeCap()) > 0 {
		price.Set(tx.GasFeeCap())
	}
	r.EffectiveGasPrice = price
	gasCost := new(big.Int).Mul(new(big.Int).SetUint64(r.GasUsed), r.EffectiveGasPrice)
	if got, want := cp.GetBalance(addrA).ToBig(), new(big.Int).Sub(startBal, new(big.Int).Add(reserve(), gasCost)); got.Cmp(want) != 0 {
		t.Errorf("sender balance %v, want %v", got, want)
	}
	tip := new(big.Int).Sub(r.EffectiveGasPrice, env.Header.BaseFee)
	if got, want := cp.GetBalance(env.Header.Coinbase).ToBig(), tip.Mul(tip, new(big.Int).SetUint64(r.GasUsed)); got.Cmp(want) != 0 {
		t.Errorf("coinbase %v, want only the gas tip %v", got, want)
	}
	for _, acc := range []common.Address{ghost.DataCommitEntryAddress, ghost.PrivTotalsAccount, ghosttree.TreeAccount(ghosttree.Data)} {
		if !cp.GetBalance(acc).IsZero() {
			t.Errorf("%x received the reserve", acc)
		}
	}
	if in, out := totals(cp); in.Cmp(reserve()) != 0 || out.Sign() != 0 {
		t.Errorf("totals in %v out %v, want the reserve in", in, out)
	}
	word := common.BigToHash(reserve())
	wantLeaf := ghosttree.K("ghost/data-commitment/v1", []byte{0x02, 0x02}, word[:], file.f[:])
	oldLeaf := ghosttree.K("ghost/data-commitment/v1", []byte{0x02, 0x02}, file.f[:])
	if wantLeaf == oldLeaf || file.commitment() != wantLeaf {
		t.Fatalf("leaf %x, want %x", file.commitment(), wantLeaf)
	}
	if len(r.Logs) != 1 || !bytes.Equal(r.Logs[0].Data[8:40], wantLeaf[:]) {
		t.Fatalf("the receipt does not record the leaf %x", wantLeaf)
	}
	if n := dataLeafCount(cp); n != 1 {
		t.Fatalf("data tree has %d leaves", n)
	}

	// A sender below the reserve: the transaction cannot pay its value, and
	// ApplyDataCommit itself refuses it, changing nothing.
	cp = st.Copy()
	if _, err := applyTx(chain, cp, env.Header, f.dataCommitTx(poorKey, 0, file, reserve())); !errors.Is(err, core.ErrInsufficientFunds) {
		t.Fatalf("data commit from a sender below the reserve: %v, want %v", err, core.ErrInsufficientFunds)
	}
	dc, err := ghostpriv.ParseDataCommit(mustSaltedData(t, file), reserve())
	if err != nil {
		t.Fatal(err)
	}
	cp = st.Copy()
	rootBefore := cp.IntermediateRoot(true)
	if err := ghostpriv.ApplyDataCommit(cp, 1, poor, dc); !errors.Is(err, ghostpriv.ErrCommitFunds) {
		t.Fatalf("ApplyDataCommit below the reserve: %v, want %v", err, ghostpriv.ErrCommitFunds)
	}
	if cp.IntermediateRoot(true) != rootBefore || len(cp.Logs()) != 0 || cp.GetBalance(poor).ToBig().Cmp(poorBal) != 0 {
		t.Fatal("a refused data commit changed the state")
	}
	// With the reserve, ApplyDataCommit makes the change.
	if err := ghostpriv.ApplyDataCommit(cp, 1, addrA, dc); err != nil {
		t.Fatal(err)
	}
	if in, _ := totals(cp); in.Cmp(reserve()) != 0 || cp.GetBalance(addrA).ToBig().Cmp(new(big.Int).Sub(startBal, reserve())) != 0 {
		t.Fatalf("ApplyDataCommit: total in %v, sender %v", in, cp.GetBalance(addrA))
	}
}

// mustSaltedData is the zero-salt commit data of d.
func mustSaltedData(t *testing.T, d dataFile) []byte {
	t.Helper()
	data, err := ghostpriv.SaltedCommitData(d.f, make([]byte, ghostpriv.SaltSize), d.note)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
