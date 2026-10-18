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
	"crypto/ecdsa"
	"encoding/binary"
	"errors"
	"math/big"
	"testing"

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
// note. The node never sees the file itself.
type dataFile struct {
	f    common.Hash
	note []byte
}

func (d dataFile) commitment() common.Hash { return ghostpriv.DataCommitment(d.f) }

func testDataFile(name string) dataFile {
	return dataFile{
		f:    ghosttree.K("ghost/test-data-f", []byte(name)),
		note: testNote(byte(0x40 + len(name))),
	}
}

// dataCommitTx is a data commit of d from key with the given value, a
// dynamic-fee transaction to the data commit entry address.
func (f *fixture) dataCommitTx(key *ecdsa.PrivateKey, nonce uint64, d dataFile, value *big.Int) *types.Transaction {
	f.t.Helper()
	data, err := ghostpriv.CommitData(d.f, d.note)
	if err != nil {
		f.t.Fatal(err)
	}
	return f.callTx(key, nonce, ghost.DataCommitEntryAddress, value, data, 60_000)
}

// dataCommitLog is the receipt log a data commit writes.
func dataCommitLog(index, position uint32, d dataFile) []byte {
	leaf := d.commitment()
	data := binary.BigEndian.AppendUint32(nil, index)
	data = binary.BigEndian.AppendUint32(data, position)
	data = append(data, leaf[:]...)
	return append(data, d.note...)
}

func dataLeafCount(st *state.StateDB) uint64 {
	return st.GetState(ghosttree.TreeAccount(ghosttree.Data), ghosttree.Slot(ghosttree.SlotLeafCount)).Big().Uint64()
}

// TestDataCommitAppendsToDataTree commits two files, from a dynamic-fee and a
// legacy transaction, in one block on the internal network and checks that
// the data tree holds the commitments the node computed under the header's
// data root, the receipt logs with leaf, tree index, position and note, and
// that the coin tree, the totals and every balance but the gas are as they
// were.
func TestDataCommitAppendsToDataTree(t *testing.T) {
	// The commitment is K over DATA and F_d, and never a coin commitment.
	known := testDataFile("known")
	want := ghosttree.K("ghost/data-commitment/v1", []byte{0x02, 0x01}, known.f[:])
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
		second = testDataFile("legacy")
		txs    []*types.Transaction
	)
	blocks, _ := f.generate(1, func(i int, b *core.BlockGen) {
		b.SetCoinbase(miner)
		txs = append(txs, f.dataCommitTx(keyA, 0, first, new(big.Int)))
		data, err := ghostpriv.CommitData(second.f, second.note)
		if err != nil {
			t.Fatal(err)
		}
		txs = append(txs, types.MustSignNewTx(keyB, f.signer, &types.LegacyTx{
			Nonce:    0,
			GasPrice: new(big.Int).Mul(gwei, big.NewInt(100)),
			Gas:      60_000,
			To:       &ghost.DataCommitEntryAddress,
			Value:    new(big.Int),
			Data:     data,
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

	// Each sender paid its gas and nothing else; the coinbase got the reward
	// and the tips.
	tips := new(big.Int)
	for i, sender := range []common.Address{addrA, addrB} {
		r := receipts[i]
		if r.Status != types.ReceiptStatusSuccessful {
			t.Fatalf("data commit %d failed", i)
		}
		gasCost := new(big.Int).Mul(new(big.Int).SetUint64(r.GasUsed), r.EffectiveGasPrice)
		if got, want := st.GetBalance(sender).ToBig(), new(big.Int).Sub(startBal, gasCost); got.Cmp(want) != 0 {
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
		if want := dataCommitLog(0, uint32(i), []dataFile{first, second}[i]); !bytes.Equal(l.Data, want) {
			t.Errorf("log %d data\n%x\nwant\n%x", i, l.Data, want)
		}
		if len(l.Data) != 4+4+32+156 {
			t.Errorf("log %d data has %d bytes", i, len(l.Data))
		}
	}

	// No value entered or left the hidden set.
	if in, out := totals(st); in.Sign() != 0 || out.Sign() != 0 {
		t.Errorf("totals in %v out %v after data commits", in, out)
	}
	if st.Exist(ghost.PrivTotalsAccount) {
		t.Error("a data commit created the totals account")
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
			b.AddTx(f.dataCommitTx(keyA, 1, third, new(big.Int)))
		}
	})
	if more[0].Hash() != block.Hash() {
		t.Fatal("the chain did not rebuild identically")
	}
	f.insert(chain, more[1:])
	r := chain.GetReceiptsByHash(more[1].Hash())[0]
	if len(r.Logs) != 1 || !bytes.Equal(r.Logs[0].Data, dataCommitLog(0, 2, third)) {
		t.Fatal("the third data commit is not at position 2")
	}
}

// TestDataCommitRejectsValueAndWrongLength sends data commits with a value,
// with data of every wrong length and version and with a zero F, and calls
// the data commit entry address from contracts: each is rejected and nothing
// changes. A block carrying a rejected data commit is invalid.
func TestDataCommitRejectsValueAndWrongLength(t *testing.T) {
	f := newFixture(t, ghost.InternalNetGasLimit, nil)
	chain := f.newChain()
	env, st := nextEnv(t, chain, chain.CurrentBlock(), common.Address{0xcb})
	good := testDataFile("rejections")
	goodData, err := ghostpriv.CommitData(good.f, good.note)
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
		{"one wei", f.callTx(keyA, 0, to, big.NewInt(1), goodData, 60_000), ghostpriv.ErrDataCommitValue},
		{"one GHOST", f.callTx(keyA, 0, to, oneGhost, goodData, 60_000), ghostpriv.ErrDataCommitValue},
		{"V_MAX", f.callTx(keyA, 0, to, ghostpriv.VMax.ToBig(), goodData, 60_000), ghostpriv.ErrDataCommitValue},
		{"empty data", f.callTx(keyA, 0, to, zero, nil, 60_000), ghostpriv.ErrCommitData},
		{"one byte", f.callTx(keyA, 0, to, zero, goodData[:1], 60_000), ghostpriv.ErrCommitData},
		{"34 bytes, no note", f.callTx(keyA, 0, to, zero, goodData[:34], 60_000), ghostpriv.ErrCommitData},
		{"189 bytes", f.callTx(keyA, 0, to, zero, goodData[:189], 60_000), ghostpriv.ErrCommitData},
		{"191 bytes, a storage location", f.callTx(keyA, 0, to, zero, append(append([]byte{}, goodData...), 1), 60_000), ghostpriv.ErrCommitData},
		{"222 bytes, a fingerprint", f.callTx(keyA, 0, to, zero, append(append([]byte{}, goodData...), make([]byte, 32)...), 60_000), ghostpriv.ErrCommitData},
		{"version 0", f.callTx(keyA, 0, to, zero, withData(func(d []byte) []byte { d[1] = 0; return d }), 60_000), ghostpriv.ErrCommitData},
		{"version 2, with a value", f.callTx(keyA, 0, to, oneGhost, withData(func(d []byte) []byte { d[1] = 2; return d }), 60_000), ghostpriv.ErrCommitData},
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

	// The control: value 0 and the exact 190 bytes are accepted. The same
	// data with value 0 to the coin commit entry is a coin commit of
	// nothing, rejected as before.
	cp := st.Copy()
	if r, err := applyTx(chain, cp, env.Header, f.dataCommitTx(keyA, 0, good, zero)); err != nil || r.Status != types.ReceiptStatusSuccessful {
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
