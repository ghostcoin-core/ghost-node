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

// commitLog is the receipt log a commit writes.
func commitLog(index, position uint32, c coin) []byte {
	leaf := c.commitment()
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
	// The known answer of the commitment.
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
		data, err := ghostpriv.CommitData(second.f, second.note)
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
	if leaves[0] != common.HexToHash("562d92a92bb8f2b3b772b55220a5ee26f189bedc0f4bfa513205df1545029458") {
		t.Fatal("the first leaf is not the known answer")
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
		if len(l.Data) != 4+4+32+32+156 {
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
	data, err := ghostpriv.CommitData(claimed.f, claimed.note)
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
	goodData, err := ghostpriv.CommitData(good.f, good.note)
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
		{"189 bytes", f.callTx(keyA, 0, ghost.CommitEntryAddress, oneGhost, goodData[:189], 60_000), false, ghostpriv.ErrCommitData, nil},
		{"191 bytes, an extra field", f.callTx(keyA, 0, ghost.CommitEntryAddress, oneGhost, append(append([]byte{}, goodData...), 1), 60_000), false, ghostpriv.ErrCommitData, nil},
		{"version 2, zero F", f.callTx(keyA, 0, ghost.CommitEntryAddress, oneGhost, func() []byte { d := append([]byte{}, zeroF...); d[1] = 2; return d }(), 60_000), false, ghostpriv.ErrCommitData, nil},
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
