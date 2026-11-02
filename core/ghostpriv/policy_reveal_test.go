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
	"fmt"
	"math/big"
	"math/rand"
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

// The frozen policy of these tests: a contract the genesis holds, marked as
// a policy created at height 0 through the registry helper.
var (
	testPolicy     = common.HexToAddress("0x9a11c1e5000000000000000000000000000beef1")
	testPolicyCode = []byte{0x60, 0x00, 0x60, 0x00, 0xf3} // PUSH1 0 PUSH1 0 RETURN
	testPolicyHash = crypto.Keccak256Hash(testPolicyCode)
)

// allocRegistry writes registry words into a genesis allocation, so that
// ghost.RegisterPolicy marks a policy of the genesis.
type allocRegistry struct{ alloc genesisT.GenesisAlloc }

func (a allocRegistry) account(addr common.Address) genesisT.GenesisAccount {
	acc := a.alloc[addr]
	if acc.Balance == nil {
		acc.Balance = new(big.Int)
	}
	if acc.Storage == nil {
		acc.Storage = map[common.Hash]common.Hash{}
	}
	return acc
}

func (a allocRegistry) GetState(addr common.Address, key common.Hash) common.Hash {
	return a.alloc[addr].Storage[key]
}

func (a allocRegistry) SetState(addr common.Address, key, value common.Hash) {
	acc := a.account(addr)
	acc.Storage[key] = value
	a.alloc[addr] = acc
}

func (a allocRegistry) GetNonce(addr common.Address) uint64 { return a.alloc[addr].Nonce }

func (a allocRegistry) SetNonce(addr common.Address, nonce uint64) {
	acc := a.account(addr)
	acc.Nonce = nonce
	a.alloc[addr] = acc
}

// policyAlloc is the genesis allocation of the test policy: its code, and
// its registry entry with the creation height 0 and its code hash.
func policyAlloc() genesisT.GenesisAlloc {
	alloc := genesisT.GenesisAlloc{testPolicy: {Code: testPolicyCode, Balance: new(big.Int)}}
	ghost.RegisterPolicy(allocRegistry{alloc}, testPolicy, 0, testPolicyHash)
	return alloc
}

// registerInState makes addr a policy with code created in the block at
// height, in st.
func registerInState(st *state.StateDB, addr common.Address, code []byte, height uint64) {
	st.SetCode(addr, code)
	ghost.RegisterPolicy(st, addr, height, crypto.Keccak256Hash(code))
}

// newPolicyReveal is a policy reveal of the given fields with the stub proof
// of its binding digest on this chain. The remainder is of value zero.
func (f *fixture) newPolicyReveal(root, marker common.Hash, policy common.Address, codeHash common.Hash, out, fee *uint256.Int) *ghostpriv.PolicyReveal {
	r := &ghostpriv.PolicyReveal{
		Version:    ghostpriv.PolicyRevealVersion,
		ChainID:    f.chainID,
		Marker:     marker,
		Root:       root,
		Remainder:  testCoin("policy rest "+marker.Hex(), new(big.Int)).commitment(),
		Out:        new(uint256.Int).Set(out),
		Fee:        new(uint256.Int).Set(fee),
		Policy:     policy,
		CodeHash:   codeHash,
		ParamsHash: ghosttree.K("ghost/test-params", marker[:]),
		ActionTag:  ghosttree.K("ghost/test-action-tag", marker[:]),
		ActionSalt: ghosttree.K("ghost/test-action-salt", marker[:]),
		Instr:      ghosttree.K("ghost/test-instr", marker[:]),
	}
	copy(r.Note[:], testNote(0x5c))
	f.provePolicy(r)
	return r
}

// provePolicy sets the stub proof of the policy reveal's binding digest.
func (f *fixture) provePolicy(r *ghostpriv.PolicyReveal) {
	r.Proof = ghostprivtest.Proof(r.BindingDigest(f.chainID, f.genesis.Hash()))
}

func clonePolicy(r *ghostpriv.PolicyReveal) *ghostpriv.PolicyReveal {
	cp := *r
	cp.Out = new(uint256.Int).Set(r.Out)
	cp.Fee = new(uint256.Int).Set(r.Fee)
	cp.Proof = common.CopyBytes(r.Proof)
	return &cp
}

func policyEnvelope(t *testing.T, r *ghostpriv.PolicyReveal) []byte {
	t.Helper()
	env, err := r.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func policyRevealTx(t *testing.T, r *ghostpriv.PolicyReveal) *types.Transaction {
	t.Helper()
	tx, err := types.NewGhostPolicyRevealTx(policyEnvelope(t, r))
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

// policyScenario is a chain with the test policy in its genesis, whose block
// 1 commits one GHOST from account A, with empty blocks after it, all
// imported, and the environment and state of the block after them.
type policyScenario struct {
	f      *fixture
	chain  *core.BlockChain
	blocks []*types.Block
	c      coin
	env    *ghostpriv.BlockEnv
	st     *state.StateDB
	miner  common.Address
}

func newPolicyScenario(t *testing.T, n int) *policyScenario {
	t.Helper()
	f := newFixture(t, ghost.InternalNetGasLimit, policyAlloc())
	c := testCoin("policy scenario", oneGhost)
	blocks, _ := f.generate(n, func(i int, b *core.BlockGen) {
		if i == 0 {
			b.AddTx(f.commitTx(keyA, 0, c))
		}
	})
	chain := f.newChain()
	f.insert(chain, blocks)
	miner := common.Address{0xcb, 0x53}
	env, st := nextEnv(t, chain, blocks[n-1].Header(), miner)
	return &policyScenario{f: f, chain: chain, blocks: blocks, c: c, env: env, st: st, miner: miner}
}

// root is the coin root of block 1, which holds the coin.
func (s *policyScenario) root() common.Hash { return *s.blocks[0].Header().CoinTreeRoot }

// fee is the window fee of the class whose gas is gas in the next block.
func (s *policyScenario) fee(t *testing.T, gas uint64) *uint256.Int {
	return chainWindowFeeGas(t, s.chain, s.env.Header, gas).Total
}

// reveal is a policy reveal of the scenario's coin into the test policy.
func (s *policyScenario) reveal(t *testing.T, marker string, out *uint256.Int) *ghostpriv.PolicyReveal {
	return s.f.newPolicyReveal(s.root(), testMarker(marker), testPolicy, testPolicyHash, out, s.fee(t, ghostpriv.GasPolicy))
}

// policySnapshot is what a policy reveal can change.
type policySnapshot struct {
	root    common.Hash
	logs    int
	coinbal string
}

func snapshotPolicy(st *state.StateDB, miner common.Address) policySnapshot {
	return policySnapshot{root: st.Copy().IntermediateRoot(true), logs: len(st.Logs()), coinbal: st.GetBalance(miner).String()}
}

// TestPolicyRevealCheckOrder gives the block after a commit a policy reveal
// that fails each of checks 1 to 11 of spec 10, section 5.2, in turn, and
// where it can a later one too: the first failing check is the one
// reported, nothing changes, and the verifier is called zero times for every
// check before 11. Check 5, the binding, computes the digest and cannot fail:
// a proof bound to other fields fails at 11.
func TestPolicyRevealCheckOrder(t *testing.T) {
	useStub(t)
	s := newPolicyScenario(t, 5)
	env, st := s.env, s.st
	base := s.reveal(t, "policy order", u256(ghostAmount(1, 2)))
	counter := &countingVerifier{}
	if _, _, err := ghostpriv.CheckPolicyReveal(st.Copy(), env, counter, policyEnvelope(t, base)); err != nil || counter.calls != 1 {
		t.Fatalf("the base policy reveal: %v, %d proofs verified", err, counter.calls)
	}
	hidden, err := ghostpriv.Hidden(st)
	if err != nil {
		t.Fatal(err)
	}
	one := uint256.NewInt(1)
	edit := func(change func(e []byte) []byte) []byte { return change(policyEnvelope(t, base)) }
	with := func(change func(r *ghostpriv.PolicyReveal), prove bool) []byte {
		r := clonePolicy(base)
		change(r)
		if prove {
			s.f.provePolicy(r)
		}
		return policyEnvelope(t, r)
	}
	spend := func(st *state.StateDB) {
		if err := ghosttree.MarkSpent(st, ghosttree.Coin, base.Marker); err != nil {
			t.Fatal(err)
		}
	}
	fill := func(st *state.StateDB) { fillCoinTree(st, env.Header.Number.Uint64()) }
	stranger := common.HexToAddress("0x5e1f000000000000000000000000000000000001")
	otherGenesis := ghostprivtest.Proof(base.BindingDigest(s.f.chainID, common.Hash{3}))
	// overdraw is the out that, with fee, takes one wei more than is hidden.
	overdraw := func(fee *uint256.Int) *uint256.Int {
		out := new(uint256.Int).Sub(hidden, fee)
		return out.AddUint64(out, 1)
	}
	const (
		offOut = 1 + 106 // the type byte, then the payload's out field
		offFee = 1 + 138
	)
	tests := []struct {
		name string
		env  []byte
		prep func(*state.StateDB)
		want error
	}{
		{"1: short", edit(func(e []byte) []byte { return e[:len(e)-1] }), nil, ghostpriv.ErrPolicyRevealLength},
		{"1: long", edit(func(e []byte) []byte { return append(e, 0) }), nil, ghostpriv.ErrPolicyRevealLength},
		{"1: an ordinary reveal's length", edit(func(e []byte) []byte { return e[:types.GhostRevealEnvelopeSize] }), nil, ghostpriv.ErrPolicyRevealLength},
		{"1: type 0x50", edit(func(e []byte) []byte { e[0] = types.GhostRevealTxType; return e }), nil, ghostpriv.ErrPolicyRevealLength},
		{"1: version 2, out not below 2^96", edit(func(e []byte) []byte { e[2] = 2; e[offOut] = 1; return e }), nil, ghostpriv.ErrPolicyRevealVersion},
		{"1: version 0", edit(func(e []byte) []byte { e[2] = 0; return e }), nil, ghostpriv.ErrPolicyRevealVersion},
		{"2: out not below 2^96, wrong chain", edit(func(e []byte) []byte { e[offOut+19] = 1; e[1+9] ^= 1; return e }), nil, ghostpriv.ErrPolicyRevealAmount},
		{"2: fee not below 2^96", edit(func(e []byte) []byte { e[offFee] = 1; return e }), nil, ghostpriv.ErrPolicyRevealAmount},
		{"3: wrong chain, wrong fee", with(func(r *ghostpriv.PolicyReveal) { r.ChainID++; r.Fee.Add(r.Fee, one) }, true), nil, ghostpriv.ErrPolicyRevealChainID},
		{"4: fee one wei high, unknown root", with(func(r *ghostpriv.PolicyReveal) { r.Fee.Add(r.Fee, one); r.Root = common.Hash{1} }, true), nil, ghostpriv.ErrPolicyRevealFee},
		{"4: the ordinary class's fee", with(func(r *ghostpriv.PolicyReveal) { r.Fee = s.fee(t, ghostpriv.GasPriv) }, true), nil, ghostpriv.ErrPolicyRevealFee},
		{"4: the data class's fee", with(func(r *ghostpriv.PolicyReveal) { r.Fee = s.fee(t, ghostpriv.GasData) }, true), nil, ghostpriv.ErrPolicyRevealFee},
		{"6: unknown root, marker spent", with(func(r *ghostpriv.PolicyReveal) { r.Root = common.Hash{1} }, true), spend, ghostpriv.ErrPolicyRevealRoot},
		{"7: marker spent, overdraw", with(func(r *ghostpriv.PolicyReveal) { r.Out = new(uint256.Int).Set(hidden) }, true), spend, ghostpriv.ErrPolicyRevealMarker},
		{"7: zero marker, overdraw", with(func(r *ghostpriv.PolicyReveal) { r.Marker = common.Hash{}; r.Out = new(uint256.Int).Set(hidden) }, true), nil, ghostpriv.ErrPolicyRevealMarker},
		{"8: overdraw, no policy", with(func(r *ghostpriv.PolicyReveal) { r.Out = overdraw(r.Fee); r.Policy = stranger }, true), nil, ghostpriv.ErrPolicyRevealBackstop},
		{"9: no policy, full tree", with(func(r *ghostpriv.PolicyReveal) { r.Policy = stranger }, true), fill, ghostpriv.ErrPolicyRevealPolicy},
		{"9: another code hash, full tree", with(func(r *ghostpriv.PolicyReveal) { r.CodeHash = common.Hash{9} }, true), fill, ghostpriv.ErrPolicyRevealPolicy},
		{"10: full tree, stale proof", with(func(r *ghostpriv.PolicyReveal) { r.Instr[0] ^= 1 }, false), fill, ghostpriv.ErrPolicyRevealTree},
		{"11: proof of another instruction", with(func(r *ghostpriv.PolicyReveal) { r.Instr[0] ^= 1 }, false), nil, ghostpriv.ErrPolicyRevealProof},
		{"11: proof bound to another genesis", with(func(r *ghostpriv.PolicyReveal) { r.Proof = otherGenesis }, false), nil, ghostpriv.ErrPolicyRevealProof},
		{"11: no proof", with(func(r *ghostpriv.PolicyReveal) { r.Proof = nil }, false), nil, ghostpriv.ErrPolicyRevealProof},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cp := st.Copy()
			if tt.prep != nil {
				tt.prep(cp)
			}
			before := snapshotPolicy(cp, s.miner)
			counter.calls = 0
			if _, _, err := ghostpriv.CheckPolicyReveal(cp, env, counter, tt.env); !errors.Is(err, tt.want) {
				t.Fatalf("check: error %v, want %v", err, tt.want)
			}
			err := ghostpriv.ApplyPolicyReveal(cp, env, counter, tt.env)
			if !errors.Is(err, tt.want) {
				t.Fatalf("apply: error %v, want %v", err, tt.want)
			}
			if tt.want == ghostpriv.ErrPolicyRevealTree && !errors.Is(err, ghosttree.ErrFillingBlock) {
				t.Fatalf("full tree: %v, want %v", err, ghosttree.ErrFillingBlock)
			}
			want := 0
			if tt.want == ghostpriv.ErrPolicyRevealProof {
				want = 2 // once by the check, once by the apply
			}
			if counter.calls != want {
				t.Fatalf("%d proofs verified, want %d", counter.calls, want)
			}
			if after := snapshotPolicy(cp, s.miner); after != before {
				t.Fatalf("a rejected policy reveal changed the state:\n%+v\n%+v", before, after)
			}
		})
	}

	// The base policy reveal applies.
	cp := st.Copy()
	if err := ghostpriv.ApplyPolicyReveal(cp, env, stub, policyEnvelope(t, base)); err != nil {
		t.Fatal(err)
	}
	if snapshotPolicy(cp, s.miner) == snapshotPolicy(st, s.miner) {
		t.Fatal("the base policy reveal changed nothing")
	}
}

// TestPolicyRevealRP9 checks RP-9: a policy reveal whose address is not a
// frozen policy created in an earlier block, or whose code hash is another,
// is rejected at check 9 before the proof, which the counting verifier never
// sees. The cases are an unregistered contract, a policy created in the
// including block itself, a wrong code hash (registry and EXTCODEHASH), a
// registered policy whose EXTCODEHASH differs from its registry entry, and a
// reserved address marked as a policy. The test policy of the genesis passes,
// with one proof verified.
func TestPolicyRevealRP9(t *testing.T) {
	useStub(t)
	s := newPolicyScenario(t, 3)
	height := s.env.Header.Number.Uint64()
	var (
		unregistered = common.HexToAddress("0x5e1f000000000000000000000000000000000002")
		sameBlock    = common.HexToAddress("0x5e1f000000000000000000000000000000000003")
		recoded      = common.HexToAddress("0x5e1f000000000000000000000000000000000004")
		otherCode    = []byte{0x60, 0x01, 0x60, 0x00, 0xf3}
	)
	out := u256(ghostAmount(1, 4))
	fee := s.fee(t, ghostpriv.GasPolicy)
	for _, tt := range []struct {
		name     string
		policy   common.Address
		codeHash common.Hash
		prep     func(st *state.StateDB)
		want     error
	}{
		{"an unregistered contract", unregistered, testPolicyHash, func(st *state.StateDB) { st.SetCode(unregistered, testPolicyCode) }, ghostpriv.ErrPolicyRevealPolicy},
		{"a policy created in the same block", sameBlock, testPolicyHash, func(st *state.StateDB) { registerInState(st, sameBlock, testPolicyCode, height) }, ghostpriv.ErrPolicyRevealPolicy},
		{"a policy created in a later block", sameBlock, testPolicyHash, func(st *state.StateDB) { registerInState(st, sameBlock, testPolicyCode, height+1) }, ghostpriv.ErrPolicyRevealPolicy},
		{"another code hash", testPolicy, crypto.Keccak256Hash(otherCode), nil, ghostpriv.ErrPolicyRevealPolicy},
		{"a code other than the registered one", recoded, testPolicyHash, func(st *state.StateDB) {
			registerInState(st, recoded, testPolicyCode, 0)
			st.SetCode(recoded, otherCode)
		}, ghostpriv.ErrPolicyRevealPolicy},
		{"a reserved address", ghost.EscrowAccount, testPolicyHash, func(st *state.StateDB) { registerInState(st, ghost.EscrowAccount, testPolicyCode, 0) }, ghostpriv.ErrPolicyRevealPolicy},
		{"the frozen policy of the genesis", testPolicy, testPolicyHash, nil, nil},
		{"a policy created in the block before", sameBlock, testPolicyHash, func(st *state.StateDB) { registerInState(st, sameBlock, testPolicyCode, height-1) }, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cp := s.st.Copy()
			if tt.prep != nil {
				tt.prep(cp)
			}
			r := s.f.newPolicyReveal(s.root(), testMarker("rp9 "+tt.name), tt.policy, tt.codeHash, out, fee)
			counter := &countingVerifier{}
			before := snapshotPolicy(cp, s.miner)
			err := ghostpriv.ApplyPolicyReveal(cp, s.env, counter, policyEnvelope(t, r))
			if tt.want == nil {
				if err != nil || counter.calls != 1 {
					t.Fatalf("%v, %d proofs verified, want acceptance after one", err, counter.calls)
				}
				return
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("%v, want %v", err, tt.want)
			}
			if counter.calls != 0 {
				t.Fatalf("%d proofs verified before the policy check", counter.calls)
			}
			if after := snapshotPolicy(cp, s.miner); after != before {
				t.Fatal("a rejected policy reveal changed the state")
			}
		})
	}
}

// slotWords reads the eight storage words of the slot of marker.
func slotWords(st *state.StateDB, marker common.Hash) [ghostpriv.EscrowSlotWords]common.Hash {
	var w [ghostpriv.EscrowSlotWords]common.Hash
	for i := range w {
		w[i] = st.GetState(ghost.EscrowAccount, ghostpriv.EscrowSlotKey(marker, byte(i)))
	}
	return w
}

// amount12 is v as the 12 bytes of a slot amount.
func amount12(v *uint256.Int) []byte {
	w := v.Bytes32()
	return w[20:]
}

// TestPolicyRevealEffects applies a policy reveal with out > 0 and one with
// out = 0 and checks the effects of spec 10, section 5.3: the marker spent,
// the zero-value remainder appended with its note, the fee paid (the tip to
// the coinbase, the burn G_POLICY times the price to nobody), the totals,
// the slot's eight words of section 7.1 at their keys, and the receipt log
// and slot-opened log of section 7.5. With out = 0 no slot opens and no
// slot log is written, and the fee is still paid and the marker spent. No
// balance but the tip is credited, the policy's included.
func TestPolicyRevealEffects(t *testing.T) {
	useStub(t)
	s := newPolicyScenario(t, 5)
	height := s.env.Header.Number.Uint64()
	feeSplit := chainWindowFeeGas(t, s.chain, s.env.Header, ghostpriv.GasPolicy)
	if want, _ := ghostpriv.WindowFeeGas(s.chain.GetHeaderByNumber(4).BaseFee, ghostpriv.GasPolicy); !want.Total.Eq(feeSplit.Total) {
		t.Fatalf("window fee %v, want %v", feeSplit.Total, want.Total)
	}
	split, err := feeSplit.CoverGas(s.env.Header.BaseFee, ghostpriv.GasPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if want := new(uint256.Int).Mul(uint256.NewInt(ghostpriv.GasPolicy), feeSplit.Price); !split.Burn.Eq(want) {
		t.Fatalf("burn %v, want G_POLICY times the price %v", split.Burn, want)
	}
	hiddenBefore, err := ghostpriv.Hidden(s.st)
	if err != nil {
		t.Fatal(err)
	}
	inBefore, outBefore := ghostpriv.Totals(s.st)

	for _, out := range []*uint256.Int{u256(ghostAmount(3, 10)), new(uint256.Int)} {
		t.Run(fmt.Sprintf("out %v", out), func(t *testing.T) {
			st := s.st.Copy()
			r := s.reveal(t, "effects "+out.Dec(), out)
			leaves := coinLeafCount(st)
			minerBefore := st.GetBalance(s.miner).Clone()
			logsBefore := len(st.Logs())
			if err := ghostpriv.ApplyPolicyReveal(st, s.env, stub, policyEnvelope(t, r)); err != nil {
				t.Fatal(err)
			}
			// The marker is spent, in the coin spent set.
			if !ghosttree.IsSpent(st, ghosttree.Coin, r.Marker) || ghosttree.IsSpent(st, ghosttree.Data, r.Marker) {
				t.Fatal("the marker is not spent in the coin set")
			}
			// The fee: the tip to the coinbase; nothing to the policy.
			if got := new(uint256.Int).Sub(st.GetBalance(s.miner), minerBefore); !got.Eq(split.Tip) {
				t.Errorf("coinbase gained %v, want the tip %v", got, split.Tip)
			}
			if !st.GetBalance(testPolicy).IsZero() || !st.GetBalance(ghost.EscrowAccount).IsZero() {
				t.Error("the policy or the escrow account holds a balance")
			}
			// The totals: out plus fee left the hidden set, out is in escrow.
			in, total := ghostpriv.Totals(st)
			if !in.Eq(inBefore) || !total.Eq(new(uint256.Int).Add(outBefore, new(uint256.Int).Add(out, r.Fee))) {
				t.Errorf("totals in %v out %v", in, total)
			}
			if escrow := ghostpriv.TotalEscrow(st); !escrow.Eq(out) {
				t.Errorf("total escrow %v, want %v", escrow, out)
			}
			hidden, err := ghostpriv.Hidden(st)
			if err != nil || !hidden.Eq(new(uint256.Int).Sub(hiddenBefore, new(uint256.Int).Add(out, r.Fee))) {
				t.Errorf("hidden %v (%v)", hidden, err)
			}
			// The remainder is appended.
			if n := coinLeafCount(st); n != leaves+1 {
				t.Fatalf("coin tree has %d leaves, want %d", n, leaves+1)
			}

			// The receipt log, then the slot log when a slot opens.
			logs := st.Logs()[logsBefore:]
			wantLogs := 2
			if out.IsZero() {
				wantLogs = 1
			}
			if len(logs) != wantLogs {
				t.Fatalf("%d logs, want %d", len(logs), wantLogs)
			}
			rl := logs[0]
			if rl.Address != ghosttree.TreeAccount(ghosttree.Coin) || len(rl.Topics) != 2 || rl.Topics[0] != ghosttree.K("ghost/policy-reveal-receipt/v1") || rl.Topics[1] != r.Marker {
				t.Fatalf("receipt log address %x topics %x", rl.Address, rl.Topics)
			}
			outWord := out.Bytes32()
			wantData := binary.BigEndian.AppendUint32(nil, 0)
			wantData = binary.BigEndian.AppendUint32(wantData, uint32(leaves))
			wantData = append(wantData, r.Remainder[:]...)
			wantData = append(wantData, r.Note[:]...)
			wantData = append(wantData, testPolicy[:]...)
			wantData = append(wantData, outWord[:]...)
			wantData = append(wantData, r.Instr[:]...)
			if len(rl.Data) != 504 || !bytes.Equal(rl.Data, wantData) {
				t.Fatalf("receipt log data of %d bytes\n%x\nwant\n%x", len(rl.Data), rl.Data, wantData)
			}
			records, err := ghostpriv.HistoryRecords(types.Receipts{{Logs: logs}})
			if err != nil || len(records) != 2 || records[0].Kind != ghosttree.Coin || records[0].Leaf != r.Remainder || records[0].Note != r.Note || records[1].Kind != ghosttree.CoinMarkers || records[1].Leaf != r.Marker {
				t.Fatalf("history records %+v (%v)", records, err)
			}

			words := slotWords(st, r.Marker)
			slot, ok := ghostpriv.ReadEscrowSlot(st, r.Marker)
			if out.IsZero() {
				if ok || words != ([ghostpriv.EscrowSlotWords]common.Hash{}) {
					t.Fatal("out = 0 opened a slot")
				}
				return
			}
			// The slot's words, of section 7.1.
			var want [ghostpriv.EscrowSlotWords]common.Hash
			copy(want[0][0:20], testPolicy[:])
			want[0][20] = 1 // open; action_nonce 0
			copy(want[1][0:12], amount12(out))
			copy(want[1][12:24], amount12(out))
			binary.BigEndian.PutUint64(want[1][24:32], height)
			binary.BigEndian.PutUint64(want[2][0:8], s.env.Header.Time) // paid and recommitted 0
			want[4], want[5], want[6], want[7] = r.ParamsHash, r.ActionTag, r.ActionSalt, r.Instr
			if words != want {
				t.Fatalf("slot words\n%x\nwant\n%x", words, want)
			}
			for i := byte(0); i < ghostpriv.EscrowSlotWords; i++ {
				if want := ghosttree.K("ghost/escrow-slot/v1", r.Marker[:], []byte{i}); ghostpriv.EscrowSlotKey(r.Marker, i) != want {
					t.Fatalf("key of word %d", i)
				}
			}
			if !ok || !slot.Open || slot.Policy != testPolicy || !slot.Remaining.Eq(out) || !slot.Out.Eq(out) || slot.Height != height || !slot.Balanced() {
				t.Fatalf("slot %+v", slot)
			}
			if st.GetNonce(ghost.EscrowAccount) != 1 || len(st.GetCode(ghost.EscrowAccount)) != 0 {
				t.Error("the escrow account has no nonce, or has code")
			}
			sl := logs[1]
			if sl.Address != ghost.EscrowAccount || len(sl.Topics) != 2 || sl.Topics[0] != ghosttree.K("ghost/slot-opened/v1") || sl.Topics[1] != r.Marker {
				t.Fatalf("slot log address %x topics %x", sl.Address, sl.Topics)
			}
			slotData := append(common.LeftPadBytes(testPolicy[:], 32), outWord[:]...)
			slotData = append(slotData, r.Instr[:]...)
			if !bytes.Equal(sl.Data, slotData) {
				t.Fatalf("slot log data\n%x\nwant\n%x", sl.Data, slotData)
			}
		})
	}
}

// TestPolicyRevealSharedMarkers checks RP-8: the ordinary and the policy
// class share the coin spent set, so a coin spent by one class cannot be
// spent by the other, in either order, in the same block or a later one, and
// the second spend is refused at the marker check with no proof verified.
func TestPolicyRevealSharedMarkers(t *testing.T) {
	useStub(t)
	s := newPolicyScenario(t, 5)
	marker := "shared"
	out := u256(ghostAmount(1, 4))
	coinFee := s.fee(t, ghostpriv.GasPriv)
	rest := new(uint256.Int).Sub(s.c.value, new(uint256.Int).Add(out, coinFee))
	ordinary := s.f.newReveal(s.root(), testMarker(marker), testCoin("shared rest", rest.ToBig()), addrB, out, coinFee)
	policy := s.reveal(t, marker, out)

	t.Run("ordinary then policy", func(t *testing.T) {
		st := s.st.Copy()
		if err := ghostpriv.ApplyReveal(st, s.env, stub, envelope(t, ordinary)); err != nil {
			t.Fatal(err)
		}
		counter := &countingVerifier{}
		before := snapshotPolicy(st, s.miner)
		if err := ghostpriv.ApplyPolicyReveal(st, s.env, counter, policyEnvelope(t, policy)); !errors.Is(err, ghostpriv.ErrPolicyRevealMarker) {
			t.Fatalf("policy reveal of a spent coin: %v, want %v", err, ghostpriv.ErrPolicyRevealMarker)
		}
		if counter.calls != 0 || snapshotPolicy(st, s.miner) != before {
			t.Fatalf("%d proofs verified, state changed", counter.calls)
		}
	})
	t.Run("policy then ordinary", func(t *testing.T) {
		st := s.st.Copy()
		if err := ghostpriv.ApplyPolicyReveal(st, s.env, stub, policyEnvelope(t, policy)); err != nil {
			t.Fatal(err)
		}
		counter := &countingVerifier{}
		before := snapshotPolicy(st, s.miner)
		if err := ghostpriv.ApplyReveal(st, s.env, counter, envelope(t, ordinary)); !errors.Is(err, ghostpriv.ErrRevealMarker) {
			t.Fatalf("ordinary reveal of a spent coin: %v, want %v", err, ghostpriv.ErrRevealMarker)
		}
		if counter.calls != 0 || snapshotPolicy(st, s.miner) != before {
			t.Fatalf("%d proofs verified, state changed", counter.calls)
		}
	})
	t.Run("across blocks", func(t *testing.T) {
		f := s.f
		for name, order := range map[string][2]func(b *core.BlockGen) *types.Transaction{
			"ordinary then policy": {
				func(b *core.BlockGen) *types.Transaction {
					fee := genWindowFee(t, b).Total
					rest := new(uint256.Int).Sub(s.c.value, new(uint256.Int).Add(out, fee))
					return revealTx(t, f.newReveal(genParentRoot(b), testMarker(marker), testCoin("shared rest", rest.ToBig()), addrB, out, fee))
				},
				func(b *core.BlockGen) *types.Transaction {
					return policyRevealTx(t, f.newPolicyReveal(*b.PrevBlock(0).Header().CoinTreeRoot, testMarker(marker), testPolicy, testPolicyHash, out, genWindowFeeGas(t, b, ghostpriv.GasPolicy).Total))
				},
			},
			"policy then ordinary": {
				func(b *core.BlockGen) *types.Transaction {
					return policyRevealTx(t, f.newPolicyReveal(genParentRoot(b), testMarker(marker), testPolicy, testPolicyHash, out, genWindowFeeGas(t, b, ghostpriv.GasPolicy).Total))
				},
				func(b *core.BlockGen) *types.Transaction {
					fee := genWindowFee(t, b).Total
					rest := new(uint256.Int).Sub(s.c.value, new(uint256.Int).Add(out, fee))
					return revealTx(t, f.newReveal(*b.PrevBlock(0).Header().CoinTreeRoot, testMarker(marker), testCoin("shared rest", rest.ToBig()), addrB, out, fee))
				},
			},
		} {
			blocks, _ := f.generate(4, func(i int, b *core.BlockGen) {
				switch i {
				case 0:
					b.AddTx(f.commitTx(keyA, 0, s.c))
					b.AddTx(f.commitTx(keyB, 0, testCoin("shared, second", oneGhost)))
				case 2:
					b.AddTx(order[0](b))
				case 3:
					b.AddUncheckedTx(order[1](b))
				}
			})
			chain := f.newChain()
			f.insert(chain, blocks[:3])
			if _, err := chain.InsertChain(blocks[3:]); !errors.Is(err, ghostpriv.ErrRevealMarker) && !errors.Is(err, ghostpriv.ErrPolicyRevealMarker) {
				t.Fatalf("%s: block spending the coin again: %v", name, err)
			}
			if chain.CurrentBlock().Hash() != blocks[2].Hash() {
				t.Fatalf("%s: the head moved", name)
			}
		}
	})
}

// escrowModel is what the accounting test expects of one slot.
type escrowModel struct {
	marker common.Hash
	policy common.Address
}

// TestPolicyRevealAccounting checks RP-13 over a random sequence of the
// escrow helpers, valid and invalid: after every operation each slot keeps
// out = remaining + paid + recommitted + action_debits + forfeited, the sum
// of remaining over the slots is total_escrow, and value is conserved: the
// hidden total, total_escrow, what was paid out, forfeited and debited add up
// to what was committed. The hidden total moves only on an opening and a
// recommit; a refused operation changes nothing.
func TestPolicyRevealAccounting(t *testing.T) {
	s := newPolicyScenario(t, 2)
	st := s.st.Copy()
	height := s.env.Header.Number.Uint64()
	committed, err := ghostpriv.Hidden(st)
	if err != nil {
		t.Fatal(err)
	}
	other := common.HexToAddress("0x9a11c1e5000000000000000000000000000beef2")
	registerInState(st, other, []byte{0x00}, 0)
	rng := rand.New(rand.NewSource(20261102))
	var (
		slots     = []escrowModel{}
		paidTo    = map[common.Address]bool{}
		forfeited = new(uint256.Int)
		debited   = new(uint256.Int)
	)
	amount := func(max *uint256.Int) *uint256.Int {
		if max.IsZero() || rng.Intn(8) == 0 {
			return new(uint256.Int).AddUint64(max, uint64(rng.Intn(3))) // at or beyond the remaining value
		}
		return new(uint256.Int).AddUint64(new(uint256.Int).Mod(new(uint256.Int).SetUint64(rng.Uint64()), max), 1)
	}
	check := func(step int, op string) {
		t.Helper()
		sum := new(uint256.Int)
		for _, m := range slots {
			slot, ok := ghostpriv.ReadEscrowSlot(st, m.marker)
			if !ok || !slot.Balanced() {
				t.Fatalf("step %d (%s): slot %x unbalanced: %+v", step, op, m.marker, slot)
			}
			if slot.Open == slot.Remaining.IsZero() {
				t.Fatalf("step %d (%s): slot %x open %v with remaining %v", step, op, m.marker, slot.Open, slot.Remaining)
			}
			sum.Add(sum, slot.Remaining)
		}
		if escrow := ghostpriv.TotalEscrow(st); !escrow.Eq(sum) {
			t.Fatalf("step %d (%s): total escrow %v, sum of remaining %v", step, op, escrow, sum)
		}
		hidden, err := ghostpriv.Hidden(st)
		if err != nil {
			t.Fatal(err)
		}
		paid := new(uint256.Int)
		for a := range paidTo {
			paid.Add(paid, st.GetBalance(a))
		}
		total := new(uint256.Int).Add(hidden, ghostpriv.TotalEscrow(st))
		total.Add(total, paid).Add(total, forfeited).Add(total, debited)
		if !total.Eq(committed) {
			t.Fatalf("step %d (%s): hidden %v, escrow %v, paid %v, forfeited %v, debited %v make %v, committed %v", step, op, hidden, ghostpriv.TotalEscrow(st), paid, forfeited, debited, total, committed)
		}
	}
	fingerprint := func() string {
		in, out := ghostpriv.Totals(st)
		return fmt.Sprintf("%v %v %v %x %d", in, out, ghostpriv.TotalEscrow(st), st.Copy().IntermediateRoot(true), len(st.Logs()))
	}

	for step := 0; step < 400; step++ {
		hiddenBefore, _ := ghostpriv.Hidden(st)
		before := fingerprint()
		var (
			op  string
			err error
		)
		if len(slots) == 0 || rng.Intn(5) == 0 {
			op = "open"
			m := escrowModel{marker: testMarker(fmt.Sprintf("accounting %d", step)), policy: testPolicy}
			if rng.Intn(2) == 0 {
				m.policy = other
			}
			hidden, _ := ghostpriv.Hidden(st)
			out := amount(new(uint256.Int).Div(hidden, uint256.NewInt(8)))
			err = ghostpriv.OpenEscrowSlot(st, m.marker, &ghostpriv.EscrowSlot{Policy: m.policy, Out: out, Height: height, Instr: m.marker})
			if err == nil {
				slots = append(slots, m)
			}
		} else {
			m := slots[rng.Intn(len(slots))]
			caller := m.policy
			if rng.Intn(10) == 0 {
				caller = common.Address{0x0b, byte(step)} // not the slot's policy
			}
			remaining := new(uint256.Int)
			if slot, ok := ghostpriv.ReadEscrowSlot(st, m.marker); ok {
				remaining = slot.Remaining
			}
			switch rng.Intn(5) {
			case 0, 1:
				op = "pay"
				dest := common.Address{0xde, byte(rng.Intn(4))}
				switch rng.Intn(10) {
				case 0:
					dest = testPolicy
				case 1:
					dest = ghost.PrivTotalsAccount
				}
				a := amount(remaining)
				if err = ghostpriv.PayEscrowSlot(st, height, caller, m.marker, dest, a); err == nil {
					paidTo[dest] = true
				}
			case 2:
				op = "recommit"
				var salt [ghostpriv.SaltSize]byte
				var note [ghostpriv.NoteSize]byte
				err = ghostpriv.RecommitEscrowSlot(st, height, caller, m.marker, testMarker(fmt.Sprintf("recommit %d", step)), salt, amount(remaining), note)
			case 3:
				op = "debit"
				d := amount(remaining)
				if d.Gt(remaining) || rng.Intn(4) != 0 {
					d = new(uint256.Int).Div(d, uint256.NewInt(2))
				}
				if err = ghostpriv.DebitEscrowSlot(st, height, caller, m.marker, d); err == nil {
					debited.Add(debited, d)
				}
			case 4:
				op = "close"
				if err = ghostpriv.CloseEscrowSlot(st, height, caller, m.marker); err == nil {
					forfeited.Add(forfeited, remaining)
				}
			}
		}
		if err != nil {
			if fingerprint() != before {
				t.Fatalf("step %d: a refused %s changed the state: %v", step, op, err)
			}
			continue
		}
		hiddenAfter, _ := ghostpriv.Hidden(st)
		if op != "open" && op != "recommit" && !hiddenAfter.Eq(hiddenBefore) {
			t.Fatalf("step %d: a %s moved the hidden total", step, op)
		}
		check(step, op)
	}
	if len(slots) < 10 {
		t.Fatalf("only %d slots opened", len(slots))
	}
	// A closed slot is never reopened, and rejects every function.
	for _, m := range slots {
		slot, _ := ghostpriv.ReadEscrowSlot(st, m.marker)
		if slot.Open {
			continue
		}
		if err := ghostpriv.OpenEscrowSlot(st, m.marker, &ghostpriv.EscrowSlot{Policy: m.policy, Out: uint256.NewInt(1)}); !errors.Is(err, ghostpriv.ErrEscrowSlotExists) {
			t.Fatalf("reopening a closed slot: %v", err)
		}
		if err := ghostpriv.PayEscrowSlot(st, height, m.policy, m.marker, common.Address{0xde}, uint256.NewInt(1)); !errors.Is(err, ghostpriv.ErrEscrowSlotClosed) {
			t.Fatalf("paying from a closed slot: %v", err)
		}
		if slot.ParamsHash != (common.Hash{}) || slot.Instr != (common.Hash{}) {
			t.Fatal("a closed slot kept words 4 to 7")
		}
		return
	}
	t.Fatal("no slot closed")
}

// TestOrdinaryRevealV2Recipient checks the recipient check of spec 10,
// section 4.5: an ordinary reveal to a registered policy is rejected with
// ErrRevealRecipient after the fee check and before the binding and the
// root, with no proof verified and nothing changed; a policy created in the
// same block is a registered policy too; an unregistered contract is a valid
// recipient.
func TestOrdinaryRevealV2Recipient(t *testing.T) {
	useStub(t)
	s := newPolicyScenario(t, 5)
	height := s.env.Header.Number.Uint64()
	fee := s.fee(t, ghostpriv.GasPriv)
	out := u256(ghostAmount(1, 4))
	rest := new(uint256.Int).Sub(s.c.value, new(uint256.Int).Add(out, fee))
	reveal := func(recipient common.Address, root common.Hash, fee *uint256.Int) []byte {
		return envelope(t, s.f.newReveal(root, testMarker("recipient"), testCoin("recipient rest", rest.ToBig()), recipient, out, fee))
	}
	fresh := common.HexToAddress("0x5e1f000000000000000000000000000000000005")
	contract := common.HexToAddress("0x5e1f000000000000000000000000000000000006")
	one := uint256.NewInt(1)
	for _, tt := range []struct {
		name string
		env  []byte
		prep func(*state.StateDB)
		want error
	}{
		{"a policy of the genesis", reveal(testPolicy, s.root(), fee), nil, ghostpriv.ErrRevealRecipient},
		{"a policy, unknown root", reveal(testPolicy, common.Hash{1}, fee), nil, ghostpriv.ErrRevealRecipient},
		{"a policy of this block", reveal(fresh, s.root(), fee), func(st *state.StateDB) { registerInState(st, fresh, testPolicyCode, height) }, ghostpriv.ErrRevealRecipient},
		{"a policy, wrong fee", reveal(testPolicy, s.root(), new(uint256.Int).Add(fee, one)), nil, ghostpriv.ErrRevealFee},
		{"a policy, wrong chain", func() []byte {
			r := s.f.newReveal(s.root(), testMarker("recipient"), testCoin("recipient rest", rest.ToBig()), testPolicy, out, fee)
			r.ChainID++
			return envelope(t, r)
		}(), nil, ghostpriv.ErrRevealChainID},
		{"an unregistered contract", reveal(contract, s.root(), fee), func(st *state.StateDB) { st.SetCode(contract, testPolicyCode) }, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cp := s.st.Copy()
			if tt.prep != nil {
				tt.prep(cp)
			}
			counter := &countingVerifier{}
			before := snapshotPolicy(cp, s.miner)
			err := ghostpriv.ApplyReveal(cp, s.env, counter, tt.env)
			if tt.want == nil {
				if err != nil || counter.calls != 1 {
					t.Fatalf("%v, %d proofs verified", err, counter.calls)
				}
				return
			}
			if !errors.Is(err, tt.want) || counter.calls != 0 {
				t.Fatalf("%v with %d proofs verified, want %v and none", err, counter.calls, tt.want)
			}
			if after := snapshotPolicy(cp, s.miner); after != before {
				t.Fatal("a rejected reveal changed the state")
			}
			if tt.want == ghostpriv.ErrRevealRecipient && cp.GetBalance(testPolicy).Sign() != 0 {
				t.Fatal("the policy was credited")
			}
		})
	}
}

// TestOrdinaryRevealV2Decode checks the version 2 ordinary reveal: a payload
// of 1,311,290 bytes, the 380-byte note at its end round-tripping through
// MarshalBinary and DecodeReveal, version 2 only (a version 1 reveal is not
// accepted, at its old length or the new one), the 607-byte binding under
// the version 2 tag with the type COIN version 2, and the 380-byte note in
// the verifier's inputs and the receipt log.
func TestOrdinaryRevealV2Decode(t *testing.T) {
	if types.GhostRevealPayloadSize != 1_311_290 || ghostpriv.PayloadSize != 1_311_290 || ghostpriv.EnvelopeSize != 1_311_291 {
		t.Fatalf("payload %d, envelope %d", ghostpriv.PayloadSize, ghostpriv.EnvelopeSize)
	}
	if ghostpriv.RevealVersion != 2 || ghostpriv.NoteSize != 380 || ghostpriv.BindingSize != 607 {
		t.Fatalf("version %d, note %d, binding %d", ghostpriv.RevealVersion, ghostpriv.NoteSize, ghostpriv.BindingSize)
	}
	r := layoutReveal()
	for i := range r.Note {
		r.Note[i] = byte(i) | 0x80
	}
	env, err := r.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(env) != 1_311_291 || binary.BigEndian.Uint16(env[1:3]) != 2 || !bytes.Equal(env[len(env)-380:], r.Note[:]) {
		t.Fatalf("envelope of %d bytes", len(env))
	}
	dec, err := ghostpriv.DecodeReveal(env)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Version != 2 || dec.Note != r.Note {
		t.Fatal("decode does not give back the version and the note")
	}
	if tx, err := types.NewGhostRevealTx(env); err != nil || tx.Size() != 1_311_291 || tx.Gas() != 21_111_656 {
		t.Fatalf("transaction: %v", err)
	}

	// Version 1 is not accepted, at the old length or the new one.
	v1 := append([]byte{}, env...)
	binary.BigEndian.PutUint16(v1[1:3], 1)
	if _, err := ghostpriv.DecodeReveal(v1); !errors.Is(err, ghostpriv.ErrRevealVersion) {
		t.Errorf("version 1 at the new length: %v", err)
	}
	old := v1[:1+1_311_066]
	if _, err := ghostpriv.DecodeReveal(old); !errors.Is(err, ghostpriv.ErrRevealLength) {
		t.Errorf("version 1 at the old length: %v", err)
	}
	if _, err := types.NewGhostRevealTx(old); err == nil {
		t.Error("a version 1 envelope wrapped as a transaction")
	}

	// The binding: 607 bytes under the version 2 tag, type COIN version 2,
	// the whole note at its end.
	const chainID = 6_777_971
	genesis := filled(0x88)
	in := r.BindingInput(chainID, genesis)
	if len(in) != 607 || !bytes.Equal(in[44:46], []byte{0x02, 0x01}) || !bytes.Equal(in[42:44], []byte{0x01, 0x02}) || !bytes.Equal(in[607-380:], r.Note[:]) {
		t.Fatalf("binding input of %d bytes", len(in))
	}
	if r.BindingDigest(chainID, genesis) != ghosttree.K("ghost/coin-reveal-binding/v2", in) {
		t.Fatal("binding digest is not K over the input under the version 2 tag")
	}
	vin := r.VerifyInputs(chainID, genesis)
	if vin.Note != r.Note || vin.Binding != r.BindingDigest(chainID, genesis) || vin.Kind != ghosttree.Coin || vin.Purpose != ghostpriv.PurposeReveal {
		t.Fatal("the verifier's inputs do not carry the note and the binding")
	}

	// The receipt log of an applied reveal carries the 380-byte note.
	useStub(t)
	s := newScenario(t, 5)
	env5, st := nextEnv(t, s.chain, s.blocks[4].Header(), common.Address{0xcb})
	fee := chainWindowFee(t, s.chain, env5.Header).Total
	rv := s.reveal(t, "v2 log", u256(ghostAmount(1, 4)), fee)
	ls := &logState{StateDB: st.Copy()}
	if err := ghostpriv.ApplyReveal(ls, env5, stub, envelope(t, rv)); err != nil {
		t.Fatal(err)
	}
	if len(ls.logs) != 1 || len(ls.logs[0].Data) != 8+32+380+20+32 || !bytes.Equal(ls.logs[0].Data[40:420], rv.Note[:]) {
		t.Fatal("the receipt log does not carry the 380-byte note")
	}
}
