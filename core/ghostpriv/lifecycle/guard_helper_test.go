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

package lifecycle

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/consensus/randomx"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghostpriv/ghostprivtest"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/holiman/uint256"
)

// The helpers of the Guard lifecycle (spec 10, section 12): a block builder
// that also takes policy reveals and policy actions and, like the node's
// miner, leaves out a transaction it cannot apply; Guard's calldata; the
// words-only sweep into Guard and the stop card's cancel; and a restore and
// the totals' identity that read the policy reveal's receipts too. The
// calldata helpers are those of core/vm/guard_test.go, the policy reveal
// and action those of the ghostpriv tests, over exported packages only.

const (
	// guardSpacing is the timestamp step of the blocks of the Guard tests:
	// 8,640 blocks of 30 seconds are 259,200 seconds, so the hold reaches its
	// block floor and its time floor in the same block. At blockSpacing they
	// would span 86,400 seconds only.
	guardSpacing = 30

	// guardCreateGas and guardReleaseGas are the gas of the factory call that
	// creates Guard and of a release, beyond the account transaction's own.
	guardCreateGas  = 2_000_000
	guardReleaseGas = 500_000

	// guardShareBatch is the number of blocks of the hold handed to the other
	// nodes in one import.
	guardShareBatch = 512
)

// guardActionTip is what a stop card's action pays the coinbase above the
// burn of G_ACTION times the base fee.
var guardActionTip = uint256.NewInt(123_456_789)

// Guard's entry points.
var (
	guardReleaseSelector = guardSelector("release(bytes32)")
	guardCancelSelector  = guardSelector("cancel(bytes32,bytes16,bytes)")
)

func guardSelector(sig string) [4]byte {
	var s [4]byte
	copy(s[:], crypto.Keccak256([]byte(sig))[:4])
	return s
}

func guardWord(v uint64) []byte { return common.LeftPadBytes(binary.BigEndian.AppendUint64(nil, v), 32) }

// guardReleaseIn is the calldata of release(marker), 36 bytes.
func guardReleaseIn(marker common.Hash) []byte {
	return append(append([]byte{}, guardReleaseSelector[:]...), marker[:]...)
}

// guardCancelIn is the calldata of cancel(f, salt, note), 516 bytes: the
// selector, f, the salt word, the note's offset 0x60 and length 380, and the
// note padded to 384 bytes.
func guardCancelIn(f common.Hash, salt [ghostpriv.SaltSize]byte, note [ghostpriv.NoteSize]byte) []byte {
	in := append([]byte{}, guardCancelSelector[:]...)
	in = append(in, f[:]...)
	in = append(in, common.RightPadBytes(salt[:], 32)...)
	in = append(in, guardWord(0x60)...)
	in = append(in, guardWord(ghostpriv.NoteSize)...)
	return append(in, common.RightPadBytes(note[:], (ghostpriv.NoteSize+31)/32*32)...)
}

// guardInstr is the instruction word that pays to dest.
func guardInstr(dest common.Address) common.Hash { return common.BytesToHash(dest[:]) }

// guardParamsHash is the parameters hash of Guard's slots: Guard has empty
// parameters and reads none.
var guardParamsHash = crypto.Keccak256Hash()

// guardOwner holds a Guard coin: the words, the wallet whose commitments the
// coin is, and the stop card, the action key of every slot a sweep of one of
// its coins opens. With the words and the override the coin spends as any
// coin does; with the words alone it can only be swept into Guard, into a
// slot the stop card cancels until the hold is over. The real proof of the
// sweep binds the action tag to the coin, so whoever sweeps it, the owner or
// a thief with the words, opens a slot of the card; the stub verifier checks
// the binding digest alone, and the sweeps here carry the card's tag as the
// circuit makes them.
type guardOwner struct {
	words *wallet
	card  string
}

func newGuardOwner(words, card string) *guardOwner {
	return &guardOwner{words: newWallet(words), card: card}
}

func (o *guardOwner) cardSecret(tag string, i int) common.Hash {
	return ghosttree.K(tag, []byte(o.card), binary.BigEndian.AppendUint64(nil, uint64(i)))
}

// actionRoot, actionSalt and actionTag are the action key of the slot of
// the owner's commitment i, behind its tag under its salt.
func (o *guardOwner) actionRoot(i int) common.Hash {
	return o.cardSecret("ghost/test-guard/stop-card-root", i)
}

func (o *guardOwner) actionSalt(i int) common.Hash {
	return o.cardSecret("ghost/test-guard/stop-card-salt", i)
}

func (o *guardOwner) actionTag(i int) common.Hash {
	return ghostpriv.PolicyActionTag(o.actionRoot(i), o.actionSalt(i))
}

// recommitSalt is the salt the card's cancel of the slot of commitment i
// re-commits under.
func (o *guardOwner) recommitSalt(i int) [ghostpriv.SaltSize]byte {
	var salt [ghostpriv.SaltSize]byte
	k := o.cardSecret("ghost/test-guard/recommit-salt", i)
	copy(salt[:], k[:])
	return salt
}

// guardPlan is what a node puts into a block of the Guard tests.
type guardPlan struct {
	coinbase   common.Address
	spacing    uint64               // the timestamp step from the parent; 0 is guardSpacing
	txs        []*types.Transaction // applied by the miner, which must accept each
	candidates []*types.Transaction // offered after txs; the miner leaves out any it cannot apply
	unchecked  []*types.Transaction // carried after the others without being applied
}

// mineGuardOn builds and seals a block on parent as the node's miner does:
// each transaction is applied as block processing applies it, the policy
// reveal with G_POLICY, the policy action through core.ApplyPolicyAction,
// and a transaction that fails is undone and left out. It returns the block
// and the candidates left out, with the error each failed with.
func (n *node) mineGuardOn(parent *types.Header, plan guardPlan) (*types.Block, map[common.Hash]error) {
	t := n.t
	t.Helper()
	spacing := plan.spacing
	if spacing == 0 {
		spacing = guardSpacing
	}
	header := n.nextHeader(parent, plan.coinbase)
	header.Time = parent.Time + spacing
	if err := n.engine.Prepare(n.chain, header); err != nil {
		t.Fatalf("node %s: prepare block %d: %v", n.name, header.Number, err)
	}
	var (
		st       = n.stateAt(parent)
		gp       = new(core.GasPool).AddGas(header.GasLimit)
		txs      []*types.Transaction
		receipts []*types.Receipt
		refused  = make(map[common.Hash]error)
	)
	apply := func(tx *types.Transaction) error {
		st.SetTxContext(tx.Hash(), len(txs))
		snap, gas, used := st.Snapshot(), gp.Gas(), header.GasUsed
		receipt, err := n.applyGuardTx(gp, st, header, tx)
		if err != nil {
			st.RevertToSnapshot(snap)
			gp.SetGas(gas)
			header.GasUsed = used
			return err
		}
		txs = append(txs, tx)
		receipts = append(receipts, receipt)
		return nil
	}
	for i, tx := range plan.txs {
		if err := apply(tx); err != nil {
			t.Fatalf("node %s cannot build block %d: transaction %d: %v", n.name, header.Number, i, err)
		}
	}
	for _, tx := range plan.candidates {
		if err := apply(tx); err != nil {
			refused[tx.Hash()] = err
		}
	}
	all := append(append([]*types.Transaction{}, txs...), plan.unchecked...)
	block, err := n.engine.FinalizeAndAssemble(n.chain, header, st, all, nil, receipts, nil)
	if err != nil {
		t.Fatalf("node %s: assemble block %d: %v", n.name, header.Number, err)
	}
	return n.seal(block), refused
}

// applyGuardTx applies one transaction of a block the node builds.
func (n *node) applyGuardTx(gp *core.GasPool, st *state.StateDB, header *types.Header, tx *types.Transaction) (*types.Receipt, error) {
	config := n.chain.Config()
	switch tx.Type() {
	case types.GhostRevealTxType:
		return n.applyReveal(gp, st, header, tx)
	case types.GhostPolicyRevealTxType:
		return n.applyPolicyReveal(gp, st, header, tx)
	case types.GhostPolicyActionTxType:
		return core.ApplyPolicyAction(config, n.chain, gp, st, header, n.chain.Genesis().Hash(), common.Hash{}, tx, &header.GasUsed, vm.Config{})
	default:
		return core.ApplyTransaction(config, n.chain, &header.Coinbase, gp, st, header, tx, &header.GasUsed, vm.Config{})
	}
}

// applyPolicyReveal is the miner's side of a policy reveal: G_POLICY from
// the pool, the policy reveal's checks and change with the active verifier,
// and the receipt.
func (n *node) applyPolicyReveal(gp *core.GasPool, st *state.StateDB, header *types.Header, tx *types.Transaction) (*types.Receipt, error) {
	gas := tx.Gas()
	if err := gp.SubGas(gas); err != nil {
		return nil, err
	}
	if err := ghostpriv.ApplyPolicyReveal(st, n.env(header), ghostpriv.ActiveVerifier(), tx.GhostPolicyRevealEnvelope()); err != nil {
		return nil, err
	}
	st.Finalise(true)
	header.GasUsed += gas
	receipt := &types.Receipt{
		Type:              types.GhostPolicyRevealTxType,
		Status:            types.ReceiptStatusSuccessful,
		CumulativeGasUsed: header.GasUsed,
		TxHash:            tx.Hash(),
		GasUsed:           gas,
		EffectiveGasPrice: new(big.Int),
		Logs:              st.GetLogs(tx.Hash(), header.Number.Uint64(), common.Hash{}),
	}
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
	return receipt, nil
}

// mineGuard has miner build a block on its head and hands it to every node.
// It returns the block and the candidates the miner left out.
func (net *network) mineGuard(miner *node, plan guardPlan) (*types.Block, map[common.Hash]error) {
	net.t.Helper()
	block, refused := miner.mineGuardOn(miner.head(), plan)
	net.share(block)
	return block, refused
}

// pendingChain is a node's chain together with headers built on it that it
// has not imported yet, so the engine can prepare and seal a block on them.
type pendingChain struct {
	*core.BlockChain
	headers map[common.Hash]*types.Header
}

func (p *pendingChain) GetHeader(hash common.Hash, number uint64) *types.Header {
	if h, ok := p.headers[hash]; ok {
		return h
	}
	return p.BlockChain.GetHeader(hash, number)
}

// hold mines count empty blocks of guardSpacing on miner's head, as the chain
// maker does: each block is built on the state the one before left, without
// waiting for an import. Every node, the miner too, imports them in batches
// in its own goroutine while the next batch is sealed, and checks every one
// in full; at the end each node's head is the last block.
func (net *network) hold(miner *node, count uint64, coinbase common.Address) {
	t := net.t
	t.Helper()
	var (
		pending = &pendingChain{BlockChain: miner.chain, headers: make(map[common.Hash]*types.Header)}
		parent  = miner.head()
		st      = miner.stateAt(parent)
		feeds   = make([]chan []*types.Block, len(net.nodes))
		errs    = make([]error, len(net.nodes))
		wg      sync.WaitGroup
	)
	for i, n := range net.nodes {
		feeds[i] = make(chan []*types.Block, 4)
		wg.Add(1)
		go func(i int, chain *core.BlockChain, feed <-chan []*types.Block) {
			defer wg.Done()
			for batch := range feed {
				if errs[i] == nil {
					if _, err := chain.InsertChain(batch); err != nil {
						errs[i] = err
					}
				}
			}
		}(i, n.chain, feeds[i])
	}
	stop := func() {
		for _, feed := range feeds {
			close(feed)
		}
		wg.Wait()
	}
	var batch []*types.Block
	for i := uint64(0); i < count; i++ {
		header := miner.nextHeader(parent, coinbase)
		header.Time = parent.Time + guardSpacing
		if err := miner.engine.Prepare(pending, header); err != nil {
			stop()
			t.Fatalf("node %s: prepare block %d: %v", miner.name, header.Number, err)
		}
		block, err := miner.engine.FinalizeAndAssemble(pending, header, st, nil, nil, nil, nil)
		if err != nil {
			stop()
			t.Fatalf("node %s: assemble block %d: %v", miner.name, header.Number, err)
		}
		if block, err = sealOn(pending, miner.engine, block); err != nil {
			stop()
			t.Fatalf("node %s: %v", miner.name, err)
		}
		parent = block.Header()
		pending.headers[parent.Hash()] = parent
		if batch = append(batch, block); len(batch) == guardShareBatch || i == count-1 {
			for _, feed := range feeds {
				feed <- batch
			}
			batch = nil
		}
	}
	stop()
	for i, n := range net.nodes {
		if errs[i] != nil {
			t.Fatalf("node %s did not import the hold: %v", n.name, errs[i])
		}
		if n.head().Hash() != parent.Hash() {
			t.Fatalf("node %s: head %d after the hold, want %d", n.name, n.head().Number, parent.Number)
		}
	}
}

// sealOn searches a block's RandomX nonce, with the engine reading headers
// from chain.
func sealOn(chain consensus.ChainHeaderReader, engine *randomx.RandomX, block *types.Block) (*types.Block, error) {
	results, stop := make(chan *types.Block, 1), make(chan struct{})
	defer close(stop)
	if err := engine.Seal(chain, block, results, stop); err != nil {
		return nil, fmt.Errorf("seal block %d: %w", block.Number(), err)
	}
	select {
	case sealed := <-results:
		return sealed, nil
	case <-time.After(sealTimeout):
		return nil, fmt.Errorf("block %d not sealed in %v", block.Number(), sealTimeout)
	}
}

// validate makes every check a node makes of a block before it imports it,
// without importing it: the header with its seal, the body, the block's
// processing on a copy of its parent's state, and the state, receipt and
// tree roots. It returns the receipts and the state after the block.
func (n *node) validate(block *types.Block) (types.Receipts, *state.StateDB) {
	n.t.Helper()
	what := "node " + n.name + " checking block " + block.Number().String()
	if err := n.engine.VerifyHeader(n.chain, block.Header(), true); err != nil {
		n.t.Fatalf("%s: header: %v", what, err)
	}
	if err := n.chain.Validator().ValidateBody(block); err != nil {
		n.t.Fatalf("%s: body: %v", what, err)
	}
	parent := n.chain.GetHeader(block.ParentHash(), block.NumberU64()-1)
	if parent == nil {
		n.t.Fatalf("%s: no parent", what)
	}
	st := n.stateAt(parent).Copy()
	receipts, _, used, err := core.NewStateProcessor(n.chain.Config(), n.chain, n.engine).Process(block, st, vm.Config{})
	if err != nil {
		n.t.Fatalf("%s: processing: %v", what, err)
	}
	if err := n.chain.Validator().ValidateState(block, st, receipts, used); err != nil {
		n.t.Fatalf("%s: state: %v", what, err)
	}
	return receipts, st
}

// receiptOf is the receipt of tx in a block the node holds.
func receiptOf(t *testing.T, n *node, block *types.Block, tx *types.Transaction) *types.Receipt {
	t.Helper()
	receipts := n.chain.GetReceiptsByHash(block.Hash())
	for i, btx := range block.Transactions() {
		if btx.Hash() == tx.Hash() {
			return receipts[i]
		}
	}
	t.Fatalf("node %s: block %d does not carry transaction %x", n.name, block.NumberU64(), tx.Hash())
	return nil
}

// feeGasOn is the window fee for gas of a native transaction in a block on
// parent, from the base fee of the first block of its window, found on
// parent's own branch.
func (n *node) feeGasOn(parent *types.Header, gas uint64) ghostpriv.Fee {
	n.t.Helper()
	number := parent.Number.Uint64() + 1
	start := ghostpriv.WindowStart(number)
	bRef := eip1559.CalcBaseFee(n.chain.Config(), parent)
	if start != number {
		h := parent
		for h.Number.Uint64() > start {
			if h = n.chain.GetHeader(h.ParentHash, h.Number.Uint64()-1); h == nil {
				n.t.Fatalf("node %s: no ancestor at height %d", n.name, start)
			}
		}
		bRef = h.BaseFee
	}
	fee, err := ghostpriv.WindowFeeGas(bRef, gas)
	if err != nil {
		n.t.Fatal(err)
	}
	return fee
}

// payerCall is the payer's call of to with data, signed with nonce, an
// account transaction of the network's chain.
func (s *scenario) payerCall(n *node, nonce uint64, to common.Address, data []byte, gas uint64) *types.Transaction {
	s.t.Helper()
	return accountCallTx(s.t, n.chain, s.funder, nonce, to, new(big.Int), data, gas)
}

func (s *scenario) payerNonce(n *node) uint64 { return n.headState().GetNonce(s.payer) }

// createGuard creates Guard through the policy factory at its fixed salt, in
// an ordinary transaction of the payer mined by miner, and checks on every
// node that the factory stored GuardRuntimeCode at GuardAddress and
// registered it in that block with GuardCodeHash.
func (s *scenario) createGuard(miner *node) *types.Block {
	s.t.Helper()
	data := append(ghost.GuardSalt.Bytes(), ghost.GuardInitCode...)
	tx := s.payerCall(miner, s.payerNonce(miner), ghost.PolicyFactoryAddress, data, guardCreateGas)
	block := s.net.mine(miner, blockPlan{coinbase: address("guard factory miner"), txs: []*types.Transaction{tx}})
	for _, n := range s.net.nodes {
		if r := receiptOf(s.t, n, block, tx); r.Status != types.ReceiptStatusSuccessful {
			s.t.Fatalf("node %s: the factory call failed", n.name)
		}
		st := n.headState()
		if code := st.GetCode(ghost.GuardAddress); string(code) != string(ghost.GuardRuntimeCode) {
			s.t.Fatalf("node %s: %d bytes of code at GuardAddress, want GuardRuntimeCode", n.name, len(code))
		}
		height, codeHash, ok := ghost.PolicyRegistryEntry(st, ghost.GuardAddress)
		if !ok || height != block.NumberU64() || codeHash != ghost.GuardCodeHash {
			s.t.Fatalf("node %s: registry entry of Guard: registered %v at %d with %x", n.name, ok, height, codeHash)
		}
		if !st.GetBalance(ghost.GuardAddress).IsZero() {
			s.t.Fatalf("node %s: Guard holds a balance", n.name)
		}
	}
	return block
}

// guardSweep is a words-only spend of a Guard coin: a policy reveal of the
// whole coin into Guard, out = v - fee with a zero remainder, whose slot
// pays instr after the hold unless the card cancels it.
type guardSweep struct {
	spend  coin
	rest   coin
	owner  *guardOwner // whose card the slot answers to
	instr  common.Address
	out    *uint256.Int
	fee    ghostpriv.Fee
	reveal *ghostpriv.PolicyReveal
	tx     *types.Transaction
}

// prepareSweep builds the sweep of spend into Guard for a block on miner's
// head, to instr, leaving the zero remainder rest. The root is the head's
// coin tree root.
func prepareSweep(t *testing.T, miner *node, spend coin, owner *guardOwner, rest coin, instr common.Address) *guardSweep {
	t.Helper()
	head := miner.head()
	fee := miner.feeGasOn(head, ghostpriv.GasPolicy)
	if fee.Total.Gt(spend.value) || !rest.value.IsZero() {
		t.Fatalf("a sweep of %v paying %v with a remainder of %v", spend.value, fee.Total, rest.value)
	}
	r := &ghostpriv.PolicyReveal{
		Version:    ghostpriv.PolicyRevealVersion,
		ChainID:    miner.chain.Config().GetChainID().Uint64(),
		Marker:     spend.marker(),
		Root:       *head.CoinTreeRoot,
		Remainder:  rest.leaf(),
		Out:        sub(spend.value, fee.Total),
		Fee:        new(uint256.Int).Set(fee.Total),
		Policy:     ghost.GuardAddress,
		CodeHash:   ghost.GuardCodeHash,
		ParamsHash: guardParamsHash,
		ActionTag:  owner.actionTag(spend.index),
		ActionSalt: owner.actionSalt(spend.index),
		Instr:      guardInstr(instr),
	}
	note := rest.note()
	copy(r.Note[:], note[:])
	r.Proof = ghostprivtest.Proof(r.BindingDigest(r.ChainID, miner.chain.Genesis().Hash()))
	env, err := r.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	tx, err := types.NewGhostPolicyRevealTx(env)
	if err != nil {
		t.Fatal(err)
	}
	return &guardSweep{spend: spend, rest: rest, owner: owner, instr: instr, out: new(uint256.Int).Set(r.Out), fee: fee, reveal: r, tx: tx}
}

// checkSweep checks a block holding one sweep on a node: the receipt and its
// two logs, the marker, the remainder leaf, the slot Guard holds with out,
// the opening height and time, the card's tag and instr, the totals, the
// tip and that nothing was paid to instr.
func checkSweep(t *testing.T, n *node, block *types.Block, sw *guardSweep) {
	t.Helper()
	header := block.Header()
	parent := n.chain.GetHeader(block.ParentHash(), block.NumberU64()-1)
	pre, post := n.stateAt(parent), n.stateAt(header)
	rc := receiptOf(t, n, block, sw.tx)
	if rc.Type != types.GhostPolicyRevealTxType || rc.Status != types.ReceiptStatusSuccessful || rc.GasUsed != ghostpriv.GasPolicy || sw.tx.Gas() != ghostpriv.GasPolicy {
		t.Fatalf("node %s: sweep receipt of type %#x, status %d, gas %d", n.name, rc.Type, rc.Status, rc.GasUsed)
	}
	var revealLogs, openLogs int
	for _, l := range rc.Logs {
		switch {
		case l.Address == coinTreeAccount && l.Topics[0] == policyRevealTopic:
			revealLogs++
			if len(l.Topics) != 2 || l.Topics[1] != sw.spend.marker() || len(l.Data) != policyRevealLogSize {
				t.Fatalf("node %s: policy reveal log of %d topics and %d bytes", n.name, len(l.Topics), len(l.Data))
			}
			d := l.Data
			if uint64(binary.BigEndian.Uint32(d[4:8])) != leafCount(pre) || common.BytesToHash(d[8:40]) != sw.rest.leaf() {
				t.Fatalf("node %s: the remainder logged at %d as %x", n.name, binary.BigEndian.Uint32(d[4:8]), d[8:40])
			}
			tail := d[40+ghostpriv.NoteSize:]
			if common.BytesToAddress(tail[:20]) != ghost.GuardAddress || !new(uint256.Int).SetBytes(tail[20:52]).Eq(sw.out) || common.BytesToHash(tail[52:]) != guardInstr(sw.instr) {
				t.Fatalf("node %s: the policy reveal log names policy %x, out %x, instr %x", n.name, tail[:20], tail[20:52], tail[52:])
			}
		case l.Address == ghost.EscrowAccount && l.Topics[0] == slotOpenedTopic:
			openLogs++
		}
	}
	if revealLogs != 1 || openLogs != 1 {
		t.Fatalf("node %s: %d policy reveal logs and %d slot-opened logs, want one each", n.name, revealLogs, openLogs)
	}
	if ghosttree.IsSpent(pre, ghosttree.Coin, sw.spend.marker()) || !ghosttree.IsSpent(post, ghosttree.Coin, sw.spend.marker()) {
		t.Fatalf("node %s: the marker was not unspent before and spent after", n.name)
	}
	if leafCount(post) != leafCount(pre)+1 {
		t.Fatalf("node %s: %d leaves after the sweep, want %d", n.name, leafCount(post), leafCount(pre)+1)
	}
	slot, ok := ghostpriv.ReadEscrowSlot(post, sw.spend.marker())
	switch {
	case !ok || !slot.Open || slot.Policy != ghost.GuardAddress:
		t.Fatalf("node %s: no open Guard slot after the sweep", n.name)
	case !slot.Out.Eq(sw.out) || !slot.Remaining.Eq(sw.out) || !slot.Balanced():
		t.Fatalf("node %s: slot of out %v and remaining %v, want %v", n.name, slot.Out, slot.Remaining, sw.out)
	case slot.Height != header.Number.Uint64() || slot.Timestamp != header.Time || slot.ActionNonce != 0:
		t.Fatalf("node %s: slot opened at %d/%d with nonce %d, want block %d/%d", n.name, slot.Height, slot.Timestamp, slot.ActionNonce, header.Number, header.Time)
	case slot.ActionTag != sw.owner.actionTag(sw.spend.index) || slot.ActionSalt != sw.owner.actionSalt(sw.spend.index) || slot.Instr != guardInstr(sw.instr) || slot.ParamsHash != guardParamsHash:
		t.Fatalf("node %s: the slot does not carry the card's action key and instr", n.name)
	}
	if got := sub(ghostpriv.TotalEscrow(post), ghostpriv.TotalEscrow(pre)); !got.Eq(sw.out) {
		t.Fatalf("node %s: total escrow up by %v, want %v", n.name, got, sw.out)
	}
	hiddenPre, err := ghostpriv.Hidden(pre)
	if err != nil {
		t.Fatal(err)
	}
	hiddenPost, err := ghostpriv.Hidden(post)
	if err != nil {
		t.Fatal(err)
	}
	if got := sub(hiddenPre, hiddenPost); !got.Eq(add(sw.out, sw.fee.Total)) {
		t.Fatalf("node %s: the hidden set down by %v, want out and fee %v", n.name, got, add(sw.out, sw.fee.Total))
	}
	if delta(pre, post, sw.instr).Sign() != 0 {
		t.Fatalf("node %s: the sweep paid instr", n.name)
	}
	if len(block.Transactions()) == 1 {
		split, err := sw.fee.CoverGas(header.BaseFee, ghostpriv.GasPolicy)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := delta(pre, post, header.Coinbase), add(reward(header.Number.Uint64()), split.Tip); got.Cmp(want.ToBig()) != 0 {
			t.Fatalf("node %s: the coinbase got %v, want the reward and the tip %v", n.name, got, want)
		}
	}
	requireRootMatchesState(t, n, header, post)
}

// guardCancel is the stop card's cancel of a slot: a policy action that
// debits the burn and a tip and calls cancel, re-committing what is left to
// a commitment of a new key.
type guardCancel struct {
	marker common.Hash
	before *ghostpriv.EscrowSlot
	debit  *uint256.Int
	coin   coin // the re-committed coin
	salt   [ghostpriv.SaltSize]byte
	action *ghostpriv.Action
	tx     *types.Transaction
}

// prepareCancel builds the card's cancel of the slot of sw for a block on
// parent, re-committing to commitment index of newKey. The proof is the stub
// over the action's binding digest, which binds the slot's action tag and
// salt: the real one shows knowledge of the card's action root behind them.
func prepareCancel(t *testing.T, n *node, parent *types.Header, sw *guardSweep, newKey *wallet, index int) *guardCancel {
	t.Helper()
	marker := sw.spend.marker()
	slot, ok := ghostpriv.ReadEscrowSlot(n.stateAt(parent), marker)
	if !ok {
		t.Fatalf("node %s: no slot of the sweep to cancel", n.name)
	}
	if ghostpriv.PolicyActionTag(sw.owner.actionRoot(sw.spend.index), slot.ActionSalt) != slot.ActionTag {
		t.Fatal("the card's action root is not behind the slot's tag")
	}
	burn, err := ghostpriv.ActionBurn(uint256.MustFromBig(eip1559.CalcBaseFee(n.chain.Config(), parent)))
	if err != nil {
		t.Fatal(err)
	}
	debit := add(burn, guardActionTip)
	if debit.Gt(slot.Remaining) {
		t.Fatalf("a debit of %v from a slot of %v", debit, slot.Remaining)
	}
	c := newKey.coin(index, sub(slot.Remaining, debit))
	salt := sw.owner.recommitSalt(sw.spend.index)
	chainID := n.chain.Config().GetChainID().Uint64()
	a := &ghostpriv.Action{
		Version:           ghostpriv.PolicyActionVersion,
		ChainID:           chainID,
		Marker:            marker,
		Nonce:             slot.ActionNonce,
		ExpectedRemaining: new(uint256.Int).Set(slot.Remaining),
		Debit:             debit,
		Expiry:            parent.Number.Uint64() + 16,
		Calldata:          guardCancelIn(newKey.fingerprint(index), salt, c.note()),
	}
	a.Proof = ghostprivtest.ActionProof(a.BindingDigest(chainID, n.chain.Genesis().Hash(), slot))
	env, err := a.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	tx, err := types.NewGhostPolicyActionTx(env)
	if err != nil {
		t.Fatal(err)
	}
	return &guardCancel{marker: marker, before: slot, debit: debit, coin: c, salt: salt, action: a, tx: tx}
}

// checkCancel checks the cancel in a block on a node: the action's receipt
// and its result log of a successful call, the slot closed with all of its
// remaining debited or re-committed, the commit receipt of the new coin
// with the salt, and the totals.
func checkCancel(t *testing.T, n *node, block *types.Block, c *guardCancel) {
	t.Helper()
	header := block.Header()
	parent := n.chain.GetHeader(block.ParentHash(), block.NumberU64()-1)
	pre, post := n.stateAt(parent), n.stateAt(header)
	rc := receiptOf(t, n, block, c.tx)
	if rc.Type != types.GhostPolicyActionTxType || rc.Status != types.ReceiptStatusSuccessful || rc.GasUsed != ghostpriv.GasAction {
		t.Fatalf("node %s: action receipt of type %#x, status %d, gas %d", n.name, rc.Type, rc.Status, rc.GasUsed)
	}
	var results, commits int
	for _, l := range rc.Logs {
		switch {
		case l.Address == ghost.EscrowAccount && l.Topics[0] == actionResultTopic:
			results++
			if l.Topics[1] != c.marker || len(l.Data) != 160 || !new(uint256.Int).SetBytes(l.Data[32:64]).Eq(c.debit) || l.Data[95] != 1 {
				t.Fatalf("node %s: the action result does not show the debit and a successful call", n.name)
			}
		case l.Address == coinTreeAccount && l.Topics[0] == commitTopic:
			commits++
			leaf, _, _ := parseCoinLog(t, l)
			if leaf.leaf != c.coin.leaf() || !leaf.amount.Eq(c.coin.value) || leaf.note != c.coin.note() || string(l.Data[commitLogSize-ghostpriv.SaltSize:]) != string(c.salt[:]) {
				t.Fatalf("node %s: the re-commit logged leaf %x of %v", n.name, leaf.leaf, leaf.amount)
			}
		}
	}
	if results != 1 || commits != 1 {
		t.Fatalf("node %s: %d action results and %d commits, want one each", n.name, results, commits)
	}
	slot, ok := ghostpriv.ReadEscrowSlot(post, c.marker)
	switch {
	case !ok || slot.Open || !slot.Remaining.IsZero():
		t.Fatalf("node %s: the slot is still open after the cancel", n.name)
	case !slot.Recommitted.Eq(c.coin.value) || !slot.ActionDebits.Eq(c.debit) || !slot.Paid.IsZero() || !slot.Forfeited.IsZero() || !slot.Balanced():
		t.Fatalf("node %s: slot after the cancel %+v", n.name, slot)
	case slot.ActionNonce != c.before.ActionNonce+1 || slot.Instr != (common.Hash{}) || slot.ActionTag != (common.Hash{}):
		t.Fatalf("node %s: the closed slot kept nonce %d and its key", n.name, slot.ActionNonce)
	}
	if got := sub(ghostpriv.TotalEscrow(pre), ghostpriv.TotalEscrow(post)); !got.Eq(c.before.Remaining) {
		t.Fatalf("node %s: total escrow down by %v, want the slot's %v", n.name, got, c.before.Remaining)
	}
	inPre, outPre := ghostpriv.Totals(pre)
	inPost, outPost := ghostpriv.Totals(post)
	if !sub(inPost, inPre).Eq(c.coin.value) || !outPost.Eq(outPre) {
		t.Fatalf("node %s: totals %v/%v to %v/%v, want total in up by %v", n.name, inPre, outPre, inPost, outPost, c.coin.value)
	}
	if ghosttree.IsSpent(post, ghosttree.Coin, c.coin.marker()) || leafCount(post) != leafCount(pre)+1 {
		t.Fatalf("node %s: the re-committed coin is not a fresh leaf", n.name)
	}
	requireRootMatchesState(t, n, header, post)
}

// The receipt logs the Guard tests read beside the coin tree's.
var (
	policyRevealTopic = ghosttree.K(ghostpriv.TagPolicyRevealReceipt)
	slotOpenedTopic   = ghosttree.K(ghostpriv.TagSlotOpened)
	slotPaidTopic     = ghosttree.K(ghostpriv.TagSlotPaid)
	actionResultTopic = ghosttree.K(ghostpriv.TagActionResult)
)

const policyRevealLogSize = 8 + 32 + ghostpriv.NoteSize + 20 + 32 + 32

// guardChain is what the receipts of a node's canonical chain say about the
// coin tree, reveals and policy reveals alike, and the markers of the escrow
// slots they opened.
type guardChain struct {
	*chainScan
	spent map[common.Hash]uint64 // the markers spent, by either class, with their blocks
	slots []common.Hash          // the markers of the slots opened, in order
}

// guardScan reads the receipts of every canonical block of the node. The
// leaves must come in tree 0 at consecutive positions and no marker may be
// spent twice; anything else fails the test.
func guardScan(t *testing.T, n *node) *guardChain {
	t.Helper()
	g := &guardChain{chainScan: &chainScan{head: n.head(), reveals: make(map[common.Hash]revealLog)}, spent: make(map[common.Hash]uint64)}
	for num := uint64(1); num <= g.head.Number.Uint64(); num++ {
		block := n.chain.GetBlockByNumber(num)
		if block == nil {
			t.Fatalf("node %s: no canonical block %d", n.name, num)
		}
		receipts := n.chain.GetReceiptsByHash(block.Hash())
		if len(receipts) != len(block.Transactions()) {
			t.Fatalf("node %s: block %d has %d receipts for %d transactions", n.name, num, len(receipts), len(block.Transactions()))
		}
		for _, receipt := range receipts {
			for _, l := range receipt.Logs {
				if receipt.Status != types.ReceiptStatusSuccessful {
					t.Fatalf("node %s: a log in a failed receipt of block %d", n.name, num)
				}
				if l.Address == ghost.EscrowAccount && len(l.Topics) == 2 && l.Topics[0] == slotOpenedTopic {
					g.slots = append(g.slots, l.Topics[1])
				}
				if l.Address != coinTreeAccount {
					continue
				}
				var (
					leaf   leafLog
					marker *common.Hash
				)
				if l.Topics[0] == policyRevealTopic {
					if len(l.Topics) != 2 || len(l.Data) != policyRevealLogSize {
						t.Fatalf("node %s: policy reveal log of %d topics and %d bytes in block %d", n.name, len(l.Topics), len(l.Data), num)
					}
					leaf = leafLog{
						tree:     binary.BigEndian.Uint32(l.Data[0:4]),
						position: binary.BigEndian.Uint32(l.Data[4:8]),
						leaf:     common.BytesToHash(l.Data[8:40]),
						block:    num,
					}
					copy(leaf.note[:], l.Data[40:40+ghostpriv.NoteSize])
					marker = &l.Topics[1]
				} else {
					var reveal *revealLog
					leaf, reveal, _ = parseCoinLog(t, l)
					if reveal != nil {
						marker = &reveal.marker
						g.reveals[reveal.marker] = *reveal
					}
				}
				if leaf.tree != 0 || leaf.position != uint32(len(g.leaves)) {
					t.Fatalf("node %s: leaf at tree %d position %d in block %d, want tree 0 position %d", n.name, leaf.tree, leaf.position, num, len(g.leaves))
				}
				g.leaves = append(g.leaves, leaf)
				if marker != nil {
					if prev, dup := g.spent[*marker]; dup {
						t.Fatalf("node %s: marker %x spent in block %d and again in block %d", n.name, *marker, prev, num)
					}
					g.spent[*marker] = num
				}
			}
		}
	}
	return g
}

// guardRestore finds a wallet's coins from its words and the node's chain
// alone, as restore does, with the policy reveals' receipts read too: the
// leaf count and the coin tree root of the receipts against the head state,
// and for every coin found its membership and its marker by the receipts
// and by ghosttree.IsSpent.
func guardRestore(t *testing.T, n *node, g *guardChain, w *wallet) []restored {
	t.Helper()
	st := n.stateAt(g.head)
	if count := leafCount(st); count != uint64(len(g.leaves)) {
		t.Fatalf("node %s: %d leaves in the receipts, %d in the head state", n.name, len(g.leaves), count)
	}
	roots := g.pageRoots()
	if root := ghosttree.RootFromPageRoots(ghosttree.Coin, roots); root != *g.head.CoinTreeRoot {
		t.Fatalf("node %s: coin tree root %x from the receipts, %x in the head", n.name, root, *g.head.CoinTreeRoot)
	}
	hashes := g.leafHashes()
	var found []restored
	for i, misses := 0, 0; misses < gapLimit; i++ {
		var match *restored
		for _, l := range g.leaves {
			v, ok := w.openNote(i, l.note)
			if !ok {
				continue
			}
			c := w.coin(i, v)
			if c.leaf() != l.leaf {
				t.Fatalf("node %s: the note at position %d opens for commitment %d, but the leaf is not its commitment", n.name, l.position, i)
			}
			if l.commit && !l.amount.Eq(v) {
				t.Fatalf("node %s: commit at position %d of %v, the note says %v", n.name, l.position, l.amount, v)
			}
			if match != nil {
				t.Fatalf("node %s: commitment %d found at positions %d and %d", n.name, i, match.position, l.position)
			}
			match = &restored{coin: c, position: l.position, block: l.block}
		}
		if match == nil {
			misses++
			continue
		}
		misses = 0
		_, byReceipts := g.spent[match.coin.marker()]
		if byState := ghosttree.IsSpent(st, ghosttree.Coin, match.coin.marker()); byReceipts != byState {
			t.Fatalf("node %s: commitment %d spent %v by the receipts, %v by the head state", n.name, i, byReceipts, byState)
		}
		match.spent = byReceipts
		page := int(match.position) / ghosttree.PageLeaves * ghosttree.PageLeaves
		path, err := ghosttree.Witness(ghosttree.Coin, match.position, hashes[page:min(page+ghosttree.PageLeaves, len(hashes))], roots)
		if err != nil {
			t.Fatalf("node %s: witness of commitment %d: %v", n.name, i, err)
		}
		if !ghosttree.VerifyMembership(g.head, ghosttree.Coin, match.position, match.coin.leaf(), path) {
			t.Fatalf("node %s: commitment %d is not a member of the head's coin tree", n.name, i)
		}
		found = append(found, *match)
	}
	return found
}

func guardUnspent(t *testing.T, n *node, g *guardChain, w *wallet) []restored {
	t.Helper()
	var out []restored
	for _, r := range guardRestore(t, n, g, w) {
		if !r.spent {
			out = append(out, r)
		}
	}
	return out
}

// requireGuardCurrent restores a wallet on every node and checks that its
// one unspent coin is want, or, for a nil want, that it has none.
func (s *scenario) requireGuardCurrent(w *wallet, want *coin) {
	s.t.Helper()
	for _, n := range s.net.nodes {
		coins := guardUnspent(s.t, n, guardScan(s.t, n), w)
		if want == nil {
			if len(coins) != 0 {
				s.t.Fatalf("node %s: %d unspent coins restored, want none", n.name, len(coins))
			}
			continue
		}
		if len(coins) != 1 {
			s.t.Fatalf("node %s: %d unspent coins restored, want 1", n.name, len(coins))
		}
		got := coins[0].coin
		if got.index != want.index || !got.value.Eq(want.value) || got.leaf() != want.leaf() {
			s.t.Fatalf("node %s: restored commitment %d of %v, want %d of %v", n.name, got.index, got.value, want.index, want.value)
		}
	}
}

// requireIdentity checks on every node the hidden total and total_escrow
// against the test's own account of them and against the chain: the hidden
// total, total in less total out, is hidden and is the value of the unspent
// coins the wallets, which must hold every coin of the chain, restore from
// the receipts; total_escrow is escrow and the sum of remaining over every
// slot the receipts show opened, each of which keeps out = remaining + paid
// + recommitted + action_debits + forfeited, and is Guard's.
func (s *scenario) requireIdentity(hidden, escrow *uint256.Int, wallets ...*wallet) {
	s.t.Helper()
	for _, n := range s.net.nodes {
		st := n.headState()
		got, err := ghostpriv.Hidden(st)
		if err != nil || !got.Eq(hidden) {
			s.t.Fatalf("node %s: hidden total %v (%v), want %v", n.name, got, err, hidden)
		}
		if got := ghostpriv.TotalEscrow(st); !got.Eq(escrow) {
			s.t.Fatalf("node %s: total escrow %v, want %v", n.name, got, escrow)
		}
		g := guardScan(s.t, n)
		coins := new(uint256.Int)
		for _, w := range wallets {
			for _, r := range guardUnspent(s.t, n, g, w) {
				coins.Add(coins, r.coin.value)
			}
		}
		if !coins.Eq(hidden) {
			s.t.Fatalf("node %s: the unspent coins hold %v, the hidden total is %v", n.name, coins, hidden)
		}
		remaining := new(uint256.Int)
		for _, marker := range g.slots {
			slot, ok := ghostpriv.ReadEscrowSlot(st, marker)
			if !ok || !slot.Balanced() || slot.Policy != ghost.GuardAddress {
				s.t.Fatalf("node %s: the slot of %x is missing, unbalanced or not Guard's", n.name, marker)
			}
			remaining.Add(remaining, slot.Remaining)
		}
		if !remaining.Eq(escrow) {
			s.t.Fatalf("node %s: the slots hold %v, total escrow is %v", n.name, remaining, escrow)
		}
	}
}
