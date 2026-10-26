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

package datalifecycle

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/big"
	"slices"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/holiman/uint256"
)

// The conformance cases of the data commitment specification (spec 04,
// section 11), one test each. Every test asserts the exact check that must
// refuse, so it fails if that check is removed. A case whose outcome the
// spec does not settle is asserted as refused.

// TestDataLifecycleCRD1 commits, proves holding twice and revokes, then
// tries every byte string published on chain and in the proofs of holding,
// every value derivable from them without the digits and the note plaintext
// as k_data, as a share and as a wrapping of it: none opens the file. A
// commit with an extra field to carry a key is refused at the exact length.
func TestDataLifecycleCRD1(t *testing.T) {
	s := newScenario(t)
	plaintext := testFile("CR-D1")
	h := s.commitFile(s.node(0), "CR-D1", plaintext)
	w := s.wallet(h)
	v := newHoldingVerifier("CR-D1", s.node(1), s.sys)
	p1 := s.requireHold(s.node(1), h, v)
	s.net.mine(s.node(2), blockPlan{coinbase: address("CR-D1 filler")})
	p2 := s.requireHold(s.node(2), h, v)
	block := s.reveal(s.node(0), h, ghostpriv.PurposeRevoke, common.Address{})
	ciphertext, _ := s.host.get(w.locator())

	n := s.node(1)
	var published [][]byte
	for _, b := range []*types.Block{h.block, block} {
		for _, tx := range b.Transactions() {
			enc, err := tx.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			published = append(published, enc)
		}
		for _, r := range n.chain.GetReceiptsByHash(b.Hash()) {
			for _, l := range r.Logs {
				published = append(published, l.Data)
				for _, topic := range l.Topics {
					published = append(published, topic[:])
				}
			}
		}
	}
	published = append(published, p1.encode(), p2.encode())
	// The note plaintext, decrypted with the digits from the note on chain.
	r, err := w.restore(newEndpoint(t, n))
	if err != nil {
		t.Fatal(err)
	}
	notePlain, err := w.open(w.noteKey(), r.notes[r.position].note[:])
	if err != nil {
		t.Fatal(err)
	}
	published = append(published, notePlain)

	ad := w.associatedData()
	tags, err := knownTags()
	if err != nil {
		t.Fatal(err)
	}
	if found := keySearch(published, tags, ciphertext, ad); found != "" {
		t.Fatalf("the data key is derivable from published values: %s", found)
	}

	// The search finds a key that is there: a note that carried k_data, or
	// two published halves of a share of it, would be caught.
	k := w.dataKey()
	if keySearch([][]byte{append(common.CopyBytes(notePlain[:7]), k[:]...)}, tags, ciphertext, ad) == "" {
		t.Fatal("the key search misses k_data written in a byte string")
	}
	mask := ghosttree.K("ghost/test-data-lifecycle/share/v1")
	var share common.Hash
	for i := range share {
		share[i] = k[i] ^ mask[i]
	}
	if keySearch([][]byte{share[:], mask[:]}, tags, ciphertext, ad) == "" {
		t.Fatal("the key search misses k_data split into two shares")
	}

	// A commit that carries an extra field, here k_data itself, is refused.
	data := append(commitData(t, w, plaintext), k[:]...)
	s.rejectTx(s.node(2), ghostpriv.ErrCommitData, nil, s.dataCommitTx(s.node(2), data, new(big.Int)))
}

// keySearch tries every 32-byte window of every byte string, every tagged
// hash and Keccak-256 hash of each string and window, the XOR of every pair
// of windows, and every 32-byte window of the plaintext of any string of 60
// to wrapLimit bytes that opens under one of these, as the key of the
// ciphertext. It names the first that opens it, or returns "".
func keySearch(strs [][]byte, tags []string, ciphertext, ad []byte) string {
	// A wrapping holds a 32-byte key in 60 bytes; the reveal envelope, the
	// one longer string, is covered by its windows and hashes.
	const wrapLimit = 4096
	seen := make(map[common.Hash]bool)
	var base []common.Hash
	addKey := func(k common.Hash) {
		if !seen[k] {
			seen[k] = true
			base = append(base, k)
		}
	}
	for _, s := range strs {
		addKey(crypto.Keccak256Hash(s))
		for _, tag := range tags {
			addKey(ghosttree.K(tag, s))
		}
		for off := 0; off+32 <= len(s); off++ {
			w := common.BytesToHash(s[off : off+32])
			if hasZeroRun(w[:]) && w != (common.Hash{}) {
				continue
			}
			addKey(w)
			addKey(crypto.Keccak256Hash(w[:]))
		}
	}
	try := func(k common.Hash) bool {
		_, err := openSealed(k, ciphertext, ad)
		return err == nil
	}
	for _, k := range base {
		if try(k) {
			return "a published value or its hash"
		}
	}
	// Shares: the XOR of two published words.
	var words []common.Hash
	for _, s := range strs {
		for off := 0; off+32 <= len(s); off++ {
			w := common.BytesToHash(s[off : off+32])
			if !hasZeroRun(w[:]) {
				words = append(words, w)
			}
		}
	}
	for i := range words {
		for j := i + 1; j < len(words); j++ {
			var x common.Hash
			for b := range x {
				x[b] = words[i][b] ^ words[j][b]
			}
			if try(x) {
				return "the XOR of two published words"
			}
		}
	}
	// Wrappings: any string that opens under a candidate key to 32 bytes.
	for _, s := range strs {
		if len(s) < 60 || len(s) > wrapLimit {
			continue
		}
		for _, k := range base {
			for _, ad2 := range [][]byte{ad, nil} {
				if plain, err := openSealed(k, s, ad2); err == nil && len(plain) >= 32 {
					for off := 0; off+32 <= len(plain); off++ {
						if try(common.BytesToHash(plain[off : off+32])) {
							return "a key wrapped in a published string"
						}
					}
				}
			}
		}
	}
	return ""
}

// TestDataLifecycleCRD2 revokes commitment A while the prover's own
// commitment B stays unspent: A's earlier proof is refused at check 3 and,
// under a fresh challenge, at check 5; no new proof opening A exists; A's
// marker is refused on chain; a proof opening B verifies and names neither
// commitment nor marker.
func TestDataLifecycleCRD2(t *testing.T) {
	s := newScenario(t)
	a := s.commitFile(s.node(0), "CR-D2 A", testFile("CR-D2 A"))
	b := s.commitFile(s.node(1), "CR-D2 B", testFile("CR-D2 B"))
	v := newHoldingVerifier("CR-D2", s.node(2), s.sys)
	pa := s.requireHold(s.node(0), a, v)

	s.reveal(s.node(2), a, ghostpriv.PurposeRevoke, common.Address{})
	requireErr(t, v.verify(pa), errHoldChallenge, "A's earlier proof presented again")
	s.requireNoHold(s.node(0), a, v, pa)

	wa := s.wallet(a)
	miner := s.node(1)
	s.rejectTx(miner, ghostpriv.ErrDataRevealMarker, nil, dataRevealTx(t, wa.dataReveal(miner, *miner.head().DataTreeRoot, ghostpriv.PurposeReveal, v.id)))

	pb := s.requireHold(s.node(1), b, v)
	enc := pb.encode()
	wb := s.wallet(b)
	for name, secret := range map[string]common.Hash{
		"A's marker": wa.marker(),
		"B's marker": wb.marker(),
		"A's C":      wa.commitment(contentFingerprint(a.plaintext)),
		"B's C":      wb.commitment(contentFingerprint(b.plaintext)),
	} {
		if bytes.Contains(enc, secret[:]) {
			t.Fatalf("B's proof of holding names %s", name)
		}
	}
}

// TestDataLifecycleCRD3 presents a proof of holding made for verifier X to
// verifier Y holding the same challenge value: Y refuses it at check 4, and
// at check 6 once Y's identity is substituted.
func TestDataLifecycleCRD3(t *testing.T) {
	s := newScenario(t)
	h := s.commitFile(s.node(0), "CR-D3", testFile("CR-D3"))
	x := newHoldingVerifier("CR-D3 X", s.node(1), s.sys)
	y := newHoldingVerifier("CR-D3 Y", s.node(2), s.sys)
	c := x.issue()
	y.issueValue(c)
	p, err := proveHolding(t, s.sys, s.node(0), s.node(0).head(), s.wallet(h), x.id, c)
	if err != nil {
		t.Fatal(err)
	}
	requireErr(t, y.verify(p), errHoldVerifier, "X's proof at Y")
	q := p
	q.Verifier = y.id
	requireErr(t, y.verify(q), errHoldProof, "X's proof at Y with Y's identity")
	if err := x.verify(p); err != nil {
		t.Fatalf("X refuses its own proof: %v", err)
	}
}

// TestDataLifecycleCRD4 has a verifier accept a proof for challenge c, then
// refuse at check 3 the same proof, a new proof for c, a proof for a
// challenge it never issued and one for an expired challenge.
func TestDataLifecycleCRD4(t *testing.T) {
	s := newScenario(t)
	h := s.commitFile(s.node(0), "CR-D4", testFile("CR-D4"))
	w := s.wallet(h)
	n := s.node(1)
	v := newHoldingVerifier("CR-D4", s.node(2), s.sys)
	prove := func(c common.Hash) holdingProof {
		t.Helper()
		p, err := proveHolding(t, s.sys, n, n.head(), w, v.id, c)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	c := v.issue()
	p := prove(c)
	if err := v.verify(p); err != nil {
		t.Fatalf("first answer to c: %v", err)
	}
	requireErr(t, v.verify(p), errHoldChallenge, "the same proof again")
	s.net.mine(s.node(0), blockPlan{coinbase: address("CR-D4 filler")})
	requireErr(t, v.verify(prove(c)), errHoldChallenge, "a new proof for an answered challenge")
	requireErr(t, v.verify(prove(ghosttree.K("ghost/test-data-lifecycle/unissued/v1"))), errHoldChallenge, "a proof for a challenge never issued")

	late := v.issue()
	v.now += v.limit + 1
	requireErr(t, v.verify(prove(late)), errHoldChallenge, "a proof for an expired challenge")
	if err := v.verify(prove(v.issue())); err != nil {
		t.Fatalf("a fresh challenge after the clock moved: %v", err)
	}
}

// countingVerifier counts the proofs it is asked to verify.
type countingVerifier struct {
	inner ghostpriv.Verifier
	calls int
}

func (c *countingVerifier) VerifyReveal(in *ghostpriv.VerifyInputs, proof []byte) error {
	c.calls++
	return c.inner.VerifyReveal(in, proof)
}

// TestDataLifecycleCRD5 shows a data commitment mints nothing: its commit
// burns the reserve and nothing more; a data reveal presented to the coin
// reveal is refused at the type check with no proof verified, no marker
// recorded and no balance changed, and refused by every node under the coin
// type byte, where its data root is no coin root; a data commit with a value
// other than the reserve is refused at the value check and burns nothing.
func TestDataLifecycleCRD5(t *testing.T) {
	s := newScenario(t)
	h := s.commitFile(s.node(0), "CR-D5", testFile("CR-D5")) // checkDataCommit: the reserve and the gas
	w := s.wallet(h)
	n := s.node(1)
	head := n.head()
	r := w.dataReveal(n, *head.DataTreeRoot, ghostpriv.PurposeReveal, address("CR-D5 recipient"))
	env := dataEnvelope(t, r)

	st := n.headState().Copy()
	before := st.IntermediateRoot(true)
	counter := &countingVerifier{inner: ghostpriv.ActiveVerifier()}
	header := n.nextHeader(head, address("CR-D5 coinbase"))
	_, _, err := ghostpriv.CheckReveal(st, n.env(header), counter, env)
	requireErr(t, err, ghostpriv.ErrRevealLength, "a data reveal at the coin reveal check")
	requireErr(t, ghostpriv.ApplyReveal(st, n.env(header), counter, env), ghostpriv.ErrRevealLength, "a data reveal applied as a coin reveal")
	if counter.calls != 0 {
		t.Fatalf("%d proofs verified", counter.calls)
	}
	if st.IntermediateRoot(true) != before {
		t.Fatal("the state changed")
	}
	if ghosttree.IsSpent(st, ghosttree.Coin, r.Marker) || ghosttree.IsSpent(st, ghosttree.Data, r.Marker) {
		t.Fatal("a marker was recorded")
	}

	// The data payload under the coin type byte fails the coin checks.
	coinTx, err := types.NewGhostRevealTx(append([]byte{types.GhostRevealTxType}, env[1:]...))
	if err != nil {
		t.Fatal(err)
	}
	s.rejectTx(n, ghostpriv.ErrRevealRoot, nil, coinTx)

	// A data commit with a value other than the reserve is refused and
	// nothing is burned.
	payer := n.headState().GetBalance(s.payer)
	in, out := ghostpriv.Totals(n.headState())
	w2 := openWallet(newPhantomKey("CR-D5 value"), s.chainID())
	valued := s.dataCommitTx(n, commitData(t, w2, testFile("CR-D5 value")), big.NewInt(1))
	s.rejectTx(n, ghostpriv.ErrDataCommitValue, nil, valued)
	for _, m := range s.net.nodes {
		st := m.headState()
		gotIn, gotOut := ghostpriv.Totals(st)
		if !st.GetBalance(s.payer).Eq(payer) || !gotIn.Eq(in) || !gotOut.Eq(out) {
			t.Fatalf("node %s: the refused data commit moved value", m.name)
		}
	}
}

// TestDataLifecycleCRD6 keeps coin leaves out of data: a data reveal against
// a coin tree root is refused at the root check, a proof of holding against
// a coin tree root at verifier check 5, and against a data tree root no
// proof opening a coin leaf under the data outer hash exists, and one
// presented anyway fails check 6.
func TestDataLifecycleCRD6(t *testing.T) {
	s := newScenario(t)
	h := s.commitFile(s.node(0), "CR-D6", testFile("CR-D6"))
	w := s.wallet(h)

	// A coin commit puts a coin leaf in the coin tree.
	n := s.node(1)
	coinF := ghosttree.K("ghost/test-data-lifecycle/coin-fingerprint/v1", []byte("CR-D6"))
	coinData, err := ghostpriv.SaltedCommitData(coinF, make([]byte, ghostpriv.SaltSize), make([]byte, ghostpriv.NoteSize))
	if err != nil {
		t.Fatal(err)
	}
	coinTx := accountCallTx(t, n.chain, s.funder, n.headState().GetNonce(s.payer), ghost.CommitEntryAddress, big.NewInt(1), coinData, dataCommitGas)
	s.net.mine(n, blockPlan{coinbase: address("CR-D6 miner"), txs: []*types.Transaction{coinTx}})
	head := n.head()
	coinRoot := *head.CoinTreeRoot
	if coinRoot == ghosttree.EmptyRoot(ghosttree.Coin) {
		t.Fatal("the coin commit left the coin tree empty")
	}

	// A data reveal against the coin tree root.
	s.rejectTx(n, ghostpriv.ErrDataRevealRoot, nil, dataRevealTx(t, w.dataReveal(n, coinRoot, ghostpriv.PurposeReveal, address("CR-D6 verifier"))))

	// A proof of holding against the coin tree root, which a proof for the
	// coin statement would satisfy at check 6.
	v := newHoldingVerifier("CR-D6", s.node(2), s.sys)
	p := holdingRequest(n, head, v.id, v.issue())
	p.DataRoot = coinRoot
	p.Proof = s.sys.proofOf(holdingBinding(p, n.chain.Genesis().Hash()))
	requireErr(t, v.verify(p), errHoldRoot, "a proof of holding against a coin tree root")

	// Against the data tree root, opening the coin leaf's fingerprint under
	// the data outer hash.
	r, err := w.restore(newEndpoint(t, n))
	if err != nil {
		t.Fatal(err)
	}
	c := v.issue()
	wit := holdingWitness{w: w, cf: r.content.cf, position: r.position, path: witness(t, r.notes, r.position), opens: &coinF}
	if _, err := s.sys.prove(n, head, wit, holdingRequest(n, head, v.id, c)); !errors.Is(err, errNoProof) {
		t.Fatalf("a proof opening a coin leaf was made: %v", err)
	}
	forged := holdingRequest(n, head, v.id, c)
	forged.Proof = ghosttree.K("ghost/test-data-lifecycle/forged-proof/v1", coinF[:])
	requireErr(t, v.verify(forged), errHoldProof, "a forged proof opening a coin leaf")
}

// withGasLimit is block with its gas limit set outright and sealed again,
// which may be a limit no node accepts.
func (n *node) withGasLimit(block *types.Block, gasLimit uint64) *types.Block {
	n.t.Helper()
	header := block.Header()
	header.GasLimit = gasLimit
	return n.seal(block.WithSeal(header))
}

// rejectAboveMaxGasLimit imports a block on the node's head, which must
// refuse it for a gas limit above the consensus maximum, leaving the head
// where it was.
func (n *node) rejectAboveMaxGasLimit(block *types.Block) {
	n.t.Helper()
	head := n.head()
	if block.GasLimit() <= ghost.MaxBlockGasLimit {
		n.t.Fatalf("node %s: gas limit %d is not above the consensus maximum", n.name, block.GasLimit())
	}
	_, err := n.chain.InsertChain(types.Blocks{block})
	if err == nil || !strings.Contains(err.Error(), "gas limit above the consensus maximum") {
		n.t.Fatalf("node %s importing block %d: error %v, want the gas limit above the consensus maximum", n.name, block.NumberU64(), err)
	}
	if n.head().Hash() != head.Hash() {
		n.t.Fatalf("node %s: the head moved to the rejected block", n.name)
	}
}

// process runs the node's block processing over a block on its head, against
// a copy of the head state, without the header checks.
func (n *node) process(block *types.Block) error {
	n.t.Helper()
	parent := n.chain.GetHeader(block.ParentHash(), block.NumberU64()-1)
	if parent == nil {
		n.t.Fatalf("node %s: no parent for block %d", n.name, block.NumberU64())
	}
	_, _, _, err := core.NewStateProcessor(n.chain.Config(), n.chain, n.engine).Process(block, n.stateAt(parent).Copy(), vm.Config{})
	return err
}

// TestDataLifecycleCRD7 refuses a second reveal and a revocation of a spent
// marker, in a later block and in the same block, and the block carrying it.
// A block holding two data reveals is above the consensus maximum gas limit,
// so the same-block case is checked both at import, where the gas limit
// refuses it, and by block processing alone, where the marker does.
func TestDataLifecycleCRD7(t *testing.T) {
	s := newScenario(t)
	h := s.commitFile(s.node(0), "CR-D7", testFile("CR-D7"))
	w := s.wallet(h)
	verifier := address("CR-D7 verifier")
	s.reveal(s.node(1), h, ghostpriv.PurposeReveal, verifier)

	// In a later block.
	miner := s.node(2)
	root := *miner.head().DataTreeRoot
	s.rejectTx(miner, ghostpriv.ErrDataRevealMarker, nil, dataRevealTx(t, w.dataReveal(miner, root, ghostpriv.PurposeReveal, address("CR-D7 other"))))
	s.rejectTx(miner, ghostpriv.ErrDataRevealMarker, nil, dataRevealTx(t, w.dataReveal(miner, root, ghostpriv.PurposeRevoke, verifier)))

	// In the same block as the first spend of a fresh marker.
	h2 := s.commitFile(s.node(0), "CR-D7 same block", testFile("CR-D7 same block"))
	if 2*types.GhostDataRevealGas <= ghost.MaxBlockGasLimit {
		t.Fatalf("the consensus maximum %d holds two data reveals", ghost.MaxBlockGasLimit)
	}
	w2 := s.wallet(h2)
	root = *miner.head().DataTreeRoot
	first := dataRevealTx(t, w2.dataReveal(miner, root, ghostpriv.PurposeReveal, verifier))
	for _, purpose := range []byte{ghostpriv.PurposeReveal, ghostpriv.PurposeRevoke} {
		second := dataRevealTx(t, w2.dataReveal(miner, root, purpose, address("CR-D7 second")))
		block := miner.mine(blockPlan{coinbase: address("miner " + miner.name), txs: []*types.Transaction{first}, unchecked: []*types.Transaction{second}})
		block = miner.withGasLimit(block, 2*types.GhostDataRevealGas+1_000_000)
		for _, n := range s.net.nodes {
			n.rejectAboveMaxGasLimit(block)
			requireErr(t, n.process(block), ghostpriv.ErrDataRevealMarker, "node "+n.name+": processing the block holding both data reveals")
		}
	}
	for _, n := range s.net.nodes {
		if ghosttree.IsSpent(n.headState(), ghosttree.Data, w2.marker()) {
			t.Fatalf("node %s: the refused block left the marker spent", n.name)
		}
	}
}

// TestDataLifecycleCRD8 revokes at height h: no proof of holding exists
// against the roots of h or later; one made against h - 1 is accepted by a
// verifier that issued its challenge and accepts h - 1 as current, and
// refused at check 5 by one that takes the latest header.
func TestDataLifecycleCRD8(t *testing.T) {
	s := newScenario(t)
	held := s.commitFile(s.node(0), "CR-D8", testFile("CR-D8"))
	w := s.wallet(held)
	n := s.node(1)
	before := n.head()
	revoke := s.reveal(s.node(2), held, ghostpriv.PurposeRevoke, common.Address{})
	if revoke.NumberU64() != before.Number.Uint64()+1 {
		t.Fatal("the revocation is not the block after h - 1")
	}
	latest := newHoldingVerifier("CR-D8 latest", n, s.sys)
	for i := range 2 {
		if _, err := proveHolding(t, s.sys, n, n.head(), w, latest.id, latest.issue()); !errors.Is(err, errNoProof) {
			t.Fatalf("a proof of holding at height %d after the revocation: %v", n.head().Number, err)
		}
		if i == 0 {
			s.net.mine(s.node(0), blockPlan{coinbase: address("CR-D8 filler")})
		}
	}

	pinned := newHoldingVerifier("CR-D8 pinned", n, s.sys)
	pinned.current = before
	p, err := proveHolding(t, s.sys, n, before, w, pinned.id, pinned.issue())
	if err != nil {
		t.Fatalf("a proof against h - 1: %v", err)
	}
	if err := pinned.verify(p); err != nil {
		t.Fatalf("a verifier that accepts h - 1 refuses the proof: %v", err)
	}
	q, err := proveHolding(t, s.sys, n, before, w, latest.id, latest.issue())
	if err != nil {
		t.Fatal(err)
	}
	requireErr(t, latest.verify(q), errHoldRoot, "a proof against h - 1 at a verifier taking the latest header")
}

// TestDataLifecycleCRD9 has the host answer with another ciphertext, with
// the right one with a bit flipped, and with one made for another chain:
// authenticated decryption fails each time and nothing is shown. A
// ciphertext that decrypts under k_data to other bytes fails the fingerprint
// check.
func TestDataLifecycleCRD9(t *testing.T) {
	s := newScenario(t)
	plaintext := testFile("CR-D9")
	h := s.commitFile(s.node(0), "CR-D9", plaintext)
	other := s.commitFile(s.node(1), "CR-D9 other", testFile("CR-D9 other"))
	w := s.wallet(h)
	r, err := w.restore(newEndpoint(t, s.node(2)))
	if err != nil {
		t.Fatal(err)
	}
	right, _ := s.host.get(w.locator())
	answer := func(name string, ciphertext []byte, want error) {
		t.Helper()
		s.host.put(w.locator(), ciphertext)
		got, err := w.read(s.host, r.content)
		if got != nil {
			t.Fatalf("%s: the wallet showed %d bytes", name, len(got))
		}
		requireErr(t, err, want, name)
	}
	otherCT, _ := s.host.get(s.wallet(other).locator())
	answer("another file's ciphertext", otherCT, errDecrypt)
	for _, bit := range []int{0, 12 * 8, len(right) * 4, len(right)*8 - 1} {
		flipped := common.CopyBytes(right)
		flipped[bit/8] ^= 1 << (bit % 8)
		answer("one bit flipped", flipped, errDecrypt)
	}
	answer("a ciphertext for another chain", openWallet(h.key, s.chainID()+1).encryptFile(plaintext), errDecrypt)
	answer("other bytes under k_data", w.encryptFile(testFile("CR-D9 substitute")), errFingerprint)

	s.host.put(w.locator(), right)
	if got, err := w.read(s.host, r.content); err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("the right answer: %v", err)
	}
}

// TestDataLifecycleCRD10 deletes the host: proofs of holding, a reveal and a
// revocation still verify, and the wallet reports the data unavailable
// rather than failing silently or showing other bytes.
func TestDataLifecycleCRD10(t *testing.T) {
	s := newScenario(t)
	a := s.commitFile(s.node(0), "CR-D10 reveal", testFile("CR-D10 reveal"))
	b := s.commitFile(s.node(1), "CR-D10 revoke", testFile("CR-D10 revoke"))
	s.host.wipe()
	if len(s.host.all()) != 0 {
		t.Fatal("the host kept a ciphertext")
	}

	for _, h := range []*held{a, b} {
		w := s.wallet(h)
		r, err := w.restore(newEndpoint(t, s.node(2)))
		if err != nil {
			t.Fatal(err)
		}
		got, err := w.read(s.host, r.content)
		if got != nil || err != errDataUnavailable {
			t.Fatalf("with the host lost: %d bytes, %v; want %v", len(got), err, errDataUnavailable)
		}
	}
	v := newHoldingVerifier("CR-D10", s.node(2), s.sys)
	s.requireHold(s.node(0), a, v)
	s.requireHold(s.node(1), b, v)
	s.reveal(s.node(2), a, ghostpriv.PurposeReveal, v.id)
	s.reveal(s.node(0), b, ghostpriv.PurposeRevoke, common.Address{})
}

// TestDataLifecycleCRD11 restores on a clean device with nothing but the
// digits: C, its marker status and k_data, which decrypts a supplied
// ciphertext. The endpoint's request log shows only bulk note and
// marker-set fetches. A restore whose recomputed C differs from the stored
// leaf fails closed.
func TestDataLifecycleCRD11(t *testing.T) {
	s := newScenario(t)
	plaintext := testFile("CR-D11")
	s.commitFile(s.node(1), "CR-D11 other", testFile("CR-D11 other"))
	h := s.commitFile(s.node(0), "CR-D11", plaintext)
	supplied, _ := s.host.get(s.wallet(h).locator())

	device := openWallet(phantomKey(string([]byte(h.key))), s.node(2).chain.Config().GetChainID().Uint64())
	ep := newEndpoint(t, s.node(2))
	r, err := device.restore(ep)
	if err != nil {
		t.Fatal(err)
	}
	if r.leaf != device.commitment(contentFingerprint(plaintext)) || r.spent {
		t.Fatalf("restored leaf %x, spent %v", r.leaf, r.spent)
	}
	got, err := device.decryptFile(supplied, r.content)
	if err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("the restored k_data does not decrypt the supplied ciphertext: %v", err)
	}
	if !slices.Equal(ep.requests, []string{"notes", "markers"}) {
		t.Fatalf("the endpoint served %q, want only the bulk note and marker-set fetches", ep.requests)
	}
	if len(r.notes) != 2 {
		t.Fatalf("the bulk note fetch returned %d notes, want every one, 2", len(r.notes))
	}

	// The endpoint stores another leaf with the wallet's note.
	bad := newEndpoint(t, s.node(2))
	bad.alter = func(notes []noteRecord) []noteRecord {
		notes[0].leaf, notes[1].leaf = notes[1].leaf, notes[0].leaf
		return notes
	}
	if _, err := device.restore(bad); !errors.Is(err, errRestoreMismatch) {
		t.Fatalf("restore with a swapped leaf: %v, want %v", err, errRestoreMismatch)
	}

	// The marker status follows the chain.
	s.reveal(s.node(1), h, ghostpriv.PurposeRevoke, common.Address{})
	if r, err := device.restore(newEndpoint(t, s.node(2))); err != nil || !r.spent {
		t.Fatalf("restore after the revocation: %v", err)
	}
}

// TestDataLifecycleCRD12 forges the fingerprint: other bytes encrypted under
// k_data by someone with the digits fail the fingerprint check, and a note
// whose cf is changed makes the recomputed C differ from the leaf, so
// restore fails closed.
func TestDataLifecycleCRD12(t *testing.T) {
	s := newScenario(t)
	plaintext := testFile("CR-D12")
	h := s.commitFile(s.node(0), "CR-D12", plaintext)
	w := s.wallet(h)
	r, err := w.restore(newEndpoint(t, s.node(1)))
	if err != nil {
		t.Fatal(err)
	}
	s.host.put(w.locator(), w.encryptFile(testFile("CR-D12 forged")))
	if got, err := w.read(s.host, r.content); got != nil || !errors.Is(err, errFingerprint) {
		t.Fatalf("forged bytes under k_data: %v, want %v", err, errFingerprint)
	}

	// A commitment whose note names another cf than the one in F_d.
	forger := openWallet(newPhantomKey("CR-D12 changed note"), s.chainID())
	cf := contentFingerprint(plaintext)
	note := forger.noteFor(uint64(len(plaintext)), contentFingerprint(testFile("CR-D12 changed")))
	data, err := ghostpriv.SaltedCommitData(forger.fingerprint(cf), make([]byte, ghostpriv.SaltSize), note[:])
	if err != nil {
		t.Fatal(err)
	}
	s.net.mine(s.node(1), blockPlan{coinbase: address("CR-D12 miner"), txs: []*types.Transaction{s.dataCommitTx(s.node(1), data, ghostpriv.DataReserve.ToBig())}})
	if _, err := forger.restore(newEndpoint(t, s.node(2))); !errors.Is(err, errRestoreMismatch) {
		t.Fatalf("restore of a note with a changed cf: %v, want %v", err, errRestoreMismatch)
	}
}

// TestDataLifecycleCRD13 discards a branch whose block appended a data
// commitment: a proof of holding and a data reveal against the data tree
// root only that branch had are refused at verifier check 5 and at the
// node's root check, even by nodes that saw the branch.
func TestDataLifecycleCRD13(t *testing.T) {
	s := newScenario(t)
	h := s.commitFile(s.node(0), "CR-D13", testFile("CR-D13"))
	w := s.wallet(h)
	a, b, c := s.node(0), s.node(1), s.node(2)

	side := openWallet(newPhantomKey("CR-D13 side"), s.chainID())
	sideTx := s.dataCommitTx(a, commitData(t, side, testFile("CR-D13 side")), ghostpriv.DataReserve.ToBig())
	blockX := a.mine(blockPlan{coinbase: address("CR-D13 side miner"), txs: []*types.Transaction{sideTx}})
	s.net.shareWith([]*node{a, c}, blockX)
	sideRoot := *blockX.Header().DataTreeRoot

	v := newHoldingVerifier("CR-D13", c, s.sys)
	p, err := proveHolding(t, s.sys, a, blockX.Header(), w, v.id, v.issue())
	if err != nil {
		t.Fatalf("a proof on the side branch: %v", err)
	}
	if p.DataRoot != sideRoot {
		t.Fatal("the proof does not use the side branch's root")
	}

	b1 := b.mine(blockPlan{coinbase: address("CR-D13 miner")})
	b.insert(b1)
	b2 := b.mine(blockPlan{coinbase: address("CR-D13 miner")})
	b.insert(b2)
	a.insert(b1, b2)
	c.insert(b1, b2)
	s.net.converged()
	for num := uint64(0); num <= b2.NumberU64(); num++ {
		if *c.chain.GetHeaderByNumber(num).DataTreeRoot == sideRoot {
			t.Fatal("the side branch's root is canonical")
		}
	}

	requireErr(t, v.verify(p), errHoldRoot, "a proof of holding against a discarded branch's root")
	s.rejectTx(b, ghostpriv.ErrDataRevealRoot, nil, dataRevealTx(t, w.dataReveal(b, sideRoot, ghostpriv.PurposeReveal, v.id)))
	s.requireHold(a, h, v)
}

// TestDataLifecycleCRD14 refuses a data commit whose note is one byte short
// or long; nothing is written.
func TestDataLifecycleCRD14(t *testing.T) {
	s := newScenario(t)
	w := openWallet(newPhantomKey("CR-D14"), s.chainID())
	plaintext := testFile("CR-D14")
	f := w.fingerprint(contentFingerprint(plaintext))
	note := w.note(plaintext)
	n := s.node(0)
	leaves := dataLeafCount(n.headState())
	for _, size := range []int{ghostpriv.NoteSize - 1, ghostpriv.NoteSize + 1} {
		bad := make([]byte, size)
		copy(bad, note[:])
		if _, err := ghostpriv.SaltedCommitData(f, make([]byte, ghostpriv.SaltSize), bad); err == nil {
			t.Fatalf("SaltedCommitData took a note of %d bytes", size)
		}
		data := binary.BigEndian.AppendUint16(nil, ghostpriv.Version)
		data = append(append(data, f[:]...), bad...)
		s.rejectTx(n, ghostpriv.ErrCommitData, nil, s.dataCommitTx(n, data, new(big.Int)))
	}
	for _, m := range s.net.nodes {
		if got := dataLeafCount(m.headState()); got != leaves {
			t.Fatalf("node %s: %d data leaves, want %d", m.name, got, leaves)
		}
	}
}

// TestDataLifecycleCRD15 runs the linkage test over a commit, two proofs of
// holding and a revocation, which passes, and over deliberately linked
// designs, which fail.
func TestDataLifecycleCRD15(t *testing.T) {
	s := newScenario(t)
	r := newLinkageRun(t, s, "CR-D15", ghostpriv.PurposeRevoke)
	requireUnlinked(t, r)
	checkLinkedDesigns(t, r)
}

// TestDataLifecycleCRD16 binds chain and purpose: a proof of holding with
// another chain id or version is refused at verifier check 2; a data reveal
// made for one purpose and submitted as the other fails the proof check,
// as the purpose is in the node's binding digest; an unknown purpose and
// another chain id are refused at their own checks.
func TestDataLifecycleCRD16(t *testing.T) {
	s := newScenario(t)
	h := s.commitFile(s.node(0), "CR-D16", testFile("CR-D16"))
	w := s.wallet(h)
	n := s.node(1)
	v := newHoldingVerifier("CR-D16", s.node(2), s.sys)
	p, err := proveHolding(t, s.sys, n, n.head(), w, v.id, v.issue())
	if err != nil {
		t.Fatal(err)
	}
	q := p
	q.ChainID++
	requireErr(t, v.verify(q), errHoldChain, "a proof of holding from another chain")
	q = p
	q.Version++
	requireErr(t, v.verify(q), errHoldChain, "a proof of holding of another version")
	q = p
	q.Purpose = ghostpriv.PurposeReveal
	requireErr(t, v.verify(q), errHoldType, "a proof of holding with the reveal purpose")

	root := *n.head().DataTreeRoot
	swap := func(made, sent byte) *types.Transaction {
		r := w.dataReveal(n, root, made, v.id)
		r.Purpose = ghostpriv.PurposeField(sent)
		return dataRevealTx(t, r)
	}
	s.rejectTx(n, ghostpriv.ErrDataRevealProof, nil, swap(ghostpriv.PurposeReveal, ghostpriv.PurposeRevoke))
	s.rejectTx(n, ghostpriv.ErrDataRevealProof, nil, swap(ghostpriv.PurposeRevoke, ghostpriv.PurposeReveal))

	unknown := w.dataReveal(n, root, ghostpriv.PurposeReveal, v.id)
	unknown.Purpose = ghostpriv.PurposeField(0x03)
	stubProve(n, unknown)
	s.rejectTx(n, ghostpriv.ErrDataRevealPurpose, nil, dataRevealTx(t, unknown))
	leading := w.dataReveal(n, root, ghostpriv.PurposeReveal, v.id)
	leading.Purpose[0] = 0x01
	s.rejectTx(n, ghostpriv.ErrDataRevealPurpose, nil, dataRevealTx(t, leading))

	otherChain := w.dataReveal(n, root, ghostpriv.PurposeReveal, v.id)
	otherChain.ChainID++
	stubProve(n, otherChain)
	s.rejectTx(n, ghostpriv.ErrDataRevealChainID, nil, dataRevealTx(t, otherChain))

	// The holder's own reveal still goes through.
	s.reveal(n, h, ghostpriv.PurposeReveal, v.id)
}

// TestDataLifecycleCRD17 removes the block of a revocation by a
// reorganisation: afterwards the marker is unspent and a fresh proof of
// holding on the new canonical chain is accepted.
func TestDataLifecycleCRD17(t *testing.T) {
	s := newScenario(t)
	h := s.commitFile(s.node(0), "CR-D17", testFile("CR-D17"))
	w := s.wallet(h)
	a, b, c := s.node(0), s.node(1), s.node(2)
	v := newHoldingVerifier("CR-D17", c, s.sys)
	old := s.requireHold(a, h, v)

	revoke := a.mine(blockPlan{coinbase: address("CR-D17 a"), txs: []*types.Transaction{dataRevealTx(t, w.dataReveal(a, *a.head().DataTreeRoot, ghostpriv.PurposeRevoke, common.Address{}))}})
	s.net.shareWith([]*node{a, c}, revoke)
	checkDataReveal(t, c, revoke, w.marker(), ghostpriv.PurposeRevoke, common.Address{})
	s.requireNoHold(c, h, v, old)

	b1 := b.mine(blockPlan{coinbase: address("CR-D17 b")})
	b.insert(b1)
	b2 := b.mine(blockPlan{coinbase: address("CR-D17 b")})
	b.insert(b2)
	a.insert(b1, b2)
	c.insert(b1, b2)
	s.net.converged()
	if c.chain.GetBlockByNumber(revoke.NumberU64()).Hash() == revoke.Hash() {
		t.Fatal("the revocation's block is still canonical")
	}
	for _, n := range s.net.nodes {
		if ghosttree.IsSpent(n.headState(), ghosttree.Data, w.marker()) {
			t.Fatalf("node %s: the marker stayed spent", n.name)
		}
		r, err := w.restore(newEndpoint(t, n))
		if err != nil || r.spent {
			t.Fatalf("node %s: restore after the reorganisation: %v", n.name, err)
		}
		s.requireHold(n, h, v)
	}
}

// TestDataLifecycleCRD18 settles the data reveal fee from the reserve: a
// data reveal paying more than the reserve is refused by every node, at the
// fee check, and in a block whose window fee is above the reserve the window
// fee itself is refused before any proof is verified; a data commit of any
// value but the reserve is refused at the value check. The holder's reveal at
// the window fee goes through.
func TestDataLifecycleCRD18(t *testing.T) {
	s := newScenario(t)
	h := s.commitFile(s.node(0), "CR-D18", testFile("CR-D18"))
	w := s.wallet(h)
	n := s.node(1)
	root := *n.head().DataTreeRoot
	verifier := address("CR-D18 verifier")

	// A fee of the reserve plus one wei, carried in a block.
	above := w.dataReveal(n, root, ghostpriv.PurposeReveal, verifier)
	above.Fee = new(uint256.Int).AddUint64(ghostpriv.DataReserve, 1)
	stubProve(n, above)
	s.rejectTx(n, ghostpriv.ErrDataRevealFee, nil, dataRevealTx(t, above))

	// A block that starts a fee window with a base fee whose window fee is
	// above the reserve: the reserve cannot pay that fee.
	for next := n.head().Number.Uint64() + 1; ghostpriv.WindowStart(next) != next; next++ {
		s.net.mine(n, blockPlan{coinbase: address("CR-D18 filler")})
	}
	header := n.nextHeader(n.head(), address("CR-D18 coinbase"))
	header.BaseFee = new(big.Int).Mul(gwei, big.NewInt(20))
	fee, err := ghostpriv.WindowFee(header.BaseFee)
	if err != nil {
		t.Fatal(err)
	}
	if !fee.Total.Gt(ghostpriv.DataReserve) {
		t.Fatalf("window fee %v is not above the reserve", fee.Total)
	}
	r := w.dataReveal(n, root, ghostpriv.PurposeReveal, verifier)
	r.Fee = fee.Total
	stubProve(n, r)
	for _, m := range s.net.nodes {
		counter := &countingVerifier{inner: ghostpriv.ActiveVerifier()}
		st := m.headState().Copy()
		before := st.IntermediateRoot(true)
		err := ghostpriv.ApplyDataReveal(st, m.env(header), counter, dataEnvelope(t, r))
		requireErr(t, err, ghostpriv.ErrDataRevealFeeAboveReserve, "node "+m.name+" applying a data reveal whose window fee is above the reserve")
		if counter.calls != 0 || st.IntermediateRoot(true) != before {
			t.Fatalf("node %s: %d proofs verified, state changed %v", m.name, counter.calls, st.IntermediateRoot(true) != before)
		}
	}

	// A data commit of any value but the reserve.
	w2 := openWallet(newPhantomKey("CR-D18 value"), s.chainID())
	data := commitData(t, w2, testFile("CR-D18 value"))
	one := big.NewInt(1)
	for _, value := range []*big.Int{new(big.Int), new(big.Int).Sub(ghostpriv.DataReserve.ToBig(), one), new(big.Int).Add(ghostpriv.DataReserve.ToBig(), one)} {
		s.rejectTx(n, ghostpriv.ErrDataCommitValue, nil, s.dataCommitTx(n, data, value))
	}

	// The holder's reveal at the window fee.
	s.reveal(n, h, ghostpriv.PurposeReveal, verifier)
}
