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
	"slices"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/types"
)

// testFile is the plaintext of a synthetic file; each label gives other
// bytes.
func testFile(label string) []byte {
	return []byte("synthetic test file for the data lifecycle, example content only: " + label)
}

// TestDataLifecycleCommitAndHold commits a file and gets its Phantom Key
// back, checks that the file stays off chain, encrypted under a key derived
// from the digits, and proves holding again and again, each time to the
// verifier and for a fresh challenge, with every replay refused.
func TestDataLifecycleCommitAndHold(t *testing.T) {
	s := newScenario(t)
	plaintext := testFile("commit and hold")
	h := s.commitFile(s.node(0), "commit and hold", plaintext)
	s.net.converged()

	// The Phantom Key is the digits, and nothing else is kept.
	if len(h.key) != digitCount || strings.Trim(string(h.key), "0123456789") != "" {
		t.Fatalf("Phantom Key %q is not %d digits", h.key, digitCount)
	}

	// Off chain: the host holds a ciphertext that opens only under k_data,
	// derived from the digits, and nothing on chain carries the file, the
	// ciphertext, a key or the digits.
	w := s.wallet(h)
	ciphertext, ok := s.host.get(w.locator())
	if !ok {
		t.Fatal("the host does not hold the file")
	}
	if bytes.Contains(ciphertext, plaintext[:16]) {
		t.Fatal("the host holds the file in the clear")
	}
	content := noteContent{length: uint64(len(plaintext)), cf: contentFingerprint(plaintext)}
	if got, err := w.decryptFile(ciphertext, content); err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("k_data from the digits does not open the file: %v", err)
	}
	if _, err := openSealed(w.noteKey(), ciphertext, w.associatedData()); err == nil {
		t.Fatal("the note key opens the file")
	}
	other := openWallet(newPhantomKey("other digits"), s.chainID())
	if _, err := other.decryptFile(ciphertext, content); err == nil {
		t.Fatal("another Phantom Key opens the file")
	}
	for _, n := range s.net.nodes {
		requireOffChain(t, n, map[string][]byte{
			"plaintext":   plaintext,
			"ciphertext":  ciphertext,
			"k_data":      w.dataKey().Bytes(),
			"k_note":      w.noteKey().Bytes(),
			"digits":      []byte(h.key),
			"locator":     w.locator().Bytes(),
			"cf":          content.cf.Bytes(),
			"data marker": w.marker().Bytes(),
		})
	}

	// Proof of holding, repeatedly, on every node and across blocks, each for
	// a fresh challenge of the verifier.
	v := newHoldingVerifier("hold", s.node(0), s.sys)
	var proofs []holdingProof
	for i := range 4 {
		p := s.requireHold(s.node(i), h, v)
		for _, q := range proofs {
			if q.Challenge == p.Challenge || q.Proof == p.Proof {
				t.Fatalf("proof %d repeats the challenge or proof of an earlier one", i)
			}
		}
		proofs = append(proofs, p)
		s.net.mine(s.node(i+1), blockPlan{coinbase: address("hold filler")})
	}

	// Bound to the verifier: another verifier holding the same challenge
	// refuses a proof made for this one.
	other2 := newHoldingVerifier("another", s.node(1), s.sys)
	c := v.issue()
	other2.issueValue(c)
	p, err := proveHolding(t, s.sys, s.node(2), s.node(2).head(), w, v.id, c)
	if err != nil {
		t.Fatal(err)
	}
	requireErr(t, other2.verify(p), errHoldVerifier, "a proof of holding presented to another verifier")
	if err := v.verify(p); err != nil {
		t.Fatalf("the verifier the proof was made for refuses it: %v", err)
	}

	// Replays fail, every one of them.
	for i, q := range append(proofs, p) {
		requireErr(t, v.verify(q), errHoldChallenge, "replay of proof of holding "+string(rune('0'+i)))
	}
}

// requireOffChain checks that none of the secrets, or a 16-byte run of one,
// appears in any transaction or receipt of the node's canonical chain.
func requireOffChain(t *testing.T, n *node, secrets map[string][]byte) {
	t.Helper()
	head := n.head().Number.Uint64()
	for num := uint64(0); num <= head; num++ {
		block := n.chain.GetBlockByNumber(num)
		var blobs [][]byte
		for _, tx := range block.Transactions() {
			enc, err := tx.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			blobs = append(blobs, enc)
		}
		for _, r := range n.chain.GetReceiptsByHash(block.Hash()) {
			for _, l := range r.Logs {
				blobs = append(blobs, l.Data)
				for _, topic := range l.Topics {
					blobs = append(blobs, topic[:])
				}
			}
		}
		for name, secret := range secrets {
			for off := 0; off+16 <= len(secret); off++ {
				run := secret[off : off+16]
				for _, blob := range blobs {
					if bytes.Contains(blob, run) {
						t.Fatalf("node %s: block %d carries 16 bytes of the %s at offset %d", n.name, num, name, off)
					}
				}
			}
		}
	}
}

// TestDataLifecycleRevealOnce reveals a commitment once to a verifier, then
// has every second reveal, the same transaction again, a new one and a
// revocation, refused, and no proof of holding made after it.
func TestDataLifecycleRevealOnce(t *testing.T) {
	s := newScenario(t)
	h := s.commitFile(s.node(0), "reveal once", testFile("reveal once"))
	w := s.wallet(h)
	v := newHoldingVerifier("reveal", s.node(0), s.sys)
	held := s.requireHold(s.node(1), h, v)

	block := s.reveal(s.node(1), h, ghostpriv.PurposeReveal, v.id)
	s.net.converged()
	first := block.Transactions()[0]

	// The same reveal again, byte for byte, then a new reveal for another
	// verifier and a revocation: all refused at the marker, by every node.
	again, err := types.NewGhostDataRevealTx(first.GhostDataRevealEnvelope())
	if err != nil {
		t.Fatal(err)
	}
	miner := s.node(2)
	root := *miner.head().DataTreeRoot
	for _, tx := range []*types.Transaction{
		again,
		dataRevealTx(t, w.dataReveal(miner, root, ghostpriv.PurposeReveal, address("second verifier"))),
		dataRevealTx(t, w.dataReveal(miner, root, ghostpriv.PurposeRevoke, v.id)),
	} {
		s.rejectTx(miner, ghostpriv.ErrDataRevealMarker, nil, tx)
	}
	for _, n := range s.net.nodes {
		requireErr(t, n.checkNextData(w.dataReveal(n, root, ghostpriv.PurposeReveal, v.id)), ghostpriv.ErrDataRevealMarker, "node "+n.name+" checking a second reveal")
	}

	// The reveal spent the marker, so holding can no longer be proven.
	for _, n := range s.net.nodes {
		s.requireNoHold(n, h, v, held)
	}
}

// TestDataLifecycleRestore restores a commitment on a clean device from the
// digits alone, through a node that never saw the wallet: the commitment,
// its marker status and k_data, which opens the hosted file. Wrong digits
// restore nothing, and a revocation shows as spent after a new restore.
func TestDataLifecycleRestore(t *testing.T) {
	s := newScenario(t)
	plaintext := testFile("restore")
	s.commitFile(s.node(1), "restore neighbour", testFile("restore neighbour"))
	h := s.commitFile(s.node(0), "restore", plaintext)
	s.commitFile(s.node(1), "restore later neighbour", testFile("restore later neighbour"))

	// The clean device has the digits, typed in, and nothing else.
	digits := phantomKey(strings.Clone(string(h.key)))
	clean := openWallet(digits, s.node(2).chain.Config().GetChainID().Uint64())
	ep := newEndpoint(t, s.node(2))
	r, err := clean.restore(ep)
	if err != nil {
		t.Fatalf("restore from the digits: %v", err)
	}
	want := ghostpriv.DataCommitmentVersion(ghostpriv.SaltedCommitVersion, clean.fingerprint(contentFingerprint(plaintext)))
	if r.leaf != want || r.position != 1 || r.spent || r.block != h.block.NumberU64() {
		t.Fatalf("restored leaf %x at %d in block %d, spent %v; want %x at 1 in block %d, unspent", r.leaf, r.position, r.block, r.spent, want, h.block.NumberU64())
	}
	if r.content.length != uint64(len(plaintext)) || r.content.cf != contentFingerprint(plaintext) {
		t.Fatal("the restored note does not describe the file")
	}
	got, err := clean.read(s.host, r.content)
	if err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("the restored k_data does not open the hosted file: %v", err)
	}
	if !slices.Equal(ep.requests, []string{"notes", "markers"}) {
		t.Fatalf("the endpoint served %q, want one bulk note and one bulk marker request", ep.requests)
	}

	// The restored wallet proves holding.
	v := newHoldingVerifier("restore", s.node(2), s.sys)
	p, err := proveHolding(t, s.sys, s.node(2), s.node(2).head(), clean, v.id, v.issue())
	if err != nil {
		t.Fatal(err)
	}
	if err := v.verify(p); err != nil {
		t.Fatalf("a proof of holding of the restored wallet: %v", err)
	}

	// Wrong digits find nothing.
	if _, err := openWallet(newPhantomKey("restore with wrong digits"), clean.chainID).restore(newEndpoint(t, s.node(2))); err != errNoteNotFound {
		t.Fatalf("restore with wrong digits: %v, want %v", err, errNoteNotFound)
	}

	// After a revocation every node's restore reports the marker spent.
	s.reveal(s.node(0), h, ghostpriv.PurposeRevoke, common.Address{})
	for _, n := range s.net.nodes {
		r, err := clean.restore(newEndpoint(t, n))
		if err != nil || !r.spent {
			t.Fatalf("node %s: restore after the revocation: spent %v, %v", n.name, r != nil && r.spent, err)
		}
	}
}

// TestDataLifecycleRevoke has the holder revoke: every later proof of
// holding fails, old proofs are refused, the marker cannot be revealed or
// revoked again, and another holder's commitment is untouched.
func TestDataLifecycleRevoke(t *testing.T) {
	s := newScenario(t)
	h := s.commitFile(s.node(0), "revoke", testFile("revoke"))
	keep := s.commitFile(s.node(1), "revoke bystander", testFile("revoke bystander"))
	v := newHoldingVerifier("revoke", s.node(2), s.sys)
	before := s.requireHold(s.node(0), h, v)
	s.requireHold(s.node(1), keep, v)

	s.reveal(s.node(2), h, ghostpriv.PurposeRevoke, common.Address{})
	s.net.converged()
	for _, n := range s.net.nodes {
		if !ghosttree.IsSpent(n.headState(), ghosttree.Data, s.wallet(h).marker()) {
			t.Fatalf("node %s: the revoked marker is not spent", n.name)
		}
		s.requireNoHold(n, h, v, before)
	}
	// Still none blocks later.
	s.net.mine(s.node(0), blockPlan{coinbase: address("revoke filler")})
	s.requireNoHold(s.node(1), h, v, before)

	w := s.wallet(h)
	miner := s.node(1)
	root := *miner.head().DataTreeRoot
	s.rejectTx(miner, ghostpriv.ErrDataRevealMarker, nil, dataRevealTx(t, w.dataReveal(miner, root, ghostpriv.PurposeRevoke, common.Address{})))
	s.rejectTx(miner, ghostpriv.ErrDataRevealMarker, nil, dataRevealTx(t, w.dataReveal(miner, root, ghostpriv.PurposeReveal, v.id)))

	// The bystander still proves holding.
	for _, n := range s.net.nodes {
		s.requireHold(n, keep, v)
	}
}

// linkageRun is one data commitment's published hops on the chain: the
// commit, two proofs of holding to two verifiers and the final reveal or
// revocation, with the whitelist of the chain they are on.
type linkageRun struct {
	hops      []*hop
	wl        *whitelist
	h         *held
	w         *wallet
	commit    *hop
	holdings  [2][]byte
	envelope  []byte
	finalLog  *types.Log
	finalName string
}

func newLinkageRun(t *testing.T, s *scenario, label string, purpose byte) *linkageRun {
	t.Helper()
	h := s.commitFile(s.node(0), label, testFile(label))
	v1 := newHoldingVerifier(label+" one", s.node(1), s.sys)
	v2 := newHoldingVerifier(label+" two", s.node(2), s.sys)
	p1 := s.requireHold(s.node(1), h, v1)
	s.net.mine(s.node(1), blockPlan{coinbase: address("linkage filler")})
	p2 := s.requireHold(s.node(2), h, v2)
	block := s.reveal(s.node(2), h, purpose, v1.id)
	s.net.converged()

	reader := s.node(1)
	run := &linkageRun{h: h, w: s.wallet(h), finalName: "revocation"}
	if purpose == ghostpriv.PurposeReveal {
		run.finalName = "reveal"
	}
	run.commit = commitHop(t, reader, h.block, h.tx.Hash())
	run.holdings = [2][]byte{p1.encode(), p2.encode()}
	stored := reader.chain.GetBlock(block.Hash(), block.NumberU64())
	run.envelope = stored.Transactions()[0].GhostDataRevealEnvelope()
	run.finalLog = reader.chain.GetReceiptsByHash(block.Hash())[0].Logs[0]
	run.wl = newWhitelist(reader, []*holdingVerifier{v1, v2})
	run.hops = run.build(t, run.holdings, run.envelope)
	return run
}

// build is the hops with the given proofs of holding and final envelope, so
// a test can swap in a linked variant at the byte level.
func (r *linkageRun) build(t *testing.T, holdings [2][]byte, envelope []byte) []*hop {
	t.Helper()
	return []*hop{
		r.commit,
		holdingHop(t, "holding 1", holdings[0]),
		holdingHop(t, "holding 2", holdings[1]),
		revealHop(t, r.finalName, envelope, r.finalLog),
	}
}

// requireUnlinked runs the checker over the real design, which must pass.
func requireUnlinked(t *testing.T, r *linkageRun) {
	t.Helper()
	if links := checkLinkage(t, r.hops, r.wl); len(links) != 0 {
		for _, l := range links {
			t.Error(l)
		}
		t.Fatalf("%d links between the hops of one data commitment", len(links))
	}
}

// requireLinked runs the checker over a linked variant, which must fail with
// a link between hops from and to.
func requireLinked(t *testing.T, name string, r *linkageRun, hops []*hop, from, to, how string) {
	t.Helper()
	links := checkLinkage(t, hops, r.wl)
	for _, l := range links {
		if ((l.from == from && l.to == to) || (l.from == to && l.to == from)) && strings.HasPrefix(l.how, how) {
			t.Logf("%s: caught: %v", name, l)
			return
		}
	}
	t.Fatalf("%s: the linkage checker did not find a %s link between %s and %s; found %v", name, how, from, to, links)
}

// TestDataLifecycleLinkage runs the linkage test over two data commitments:
// one committed, proven twice to two verifiers and revealed once, one
// committed, proven twice and revoked. No value is shared between the hops
// of either beyond the whitelist.
func TestDataLifecycleLinkage(t *testing.T) {
	s := newScenario(t)
	for _, purpose := range []byte{ghostpriv.PurposeReveal, ghostpriv.PurposeRevoke} {
		r := newLinkageRun(t, s, "linkage "+string(rune('0'+purpose)), purpose)
		requireUnlinked(t, r)
	}
}

// TestDataLifecycleLinkageCatchesLinkedDesign shows the linkage test fails
// against deliberately linked designs built at the byte level from the real
// hops: a revocation that publishes C, two proofs of holding sharing a
// value, a proof of holding that carries a tagged hash of the commit's F_d,
// and a revocation that carries 16 bytes of the commit's note off any field
// boundary.
func TestDataLifecycleLinkageCatchesLinkedDesign(t *testing.T) {
	s := newScenario(t)
	r := newLinkageRun(t, s, "linked design", ghostpriv.PurposeRevoke)
	requireUnlinked(t, r)
	checkLinkedDesigns(t, r)
}

// checkLinkedDesigns runs every linked variant of a real run.
func checkLinkedDesigns(t *testing.T, r *linkageRun) {
	t.Helper()
	leaf := r.w.commitment(contentFingerprint(r.h.plaintext))
	fd := r.w.fingerprint(contentFingerprint(r.h.plaintext))

	// The revocation publishes C as its marker.
	env := common.CopyBytes(r.envelope)
	copy(env[1+10:1+42], leaf[:])
	requireLinked(t, "revocation publishes C", r, r.build(t, r.holdings, env), "commit", r.finalName, "field")

	// The proofs of holding share a value the wallet derives for the
	// commitment.
	shared := ghosttree.K("ghost/test-linked/holding-tag/v1", fd[:])
	var linked [2][]byte
	for i, enc := range r.holdings {
		p, err := decodeHolding(enc)
		if err != nil {
			t.Fatal(err)
		}
		p.Proof = shared
		linked[i] = p.encode()
	}
	requireLinked(t, "proofs of holding share a value", r, r.build(t, linked, r.envelope), "holding 1", "holding 2", "field")

	// A proof of holding carries K(data marker tag, F_d).
	p, err := decodeHolding(r.holdings[0])
	if err != nil {
		t.Fatal(err)
	}
	p.Proof = ghosttree.K(ghostpriv.TagDataMarker, fd[:])
	requireLinked(t, "proof of holding carries a tagged hash of F_d", r, r.build(t, [2][]byte{p.encode(), r.holdings[1]}, r.envelope), "commit", "holding 1", "tagged hash")

	// The revocation carries 16 bytes of the note inside its proof field.
	env = common.CopyBytes(r.envelope)
	note := r.w.note(r.h.plaintext)
	copy(env[1+190+40:], note[37:53])
	requireLinked(t, "revocation carries note bytes", r, r.build(t, r.holdings, env), "commit", r.finalName, "bytes")
}
