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
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/holiman/uint256"
)

// The wallet of the real-proof tests. Its commitments are those the pinned
// prover opens (ghostverifier/examples/guardfixture.rs): commitment i has
// the secrets s_i, r_i and b_i and the salt salt_i, from the digits under
// test tags, and the rule of the coin, empty but for a policy coin:
//
//	F_i = K("ghost/coin-fingerprint/v2", s_i, r_i, b_i, salt_i, COIN_V2, 0^32, rule_i)
//	m_i = K("ghost/coin-marker/v2", r_i, b_i, salt_i)
//
// with C_i = K("ghost/coin-commitment/v1", COIN_V2, F_i, v) as for any
// salted coin. A policy coin's rule is
// K("ghost/reveal-policy/v2", the policy address left-padded to 32, its code
// hash, the parameters hash, K("ghost/policy-override/v1", override secret),
// the action tag, the action salt). TestRealWalletMatchesProver checks these
// against the committed fixtures of ghostverifier/examples/v2fixture.rs.
//
// Each proof the lifecycle needs is a job of the request the fixture
// generator proves: its secrets, the opening against the coin tree and the
// statement the node builds. Recording, the scenario runs on the stub
// verifier and its wallets hand out stub proofs; with the fixture loaded,
// it runs on the default verifier and each proof is the fixture's, for a job
// that must be the fixture's byte for byte.
const (
	tagRealS        = "ghost/test-wallet/real-spend-secret/v1"
	tagRealR        = "ghost/test-wallet/real-reveal-secret/v1"
	tagRealB        = "ghost/test-wallet/real-blinding/v1"
	tagRealSalt     = "ghost/test-wallet/real-salt/v1"
	tagRealOverride = "ghost/test-wallet/real-override/v1"

	// The prover's tags (proofs/src/hash.rs of the pinned ghost-proofs).
	tagProverFingerprint = "ghost/coin-fingerprint/v2"
	tagProverMarker      = "ghost/coin-marker/v2"
	tagProverRule        = "ghost/reveal-policy/v2"
	tagProverOverride    = "ghost/policy-override/v1"
)

// realProofRequestEnv names the file the real-proof test writes its request
// to, instead of running on the fixture.
const realProofRequestEnv = "GHOST_REAL_PROOF_REQUEST"

// realGuardFixture is the committed output of
// ghostverifier/examples/guardfixture.rs for the request of
// TestRealProofGuardLifecycle.
var realGuardFixture = filepath.Join("testdata", "real_guard_lifecycle.bin.gz")

const realGuardRegenerate = `regenerate the fixture: GHOST_REAL_PROOF_REQUEST=/tmp/real_guard.req CGO_ENABLED=1 go test -tags ghostproofs -run '^TestRealProofGuardLifecycle$' ./core/ghostpriv/lifecycle/, then cargo run --release --locked --manifest-path ghostverifier/Cargo.toml --example guardfixture -- /tmp/real_guard.req real_guard_lifecycle.bin and gzip -n -9 real_guard_lifecycle.bin into core/ghostpriv/lifecycle/testdata/ (see ghostverifier/examples/guardfixture.rs)`

// realKeys makes a wallet a real-proof wallet.
type realKeys struct {
	proofs *realProofs
	rules  map[int]*realRule // the policy coins' rules, by commitment number
}

// realRule is a policy coin's rule.
type realRule struct {
	policy         common.Address
	codeHash       common.Hash
	paramsHash     common.Hash
	actionTag      common.Hash
	actionSalt     common.Hash
	overrideSecret common.Hash
}

func (r *realRule) overrideHash() common.Hash {
	return ghosttree.K(tagProverOverride, r.overrideSecret[:])
}

// hash is the rule a policy coin's fingerprint binds.
func (r *realRule) hash() common.Hash {
	o := r.overrideHash()
	return ghosttree.K(tagProverRule, common.LeftPadBytes(r.policy[:], 32), r.codeHash[:], r.paramsHash[:], o[:], r.actionTag[:], r.actionSalt[:])
}

// bytes is the rule in the layout of the fixture request: the policy address
// (20), the code hash, the parameters hash, the override hash, the action
// tag and the action salt.
func (r *realRule) bytes() []byte {
	o := r.overrideHash()
	b := append([]byte{}, r.policy[:]...)
	for _, h := range []common.Hash{r.codeHash, r.paramsHash, o, r.actionTag, r.actionSalt} {
		b = append(b, h[:]...)
	}
	return b
}

func (w *wallet) realSalt(i int) [ghostpriv.SaltSize]byte {
	var salt [ghostpriv.SaltSize]byte
	k := w.secret(tagRealSalt, i)
	copy(salt[:], k[:])
	return salt
}

// ruleHash is the rule of commitment i, the empty rule for a plain coin.
func (w *wallet) ruleHash(i int) common.Hash {
	if rule := w.real.rules[i]; rule != nil {
		return rule.hash()
	}
	return common.Hash{}
}

func (w *wallet) realFingerprint(i int) common.Hash {
	return realCoinFingerprint(w.secret(tagRealS, i), w.secret(tagRealR, i), w.secret(tagRealB, i), w.realSalt(i), w.ruleHash(i))
}

func (w *wallet) realMarker(i int) common.Hash {
	return realCoinMarker(w.secret(tagRealR, i), w.secret(tagRealB, i), w.realSalt(i))
}

func realCoinFingerprint(s, r, b common.Hash, salt [ghostpriv.SaltSize]byte, rule common.Hash) common.Hash {
	return ghosttree.K(tagProverFingerprint, s[:], r[:], b[:], salt[:], ghostpriv.CoinV2[:], make([]byte, 32), rule[:])
}

func realCoinMarker(r, b common.Hash, salt [ghostpriv.SaltSize]byte) common.Hash {
	return ghosttree.K(tagProverMarker, r[:], b[:], salt[:])
}

// realMerkleRoot is the coin tree root above leaf at position with the
// sibling path, as the prover folds it.
func realMerkleRoot(leaf common.Hash, position uint32, path [32]common.Hash) common.Hash {
	cur := leaf
	for level, sibling := range path {
		if position>>level&1 == 1 {
			cur = ghosttree.K(ghosttree.TagCoinNode, []byte{byte(level)}, sibling[:], cur[:])
		} else {
			cur = ghosttree.K(ghosttree.TagCoinNode, []byte{byte(level)}, cur[:], sibling[:])
		}
	}
	return cur
}

// The jobs of the fixture request, in the layout of guardfixture.rs.
const (
	realKindReveal = 1
	realKindPolicy = 2
	realKindAction = 3

	realParamsBytes          = 8 + 2 + 32
	realOpeningBytes         = 3*32 + ghostpriv.SaltSize + 32 + 4 + 32*32
	realRemainderBytes       = 3*32 + ghostpriv.SaltSize + 32
	realRuleBytes            = common.AddressLength + 5*32
	realRevealStatementBytes = 3*32 + ghostpriv.NoteSize + common.AddressLength + 2*32
	realPolicyStatementBytes = 5*32 + common.AddressLength + 5*32 + ghostpriv.NoteSize
	realActionStatementBytes = common.AddressLength + 32 + 8 + 4*32 + 8 + 32
)

// realJobBytes is the length of a job of each kind.
var realJobBytes = map[byte]int{
	realKindReveal: 1 + realParamsBytes + realOpeningBytes + 1 + realRuleBytes + 32 + realRemainderBytes + 32 + realRevealStatementBytes,
	realKindPolicy: 1 + realParamsBytes + realOpeningBytes + 32 + realRemainderBytes + realPolicyStatementBytes,
	realKindAction: 1 + realParamsBytes + realActionStatementBytes + 32,
}

func amountBytes(v *uint256.Int) []byte {
	if v == nil {
		v = new(uint256.Int)
	}
	w := v.Bytes32()
	return w[:]
}

// realParams are the chain parameters of a statement, with its own version.
func realParams(in *ghostpriv.VerifyInputs) []byte {
	b := binary.BigEndian.AppendUint64(nil, in.ChainID)
	b = binary.BigEndian.AppendUint16(b, in.Version)
	return append(b, in.Domain[:]...)
}

// realRevealStatement is statement S1 version 2 in the layout of
// ghost_proofs.h.
func realRevealStatement(in *ghostpriv.VerifyInputs) []byte {
	b := append([]byte{}, in.Root[:]...)
	b = append(b, in.Marker[:]...)
	b = append(b, in.Remainder[:]...)
	b = append(b, in.Note[:]...)
	b = append(b, in.Recipient[:]...)
	b = append(b, amountBytes(in.Out)...)
	return append(b, amountBytes(in.Fee)...)
}

// realPolicyStatement is statement S4 in the layout of ghost_policy.h.
func realPolicyStatement(in *ghostpriv.VerifyInputs) []byte {
	b := append([]byte{}, in.Root[:]...)
	b = append(b, in.Marker[:]...)
	b = append(b, in.Remainder[:]...)
	b = append(b, amountBytes(in.Out)...)
	b = append(b, amountBytes(in.Fee)...)
	b = append(b, in.Policy[:]...)
	for _, h := range []common.Hash{in.PolicyCodeHash, in.ParamsHash, in.ActionTag, in.ActionSalt, in.Instr} {
		b = append(b, h[:]...)
	}
	return append(b, in.Note[:]...)
}

// realActionStatement is KNOW_ACTION_v1 in the layout of ghost_action.h.
func realActionStatement(in *ghostpriv.VerifyInputs) []byte {
	b := append([]byte{}, in.Policy[:]...)
	b = append(b, in.Marker[:]...)
	b = binary.BigEndian.AppendUint64(b, in.ActionNonce)
	b = append(b, in.ActionTag[:]...)
	b = append(b, in.ActionSalt[:]...)
	b = append(b, amountBytes(in.ExpectedRemaining)...)
	b = append(b, amountBytes(in.Debit)...)
	b = binary.BigEndian.AppendUint64(b, in.Expiry)
	return append(b, in.CalldataHash[:]...)
}

// realOpening is the opening of c against root, which must be the root of
// n's head: its secrets, its value, its position and its sibling path, read
// from the node's chain. The path folds to root.
func realOpening(t *testing.T, n *node, c coin, root common.Hash) []byte {
	t.Helper()
	g := guardScan(t, n)
	if *g.head.CoinTreeRoot != root {
		t.Fatalf("node %s: an opening against %x, the head's root is %x", n.name, root, *g.head.CoinTreeRoot)
	}
	position := -1
	for i, l := range g.leaves {
		if l.leaf == c.leaf() {
			if position >= 0 {
				t.Fatalf("node %s: commitment %d at positions %d and %d", n.name, c.index, position, i)
			}
			position = i
		}
	}
	if position < 0 {
		t.Fatalf("node %s: commitment %d of %v is not in the coin tree", n.name, c.index, c.value)
	}
	hashes, roots := g.leafHashes(), g.pageRoots()
	page := position / ghosttree.PageLeaves * ghosttree.PageLeaves
	path, err := ghosttree.Witness(ghosttree.Coin, uint32(position), hashes[page:min(page+ghosttree.PageLeaves, len(hashes))], roots)
	if err != nil {
		t.Fatalf("node %s: witness of commitment %d: %v", n.name, c.index, err)
	}
	if got := realMerkleRoot(c.leaf(), uint32(position), path); got != root {
		t.Fatalf("node %s: the path of commitment %d folds to %x, the root is %x", n.name, c.index, got, root)
	}
	w := c.owner
	s, r, b, salt := w.secret(tagRealS, c.index), w.secret(tagRealR, c.index), w.secret(tagRealB, c.index), w.realSalt(c.index)
	out := append([]byte{}, s[:]...)
	out = append(out, r[:]...)
	out = append(out, b[:]...)
	out = append(out, salt[:]...)
	out = append(out, amountBytes(c.value)...)
	out = binary.BigEndian.AppendUint32(out, uint32(position))
	for _, sibling := range path {
		out = append(out, sibling[:]...)
	}
	return out
}

// realRemainder is the remainder c: its secrets, salt and value.
func realRemainder(t *testing.T, c coin) []byte {
	t.Helper()
	w := c.owner
	if w.real == nil {
		t.Fatalf("the remainder %d of a real proof is a stand-in wallet's", c.index)
	}
	s, r, b, salt := w.secret(tagRealS, c.index), w.secret(tagRealR, c.index), w.secret(tagRealB, c.index), w.realSalt(c.index)
	out := append([]byte{}, s[:]...)
	out = append(out, r[:]...)
	out = append(out, b[:]...)
	out = append(out, salt[:]...)
	return append(out, amountBytes(c.value)...)
}

// realProofs are the proofs of a real-proof run, in the order it makes them.
type realProofs struct {
	jobs    [][]byte // the jobs so far
	fixture [][]byte // the fixture's jobs; nil while recording the request
	proofs  [][]byte // the fixture's proofs
}

// request is the request of the jobs so far: their number (4, big endian)
// and the jobs.
func (p *realProofs) request() []byte {
	b := binary.BigEndian.AppendUint32(nil, uint32(len(p.jobs)))
	for _, job := range p.jobs {
		b = append(b, job...)
	}
	return b
}

// load reads the fixture: the request, then each job's proof as its length
// (4, big endian) and the proof.
func (p *realProofs) load(t *testing.T, raw []byte) {
	t.Helper()
	rest := raw
	take := func(n int) []byte {
		if n < 0 || len(rest) < n {
			t.Fatalf("fixture of %d bytes is short; %s", len(raw), realGuardRegenerate)
		}
		b := rest[:n]
		rest = rest[n:]
		return b
	}
	count := int(binary.BigEndian.Uint32(take(4)))
	for i := 0; i < count; i++ {
		if len(rest) == 0 {
			t.Fatalf("fixture of %d bytes ends before job %d; %s", len(raw), i, realGuardRegenerate)
		}
		size, ok := realJobBytes[rest[0]]
		if !ok {
			t.Fatalf("fixture job %d of kind %d; %s", i, rest[0], realGuardRegenerate)
		}
		p.fixture = append(p.fixture, take(size))
	}
	for i := 0; i < count; i++ {
		p.proofs = append(p.proofs, take(int(binary.BigEndian.Uint32(take(4)))))
	}
	if len(rest) != 0 {
		t.Fatalf("fixture has %d bytes left over; %s", len(rest), realGuardRegenerate)
	}
	if count == 0 {
		t.Fatalf("fixture of no proofs; %s", realGuardRegenerate)
	}
}

// done checks that the run used every proof of the fixture: its request is
// the fixture's, byte for byte.
func (p *realProofs) done(t *testing.T, raw []byte) {
	t.Helper()
	if len(p.jobs) != len(p.fixture) {
		t.Fatalf("the lifecycle made %d proofs, the fixture has %d; %s", len(p.jobs), len(p.fixture), realGuardRegenerate)
	}
	if req := p.request(); !bytes.HasPrefix(raw, req) {
		t.Fatalf("the request is not the fixture's; %s", realGuardRegenerate)
	}
}

// prove records job, whose statement the node builds as in, and returns its
// proof: stub while recording, else the fixture's, which must be for this
// very job. The default verifier must accept it and refuse it with a byte
// flipped, and refuse the stub proof.
func (p *realProofs) prove(t *testing.T, job []byte, in *ghostpriv.VerifyInputs, stub []byte) []byte {
	t.Helper()
	if want := realJobBytes[job[0]]; len(job) != want {
		t.Fatalf("a job of kind %d and %d bytes, want %d", job[0], len(job), want)
	}
	i := len(p.jobs)
	p.jobs = append(p.jobs, job)
	if p.fixture == nil {
		return stub
	}
	if i >= len(p.fixture) {
		t.Fatalf("proof %d, the fixture has %d; %s", i, len(p.fixture), realGuardRegenerate)
	}
	if !bytes.Equal(p.fixture[i], job) {
		at := 0
		for at < len(job) && at < len(p.fixture[i]) && job[at] == p.fixture[i][at] {
			at++
		}
		t.Fatalf("proof %d is for another job, from byte %d on: the lifecycle changed; %s", i, at, realGuardRegenerate)
	}
	v, proof := ghostpriv.DefaultVerifier(), p.proofs[i]
	if err := v.VerifyReveal(in, proof); err != nil {
		t.Fatalf("proof %d: the default verifier refuses the fixture's proof: %v", i, err)
	}
	bad := common.CopyBytes(proof)
	bad[len(bad)/2] ^= 1
	if err := v.VerifyReveal(in, bad); err == nil {
		t.Fatalf("proof %d: the default verifier accepts it with a byte flipped", i)
	}
	if err := v.VerifyReveal(in, stub); err == nil {
		t.Fatalf("proof %d: the default verifier accepts the stub proof", i)
	}
	return common.CopyBytes(proof)
}

// reveal is the proof of r, an ordinary reveal of spend leaving rest, whose
// proof field holds the stub proof.
func (p *realProofs) reveal(n *node, r *ghostpriv.Reveal, spend, rest coin) []byte {
	t := n.t
	t.Helper()
	in := r.VerifyInputs(r.ChainID, n.chain.Genesis().Hash())
	job := append([]byte{realKindReveal}, realParams(in)...)
	job = append(job, realOpening(t, n, spend, r.Root)...)
	if rule := spend.owner.real.rules[spend.index]; rule != nil {
		job = append(job, 1)
		job = append(job, rule.bytes()...)
		job = append(job, rule.overrideSecret[:]...)
	} else {
		job = append(job, 0)
		job = append(job, make([]byte, realRuleBytes+32)...)
	}
	job = append(job, realRemainder(t, rest)...)
	restRule := rest.owner.ruleHash(rest.index)
	job = append(job, restRule[:]...)
	job = append(job, realRevealStatement(in)...)
	return p.prove(t, job, in, r.Proof)
}

// policyReveal is the proof of r, a sweep of the policy coin spend into its
// slot leaving the zero remainder rest, whose proof field holds the stub
// proof.
func (p *realProofs) policyReveal(n *node, r *ghostpriv.PolicyReveal, spend, rest coin) []byte {
	t := n.t
	t.Helper()
	rule := spend.owner.real.rules[spend.index]
	switch {
	case rule == nil:
		t.Fatalf("a policy reveal of the plain commitment %d", spend.index)
	case rule.policy != r.Policy || rule.codeHash != r.CodeHash || rule.paramsHash != r.ParamsHash || rule.actionTag != r.ActionTag || rule.actionSalt != r.ActionSalt:
		t.Fatalf("a policy reveal of commitment %d under another rule than the coin's", spend.index)
	case rest.owner.real != nil && rest.owner.ruleHash(rest.index) != (common.Hash{}):
		t.Fatal("a policy reveal's remainder has a rule: the prover makes it a plain coin")
	}
	in := r.VerifyInputs(r.ChainID, n.chain.Genesis().Hash())
	job := append([]byte{realKindPolicy}, realParams(in)...)
	job = append(job, realOpening(t, n, spend, r.Root)...)
	o := rule.overrideHash()
	job = append(job, o[:]...)
	job = append(job, realRemainder(t, rest)...)
	job = append(job, realPolicyStatement(in)...)
	return p.prove(t, job, in, r.Proof)
}

// action is the proof of a, an action on slot whose key is actionRoot, whose
// proof field holds the stub proof.
func (p *realProofs) action(n *node, a *ghostpriv.Action, slot *ghostpriv.EscrowSlot, actionRoot common.Hash) []byte {
	t := n.t
	t.Helper()
	if ghostpriv.PolicyActionTag(actionRoot, slot.ActionSalt) != slot.ActionTag {
		t.Fatal("the action root is not behind the slot's tag")
	}
	in := a.VerifyInputs(a.ChainID, n.chain.Genesis().Hash(), slot)
	job := append([]byte{realKindAction}, realParams(in)...)
	job = append(job, realActionStatement(in)...)
	job = append(job, actionRoot[:]...)
	return p.prove(t, job, in, a.Proof)
}

// readGzipFile reads a gzip file uncompressed.
func readGzipFile(name string) ([]byte, error) {
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	zr, err := gzip.NewReader(file)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(zr)
}

// TestRealWalletMatchesProver checks the real-proof wallet's hashes against
// the pinned prover's output in the known-answer fixtures of
// ghostverifier/examples/v2fixture.rs: from that generator's secrets, the
// policy coin's rule, fingerprint and commitment folded up its path give the
// fixtures' roots, and the markers and remainders are theirs. It also checks
// that the prover's fold of a path from ghosttree.Witness gives the node's
// coin tree root.
func TestRealWalletMatchesProver(t *testing.T) {
	fill := func(b byte) (h common.Hash) {
		for i := range h {
			h[i] = b
		}
		return h
	}
	saltOf := func(b byte) (s [ghostpriv.SaltSize]byte) {
		for i := range s {
			s[i] = b
		}
		return s
	}
	// The coin of v2fixture.rs at position 5 of a tree whose only other used
	// leaf is 0x09 bytes at position 4.
	var path [32]common.Hash
	empty := ghosttree.EmptyLeaf
	for level := range path {
		path[level] = empty
		empty = ghosttree.K(ghosttree.TagCoinNode, []byte{byte(level)}, empty[:], empty[:])
	}
	path[0] = fill(9)
	one := uint256.NewInt(1_000_000)
	load := func(name string, statementLen int) []byte {
		raw, err := readGzipFile(filepath.Join("..", "testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) <= realParamsBytes+statementLen {
			t.Fatalf("%s of %d bytes", name, len(raw))
		}
		return raw[realParamsBytes : realParamsBytes+statementLen]
	}

	// The ordinary reveal of a plain coin.
	s := load("coin_reveal_v2.bin.gz", realRevealStatementBytes)
	f := realCoinFingerprint(fill(1), fill(2), fill(3), saltOf(0x6d), common.Hash{})
	leaf := ghostpriv.CommitmentVersion(ghostpriv.SaltedCommitVersion, f, one)
	rest := ghostpriv.CommitmentVersion(ghostpriv.SaltedCommitVersion, realCoinFingerprint(fill(1), fill(2), fill(4), saltOf(0x7e), common.Hash{}), uint256.NewInt(1_000_000-600_000-21))
	if got := realMerkleRoot(leaf, 5, path); !bytes.Equal(got[:], s[0:32]) {
		t.Errorf("plain coin: root %x, the prover's %x", got, s[0:32])
	}
	if got := realCoinMarker(fill(2), fill(3), saltOf(0x6d)); !bytes.Equal(got[:], s[32:64]) {
		t.Errorf("plain coin: marker %x, the prover's %x", got, s[32:64])
	}
	if !bytes.Equal(rest[:], s[64:96]) {
		t.Errorf("plain coin: remainder %x, the prover's %x", rest, s[64:96])
	}

	// The policy reveal of a coin with a rule.
	s = load("policy_reveal.bin.gz", realPolicyStatementBytes)
	rule := &realRule{
		policy:         common.BytesToAddress(bytes.Repeat([]byte{0x50}, 20)),
		codeHash:       fill(0x51),
		paramsHash:     fill(0x52),
		actionTag:      fill(0x54),
		actionSalt:     fill(0x55),
		overrideSecret: fill(0x53),
	}
	if !bytes.Equal(rule.bytes()[:20], s[160:180]) || !bytes.Equal(rule.bytes()[20:84], s[180:244]) || !bytes.Equal(rule.bytes()[116:], s[244:308]) {
		t.Fatal("the policy fields of the fixture are not v2fixture.rs's rule")
	}
	leaf = ghostpriv.CommitmentVersion(ghostpriv.SaltedCommitVersion, realCoinFingerprint(fill(1), fill(2), fill(3), saltOf(0x6e), rule.hash()), one)
	rest = ghostpriv.CommitmentVersion(ghostpriv.SaltedCommitVersion, realCoinFingerprint(fill(1), fill(2), fill(5), saltOf(0x7f), common.Hash{}), new(uint256.Int))
	if got := realMerkleRoot(leaf, 5, path); !bytes.Equal(got[:], s[0:32]) {
		t.Errorf("policy coin: root %x, the prover's %x", got, s[0:32])
	}
	if got := realCoinMarker(fill(2), fill(3), saltOf(0x6e)); !bytes.Equal(got[:], s[32:64]) {
		t.Errorf("policy coin: marker %x, the prover's %x", got, s[32:64])
	}
	if !bytes.Equal(rest[:], s[64:96]) {
		t.Errorf("policy coin: remainder %x, the prover's %x", rest, s[64:96])
	}
	// The same coin with the plain rule is another leaf, under another root.
	plain := ghostpriv.CommitmentVersion(ghostpriv.SaltedCommitVersion, realCoinFingerprint(fill(1), fill(2), fill(3), saltOf(0x6e), common.Hash{}), one)
	if got := realMerkleRoot(plain, 5, path); bytes.Equal(got[:], s[0:32]) {
		t.Error("the policy coin's root does not depend on its rule")
	}

	// The prover's fold of the node's witnesses gives the node's root.
	leaves := []common.Hash{fill(0xa1), fill(0xa2), fill(0xa3)}
	roots := []common.Hash{ghosttree.PageRoot(ghosttree.Coin, leaves)}
	root := ghosttree.RootFromPageRoots(ghosttree.Coin, roots)
	for i, l := range leaves {
		w, err := ghosttree.Witness(ghosttree.Coin, uint32(i), leaves, roots)
		if err != nil {
			t.Fatal(err)
		}
		if got := realMerkleRoot(l, uint32(i), w); got != root {
			t.Errorf("leaf %d folds to %x, the node's root is %x", i, got, root)
		}
	}
}
