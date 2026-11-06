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

// Package docschecks checks that the node's documents state the rules the
// code applies, with the values taken from the code itself, so that a
// changed constant or a renamed error fails here until the document follows.
package docschecks

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/vars"
)

const (
	privateDoc = "docs/private-transactions.md"
	accountDoc = "docs/account-transactions.md"
)

// repoRoot is the repository root, relative to this package's directory.
var repoRoot = filepath.Join("..", "..")

func readDoc(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(name)))
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return string(data)
}

// section returns the text under the heading line, up to the next heading of
// the same or a higher level, with every run of white space made one space so
// that a phrase matches however the paragraph is wrapped.
func section(t *testing.T, name, doc, heading string) string {
	t.Helper()
	level := strings.IndexByte(heading, ' ')
	lines := strings.Split(doc, "\n")
	start := -1
	for i, line := range lines {
		if strings.TrimRight(line, " ") == heading {
			start = i + 1
			break
		}
	}
	if start < 0 {
		t.Fatalf("%s has no heading %q", name, heading)
	}
	end := len(lines)
	for i := start; i < len(lines); i++ {
		if l := headingLevel(lines[i]); l > 0 && l <= level {
			end = i
			break
		}
	}
	return strings.Join(strings.Fields(strings.Join(lines[start:end], "\n")), " ")
}

// headingLevel returns the level of a Markdown heading line, 0 for any other.
func headingLevel(line string) int {
	n := 0
	for n < len(line) && line[n] == '#' {
		n++
	}
	if n == 0 || n >= len(line) || line[n] != ' ' {
		return 0
	}
	return n
}

// comma formats n with a comma between groups of three digits, as the
// documents write numbers.
func comma(n uint64) string {
	s := strconv.FormatUint(n, 10)
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	return b.String()
}

// typeByte formats a transaction type as the documents write it, `0x55`.
func typeByte(typ byte) string {
	return fmt.Sprintf("`%#02x`", typ)
}

// requireAll reports every phrase the text does not contain.
func requireAll(t *testing.T, where, text string, phrases ...string) {
	t.Helper()
	for _, p := range phrases {
		if !strings.Contains(text, p) {
			t.Errorf("%s does not state %q", where, p)
		}
	}
}

// requireOrder reports the first phrase that is missing or that does not
// come after the one before it: the documents list checks in the order the
// node runs them.
func requireOrder(t *testing.T, where, text string, phrases ...string) {
	t.Helper()
	at := 0
	for _, p := range phrases {
		i := strings.Index(text[at:], p)
		if i < 0 {
			t.Errorf("%s does not state %q after %q", where, p, text[max(0, at-40):at])
			return
		}
		at += i + len(p)
	}
}

// errNames returns the documented form of each error, its name in
// backquotes, checking that every one is a real error of the code.
func errNames(t *testing.T, errs map[string]error) []string {
	t.Helper()
	var names []string
	for name, err := range errs {
		if err == nil {
			t.Fatalf("%s is nil", name)
		}
		names = append(names, "`"+name+"`")
	}
	return names
}

func TestPrivateAndAccountDocsCoverScaleBuild(t *testing.T) {
	private := readDoc(t, privateDoc)
	account := readDoc(t, accountDoc)

	t.Run("bundle", func(t *testing.T) { checkBundle(t, private) })
	t.Run("root verifiers", func(t *testing.T) { checkRootVerifiers(t, private) })
	t.Run("root verification time", func(t *testing.T) { checkRootTime(t, private) })
	t.Run("key registration", func(t *testing.T) { checkKeyRegistration(t, account) })
	t.Run("public root", func(t *testing.T) { checkPublicRoot(t, account) })
	t.Run("transaction types", func(t *testing.T) { checkTxTypes(t, account) })
	t.Run("links", func(t *testing.T) {
		docs := map[string]string{privateDoc: private, accountDoc: account}
		checkLinks(t, privateDoc, private, docs)
		checkLinks(t, accountDoc, account, docs)
	})
}

// checkBundle checks the private bundle (type 0x55): its layout, root inputs,
// checks, gas, receipt and admission.
func checkBundle(t *testing.T, doc string) {
	where := privateDoc + ", Private bundle"
	s := section(t, privateDoc, doc, "## Private bundle")
	envelope := uint64(1 + types.GhostBundleFixedSize)
	requireAll(t, where, s,
		"`"+fmt.Sprintf("%#02x", types.GhostBundleTxType)+" || payload`",
		"`keccak256("+fmt.Sprintf("%#02x", types.GhostBundleTxType)+" || payload)`",
		"up to "+comma(types.GhostBundleMaxReveals)+" version 2 ordinary reveals",
		fmt.Sprintf("(%d batches of 32)", types.GhostBundleMaxReveals/32),
		fmt.Sprintf("version, `%#04x`", ghostpriv.BundleVersion),
		"count, 1 to "+comma(types.GhostBundleMaxReveals),
		"| 12 | "+comma(types.GhostBundleProofSize)+" | root proof, then zeros |",
		fmt.Sprintf("| %s | %d * count | the bodies, in order |", comma(uint64(types.GhostBundleFixedSize)), types.GhostBundleBodySize),
		fmt.Sprintf("The envelope is %s + %d * count bytes", comma(envelope), types.GhostBundleBodySize),
		comma(uint64(1+types.GhostBundlePayloadSize(1)))+" for one reveal",
		comma(uint64(1+types.GhostBundlePayloadSize(types.GhostBundleMaxReveals)))+" for "+comma(types.GhostBundleMaxReveals),
		fmt.Sprintf("its first %d bytes", types.GhostBundleBodySize-ghostpriv.NoteSize),
		fmt.Sprintf("its %d-byte note", ghostpriv.NoteSize),
		"`types.ErrNoSender`",
		`K("`+ghostpriv.TagBundleContents+`", b_1 || ... || b_n)`,
		`K("`+ghostpriv.TagBundleBinding+`", fields)`,
		fmt.Sprintf("over %d bytes", ghostpriv.BundleBindingSize),
		fmt.Sprintf("purpose `%#02x` (bundle)", ghostpriv.PurposeBundle),
		"nothing of the state",
	)
	if ghostpriv.BundleBindingSize != len((&ghostpriv.BundleInputs{}).BindingInput()) {
		t.Errorf("BundleBindingSize %d is not the length of the bundle binding input %d",
			ghostpriv.BundleBindingSize, len((&ghostpriv.BundleInputs{}).BindingInput()))
	}

	// The structural checks, in the order CheckBundle runs them.
	checks := section(t, privateDoc, doc, "### Bundle checks")
	errNames(t, map[string]error{
		"ErrBundleLength": ghostpriv.ErrBundleLength, "ErrBundleCount": ghostpriv.ErrBundleCount,
		"ErrBundleVersion": ghostpriv.ErrBundleVersion, "ErrBundleBody": ghostpriv.ErrBundleBody,
		"ErrBundleChainID": ghostpriv.ErrBundleChainID, "ErrBundleUnsupported": ghostpriv.ErrBundleUnsupported,
		"ErrBundleProof": ghostpriv.ErrBundleProof,
	})
	requireOrder(t, where+", checks", checks,
		"`ErrBundleLength`", "`ErrBundleCount`", "`ErrBundleLength`", "`ErrBundleVersion`",
		"`ErrBundleBody`", "`ErrBundleChainID`", "`ErrBundleUnsupported`", "`ErrBundleProof`",
	)
	requireAll(t, where+", checks", checks,
		"makes the block invalid before any change of the bundle's",
		"checks 5 to 9 of a lone reveal and the coin tree check",
		"a marker repeated within the bundle included",
		"is skipped: it pays nothing and writes nothing",
		"the rest of the bundle runs",
		"`ghostpriv.ApplyBundle`",
	)

	// The gas: count times G_PRIV, which the consensus block gas limit
	// bounds to one reveal.
	gas := section(t, privateDoc, doc, "### Bundle gas and receipt")
	one, two := types.GhostBundleGas(1), types.GhostBundleGas(2)
	if one != types.GhostRevealGas || two != 2*types.GhostRevealGas {
		t.Fatalf("bundle gas %d, %d is not count times G_PRIV %d", one, two, types.GhostRevealGas)
	}
	if one > ghost.MaxBlockGasLimit || two <= ghost.MaxBlockGasLimit {
		t.Errorf("the document says a block holds a bundle of one reveal and no more: %d and %d gas against %d",
			one, two, ghost.MaxBlockGasLimit)
	}
	requireAll(t, where+", gas", gas,
		"`count x G_PRIV`", "`types.GhostBundleGas`", "skipped reveals included",
		"maximum block gas limit of "+comma(ghost.MaxBlockGasLimit),
		"a bundle of one reveal, "+comma(one)+" gas",
		"a bundle of two takes "+comma(two)+" gas and fits no block",
		"a skipped reveal pays none",
		"typed receipt of type "+typeByte(types.GhostBundleTxType)+", status 1",
		"the reveal logs of the applied reveals",
	)

	adm := section(t, privateDoc, doc, "### Bundle admission")
	requireAll(t, where+", admission", adm,
		"No pool takes a bundle",
		typeByte(types.GhostBundleTxType)+" with `core.ErrTxTypeNotSupported`",
		"the miner builds none",
		"`types.CheckTxType` takes the type",
	)
	if core.ErrTxTypeNotSupported == nil {
		t.Fatal("core.ErrTxTypeNotSupported is nil")
	}
}

// checkRootVerifiers checks the statement that roots are verified through
// interfaces of their own, which the default verifier does not have yet.
func checkRootVerifiers(t *testing.T, doc string) {
	where := privateDoc + ", Proof verifier"
	s := section(t, privateDoc, doc, "## Proof verifier")
	requireAll(t, where, s,
		"`ghostpriv.BundleVerifier` and `ghostpriv.PublicRootVerifier`",
		"fails every root of that kind closed, with `ErrBundleUnsupported` or `ErrPublicRootUnsupported`",
		"Neither the linked verifier nor the default of a build without it has either interface yet",
		`K("ghost/test-proof/v1", root binding)`,
		"`ghostprivtest.BundleProof`, `ghostprivtest.PublicRootProof`",
	)
	// The document says no verifier of this build verifies a root. Once one
	// does, the document must say so, and the time of its roots be measured.
	v := ghostpriv.DefaultVerifier()
	if _, ok := v.(ghostpriv.BundleVerifier); ok {
		t.Errorf("the default verifier %T verifies bundle roots: update %s (Proof verifier, Root verification time)", v, privateDoc)
	}
	if _, ok := v.(ghostpriv.PublicRootVerifier); ok {
		t.Errorf("the default verifier %T verifies public roots: update %s (Proof verifier, Root verification time)", v, privateDoc)
	}
}

// msFigure finds a time in milliseconds in the text.
var msFigure = regexp.MustCompile(`(\d[\d,.]*)\s*ms\b`)

// checkRootTime checks that the root verification time is stated against the
// budget of spec 07 and that no time is given until one is measured.
func checkRootTime(t *testing.T, doc string) {
	where := privateDoc + ", Root verification time"
	s := section(t, privateDoc, doc, "## Root verification time")
	requireAll(t, where, s,
		"Spec 07, section 4",
		"a budget of 3,000 ms to verify the four root proofs of a block",
		"No verification time is recorded against it yet",
		"measured on named hardware, with the real linked verifier, over real root proofs",
		"the stub verifier above checks one hash and times nothing of a proof",
		"a real Poseidon2 shrink proof",
		"the benchmark is blocked",
		"no time, measured or estimated",
	)
	for _, m := range msFigure.FindAllStringSubmatch(s, -1) {
		if m[1] != "3,000" {
			t.Errorf("%s gives a time of %s ms, but no time is measured yet", where, m[1])
		}
	}
	if strings.Contains(strings.ToLower(s), "| measured") {
		t.Errorf("%s holds a table of measured times, but no real root proof exists to time", where)
	}
}

// checkKeyRegistration checks the key identity and the key registry the
// public root reads.
func checkKeyRegistration(t *testing.T, doc string) {
	where := accountDoc + ", Key identity and key registration"
	s := section(t, accountDoc, doc, "## Key identity and key registration")
	requireAll(t, where, s,
		`K("`+types.GhostAccountKeyTag+`", scheme, public_key)`,
		"`0x0004` taken as `0x0003`",
		"`"+strings.ToLower(types.GhostKeyRegistryAccount.Hex())+"`",
		`K("`+types.GhostKeyRegistryTag+`", account)`,
		"`types.GhostRecordedKeyIdentity`",
		"with no value and no data",
		"It runs no code",
		"`core.ErrGhostKeyRegistration`",
		"`core.ErrGhostAccountKeyIdentity`",
	)
	if core.ErrGhostKeyRegistration == nil || core.ErrGhostAccountKeyIdentity == nil {
		t.Fatal("the key registration errors are nil")
	}
	if strings.Contains(doc, "There is no key registry") || strings.Contains(doc, "no key\nregistry") {
		t.Errorf("%s still says there is no key registry", accountDoc)
	}
}

// checkPublicRoot checks the public root (type 0x56) and the binding
// transaction (type 0x57): layouts, inputs, block rules, gas and admission.
func checkPublicRoot(t *testing.T, doc string) {
	where := accountDoc + ", Public root and binding transactions"
	s := section(t, accountDoc, doc, "## Public root and binding transactions")
	items := reflect.TypeOf(types.GhostBindingTx{}).NumField()
	requireAll(t, where, s,
		"is type "+typeByte(types.GhostBindingTxType),
		fmt.Sprintf("exactly %s items", map[int]string{10: "ten", 11: "eleven", 12: "twelve"}[items]),
		fmt.Sprintf("the %d-byte binding", types.GhostBindingSize),
		fmt.Sprintf("`binding` (%d bytes)", types.GhostBindingSize),
		fmt.Sprintf("`keccak256(%#02x || rlp(list))`, the binding included", types.GhostBindingTxType),
		fmt.Sprintf("account (%d) | key identity (%d) | transaction hash (%d)",
			common.AddressLength, common.HashLength, common.HashLength),
		fmt.Sprintf(`K("%s", %#02x, genesis_hash, keccak256(unbound))`, types.GhostBindingTxTag, types.GhostBindingTxType),
		"`types.ErrGhostBindingSender`",
		"typed receipt of type "+typeByte(types.GhostBindingTxType),
		"is type "+typeByte(types.GhostPublicRootTxType),
		fmt.Sprintf("`keccak256(%#02x || payload)`", types.GhostPublicRootTxType),
		fmt.Sprintf("version, `%#04x`", ghostpriv.PublicRootVersion),
		"| 12 | "+comma(types.GhostPublicRootProofSize)+" | root proof, then zeros |",
		fmt.Sprintf("| %s | %d * count | the bindings, in block order |", comma(uint64(types.GhostPublicRootFixedSize)), types.GhostBindingSize),
		fmt.Sprintf("The envelope is %s + %d * count bytes", comma(uint64(1+types.GhostPublicRootFixedSize)), types.GhostBindingSize),
		"on the state at the root",
		`K("`+ghostpriv.TagPublicRootContents+`", b_1 || ... || b_n)`,
		`K("`+ghostpriv.TagPublicRootBinding+`", fields)`,
		fmt.Sprintf("over %d bytes", ghostpriv.PublicRootBindingSize),
		fmt.Sprintf("purpose `%#02x` (public root)", ghostpriv.PurposePublicRoot),
		"The root proves the signatures only",
	)
	if items != 11 {
		t.Errorf("a binding transaction has %d fields; the document lists eleven", items)
	}
	if n := len((&ghostpriv.PublicRootInputs{}).BindingInput()); n != ghostpriv.PublicRootBindingSize {
		t.Errorf("PublicRootBindingSize %d is not the length of the root binding input %d", ghostpriv.PublicRootBindingSize, n)
	}
	if types.GhostBindingSize != common.AddressLength+2*common.HashLength {
		t.Errorf("a binding is %d bytes, not account, key identity and transaction hash", types.GhostBindingSize)
	}

	// The block rules, in the order the node runs them: the root's, then
	// each binding transaction's.
	rules := section(t, accountDoc, doc, "### Block rules")
	errNames(t, map[string]error{
		"ErrPublicRootRepeated": ghostpriv.ErrPublicRootRepeated, "ErrPublicRootLength": ghostpriv.ErrPublicRootLength,
		"ErrPublicRootVersion": ghostpriv.ErrPublicRootVersion, "ErrPublicRootChainID": ghostpriv.ErrPublicRootChainID,
		"ErrPublicRootCount": ghostpriv.ErrPublicRootCount, "ErrPublicRootBinding": ghostpriv.ErrPublicRootBinding,
		"ErrPublicRootUnsupported": ghostpriv.ErrPublicRootUnsupported, "ErrPublicRootProof": ghostpriv.ErrPublicRootProof,
		"ErrPublicRootMissing": ghostpriv.ErrPublicRootMissing, "ErrPublicKeyIdentity": ghostpriv.ErrPublicKeyIdentity,
		"types.ErrInvalidChainId": types.ErrInvalidChainId,
	})
	split := strings.Index(rules, "Each binding transaction is then checked")
	if split < 0 {
		t.Fatalf("%s, Block rules does not state the checks of a binding transaction", accountDoc)
	}
	requireAll(t, where+", block rules", rules[:split],
		"at most one public root, before every binding transaction it proves",
		"any failure makes the block invalid",
	)
	requireOrder(t, where+", root checks", rules[:split],
		"`ErrPublicRootRepeated`", "`ErrPublicRootLength`", "`ErrPublicRootVersion`",
		"`ErrPublicRootChainID`", "`ErrPublicRootCount`", "`ErrPublicRootBinding`",
		"`ErrPublicRootUnsupported`", "`ErrPublicRootProof`",
	)
	requireOrder(t, where+", binding transaction checks", rules[split:],
		"`ErrPublicRootMissing`", "`ErrPublicRootCount`", "`types.ErrInvalidChainId`",
		"`ErrPublicKeyIdentity`", "`ErrPublicRootBinding`", "`ErrPublicRootBinding`",
		"nonce, balance, no code at the sender, the fee caps and the gas",
		"more bindings than the block applied makes it invalid (`ErrPublicRootCount`)",
	)
	requireAll(t, where+", binding transaction checks", rules[split:],
		"an account must register its key before it sends a binding transaction",
	)

	// The gas: none for the root, that of an account transaction of its
	// scheme for each binding transaction.
	gas := section(t, accountDoc, doc, "### Gas")
	pk, sig, ok := types.GhostSchemeSizes(types.GhostSchemeMLDSA44)
	if !ok {
		t.Fatal("scheme 0x0001 has no sizes")
	}
	transfer := vars.TxGas + ghost.AccountTxSigByteGas*uint64(2+pk+sig) + ghost.AccountTxVerifyGas(types.GhostSchemeMLDSA44)
	requireAll(t, where+", gas", gas,
		"The public root takes no gas from the block gas pool and changes no state",
		"of type "+typeByte(types.GhostPublicRootTxType)+", status 1, with no gas and no logs",
		"as if it carried the scheme's public key and signature",
		"+ VERIFY_GAS[scheme]`",
		"scheme `0x0001` takes "+comma(transfer)+" gas, as one of type "+typeByte(types.GhostAccountTxType),
		"A scheme whose `VERIFY_GAS` is zero has no binding transaction accepted",
	)

	adm := section(t, accountDoc, doc, "### Admission")
	requireAll(t, where+", admission", adm,
		"No pool takes a public root or a binding transaction",
		"types "+typeByte(types.GhostPublicRootTxType)+" and "+typeByte(types.GhostBindingTxType)+" are refused with `core.ErrTxTypeNotSupported`",
		"from RPC and from peers alike",
		"the miner builds neither",
		"`types.CheckTxType` takes both",
		"[root verification time](private-transactions.md#root-verification-time)",
	)
}

// checkTxTypes checks that the list of the types the node takes names every
// native type.
func checkTxTypes(t *testing.T, doc string) {
	s := section(t, accountDoc, doc, "## The secp256k1 transaction types")
	for _, typ := range []byte{
		types.GhostRevealTxType, types.GhostDataRevealTxType, types.GhostAccountTxType,
		types.GhostPolicyRevealTxType, types.GhostPolicyActionTxType, types.GhostBundleTxType,
		types.GhostPublicRootTxType, types.GhostBindingTxType,
	} {
		if !strings.Contains(s, "("+typeByte(typ)+")") {
			t.Errorf("%s, The secp256k1 transaction types does not list type %#02x among the types the node takes", accountDoc, typ)
		}
	}
}

// linkRE finds a Markdown link to one of the two documents, or to a heading
// of the document it is in.
var linkRE = regexp.MustCompile(`\]\(((?:private-transactions\.md|account-transactions\.md)?)#([^)\s]+)\)`)

// checkLinks reports every link of doc to a heading of the two documents
// that names no heading there.
func checkLinks(t *testing.T, name, doc string, docs map[string]string) {
	t.Helper()
	for _, m := range linkRE.FindAllStringSubmatch(doc, -1) {
		target := name
		if m[1] != "" {
			target = "docs/" + m[1]
		}
		if !slugs(docs[target])[m[2]] {
			t.Errorf("%s links to %s#%s, which has no such heading", name, target, m[2])
		}
	}
}

// slugs returns the anchors of the headings of doc, as GitHub makes them.
func slugs(doc string) map[string]bool {
	anchors := make(map[string]bool)
	for _, line := range strings.Split(doc, "\n") {
		n := headingLevel(line)
		if n == 0 {
			continue
		}
		var b strings.Builder
		for _, c := range strings.ToLower(strings.TrimSpace(line[n:])) {
			switch {
			case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
				b.WriteRune(c)
			case c == ' ':
				b.WriteByte('-')
			}
		}
		anchors[b.String()] = true
	}
	return anchors
}
