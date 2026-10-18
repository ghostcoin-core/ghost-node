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
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params/ghost"
)

// The linkage test of spec 04, section 9, for one data commitment: the raw
// commit transaction with its receipt, every proof of holding, and the
// reveal or revocation with its receipt are the hops, and no value may
// appear in more than one hop, apart from the shared tree state, the chain
// constants (chain id, version, type and purpose tags, the receipt topics,
// the entry address) and the values each verifier chose (its identity and
// challenge). Every pair of hops is compared three ways:
//
//  1. fields, decoded at the width of their layout: two fields with the same
//     bytes are a link unless the whitelist admits the value;
//  2. bytes: any run of linkRun or more bytes two hops share anywhere in
//     their raw data, outside whitelisted values and zero runs, is a link;
//  3. one tagged hash: K(tag, field) for every field of one hop and every
//     hash tag written in core/ghosttree and core/ghostpriv (read from the
//     source), searched among the fields and raw bytes of the other hop.
const linkRun = 16

// field is one decoded field of a hop.
type field struct {
	name  string
	value []byte
}

// hop is one published item: its decoded fields and its raw byte strings.
type hop struct {
	name   string
	fields []field
	raws   []field
}

func (h *hop) add(name string, v []byte) { h.fields = append(h.fields, field{name, common.CopyBytes(v)}) }

func (h *hop) raw(name string, v []byte) { h.raws = append(h.raws, field{name, common.CopyBytes(v)}) }

// addNote adds a note as a whole and as its 32-byte words.
func (h *hop) addNote(prefix string, note []byte) {
	h.add(prefix, note)
	for i := 0; i < len(note); i += 32 {
		h.add(fmt.Sprintf("%s[%d:%d]", prefix, i, min(i+32, len(note))), note[i:min(i+32, len(note))])
	}
}

// commitHop reads a data commit back from node n: the transaction's binary
// encoding as stored in the block, checked against its hash, and its
// receipt.
func commitHop(t *testing.T, n *node, block *types.Block, txHash common.Hash) *hop {
	t.Helper()
	stored := n.chain.GetBlock(block.Hash(), block.NumberU64())
	if stored == nil {
		t.Fatalf("node %s: no block %d", n.name, block.NumberU64())
	}
	var tx *types.Transaction
	for _, x := range stored.Transactions() {
		if x.Hash() == txHash {
			tx = x
		}
	}
	if tx == nil {
		t.Fatalf("node %s: the commit is not in block %d", n.name, block.NumberU64())
	}
	enc, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var dec types.Transaction
	if err := dec.UnmarshalBinary(enc); err != nil || dec.Hash() != txHash {
		t.Fatalf("the stored commit does not decode to its hash: %v", err)
	}
	h := &hop{name: "commit"}
	h.raw("transaction", enc)
	h.add("tx.type", []byte{dec.Type()})
	h.add("tx.chainID", word8(dec.ChainId().Uint64()))
	h.add("tx.nonce", word8(dec.Nonce()))
	h.add("tx.tipCap", common.BigToHash(dec.GasTipCap()).Bytes())
	h.add("tx.feeCap", common.BigToHash(dec.GasFeeCap()).Bytes())
	h.add("tx.gas", word8(dec.Gas()))
	h.add("tx.to", dec.To().Bytes())
	h.add("tx.value", common.BigToHash(dec.Value()).Bytes())
	data := dec.Data()
	if len(data) != ghostpriv.CommitDataSize {
		t.Fatalf("commit data of %d bytes", len(data))
	}
	h.add("data.version", data[0:2])
	h.add("data.F_d", data[2:34])
	h.addNote("data.note", data[34:])
	v, r, s := dec.RawSignatureValues()
	h.add("tx.v", common.BigToHash(v).Bytes())
	h.add("tx.r", common.BigToHash(r).Bytes())
	h.add("tx.s", common.BigToHash(s).Bytes())

	receipts := n.chain.GetReceiptsByHash(block.Hash())
	for i, x := range stored.Transactions() {
		if x.Hash() != txHash {
			continue
		}
		for _, l := range receipts[i].Logs {
			rec, ok := parseDataCommitLog(t, l)
			if !ok {
				t.Fatalf("the commit wrote a log the test cannot decode")
			}
			h.raw("receipt", l.Data)
			h.add("receipt.topic", l.Topics[0][:])
			h.add("receipt.tree", l.Data[0:4])
			h.add("receipt.position", l.Data[4:8])
			h.add("receipt.leaf", rec.leaf[:])
			h.addNote("receipt.note", rec.note[:])
		}
	}
	return h
}

// holdingHop is a proof of holding as it travels to the verifier.
func holdingHop(t *testing.T, name string, enc []byte) *hop {
	t.Helper()
	p, err := decodeHolding(enc)
	if err != nil {
		t.Fatal(err)
	}
	h := &hop{name: name}
	h.raw("proof of holding", enc)
	h.add("type", p.Type[:])
	h.add("purpose", []byte{p.Purpose})
	h.add("version", binary.BigEndian.AppendUint16(nil, p.Version))
	h.add("chainID", word8(p.ChainID))
	h.add("verifier", p.Verifier[:])
	h.add("challenge", p.Challenge[:])
	h.add("dataRoot", p.DataRoot[:])
	h.add("markerSetRoot", p.MarkerSetRoot[:])
	h.add("proof", p.Proof[:])
	return h
}

// revealHop is a data reveal or revocation: its envelope and the log of its
// receipt.
func revealHop(t *testing.T, name string, envelope []byte, l *types.Log) *hop {
	t.Helper()
	r, err := ghostpriv.DecodeDataReveal(envelope)
	if err != nil {
		t.Fatalf("%s does not decode: %v", name, err)
	}
	h := &hop{name: name}
	h.raw("envelope", envelope)
	h.add("type", envelope[:1])
	h.add("version", binary.BigEndian.AppendUint16(nil, r.Version))
	h.add("chainID", word8(r.ChainID))
	h.add("marker", r.Marker[:])
	h.add("root", r.Root[:])
	h.add("purpose", r.Purpose[:])
	h.add("verifier", r.Verifier[:])
	h.add("out", common.Hash(r.Out.Bytes32()).Bytes())
	h.add("fee", common.Hash(r.Fee.Bytes32()).Bytes())
	h.add("proof[0:32]", r.Proof[:32])
	h.addNote("note", r.Note[:])
	if l != nil {
		rl, ok := parseDataRevealLog(t, l)
		if !ok {
			t.Fatalf("%s: a log the test cannot decode", name)
		}
		h.raw("receipt", l.Data)
		h.add("receipt.topic", l.Topics[0][:])
		h.add("receipt.marker", rl.marker[:])
		h.add("receipt.purpose", []byte{rl.purpose})
		h.add("receipt.verifier", rl.verifier[:])
	}
	return h
}

func word8(v uint64) []byte { return binary.BigEndian.AppendUint64(nil, v) }

// whitelist is the exact list of values hops may share, each with its
// reason.
type whitelist struct {
	values map[string]string // value to reason, for values of 20 bytes or more
	short  map[string]string // short chain constants, admitted only as fields
}

// newWhitelist admits the shared tree state of n's canonical chain (every
// header's data and coin tree roots and every marker-set root), the chain
// constants and the verifiers' own choices.
func newWhitelist(n *node, verifiers []*holdingVerifier) *whitelist {
	w := &whitelist{values: make(map[string]string), short: make(map[string]string)}
	head := n.head().Number.Uint64()
	for num := uint64(0); num <= head; num++ {
		h := n.chain.GetHeaderByNumber(num)
		w.values[string(h.DataTreeRoot[:])] = "shared tree state: a header's data tree root"
		w.values[string(h.CoinTreeRoot[:])] = "shared tree state: a header's coin tree root"
		msr := markerSetRoot(n, h)
		w.values[string(msr[:])] = "shared tree state: a marker-set root"
	}
	for _, v := range verifiers {
		w.values[string(v.id[:])] = "a verifier's own choice: its identity"
		for c := range v.issued {
			w.values[string(c[:])] = "a verifier's own choice: its challenge"
		}
	}
	w.values[string(dataCommitTopic[:])] = "chain constant: the data commit receipt topic"
	w.values[string(dataRevealTopic[:])] = "chain constant: the data reveal receipt topic"
	w.values[string(ghost.DataCommitEntryAddress[:])] = "chain constant: the data commit entry address"
	for _, p := range []byte{ghostpriv.PurposeReveal, ghostpriv.PurposeRevoke} {
		f := ghostpriv.PurposeField(p)
		w.values[string(f[:])] = "chain constant: a purpose field"
		w.short[string([]byte{p})] = "chain constant: a purpose tag"
	}
	w.short[string([]byte{purposeHold})] = "chain constant: the hold purpose tag"
	w.short[string(word8(n.chain.Config().GetChainID().Uint64()))] = "chain constant: the chain id"
	w.short[string(binary.BigEndian.AppendUint16(nil, ghostpriv.Version))] = "chain constant: the version"
	w.short[string(ghostpriv.Data[:])] = "chain constant: the DATA type tag"
	w.short[string([]byte{types.GhostDataRevealTxType})] = "chain constant: the data reveal type byte"
	w.short[string([]byte{types.DynamicFeeTxType})] = "chain constant: the transaction type byte"
	return w
}

// admit returns the reason a shared field value is allowed, or "".
func (w *whitelist) admit(v []byte) string {
	if allZero(v) {
		return "zero padding"
	}
	if r := w.values[string(v)]; r != "" {
		return r
	}
	return w.short[string(v)]
}

// mask marks the bytes of raw that are whitelisted values of 20 bytes or more,
// or runs of four or more zero bytes.
func (w *whitelist) mask(raw []byte) []bool {
	m := make([]bool, len(raw))
	for i := 0; i < len(raw); {
		if raw[i] != 0 {
			i++
			continue
		}
		j := i
		for j < len(raw) && raw[j] == 0 {
			j++
		}
		if j-i >= 4 {
			for k := i; k < j; k++ {
				m[k] = true
			}
		}
		i = j
	}
	for v := range w.values {
		vb := []byte(v)
		for off := 0; ; {
			k := bytes.Index(raw[off:], vb)
			if k < 0 {
				break
			}
			for x := off + k; x < off+k+len(vb); x++ {
				m[x] = true
			}
			off += k + 1
		}
	}
	return m
}

// link is a value two hops share outside the whitelist.
type link struct {
	how          string
	from, to     string // hop names
	fromF, toF   string // field names
	sharedPrefix string
}

func (l link) String() string {
	return fmt.Sprintf("%s: %s %s and %s %s share %s", l.how, l.from, l.fromF, l.to, l.toF, l.sharedPrefix)
}

// windows are the linkRun-byte runs of a hop's raw data outside the mask,
// with where each starts.
type windows map[string]string

func rawWindows(h *hop, w *whitelist, size int, masked bool) windows {
	out := make(windows)
	for _, r := range h.raws {
		var m []bool
		if masked {
			m = w.mask(r.value)
		}
		run := 0
		for i := range r.value {
			free := !masked || !m[i]
			if masked && !free {
				run = 0
				continue
			}
			run++
			if run >= size {
				start := i - size + 1
				win := r.value[start : i+1]
				if !masked && hasZeroRun(win) {
					continue
				}
				if _, ok := out[string(win)]; !ok {
					out[string(win)] = fmt.Sprintf("%s at %d", r.name, start)
				}
			}
		}
	}
	return out
}

func hasZeroRun(v []byte) bool { return bytes.Contains(v, []byte{0, 0, 0, 0}) }

// checkLinkage compares every pair of hops and returns the links.
func checkLinkage(t *testing.T, hops []*hop, w *whitelist) []link {
	t.Helper()
	tags, err := knownTags()
	if err != nil {
		t.Fatalf("reading the hash tags: %v", err)
	}
	if len(tags) < 10 {
		t.Fatalf("only %d hash tags found in the source", len(tags))
	}
	var links []link
	runs := make([]windows, len(hops))
	words := make([]windows, len(hops))
	for i, h := range hops {
		runs[i] = rawWindows(h, w, linkRun, true)
		words[i] = rawWindows(h, w, 32, false)
	}
	for i, a := range hops {
		for j, b := range hops {
			if i == j {
				continue
			}
			if i < j {
				// 1. Fields.
				for _, fa := range a.fields {
					for _, fb := range b.fields {
						if bytes.Equal(fa.value, fb.value) && w.admit(fa.value) == "" {
							links = append(links, link{"field", a.name, b.name, fa.name, fb.name, fmt.Sprintf("%x", fa.value[:min(8, len(fa.value))])})
						}
					}
				}
				// 2. Bytes.
				for win, at := range runs[i] {
					if bt, ok := runs[j][win]; ok {
						links = append(links, link{"bytes", a.name, b.name, at, bt, fmt.Sprintf("%x", win[:8])})
					}
				}
			}
			// 3. One tagged hash, from a to b.
			for _, fa := range a.fields {
				if len(fa.value) < 20 || w.admit(fa.value) != "" {
					continue
				}
				for _, tag := range tags {
					d := ghosttree.K(tag, fa.value)
					for _, fb := range b.fields {
						if bytes.Equal(fb.value, d[:]) {
							links = append(links, link{"tagged hash " + tag, a.name, b.name, fa.name, fb.name, fmt.Sprintf("%x", d[:8])})
						}
					}
					if at, ok := words[j][string(d[:])]; ok {
						links = append(links, link{"tagged hash " + tag, a.name, b.name, fa.name, at, fmt.Sprintf("%x", d[:8])})
					}
				}
			}
		}
	}
	sort.Slice(links, func(x, y int) bool { return links[x].String() < links[y].String() })
	return links
}

func allZero(v []byte) bool {
	for _, b := range v {
		if b != 0 {
			return false
		}
	}
	return true
}

// tagPattern is the shape of a hash tag.
var tagPattern = regexp.MustCompile(`^ghost/[a-z0-9/-]+$`)

// knownTags returns every hash tag written as a string in the Go files of
// core/ghosttree and core/ghostpriv and the packages below it, tests
// included, so a tag added there is covered without a change here.
func knownTags() ([]string, error) {
	set := make(map[string]bool)
	for _, dir := range []string{filepath.Join("..", "..", "ghosttree"), ".."} {
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
				return err
			}
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			ast.Inspect(file, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				if s, err := strconv.Unquote(lit.Value); err == nil && tagPattern.MatchString(s) {
					set[s] = true
				}
				return true
			})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	tags := make([]string, 0, len(set))
	for tag := range set {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	return tags, nil
}
