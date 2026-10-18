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

package linkage

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

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params/ghost"
)

// minRun is the shortest run of shared bytes that is a link.
const minRun = 16

// zeroPaddingRun is the shortest run of zero bytes taken as padding. A
// shorter run of zeros is data: it is never masked.
const zeroPaddingRun = 4

// largeInt is the number of significant bytes above which integers of
// different widths are also compared by value; below it, small counters and
// flags of different layouts would match by chance.
const largeInt = 4

// The reasons of the whitelist. Every value two hops may share has one of
// them; anything else shared is a link.
const (
	reasonTreeRoot = "a coin tree root that a block header also carries: the shared tree state every reveal proves against"
	reasonChainID  = "the chain id, the same in every transaction of the chain"
	reasonVersion  = "version 1 of the commit data and the reveal payload, the same in every private transaction"
	reasonTxType   = "the private transaction type byte 0x50, the same in every reveal"
	reasonEntry    = "the commit entry address, where every commit is sent"
	reasonTopic    = "a receipt topic constant, the same in every commit receipt or every reveal receipt"
	reasonZero     = "zero padding: an all-zero value is the same in every transaction and tells nothing"
)

// whitelist is the exact list of values hops may share.
type whitelist struct {
	chainID uint64
	roots   map[common.Hash]bool // coin tree roots of the chain's headers
}

func newWhitelist(f *fixture) *whitelist {
	return &whitelist{chainID: f.chainID, roots: f.roots}
}

// constant returns the reason a value of 20 or 32 bytes is public wherever
// it appears, "" if it is not.
func (w *whitelist) constant(v []byte) string {
	switch len(v) {
	case common.AddressLength:
		if common.BytesToAddress(v) == ghost.CommitEntryAddress {
			return reasonEntry
		}
	case common.HashLength:
		h := common.BytesToHash(v)
		if h == commitTopic || h == revealTopic {
			return reasonTopic
		}
		if w.roots[h] {
			return reasonTreeRoot
		}
	}
	return ""
}

// roleValue returns the reason a value in a field of role r is a protocol
// constant, "" if it is not. v is big-endian at any width.
func (w *whitelist) roleValue(r role, v []byte) string {
	switch r {
	case roleTxType:
		if len(v) == 1 && v[0] == types.GhostRevealTxType {
			return reasonTxType
		}
	case roleChainID:
		if n, ok := smallInt(v); ok && n == w.chainID {
			return reasonChainID
		}
	case roleVersion:
		if n, ok := smallInt(v); ok && n == uint64(ghostpriv.Version) {
			return reasonVersion
		}
	}
	return ""
}

// public returns the reason a field's value is public on its own, "" if it
// is not.
func (w *whitelist) public(f field) string {
	if allZero(f.value) {
		return reasonZero
	}
	if r := w.roleValue(f.role, f.value); r != "" {
		return r
	}
	return w.constant(f.value)
}

// shared returns the reason two fields holding the same value are not a
// link, "" if they are. A short constant is admitted only where both
// layouts put it.
func (w *whitelist) shared(a, b field) string {
	if allZero(a.value) && allZero(b.value) {
		return reasonZero
	}
	if a.role == b.role {
		if r := w.roleValue(a.role, a.value); r != "" {
			return r
		}
	}
	if bytes.Equal(a.value, b.value) {
		return w.constant(a.value)
	}
	return ""
}

// mask marks the bytes of a segment the byte-level comparison skips: zero
// padding, the short constants at their places in the layout, and the long
// constants wherever they appear.
func (w *whitelist) mask(seg segment) (all, zeros []bool) {
	n := len(seg.raw)
	all, zeros = make([]bool, n), make([]bool, n)
	for i := 0; i < n; {
		if seg.raw[i] != 0 {
			i++
			continue
		}
		j := i
		for j < n && seg.raw[j] == 0 {
			j++
		}
		if j-i >= zeroPaddingRun {
			for k := i; k < j; k++ {
				all[k], zeros[k] = true, true
			}
		}
		i = j
	}
	for _, sp := range seg.spans {
		if sp.role != roleNone && w.roleValue(sp.role, seg.raw[sp.off:sp.end]) != "" {
			for k := sp.off; k < sp.end; k++ {
				all[k] = true
			}
		}
	}
	var consts [][]byte
	consts = append(consts, ghost.CommitEntryAddress.Bytes(), commitTopic.Bytes(), revealTopic.Bytes())
	for root := range w.roots {
		consts = append(consts, root.Bytes())
	}
	for _, c := range consts {
		for from := 0; ; {
			i := bytes.Index(seg.raw[from:], c)
			if i < 0 {
				break
			}
			for k := from + i; k < from+i+len(c); k++ {
				all[k] = true
			}
			from += i + 1
		}
	}
	return all, zeros
}

// link is a value that ties two hops.
type link struct {
	hopA, fieldA string
	hopB, fieldB string
	how          string
}

func (l link) String() string {
	return fmt.Sprintf("%s %s and %s %s: %s", l.hopA, l.fieldA, l.hopB, l.fieldB, l.how)
}

// allowed is a shared value the whitelist admitted, with its reason.
type allowed struct {
	link
	reason string
}

// loc is a window of a hop's raw bytes.
type loc struct {
	seg, off int
}

// index is a hop decoded, with its masks and its windows of minRun bytes.
type index struct {
	h     *hop
	all   [][]bool // per segment, the whitelisted bytes
	byRun map[[minRun]byte][]loc
}

// newIndex indexes every window of a hop that holds no zero padding. Which
// of them touch other whitelisted bytes is decided per match, so that the
// tagged-hash search still sees them.
func newIndex(h *hop, w *whitelist) *index {
	ix := &index{h: h, byRun: make(map[[minRun]byte][]loc)}
	for s, seg := range h.segments {
		all, zeros := w.mask(seg)
		ix.all = append(ix.all, all)
		for off, bad := 0, 0; off+minRun <= len(seg.raw); off++ {
			if off == 0 {
				for k := 0; k < minRun; k++ {
					if zeros[k] {
						bad++
					}
				}
			} else {
				if zeros[off-1] {
					bad--
				}
				if zeros[off+minRun-1] {
					bad++
				}
			}
			if bad == 0 {
				var key [minRun]byte
				copy(key[:], seg.raw[off:])
				ix.byRun[key] = append(ix.byRun[key], loc{seg: s, off: off})
			}
		}
	}
	return ix
}

func (ix *index) clean(l loc, n int) bool {
	for _, m := range ix.all[l.seg][l.off : l.off+n] {
		if m {
			return false
		}
	}
	return true
}

func (ix *index) name(l loc) string { return ix.h.segments[l.seg].at(l.off) }

// find returns the places where the 32 bytes of v appear in the hop.
func (ix *index) find(v common.Hash) []loc {
	seen := make(map[loc]bool)
	var out []loc
	for half := 0; half < 2; half++ {
		var key [minRun]byte
		copy(key[:], v[half*minRun:])
		for _, l := range ix.byRun[key] {
			start := loc{seg: l.seg, off: l.off - half*minRun}
			raw := ix.h.segments[l.seg].raw
			if start.off < 0 || start.off+32 > len(raw) || seen[start] || !bytes.Equal(raw[start.off:start.off+32], v[:]) {
				continue
			}
			seen[start] = true
			out = append(out, start)
		}
	}
	return out
}

// derivation is K(tag, input) for an input taken from a field.
type derivation struct {
	field field
	tag   string
	form  string
	value common.Hash
}

// inputForm is one way of writing a field as the input of a hash.
type inputForm struct {
	name  string
	value []byte
}

// derivations hashes every field of a hop that is not public on its own
// under every known tag; an integer also in its minimal and 32-byte forms.
// The hash of a public value is public and ties nothing.
func derivations(h *hop, w *whitelist, tags []string) []derivation {
	var out []derivation
	for _, f := range h.fields {
		if w.public(f) != "" {
			continue
		}
		forms := []inputForm{{"as laid out", f.value}}
		if f.isInt {
			minimal := bytes.TrimLeft(f.value, "\x00")
			if len(minimal) != len(f.value) {
				forms = append(forms, inputForm{"minimal", minimal})
			}
			if len(f.value) != 32 {
				forms = append(forms, inputForm{"as a 32-byte word", common.LeftPadBytes(minimal, 32)})
			}
		}
		for _, form := range forms {
			for _, tag := range tags {
				out = append(out, derivation{field: f, tag: tag, form: form.name, value: ghosttree.K(tag, form.value)})
			}
		}
	}
	return out
}

// checkLinkage compares every pair of hops and returns the links, and the
// shared values the whitelist admitted.
func checkLinkage(hops []*hop, w *whitelist, tags []string) ([]link, []allowed) {
	idx := make([]*index, len(hops))
	ders := make([][]derivation, len(hops))
	for i, h := range hops {
		idx[i] = newIndex(h, w)
		ders[i] = derivations(h, w, tags)
	}
	var links []link
	var ok []allowed
	seen := make(map[string]bool)
	report := func(l link) {
		if key := l.String(); !seen[key] {
			seen[key] = true
			links = append(links, l)
		}
	}
	for i := range hops {
		for j := i + 1; j < len(hops); j++ {
			a, b := hops[i], hops[j]
			ok = append(ok, compareFields(a, b, w, report)...)
			compareRuns(idx[i], idx[j], report)
			compareDerivations(ders[i], a, idx[j], report)
			compareDerivations(ders[j], b, idx[i], report)
		}
	}
	return links, ok
}

// compareFields reports every field of a equal to a field of b at the same
// width, and every large integer equal in value across widths, unless the
// whitelist admits the value.
func compareFields(a, b *hop, w *whitelist, report func(link)) []allowed {
	var ok []allowed
	for _, fa := range a.fields {
		for _, fb := range b.fields {
			how := ""
			switch {
			case bytes.Equal(fa.value, fb.value):
				how = "equal values"
			case fa.isInt && fb.isInt:
				ma, mb := bytes.TrimLeft(fa.value, "\x00"), bytes.TrimLeft(fb.value, "\x00")
				if len(ma) > largeInt && bytes.Equal(ma, mb) {
					how = "equal integers"
				}
			}
			if how == "" {
				continue
			}
			l := link{hopA: a.name, fieldA: fa.name, hopB: b.name, fieldB: fb.name, how: how}
			if reason := w.shared(fa, fb); reason != "" {
				ok = append(ok, allowed{link: l, reason: reason})
				continue
			}
			report(l)
		}
	}
	return ok
}

// compareRuns reports every run of minRun or more bytes the raw data of the
// two hops share outside the whitelist.
func compareRuns(a, b *index, report func(link)) {
	for key, as := range a.byRun {
		bs, ok := b.byRun[key]
		if !ok {
			continue
		}
		for _, la := range as {
			if !a.clean(la, minRun) {
				continue
			}
			for _, lb := range bs {
				if !b.clean(lb, minRun) {
					continue
				}
				ra, rb := a.h.segments[la.seg].raw, b.h.segments[lb.seg].raw
				// A run longer than minRun is reported once, from its start:
				// the window one byte earlier was shared and clean too.
				if la.off > 0 && lb.off > 0 && ra[la.off-1] == rb[lb.off-1] && !a.all[la.seg][la.off-1] && !b.all[lb.seg][lb.off-1] {
					continue
				}
				n := minRun
				for la.off+n < len(ra) && lb.off+n < len(rb) && ra[la.off+n] == rb[lb.off+n] {
					n++
				}
				report(link{
					hopA: a.h.name, fieldA: a.name(la),
					hopB: b.h.name, fieldB: b.name(lb),
					how: fmt.Sprintf("share a run of at least %d bytes, %x", n, ra[la.off:la.off+n]),
				})
			}
		}
	}
}

// compareDerivations reports every K(tag, field of from) that equals a field
// or appears in the raw bytes of the other hop.
func compareDerivations(ders []derivation, from *hop, to *index, report func(link)) {
	for _, d := range ders {
		how := fmt.Sprintf("the second is K(%q, the first %s)", d.tag, d.form)
		for _, f := range to.h.fields {
			if len(f.value) == 32 && common.BytesToHash(f.value) == d.value {
				report(link{hopA: from.name, fieldA: d.field.name, hopB: to.h.name, fieldB: f.name, how: how})
			}
		}
		for _, l := range to.find(d.value) {
			report(link{hopA: from.name, fieldA: d.field.name, hopB: to.h.name, fieldB: to.name(l), how: how})
		}
	}
}

func allZero(v []byte) bool {
	for _, b := range v {
		if b != 0 {
			return false
		}
	}
	return true
}

// smallInt reads a big-endian integer of at most eight significant bytes.
func smallInt(v []byte) (uint64, bool) {
	t := bytes.TrimLeft(v, "\x00")
	if len(t) > 8 {
		return 0, false
	}
	var b [8]byte
	copy(b[8-len(t):], t)
	return binary.BigEndian.Uint64(b[:]), true
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
