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
	"fmt"

	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
)

// role marks the fields whose value the whitelist may admit by position: a
// short value is only a protocol constant where the layout puts one. The
// roles are a transaction type byte, a chain id, the version of the commit
// data or reveal payload, and the signature scheme of an account
// transaction.
type role int

const (
	roleNone role = iota
	roleTxType
	roleChainID
	roleVersion
	roleScheme
)

// field is a decoded field or sub-field of a hop, at the width of its
// layout. An integer field is big-endian.
type field struct {
	name  string
	value []byte
	role  role
	isInt bool
}

// span is where a field lies in a segment.
type span struct {
	off, end int
	name     string
	role     role
}

// segment is one run of raw bytes of a hop: the transaction, a log topic or
// a log's data.
type segment struct {
	name  string
	raw   []byte
	spans []span
}

// hop is everything one transaction put on the chain, decoded.
type hop struct {
	name     string
	fields   []field
	segments []segment
}

// at names the most specific field of the segment that holds offset off.
func (s *segment) at(off int) string {
	best := s.name
	width := len(s.raw) + 1
	for _, sp := range s.spans {
		if sp.off <= off && off < sp.end && sp.end-sp.off < width {
			best, width = sp.name, sp.end-sp.off
		}
	}
	return fmt.Sprintf("%s (byte %d)", best, off)
}

// put records a field that lies in seg at [off, off+width), from the
// segment's bytes.
func (h *hop) put(seg *segment, name string, off, width int, r role, isInt bool) {
	h.fields = append(h.fields, field{name: name, value: seg.raw[off : off+width], role: r, isInt: isInt})
	seg.spans = append(seg.spans, span{off: off, end: off + width, name: name, role: r})
}

// putNote records a note and its 32-byte words as sub-fields.
func (h *hop) putNote(seg *segment, name string, off int) {
	h.put(seg, name, off, ghostpriv.NoteSize, roleNone, false)
	for w := 0; w < ghostpriv.NoteSize; w += 32 {
		end := min(w+32, ghostpriv.NoteSize)
		h.put(seg, fmt.Sprintf("%s[%d:%d]", name, w, end), off+w, end-w, roleNone, false)
	}
}

// decodeHop decodes a hop's transaction and logs. A transaction that is
// neither a commit's account transaction nor a reveal is an error: what the
// check cannot read, it cannot clear.
func decodeHop(raw rawHop) (*hop, error) {
	h := &hop{name: raw.name}
	if len(raw.tx) == 0 {
		return nil, fmt.Errorf("%s: empty transaction", raw.name)
	}
	var err error
	switch raw.tx[0] {
	case types.GhostRevealTxType:
		err = h.decodeReveal(raw.tx)
	case types.GhostAccountTxType:
		err = h.decodeAccountTx(raw.tx)
	default:
		err = fmt.Errorf("transaction type %#x", raw.tx[0])
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", raw.name, err)
	}
	for i, l := range raw.logs {
		h.decodeLog(i, l)
	}
	return h, nil
}

// Offsets in the reveal envelope, the type byte and then the payload of
// docs/private-transactions.md. TestLinkageThreeHopsRealDesign checks them
// against ghostpriv.DecodeReveal.
const (
	revType      = 0
	revVersion   = 1
	revChainID   = 3
	revMarker    = 11
	revRoot      = 43
	revRemainder = 75
	revRecipient = 107
	revOut       = 127
	revFee       = 159
	revProof     = 191
	revNote      = revProof + ghostpriv.ProofSize
)

func (h *hop) decodeReveal(raw []byte) error {
	if len(raw) != ghostpriv.EnvelopeSize {
		return fmt.Errorf("reveal of %d bytes, want %d", len(raw), ghostpriv.EnvelopeSize)
	}
	seg := &segment{name: "transaction", raw: raw}
	h.put(seg, "transaction", 0, len(raw), roleNone, false)
	h.put(seg, "payload.type", revType, 1, roleTxType, true)
	h.put(seg, "payload.version", revVersion, 2, roleVersion, true)
	h.put(seg, "payload.chainId", revChainID, 8, roleChainID, true)
	h.put(seg, "payload.marker", revMarker, 32, roleNone, false)
	h.put(seg, "payload.root", revRoot, 32, roleNone, false)
	h.put(seg, "payload.remainder", revRemainder, 32, roleNone, false)
	h.put(seg, "payload.recipient", revRecipient, 20, roleNone, false)
	h.put(seg, "payload.out", revOut, 32, roleNone, true)
	h.put(seg, "payload.fee", revFee, 32, roleNone, true)
	h.put(seg, "payload.proof", revProof, ghostpriv.ProofSize, roleNone, false)
	h.put(seg, "payload.proof[0:32]", revProof, 32, roleNone, false)
	h.put(seg, "payload.proof[32:]", revProof+32, ghostpriv.ProofSize-32, roleNone, false)
	h.putNote(seg, "payload.note", revNote)
	h.segments = append(h.segments, *seg)
	return nil
}

// The elements of an account transaction's RLP list (type 0x52), with the
// width each takes as a field: integers are widened to the width of their
// type.
var accountTxLayout = []struct {
	name  string
	width int // 0 for a variable-length byte string
	isInt bool
	list  bool
	role  role
}{
	{name: "chainId", width: 32, isInt: true, role: roleChainID},
	{name: "nonce", width: 8, isInt: true},
	{name: "gasTipCap", width: 32, isInt: true},
	{name: "gasFeeCap", width: 32, isInt: true},
	{name: "gas", width: 8, isInt: true},
	{name: "to", width: 20},
	{name: "value", width: 32, isInt: true},
	{name: "data"},
	{name: "accessList", list: true},
	{name: "scheme", width: 2, role: roleScheme},
	{name: "publicKey"},
	{name: "signature"},
}

func (h *hop) decodeAccountTx(raw []byte) error {
	seg := &segment{name: "transaction", raw: raw}
	h.put(seg, "transaction", 0, len(raw), roleNone, false)
	h.put(seg, "transaction.type", 0, 1, roleTxType, true)
	content, rest, err := rlp.SplitList(raw[1:])
	if err != nil || len(rest) != 0 {
		return fmt.Errorf("transaction is not one RLP list: %v", err)
	}
	for _, el := range accountTxLayout {
		name := "transaction." + el.name
		kind, val, next, err := rlp.Split(content)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if (kind == rlp.List) != el.list {
			return fmt.Errorf("%s: RLP kind %v", name, kind)
		}
		end := len(raw) - len(next)
		start := end - len(val)
		content = next
		switch {
		case el.width == 0 || el.list:
			h.put(seg, name, start, len(val), el.role, false)
		case el.isInt:
			if len(val) > el.width {
				return fmt.Errorf("%s: %d bytes, the field holds %d", name, len(val), el.width)
			}
			// The field is the value widened to its type; in the segment it
			// is the minimal bytes.
			wide := make([]byte, el.width)
			copy(wide[el.width-len(val):], val)
			h.fields = append(h.fields, field{name: name, value: wide, role: el.role, isInt: true})
			seg.spans = append(seg.spans, span{off: start, end: end, name: name, role: el.role})
		default:
			if len(val) != el.width {
				return fmt.Errorf("%s: %d bytes, want %d", name, len(val), el.width)
			}
			h.put(seg, name, start, len(val), el.role, false)
		}
		if el.name == "data" && len(val) == ghostpriv.SaltedCommitDataSize {
			h.put(seg, "transaction.data.version", start, 2, roleVersion, true)
			h.put(seg, "transaction.data.F", start+2, 32, roleNone, false)
			h.put(seg, "transaction.data.salt", start+34, ghostpriv.SaltSize, roleNone, false)
			h.putNote(seg, "transaction.data.note", start+34+ghostpriv.SaltSize)
		}
	}
	if len(content) != 0 {
		return fmt.Errorf("%d bytes after the signature", len(content))
	}
	h.segments = append(h.segments, *seg)
	return nil
}

// The receipt logs of the coin tree.
var (
	commitTopic = ghosttree.K(ghostpriv.TagCommitReceipt)
	revealTopic = ghosttree.K(ghostpriv.TagRevealReceipt)
)

const (
	commitLogSize = 8 + 32 + 32 + ghostpriv.NoteSize + ghostpriv.SaltSize
	revealLogSize = 8 + 32 + ghostpriv.NoteSize + 20 + 32
)

// decodeLog records the topics and data of log i; the data of a commit or
// reveal receipt is split by its layout, any other data is one field.
func (h *hop) decodeLog(i int, l *types.Log) {
	prefix := fmt.Sprintf("log[%d]", i)
	for j, topic := range l.Topics {
		name := fmt.Sprintf("%s.topic[%d]", prefix, j)
		seg := &segment{name: name, raw: topic.Bytes()}
		h.put(seg, name, 0, 32, roleNone, false)
		h.segments = append(h.segments, *seg)
	}
	name := prefix + ".data"
	seg := &segment{name: name, raw: l.Data}
	h.put(seg, name, 0, len(l.Data), roleNone, false)
	if len(l.Topics) > 0 {
		switch {
		case l.Topics[0] == commitTopic && len(l.Data) == commitLogSize:
			h.put(seg, name+".tree", 0, 4, roleNone, true)
			h.put(seg, name+".position", 4, 4, roleNone, true)
			h.put(seg, name+".leaf", 8, 32, roleNone, false)
			h.put(seg, name+".amount", 40, 32, roleNone, true)
			h.putNote(seg, name+".note", 72)
		case l.Topics[0] == revealTopic && len(l.Data) == revealLogSize:
			h.put(seg, name+".tree", 0, 4, roleNone, true)
			h.put(seg, name+".position", 4, 4, roleNone, true)
			h.put(seg, name+".remainder", 8, 32, roleNone, false)
			h.putNote(seg, name+".note", 40)
			h.put(seg, name+".recipient", 40+ghostpriv.NoteSize, 20, roleNone, false)
			h.put(seg, name+".out", 60+ghostpriv.NoteSize, 32, roleNone, true)
		}
	}
	h.segments = append(h.segments, *seg)
}
