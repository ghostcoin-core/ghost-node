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

package qsdisc

import (
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/netutil"
)

const (
	hashBits          = 256
	bucketMinDistance = hashBits - NumBuckets
)

// Node is a node whose record was fetched from its endpoint and verified.
type Node struct {
	ID     enode.ID
	Addr   netip.AddrPort
	Record *enode.QSRecord
}

type tableNode struct {
	Node
	checked time.Time        // last live check, or when added
	fails   int              // live checks unanswered in a row
	cookie  [CookieSize]byte // the node's cookie for our endpoint, or zero
}

type bucket struct {
	entries      []*tableNode // live nodes, most recently seen first
	replacements []*tableNode // candidates, most recently added last
	ips          netutil.DistinctNetSet
}

// table holds verified nodes by log distance from the local node. Only
// verified nodes go in: the caller adds a node after its record verified for
// the endpoint it answered from.
type table struct {
	self enode.ID

	mu      sync.Mutex
	buckets [NumBuckets]*bucket
	ips     netutil.DistinctNetSet
}

func newTable(self enode.ID) *table {
	t := &table{
		self: self,
		ips:  netutil.DistinctNetSet{Subnet: TableSubnet, Limit: TableIPLimit},
	}
	for i := range t.buckets {
		t.buckets[i] = &bucket{ips: netutil.DistinctNetSet{Subnet: BucketSubnet, Limit: BucketIPLimit}}
	}
	return t
}

func (t *table) bucket(id enode.ID) *bucket {
	d := enode.LogDist(t.self, id)
	if d <= bucketMinDistance {
		return t.buckets[0]
	}
	return t.buckets[d-bucketMinDistance-1]
}

// add puts a verified node in its bucket, or among the bucket's
// replacements when the bucket is full. A node already in the table is
// replaced by the new one, which may have a new endpoint. It reports
// whether the node is in the bucket's live entries.
func (t *table) add(n Node, now time.Time) bool {
	if n.ID == t.self {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	b := t.bucket(n.ID)
	if i := indexOf(b.entries, n.ID); i >= 0 {
		old := b.entries[i]
		if old.Addr.Addr() != n.Addr.Addr() {
			t.removeIP(b, old.Addr.Addr())
			if !t.addIP(b, n.Addr.Addr()) {
				b.entries = slices.Delete(b.entries, i, i+1)
				t.promote(b)
				return false
			}
		}
		tn := &tableNode{Node: n, checked: now}
		if old.Addr == n.Addr {
			tn.cookie = old.cookie
		}
		b.entries = slices.Delete(b.entries, i, i+1)
		b.entries = slices.Insert(b.entries, 0, tn)
		return true
	}
	if i := indexOf(b.replacements, n.ID); i >= 0 {
		t.removeIP(b, b.replacements[i].Addr.Addr())
		b.replacements = slices.Delete(b.replacements, i, i+1)
	}
	if !t.addIP(b, n.Addr.Addr()) {
		return false
	}
	tn := &tableNode{Node: n, checked: now}
	if len(b.entries) < BucketSize {
		b.entries = slices.Insert(b.entries, 0, tn)
		return true
	}
	if len(b.replacements) >= MaxReplacements {
		t.removeIP(b, b.replacements[0].Addr.Addr())
		b.replacements = slices.Delete(b.replacements, 0, 1)
	}
	b.replacements = append(b.replacements, tn)
	return false
}

// remove takes a dead node out of the table and puts the most recently
// added replacement in its place.
func (t *table) remove(id enode.ID) {
	t.mu.Lock()
	defer t.mu.Unlock()
	b := t.bucket(id)
	if i := indexOf(b.entries, id); i >= 0 {
		t.removeIP(b, b.entries[i].Addr.Addr())
		b.entries = slices.Delete(b.entries, i, i+1)
		t.promote(b)
		return
	}
	if i := indexOf(b.replacements, id); i >= 0 {
		t.removeIP(b, b.replacements[i].Addr.Addr())
		b.replacements = slices.Delete(b.replacements, i, i+1)
	}
}

func (t *table) promote(b *bucket) {
	if len(b.replacements) == 0 || len(b.entries) >= BucketSize {
		return
	}
	last := len(b.replacements) - 1
	r := b.replacements[last]
	b.replacements = b.replacements[:last]
	b.entries = append(b.entries, r)
}

// checked records a successful live check of a node.
func (t *table) checked(id enode.ID, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	b := t.bucket(id)
	if i := indexOf(b.entries, id); i >= 0 {
		n := b.entries[i]
		n.checked = now
		n.fails = 0
		b.entries = slices.Delete(b.entries, i, i+1)
		b.entries = slices.Insert(b.entries, 0, n)
	}
}

// checkFailed records a live check of a node that went unanswered. The
// node is removed, and replaced, once MaxRevalidateFails checks in a row
// went unanswered; until then it stays and is checked again after
// RevalidateInterval. It reports whether the node was removed.
func (t *table) checkFailed(id enode.ID, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	b := t.bucket(id)
	i := indexOf(b.entries, id)
	if i < 0 {
		return false
	}
	n := b.entries[i]
	n.fails++
	n.checked = now
	if n.fails < MaxRevalidateFails {
		return false
	}
	t.removeIP(b, n.Addr.Addr())
	b.entries = slices.Delete(b.entries, i, i+1)
	t.promote(b)
	return true
}

// toCheck returns the live node checked longest ago, if it was checked
// before the given time.
func (t *table) toCheck(before time.Time) (Node, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	var oldest *tableNode
	for _, b := range t.buckets {
		for _, n := range b.entries {
			if oldest == nil || n.checked.Before(oldest.checked) {
				oldest = n
			}
		}
	}
	if oldest == nil || !oldest.checked.Before(before) {
		return Node{}, false
	}
	return oldest.Node, true
}

// setCookie keeps the cookie a live node at addr gave our endpoint. Kept
// with the node, it outlives the endpoints a flood of new sources pushes out
// of the node's endpoint memory.
func (t *table) setCookie(id enode.ID, addr netip.AddrPort, cookie [CookieSize]byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	b := t.bucket(id)
	if i := indexOf(b.entries, id); i >= 0 && b.entries[i].Addr == addr {
		b.entries[i].cookie = cookie
	}
}

// cookie returns the cookie a live node at addr gave our endpoint.
func (t *table) cookie(id enode.ID, addr netip.AddrPort) ([CookieSize]byte, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	b := t.bucket(id)
	if i := indexOf(b.entries, id); i >= 0 && b.entries[i].Addr == addr {
		return b.entries[i].cookie, b.entries[i].cookie != [CookieSize]byte{}
	}
	return [CookieSize]byte{}, false
}

// get returns a live node of the table.
func (t *table) get(id enode.ID) (Node, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	b := t.bucket(id)
	if i := indexOf(b.entries, id); i >= 0 {
		return b.entries[i].Node, true
	}
	return Node{}, false
}

// closest returns at most n live nodes closest to target, closest first.
func (t *table) closest(target enode.ID, n int) []Node {
	t.mu.Lock()
	defer t.mu.Unlock()
	var all []Node
	for _, b := range t.buckets {
		for _, e := range b.entries {
			all = append(all, e.Node)
		}
	}
	sortByDistance(all, target)
	if len(all) > n {
		all = all[:n]
	}
	return all
}

// len returns the number of live nodes.
func (t *table) len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for _, b := range t.buckets {
		n += len(b.entries)
	}
	return n
}

func (t *table) addIP(b *bucket, ip netip.Addr) bool {
	if !ip.IsValid() || ip.IsUnspecified() {
		return false
	}
	if netutil.AddrIsLAN(ip) {
		return true
	}
	if !t.ips.AddAddr(ip) {
		return false
	}
	if !b.ips.AddAddr(ip) {
		t.ips.RemoveAddr(ip)
		return false
	}
	return true
}

func (t *table) removeIP(b *bucket, ip netip.Addr) {
	if netutil.AddrIsLAN(ip) {
		return
	}
	t.ips.RemoveAddr(ip)
	b.ips.RemoveAddr(ip)
}

func indexOf(list []*tableNode, id enode.ID) int {
	return slices.IndexFunc(list, func(n *tableNode) bool { return n.ID == id })
}

func sortByDistance(nodes []Node, target enode.ID) {
	slices.SortFunc(nodes, func(a, b Node) int { return enode.DistCmp(target, a.ID, b.ID) })
}
