// Copyright 2026 The go-ethereum Authors
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

package snap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/holiman/uint256"
)

// slimEOABody returns the genuine slim-format encoding of an externally owned
// account (empty storage root, empty code hash), as served in AccountRange
// responses.
func slimEOABody(nonce uint64, balance *uint256.Int) rlp.RawValue {
	return types.SlimAccountRLP(types.StateAccount{
		Nonce:    nonce,
		Balance:  balance,
		Root:     types.EmptyRootHash,
		CodeHash: types.EmptyCodeHash[:],
	})
}

// accountHashAt returns a synthetic account hash that sorts in ascending order
// with the index, matching the monotonicity requirement on honest responses.
func accountHashAt(i int) common.Hash {
	var h common.Hash
	binary.BigEndian.PutUint64(h[:8], uint64(i)+1)
	h[31] = 0x7f // make it look less degenerate than a bare counter
	return h
}

// realisticAccounts generates n consecutive accounts carrying real slim EOA
// encodings of varying sizes (5 to ~15 bytes), in ascending hash order.
func realisticAccounts(n int) []*AccountData {
	accounts := make([]*AccountData, n)
	for i := 0; i < n; i++ {
		balance := new(uint256.Int).Mul(uint256.NewInt(uint64(i%5)), uint256.NewInt(1e18))
		accounts[i] = &AccountData{
			Hash: accountHashAt(i),
			Body: slimEOABody(uint64(i%7), balance),
		}
	}
	return accounts
}

// densestHonestResponse replays ServiceGetAccountRangeQuery's accounting
// (size += common.HashLength + len(body); append; stop once size > budget)
// against a maxRequestSize budget using the smallest real EOA body (a used,
// zero-balance account encodes to 5 bytes in slim format). This is the
// maximum item count an honest byte-filled response can carry.
func densestHonestResponse() []*AccountData {
	var (
		accounts []*AccountData
		size     uint64
	)
	for i := 0; ; i++ {
		body := slimEOABody(1, uint256.NewInt(0))
		size += uint64(common.HashLength + len(body))
		accounts = append(accounts, &AccountData{Hash: accountHashAt(i), Body: body})
		if size > maxRequestSize {
			break
		}
	}
	return accounts
}

// TestAccountRangeResponseItemLimit pins the AccountRangeMsg entry of
// snapResponseLimits from both sides: honest responses filled to the byte
// budget must pass, and only counts that could never fit the request
// tracker's byte bound (2*maxRequestSize) may be rejected.
func TestAccountRangeResponseItemLimit(t *testing.T) {
	limit := snapResponseLimits[AccountRangeMsg]

	check := func(t *testing.T, accounts []*AccountData) error {
		t.Helper()
		blob, err := rlp.EncodeToBytes(&AccountRangePacket{ID: 1, Accounts: accounts})
		if err != nil {
			t.Fatalf("failed to encode response: %v", err)
		}
		msg := p2p.Msg{Code: AccountRangeMsg, Size: uint32(len(blob)), Payload: bytes.NewReader(blob)}
		return checkSnapResponseItems(&msg, limit)
	}

	t.Run("honest-maximum-accepted", func(t *testing.T) {
		// A response filled to the requested byte budget with the densest
		// real accounts must never tear down the peer.
		accounts := densestHonestResponse()
		if err := check(t, accounts); err != nil {
			t.Fatalf("honest byte-filled response (%d items) rejected: %v", len(accounts), err)
		}
	})
	t.Run("regression-over-old-cap", func(t *testing.T) {
		// The previous cap of 10240 (maxCodeLookups*10) rejected honest
		// byte-filled responses: EOA items cost 37-50 accounting bytes, so a
		// 512KiB budget legitimately holds well over 10240 of them. Pin that
		// the honest maximum indeed exceeds the old cap and is now accepted.
		const oldLimit = 10240
		accounts := densestHonestResponse()
		if len(accounts) <= oldLimit {
			t.Fatalf("test lost its meaning: honest maximum %d no longer exceeds the old cap %d", len(accounts), oldLimit)
		}
		if err := check(t, accounts[:oldLimit+1]); err != nil {
			t.Fatalf("response one item over the old cap rejected: %v", err)
		}
	})
	t.Run("at-limit-accepted", func(t *testing.T) {
		if err := check(t, realisticAccounts(limit)); err != nil {
			t.Fatalf("response at the item limit (%d) rejected: %v", limit, err)
		}
	})
	t.Run("over-limit-rejected", func(t *testing.T) {
		if err := check(t, realisticAccounts(limit+1)); err == nil {
			t.Fatalf("response one item over the limit (%d) accepted", limit+1)
		}
	})
}

var errSyntheticIterator = errors.New("synthetic iterator failure")

// failingAccountIterator yields a few accounts from the real iterator and then
// stops with an error, like an iterator whose layer went stale mid-range.
type failingAccountIterator struct {
	accountIter
	left int
}

func (it *failingAccountIterator) Next() bool {
	if it.left == 0 {
		return false
	}
	it.left--
	return it.accountIter.Next()
}

func (it *failingAccountIterator) Error() error {
	if it.left == 0 {
		return errSyntheticIterator
	}
	return it.accountIter.Error()
}

// failingStorageIterator is failingAccountIterator for storage slots.
type failingStorageIterator struct {
	storageIter
	left int
}

func (it *failingStorageIterator) Next() bool {
	if it.left == 0 {
		return false
	}
	it.left--
	return it.storageIter.Next()
}

func (it *failingStorageIterator) Error() error {
	if it.left == 0 {
		return errSyntheticIterator
	}
	return it.storageIter.Error()
}

// recordingRW feeds one request message to the handler and records the
// messages it sends back.
type recordingRW struct {
	code     uint64
	data     []byte
	codes    []uint64
	payloads [][]byte
}

func (rw *recordingRW) ReadMsg() (p2p.Msg, error) {
	return p2p.Msg{
		Code:       rw.code,
		Size:       uint32(len(rw.data)),
		Payload:    bytes.NewReader(rw.data),
		ReceivedAt: time.Now(),
	}, nil
}

func (rw *recordingRW) WriteMsg(msg p2p.Msg) error {
	payload, err := io.ReadAll(msg.Payload)
	if err != nil {
		return err
	}
	rw.codes = append(rw.codes, msg.Code)
	rw.payloads = append(rw.payloads, payload)
	return nil
}

// serveSnapRequest runs one request through HandleMessage and returns the code
// and payload of the single reply, and how long serving took.
func serveSnapRequest(t *testing.T, backend *dummyBackend, code uint64, req interface{}) (uint64, []byte, time.Duration) {
	t.Helper()
	data, err := rlp.EncodeToBytes(req)
	if err != nil {
		t.Fatalf("failed to encode request: %v", err)
	}
	rw := &recordingRW{code: code, data: data}
	start := time.Now()
	if err := HandleMessage(backend, NewFakePeer(1, "synthetic-peer", rw)); err != nil {
		t.Fatalf("request %#x failed: %v", code, err)
	}
	elapsed := time.Since(start)
	if len(rw.codes) != 1 {
		t.Fatalf("request %#x got %d replies, want 1", code, len(rw.codes))
	}
	return rw.codes[0], rw.payloads[0], elapsed
}

// storageAccounts returns the hashes of the accounts with storage at root.
func storageAccounts(t *testing.T, backend *dummyBackend, root common.Hash) []common.Hash {
	t.Helper()
	it, err := backend.chain.Snapshots().AccountIterator(root, common.Hash{})
	if err != nil {
		t.Fatalf("failed to open account iterator: %v", err)
	}
	defer it.Release()
	var hashes []common.Hash
	for it.Next() {
		acc, err := types.FullAccount(it.Account())
		if err != nil {
			t.Fatalf("failed to decode account: %v", err)
		}
		if acc.Root != types.EmptyRootHash {
			hashes = append(hashes, it.Hash())
		}
	}
	return hashes
}

// TestSnapServingBoundedAndReadyChecked checks the bounds on snap serving: the
// time limit applies to account, storage and bytecode queries, an iterator that
// fails mid-range does not produce a silent partial reply, and while the
// snapshot is not ready every snap handler answers empty at once.
func TestSnapServingBoundedAndReadyChecked(t *testing.T) {
	chain := getChain()
	defer chain.Stop()
	root := trieRoot
	backend := &dummyBackend{chain}

	contracts := storageAccounts(t, backend, root)
	if len(contracts) == 0 {
		t.Fatal("test chain has no account with storage")
	}
	var (
		expired    = func() time.Time { return time.Now().Add(-2 * maxSnapServingTime) }
		codeHashes = []common.Hash{types.EmptyCodeHash, types.EmptyCodeHash, types.EmptyCodeHash}
		accountReq = func() *GetAccountRangePacket {
			return &GetAccountRangePacket{ID: 1, Root: root, Limit: common.MaxHash, Bytes: softResponseLimit}
		}
		storageReq = func() *GetStorageRangesPacket {
			return &GetStorageRangesPacket{ID: 2, Root: root, Accounts: contracts[:1], Bytes: softResponseLimit}
		}
		codesReq = func() *GetByteCodesPacket {
			return &GetByteCodesPacket{ID: 3, Hashes: codeHashes, Bytes: softResponseLimit}
		}
	)

	t.Run("time-bounded", func(t *testing.T) {
		if accounts, _ := ServiceGetAccountRangeQuery(chain, accountReq(), time.Now()); len(accounts) < 2 {
			t.Fatalf("account range within the time limit served %d accounts, want the whole range", len(accounts))
		}
		if accounts, _ := ServiceGetAccountRangeQuery(chain, accountReq(), expired()); len(accounts) != 1 {
			t.Errorf("account range past the time limit served %d accounts, want 1", len(accounts))
		}
		if slots, _ := ServiceGetStorageRangesQuery(chain, storageReq(), time.Now()); len(slots) != 1 || len(slots[0]) == 0 {
			t.Fatalf("storage range within the time limit served %d ranges, want 1", len(slots))
		}
		if slots, _ := ServiceGetStorageRangesQuery(chain, storageReq(), expired()); len(slots) != 0 {
			t.Errorf("storage range past the time limit served %d ranges, want none", len(slots))
		}
		if codes := ServiceGetByteCodesQuery(chain, codesReq(), time.Now()); len(codes) != len(codeHashes) {
			t.Fatalf("bytecodes within the time limit served %d codes, want %d", len(codes), len(codeHashes))
		}
		if codes := ServiceGetByteCodesQuery(chain, codesReq(), expired()); len(codes) != 1 {
			t.Errorf("bytecodes past the time limit served %d codes, want 1", len(codes))
		}
	})

	t.Run("iterator-errors", func(t *testing.T) {
		origAccount, origStorage := wrapAccountIterator, wrapStorageIterator
		defer func() { wrapAccountIterator, wrapStorageIterator = origAccount, origStorage }()

		wrapAccountIterator = func(it accountIter, err error) (accountIter, error) {
			if err != nil {
				return nil, err
			}
			return &failingAccountIterator{accountIter: it, left: 3}, nil
		}
		wrapStorageIterator = func(it storageIter, err error) (storageIter, error) {
			if err != nil {
				return nil, err
			}
			return &failingStorageIterator{storageIter: it, left: 3}, nil
		}
		if accounts, proofs := ServiceGetAccountRangeQuery(chain, accountReq(), time.Now()); len(accounts) != 0 || len(proofs) != 0 {
			t.Errorf("failing account iterator produced a reply with %d accounts and %d proofs, want an empty reply", len(accounts), len(proofs))
		}
		if slots, proofs := ServiceGetStorageRangesQuery(chain, storageReq(), time.Now()); len(slots) != 0 || len(proofs) != 0 {
			t.Errorf("failing storage iterator produced a reply with %d ranges and %d proofs, want an empty reply", len(slots), len(proofs))
		}
	})

	t.Run("not-ready", func(t *testing.T) {
		chain.Snapshots().Disable()
		if isSnapServingReady(chain) {
			t.Fatal("snapshot reported ready after it was disabled")
		}
		origAccount, origStorage := wrapAccountIterator, wrapStorageIterator
		defer func() { wrapAccountIterator, wrapStorageIterator = origAccount, origStorage }()

		wrapAccountIterator = func(it accountIter, err error) (accountIter, error) {
			t.Error("account iterator opened while the snapshot is not ready")
			return it, err
		}
		wrapStorageIterator = func(it storageIter, err error) (storageIter, error) {
			t.Error("storage iterator opened while the snapshot is not ready")
			return it, err
		}
		checkReply := func(name string, code, wantCode uint64, elapsed time.Duration) {
			t.Helper()
			if code != wantCode {
				t.Errorf("%s: reply code %#x, want %#x", name, code, wantCode)
			}
			if elapsed >= maxSnapServingTime {
				t.Errorf("%s: reply took %v, want an immediate answer", name, elapsed)
			}
		}

		code, payload, elapsed := serveSnapRequest(t, backend, GetAccountRangeMsg, accountReq())
		checkReply("account range", code, AccountRangeMsg, elapsed)
		var accounts AccountRangePacket
		if err := rlp.DecodeBytes(payload, &accounts); err != nil {
			t.Fatalf("account range: bad reply: %v", err)
		}
		if accounts.ID != 1 || len(accounts.Accounts) != 0 || len(accounts.Proof) != 0 {
			t.Errorf("account range: reply id %d with %d accounts and %d proofs, want id 1 and empty", accounts.ID, len(accounts.Accounts), len(accounts.Proof))
		}

		code, payload, elapsed = serveSnapRequest(t, backend, GetStorageRangesMsg, storageReq())
		checkReply("storage ranges", code, StorageRangesMsg, elapsed)
		var storage StorageRangesPacket
		if err := rlp.DecodeBytes(payload, &storage); err != nil {
			t.Fatalf("storage ranges: bad reply: %v", err)
		}
		if storage.ID != 2 || len(storage.Slots) != 0 || len(storage.Proof) != 0 {
			t.Errorf("storage ranges: reply id %d with %d ranges and %d proofs, want id 2 and empty", storage.ID, len(storage.Slots), len(storage.Proof))
		}

		code, payload, elapsed = serveSnapRequest(t, backend, GetByteCodesMsg, codesReq())
		checkReply("bytecodes", code, ByteCodesMsg, elapsed)
		var codes ByteCodesPacket
		if err := rlp.DecodeBytes(payload, &codes); err != nil {
			t.Fatalf("bytecodes: bad reply: %v", err)
		}
		if codes.ID != 3 || len(codes.Codes) != 0 {
			t.Errorf("bytecodes: reply id %d with %d codes, want id 3 and empty", codes.ID, len(codes.Codes))
		}

		// The root node of the account trie (compact encoding of the empty path).
		paths, err := rlp.EncodeToRawList([]TrieNodePathSet{{{0x00}}})
		if err != nil {
			t.Fatalf("failed to encode trie node paths: %v", err)
		}
		code, payload, elapsed = serveSnapRequest(t, backend, GetTrieNodesMsg, &GetTrieNodesPacket{ID: 4, Root: root, Paths: paths, Bytes: softResponseLimit})
		checkReply("trie nodes", code, TrieNodesMsg, elapsed)
		var nodes TrieNodesPacket
		if err := rlp.DecodeBytes(payload, &nodes); err != nil {
			t.Fatalf("trie nodes: bad reply: %v", err)
		}
		if nodes.ID != 4 || len(nodes.Nodes) != 0 {
			t.Errorf("trie nodes: reply id %d with %d nodes, want id 4 and empty", nodes.ID, len(nodes.Nodes))
		}
	})
}

// missingTrieNodePath returns the compact encoding of a short path that holds
// no node in tr. Looking it up resolves nothing from the database once the
// nodes above it are in memory.
func missingTrieNodePath(t *testing.T, tr *trie.StateTrie) []byte {
	t.Helper()
	var candidates [][]byte
	for n := byte(0); n < 16; n++ {
		candidates = append(candidates, []byte{0x10 | n}) // one nibble
	}
	for b := 0; b < 256; b++ {
		candidates = append(candidates, []byte{0x00, byte(b)}) // two nibbles
	}
	for n := byte(0); n < 16; n++ {
		for b := 0; b < 256; b++ {
			candidates = append(candidates, []byte{0x10 | n, byte(b)}) // three nibbles
		}
	}
	for _, path := range candidates {
		if blob, _, err := tr.GetNode(path); err == nil && blob == nil {
			return path
		}
	}
	t.Fatal("no missing trie node path found")
	return nil
}

// TestSnapServeTrieNodeLoadCharge checks that every requested trie node counts
// against maxTrieNodeLookups, even when the lookup reads nothing from the
// database. Asking for a missing node over and over adds neither loads nor
// bytes to the reply, so without a minimum charge it is never cut off.
func TestSnapServeTrieNodeLoadCharge(t *testing.T) {
	chain := getChain()
	defer chain.Stop()
	root := trieRoot
	backend := &dummyBackend{chain}

	contracts := storageAccounts(t, backend, root)
	if len(contracts) == 0 {
		t.Fatal("test chain has no account with storage")
	}
	accTrie, err := trie.NewStateTrie(trie.StateTrieID(root), chain.TrieDB())
	if err != nil {
		t.Fatalf("failed to open account trie: %v", err)
	}
	account, err := accTrie.GetAccountByHash(contracts[0])
	if err != nil || account == nil {
		t.Fatalf("failed to read account %x: %v", contracts[0], err)
	}
	stTrie, err := trie.NewStateTrie(trie.StorageTrieID(root, contracts[0], account.Root), chain.TrieDB())
	if err != nil {
		t.Fatalf("failed to open storage trie: %v", err)
	}
	const requested = 4 * maxTrieNodeLookups

	t.Run("account", func(t *testing.T) {
		missing := missingTrieNodePath(t, accTrie)
		sets := make([]TrieNodePathSet, requested)
		for i := range sets {
			sets[i] = TrieNodePathSet{missing}
		}
		paths, err := rlp.EncodeToRawList(sets)
		if err != nil {
			t.Fatalf("failed to encode trie node paths: %v", err)
		}
		nodes, err := ServiceGetTrieNodesQuery(chain, &GetTrieNodesPacket{ID: 1, Root: root, Paths: paths, Bytes: softResponseLimit}, time.Now())
		if err != nil {
			t.Fatalf("trie nodes query failed: %v", err)
		}
		if len(nodes) == 0 {
			t.Fatal("trie nodes query served no nodes")
		}
		if len(nodes) > maxTrieNodeLookups+1 {
			t.Errorf("served %d missing account trie nodes, want at most %d", len(nodes), maxTrieNodeLookups+1)
		}
	})

	t.Run("storage", func(t *testing.T) {
		missing := missingTrieNodePath(t, stTrie)
		set := TrieNodePathSet{contracts[0][:]}
		for i := 0; i < requested; i++ {
			set = append(set, missing)
		}
		paths, err := rlp.EncodeToRawList([]TrieNodePathSet{set})
		if err != nil {
			t.Fatalf("failed to encode trie node paths: %v", err)
		}
		nodes, err := ServiceGetTrieNodesQuery(chain, &GetTrieNodesPacket{ID: 2, Root: root, Paths: paths, Bytes: softResponseLimit}, time.Now())
		if err != nil {
			t.Fatalf("trie nodes query failed: %v", err)
		}
		if len(nodes) == 0 {
			t.Fatal("trie nodes query served no nodes")
		}
		if len(nodes) > maxTrieNodeLookups+1 {
			t.Errorf("served %d missing storage trie nodes, want at most %d", len(nodes), maxTrieNodeLookups+1)
		}
	})
}
