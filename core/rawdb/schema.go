// Copyright 2018 The go-ethereum Authors
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

// Package rawdb contains a collection of low level database accessors.
package rawdb

import (
	"bytes"
	"encoding/binary"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/metrics"
)

// The fields below define the low level database schema prefixing.
var (
	// databaseVersionKey tracks the current database version.
	databaseVersionKey = []byte("DatabaseVersion")

	// headHeaderKey tracks the latest known header's hash.
	headHeaderKey = []byte("LastHeader")

	// headBlockKey tracks the latest known full block's hash.
	headBlockKey = []byte("LastBlock")

	// headFastBlockKey tracks the latest known incomplete block's hash during fast sync.
	headFastBlockKey = []byte("LastFast")

	// headFinalizedBlockKey tracks the latest known finalized block hash.
	headFinalizedBlockKey = []byte("LastFinalized")

	// persistentStateIDKey tracks the id of latest stored state(for path-based only).
	persistentStateIDKey = []byte("LastStateID")

	// lastPivotKey tracks the last pivot block used by fast sync (to reenable on sethead).
	lastPivotKey = []byte("LastPivot")

	// fastTrieProgressKey tracks the number of trie entries imported during fast sync.
	fastTrieProgressKey = []byte("TrieSync")

	// snapshotDisabledKey flags that the snapshot should not be maintained due to initial sync.
	snapshotDisabledKey = []byte("SnapshotDisabled")

	// SnapshotRootKey tracks the hash of the last snapshot.
	SnapshotRootKey = []byte("SnapshotRoot")

	// snapshotJournalKey tracks the in-memory diff layers across restarts.
	snapshotJournalKey = []byte("SnapshotJournal")

	// snapshotGeneratorKey tracks the snapshot generation marker across restarts.
	snapshotGeneratorKey = []byte("SnapshotGenerator")

	// snapshotRecoveryKey tracks the snapshot recovery marker across restarts.
	snapshotRecoveryKey = []byte("SnapshotRecovery")

	// snapshotSyncStatusKey tracks the snapshot sync status across restarts.
	snapshotSyncStatusKey = []byte("SnapshotSyncStatus")

	// skeletonSyncStatusKey tracks the skeleton sync status across restarts.
	skeletonSyncStatusKey = []byte("SkeletonSyncStatus")

	// trieJournalKey tracks the in-memory trie node layers across restarts.
	trieJournalKey = []byte("TrieJournal")

	// txIndexTailKey tracks the oldest block whose transactions have been indexed.
	txIndexTailKey = []byte("TransactionIndexTail")

	// fastTxLookupLimitKey tracks the transaction lookup limit during fast sync.
	// This flag is deprecated, it's kept to avoid reporting errors when inspect
	// database.
	fastTxLookupLimitKey = []byte("FastTransactionLookupLimit")

	// badBlockKey tracks the list of bad blocks seen by local
	badBlockKey = []byte("InvalidBlock")

	// uncleanShutdownKey tracks the list of local crashes
	uncleanShutdownKey = []byte("unclean-shutdown") // config prefix for the db

	// transitionStatusKey tracks the eth2 transition status.
	transitionStatusKey = []byte("eth2-transition")

	// snapSyncStatusFlagKey flags that status of snap sync.
	snapSyncStatusFlagKey = []byte("SnapSyncStatus")

	// Data item prefixes (use single byte to avoid mixing data types, avoid `i`, used for indexes).
	headerPrefix       = []byte("h") // headerPrefix + num (uint64 big endian) + hash -> header
	headerTDSuffix     = []byte("t") // headerPrefix + num (uint64 big endian) + hash + headerTDSuffix -> td
	headerHashSuffix   = []byte("n") // headerPrefix + num (uint64 big endian) + headerHashSuffix -> hash
	headerNumberPrefix = []byte("H") // headerNumberPrefix + hash -> num (uint64 big endian)

	blockBodyPrefix     = []byte("b") // blockBodyPrefix + num (uint64 big endian) + hash -> block body
	blockReceiptsPrefix = []byte("r") // blockReceiptsPrefix + num (uint64 big endian) + hash -> block receipts

	txLookupPrefix        = []byte("l") // txLookupPrefix + hash -> transaction/receipt lookup metadata
	bloomBitsPrefix       = []byte("B") // bloomBitsPrefix + bit (uint16 big endian) + section (uint64 big endian) + hash -> bloom bits
	SnapshotAccountPrefix = []byte("a") // SnapshotAccountPrefix + account hash -> account trie value
	SnapshotStoragePrefix = []byte("o") // SnapshotStoragePrefix + account hash + storage hash -> storage trie value
	CodePrefix            = []byte("c") // CodePrefix + code hash -> account code
	skeletonHeaderPrefix  = []byte("S") // skeletonHeaderPrefix + num (uint64 big endian) -> header

	// Path-based storage scheme of merkle patricia trie.
	trieNodeAccountPrefix = []byte("A") // trieNodeAccountPrefix + hexPath -> trie node
	trieNodeStoragePrefix = []byte("O") // trieNodeStoragePrefix + accountHash + hexPath -> trie node
	stateIDPrefix         = []byte("L") // stateIDPrefix + state root -> state id

	PreimagePrefix = []byte("secure-key-")       // PreimagePrefix + hash -> preimage
	configPrefix   = []byte("ethereum-config-")  // config prefix for the db
	genesisPrefix  = []byte("ethereum-genesis-") // genesis state prefix for the db

	// BloomBitsIndexPrefix is the data table of a chain indexer to track its progress
	BloomBitsIndexPrefix = []byte("iB")

	ChtPrefix           = []byte("chtRootV2-") // ChtPrefix + chtNum (uint64 big endian) -> trie root hash
	ChtTablePrefix      = []byte("cht-")
	ChtIndexTablePrefix = []byte("chtIndexV2-")

	BloomTriePrefix      = []byte("bltRoot-") // BloomTriePrefix + bloomTrieNum (uint64 big endian) -> trie root hash
	BloomTrieTablePrefix = []byte("blt-")
	BloomTrieIndexPrefix = []byte("bltIndex-")

	CliqueSnapshotPrefix = []byte("clique-")

	// Commitment tree history: every leaf and note of the canonical chain,
	// the records each block added, and the roots of full pages. None of the
	// keys is 32 bytes long, so that state pruning never takes them for trie
	// nodes.
	ghostTreeLeafPrefix     = []byte("ghost-tree-leaf-")  // ghostTreeLeafPrefix + kind (1 byte) + tree index (uint64 big endian) + position (uint32 big endian) -> block number, leaf, note
	ghostTreeBlockPrefix    = []byte("ghost-tree-block-") // ghostTreeBlockPrefix + block hash -> block number, positions written by the block
	ghostTreePageRootPrefix = []byte("ghost-tree-page-")  // ghostTreePageRootPrefix + kind (1 byte) + tree index (uint64 big endian) + page (uint32 big endian) -> root of the full page
	ghostTreeTagPrefix      = []byte("ghost-tree-tag-")   // ghostTreeTagPrefix + level << 1 | kind (1 byte) + tree index (uint64 big endian) + tag (3 bytes) + position (uint32 big endian) -> empty
	ghostTreeTaggedKey      = []byte("ghost-tree-tagged") // 1 once the history keeps the tag index

	// The spent-marker index of the history: for each spent marker, the slot
	// of the record that spent it.
	ghostTreeMarkerPrefix = []byte("ghost-tree-marker-") // ghostTreeMarkerPrefix + kind (1 byte, a marker list) + marker (32 bytes) -> tree index (uint64 big endian) + position (uint32 big endian) of the record that spent it
	ghostTreeMarkedKey    = []byte("ghost-tree-marked")  // 1 once the history keeps the spent-marker index

	// Index of the tree roots carried by the headers of the canonical chain:
	// for each root, the height of the first canonical header carrying it,
	// and the block whose ancestry the index holds. Neither key is 32 bytes
	// long.
	ghostRootIndexPrefix  = []byte("ghost-root-")        // ghostRootIndexPrefix + kind (1 byte) + root -> height of the first canonical header carrying it (uint64 big endian)
	ghostRootIndexHeadKey = []byte("GhostRootIndexHead") // block number (uint64 big endian) + block hash of the head of the indexed chain

	BestUpdateKey         = []byte("update-")    // bigEndian64(syncPeriod) -> RLP(types.LightClientUpdate)  (nextCommittee only referenced by root hash)
	FixedCommitteeRootKey = []byte("fixedRoot-") // bigEndian64(syncPeriod) -> committee root hash
	SyncCommitteeKey      = []byte("committee-") // bigEndian64(syncPeriod) -> serialized committee

	preimageCounter    = metrics.NewRegisteredCounter("db/preimage/total", nil)
	preimageHitCounter = metrics.NewRegisteredCounter("db/preimage/hits", nil)
)

// LegacyTxLookupEntry is the legacy TxLookupEntry definition with some unnecessary
// fields.
type LegacyTxLookupEntry struct {
	BlockHash  common.Hash
	BlockIndex uint64
	Index      uint64
}

// encodeBlockNumber encodes a block number as big endian uint64
func encodeBlockNumber(number uint64) []byte {
	enc := make([]byte, 8)
	binary.BigEndian.PutUint64(enc, number)
	return enc
}

// headerKeyPrefix = headerPrefix + num (uint64 big endian)
func headerKeyPrefix(number uint64) []byte {
	return append(headerPrefix, encodeBlockNumber(number)...)
}

// headerKey = headerPrefix + num (uint64 big endian) + hash
func headerKey(number uint64, hash common.Hash) []byte {
	return append(append(headerPrefix, encodeBlockNumber(number)...), hash.Bytes()...)
}

// headerTDKey = headerPrefix + num (uint64 big endian) + hash + headerTDSuffix
func headerTDKey(number uint64, hash common.Hash) []byte {
	return append(headerKey(number, hash), headerTDSuffix...)
}

// headerHashKey = headerPrefix + num (uint64 big endian) + headerHashSuffix
func headerHashKey(number uint64) []byte {
	return append(append(headerPrefix, encodeBlockNumber(number)...), headerHashSuffix...)
}

// headerNumberKey = headerNumberPrefix + hash
func headerNumberKey(hash common.Hash) []byte {
	return append(headerNumberPrefix, hash.Bytes()...)
}

// blockBodyKey = blockBodyPrefix + num (uint64 big endian) + hash
func blockBodyKey(number uint64, hash common.Hash) []byte {
	return append(append(blockBodyPrefix, encodeBlockNumber(number)...), hash.Bytes()...)
}

// blockReceiptsKey = blockReceiptsPrefix + num (uint64 big endian) + hash
func blockReceiptsKey(number uint64, hash common.Hash) []byte {
	return append(append(blockReceiptsPrefix, encodeBlockNumber(number)...), hash.Bytes()...)
}

// txLookupKey = txLookupPrefix + hash
func txLookupKey(hash common.Hash) []byte {
	return append(txLookupPrefix, hash.Bytes()...)
}

// accountSnapshotKey = SnapshotAccountPrefix + hash
func accountSnapshotKey(hash common.Hash) []byte {
	return append(SnapshotAccountPrefix, hash.Bytes()...)
}

// storageSnapshotKey = SnapshotStoragePrefix + account hash + storage hash
func storageSnapshotKey(accountHash, storageHash common.Hash) []byte {
	buf := make([]byte, len(SnapshotStoragePrefix)+common.HashLength+common.HashLength)
	n := copy(buf, SnapshotStoragePrefix)
	n += copy(buf[n:], accountHash.Bytes())
	copy(buf[n:], storageHash.Bytes())
	return buf
}

// storageSnapshotsKey = SnapshotStoragePrefix + account hash + storage hash
func storageSnapshotsKey(accountHash common.Hash) []byte {
	return append(SnapshotStoragePrefix, accountHash.Bytes()...)
}

// bloomBitsKey = bloomBitsPrefix + bit (uint16 big endian) + section (uint64 big endian) + hash
func bloomBitsKey(bit uint, section uint64, hash common.Hash) []byte {
	key := append(append(bloomBitsPrefix, make([]byte, 10)...), hash.Bytes()...)

	binary.BigEndian.PutUint16(key[1:], uint16(bit))
	binary.BigEndian.PutUint64(key[3:], section)

	return key
}

// skeletonHeaderKey = skeletonHeaderPrefix + num (uint64 big endian)
func skeletonHeaderKey(number uint64) []byte {
	return append(skeletonHeaderPrefix, encodeBlockNumber(number)...)
}

// ghostTreeKey = prefix + kind + tree index (uint64 big endian) + n (uint32 big endian)
func ghostTreeKey(prefix []byte, kind uint8, treeIndex uint64, n uint32) []byte {
	key := make([]byte, len(prefix)+1+8+4)
	copy(key, prefix)
	key[len(prefix)] = kind
	binary.BigEndian.PutUint64(key[len(prefix)+1:], treeIndex)
	binary.BigEndian.PutUint32(key[len(prefix)+9:], n)
	return key
}

// ghostTreeLeafKey = ghostTreeLeafPrefix + kind + tree index + position
func ghostTreeLeafKey(kind uint8, treeIndex uint64, position uint32) []byte {
	return ghostTreeKey(ghostTreeLeafPrefix, kind, treeIndex, position)
}

// ghostTreePageRootKey = ghostTreePageRootPrefix + kind + tree index + page
func ghostTreePageRootKey(kind uint8, treeIndex uint64, page uint32) []byte {
	return ghostTreeKey(ghostTreePageRootPrefix, kind, treeIndex, page)
}

// GhostTreeTagBytes is the length of a note's lookup tag, its first bytes.
const GhostTreeTagBytes = 3

// ghostTreeTagTreeKey = ghostTreeTagPrefix + level << 1 | kind + tree index.
// The kind is 0 or 1 (a tree, never a marker list) and the level at most 24,
// so the byte keeps the key 31 bytes long.
func ghostTreeTagTreeKey(kind, level uint8, treeIndex uint64) []byte {
	key := make([]byte, len(ghostTreeTagPrefix)+1+8)
	copy(key, ghostTreeTagPrefix)
	key[len(ghostTreeTagPrefix)] = level<<1 | kind&1
	binary.BigEndian.PutUint64(key[len(ghostTreeTagPrefix)+1:], treeIndex)
	return key
}

// ghostTreeTagKey = ghostTreeTagPrefix + level << 1 | kind + tree index + tag + position
func ghostTreeTagKey(kind, level uint8, treeIndex uint64, tag [GhostTreeTagBytes]byte, position uint32) []byte {
	key := ghostTreeTagTreeKey(kind, level, treeIndex)
	key = append(key, tag[:]...)
	return binary.BigEndian.AppendUint32(key, position)
}

// ghostTreeMarkerKey = ghostTreeMarkerPrefix + kind + marker. It is 51 bytes
// long.
func ghostTreeMarkerKey(kind uint8, marker common.Hash) []byte {
	key := make([]byte, len(ghostTreeMarkerPrefix)+1+common.HashLength)
	copy(key, ghostTreeMarkerPrefix)
	key[len(ghostTreeMarkerPrefix)] = kind
	copy(key[len(ghostTreeMarkerPrefix)+1:], marker[:])
	return key
}

// ghostTreeBlockKey = ghostTreeBlockPrefix + block hash
func ghostTreeBlockKey(hash common.Hash) []byte {
	return append(append([]byte{}, ghostTreeBlockPrefix...), hash.Bytes()...)
}

// ghostRootIndexKey = ghostRootIndexPrefix + kind + root
func ghostRootIndexKey(kind uint8, root common.Hash) []byte {
	key := make([]byte, len(ghostRootIndexPrefix)+1+common.HashLength)
	copy(key, ghostRootIndexPrefix)
	key[len(ghostRootIndexPrefix)] = kind
	copy(key[len(ghostRootIndexPrefix)+1:], root[:])
	return key
}

// preimageKey = PreimagePrefix + hash
func preimageKey(hash common.Hash) []byte {
	return append(PreimagePrefix, hash.Bytes()...)
}

// codeKey = CodePrefix + hash
func codeKey(hash common.Hash) []byte {
	return append(CodePrefix, hash.Bytes()...)
}

// IsCodeKey reports whether the given byte slice is the key of contract code,
// if so return the raw code hash as well.
func IsCodeKey(key []byte) (bool, []byte) {
	if bytes.HasPrefix(key, CodePrefix) && len(key) == common.HashLength+len(CodePrefix) {
		return true, key[len(CodePrefix):]
	}
	return false, nil
}

func ConfigKey(hash common.Hash) []byte {
	return configKey(hash)
}

// configKey = configPrefix + hash
func configKey(hash common.Hash) []byte {
	return append(configPrefix, hash.Bytes()...)
}

// genesisStateSpecKey = genesisPrefix + hash
func genesisStateSpecKey(hash common.Hash) []byte {
	return append(genesisPrefix, hash.Bytes()...)
}

// stateIDKey = stateIDPrefix + root (32 bytes)
func stateIDKey(root common.Hash) []byte {
	return append(stateIDPrefix, root.Bytes()...)
}

// accountTrieNodeKey = trieNodeAccountPrefix + nodePath.
func accountTrieNodeKey(path []byte) []byte {
	return append(trieNodeAccountPrefix, path...)
}

// storageTrieNodeKey = trieNodeStoragePrefix + accountHash + nodePath.
func storageTrieNodeKey(accountHash common.Hash, path []byte) []byte {
	buf := make([]byte, len(trieNodeStoragePrefix)+common.HashLength+len(path))
	n := copy(buf, trieNodeStoragePrefix)
	n += copy(buf[n:], accountHash.Bytes())
	copy(buf[n:], path)
	return buf
}

// IsLegacyTrieNode reports whether a provided database entry is a legacy trie
// node. The characteristics of legacy trie node are:
// - the key length is 32 bytes
// - the key is the hash of val
func IsLegacyTrieNode(key []byte, val []byte) bool {
	if len(key) != common.HashLength {
		return false
	}
	return bytes.Equal(key, crypto.Keccak256(val))
}

// ResolveAccountTrieNodeKey reports whether a provided database entry is an
// account trie node in path-based state scheme, and returns the resolved
// node path if so.
func ResolveAccountTrieNodeKey(key []byte) (bool, []byte) {
	if !bytes.HasPrefix(key, trieNodeAccountPrefix) {
		return false, nil
	}
	// The remaining key should only consist a hex node path
	// whose length is in the range 0 to 64 (64 is excluded
	// since leaves are always wrapped with shortNode).
	if len(key) >= len(trieNodeAccountPrefix)+common.HashLength*2 {
		return false, nil
	}
	return true, key[len(trieNodeAccountPrefix):]
}

// IsAccountTrieNode reports whether a provided database entry is an account
// trie node in path-based state scheme.
func IsAccountTrieNode(key []byte) bool {
	ok, _ := ResolveAccountTrieNodeKey(key)
	return ok
}

// ResolveStorageTrieNode reports whether a provided database entry is a storage
// trie node in path-based state scheme, and returns the resolved account hash
// and node path if so.
func ResolveStorageTrieNode(key []byte) (bool, common.Hash, []byte) {
	if !bytes.HasPrefix(key, trieNodeStoragePrefix) {
		return false, common.Hash{}, nil
	}
	// The remaining key consists of 2 parts:
	// - 32 bytes account hash
	// - hex node path whose length is in the range 0 to 64
	if len(key) < len(trieNodeStoragePrefix)+common.HashLength {
		return false, common.Hash{}, nil
	}
	if len(key) >= len(trieNodeStoragePrefix)+common.HashLength+common.HashLength*2 {
		return false, common.Hash{}, nil
	}
	accountHash := common.BytesToHash(key[len(trieNodeStoragePrefix) : len(trieNodeStoragePrefix)+common.HashLength])
	return true, accountHash, key[len(trieNodeStoragePrefix)+common.HashLength:]
}

// IsStorageTrieNode reports whether a provided database entry is a storage
// trie node in path-based state scheme.
func IsStorageTrieNode(key []byte) bool {
	ok, _, _ := ResolveStorageTrieNode(key)
	return ok
}
