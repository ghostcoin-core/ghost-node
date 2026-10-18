# Trees and headers

The node keeps the two commitment trees of the specification (spec 05,
sections 3, 4, 6, 7 and 10): the coin tree and the data tree, each of depth
32 (2^32 leaves per tree), and one spent-marker set per kind. The code is in
`core/ghosttree`.

## Hashing

`K(tag, ...)` is Keccak-256 with the original padding over one length byte,
the ASCII tag and the inputs (spec 01, section 4; decision 0003). The empty
leaf is `K("ghost/empty-leaf/v1")`; a node at level `l` (0 just above the
leaves, 31 the root) is `K("ghost/coin-tree-node/v1", l, left, right)` or
`K("ghost/data-tree-node/v1", l, left, right)`. The empty roots are
`8e66512042388a7863d500c4f96861466ae48b9d64ea1e10ec382c31aa61b5a8` (coin) and
`3d5cea4ec4750f6e39c05a6464043afed27b95090a4d93a304d88204e9a3fe03` (data).

## Storage layout

The tree state of each kind is the storage of one reserved account. Slot keys
are the slot number as a 32-byte big-endian integer; values are 32-byte
big-endian integers or hashes.

| Slot | Content |
|---|---|
| 0 | tree index `k` |
| 1 | leaf count `n`, 0 to 2^32 |
| 2 | last filled height: the block in which tree `k` last became full, 0 if never |
| 3 | final root of tree `k` once it is full, zero otherwise |
| 4 to 35 | frontier `f_0` to `f_31` |

A marker set is the storage of its own account: the slot keyed by the 32-byte
marker holds `1` once the marker is spent. Any non-zero value counts as spent.
A coin marker is never looked up in the data set, or the other way round.

The root is computed from the stored state alone: the final root for a full
tree, otherwise the fold over the frontier and the empty subtrees. A count
above 2^32, a set bit of the count over an empty frontier slot, a full tree
without a final root, or a final root on a tree that is not full is corrupt
state, and no root is given for it.

## Accounts

| Account | Address |
|---|---|
| coin tree | `0x67686f7374000000000000000000000000000001` |
| data tree | `0x67686f7374000000000000000000000000000002` |
| coin markers | `0x67686f7374000000000000000000000000000003` |
| data markers | `0x67686f7374000000000000000000000000000004` |

These are internal-test values ("ghost" in ASCII and a counter), in
`params/ghost/treeaccounts.go`. The launch values come with the
transaction-format specification and replace them in a constants-only change.

## Header layout

`Header` has two fields, `CoinTreeRoot` and `DataTreeRoot`, encoded by the
hand-written `EncodeRLP` and `DecodeRLP` of `core/types/header_ghost.go`:

- With both roots nil, a header encodes exactly as before, with the base
  client's optional fields.
- With both roots set, the base fee set and no withdrawals root, blob gas
  fields or parent beacon root, a header is the 18-item list of spec 05,
  section 10: fields 0 to 14, the base fee, the coin tree root and the data
  tree root.
- Any other combination does not encode.

The decoder reads a list of exactly 18 items with a 32-byte string at index 17
as the Ghost layout, and anything else as before; in the base layout index 17
is the blob gas used, an integer of at most 8 bytes. `DecodeGhostHeader` is
the strict reference decoder of the specification, which rejects with the
reasons `non-canonical-rlp`, `trailing-bytes`, `item-count`, `field-size`,
`non-canonical-integer` and `integer-range`. The JSON encoding of
`types.Header` is unchanged.

The RandomX engine sets both roots from the final state in
`FinalizeAndAssemble`, after the block reward and before the state root,
requires them in every header with a base fee, and covers them with the seal
hash. Block validation recomputes both roots after execution and rejects a
block whose roots differ. The genesis of the internal network and of
developer mode carries the empty roots; the genesis state root stays that of
the allocation. Developer mode's configuration has no EIP-1559, so its later
blocks have no base fee and carry no roots.

The JSON header of `eth_getBlockByNumber`, `eth_getBlockByHash` and the
header methods carries `coinTreeRoot` and `dataTreeRoot` when the header has
them, and leaves them out otherwise.

## Pages

Tree data is served in pages of `PageLeaves = 4096` consecutive positions
(spec 05, section 8): page `p` of a tree holds positions `4096 p` to
`4096 p + 4095`. The page size is a constant of the protocol. Each leaf is
stored with its note of `NoteBytes = 156` bytes. The code is in
`core/ghosttree/pages.go`:

- `PageRoot(kind, leaves)` is the level-11 node over a page, with the empty
  leaf at the positions past the given leaves. An empty page has the root
  `Z_12`.
- `RootFromPageRoots(kind, roots)` is the tree root from the page-root list
  alone: the 20 levels above the pages, with `Z_12` for every page past the
  list.
- `Witness(kind, position, page, roots)` builds a leaf's path the way a wallet
  does: 12 siblings from the leaves of its page and 20 from the page-root
  list, after checking the page against its entry of the list. The path
  verifies with `VerifyMembership` against the header root.

Both are checked against the vector `coin-page-two-leaves` of spec 05,
section 11: the page root
`06d032e35a1f30a5773c38d9631f5e4ec069786f4d22131ef0bbba75acf2b717`, the empty
page root `b50ae40977b91a1a10c7965cd40294eac6f63cbc40b5e57b9d4aa215956142d4`
and the tree root
`142c6bdf0882396330f9942ddd49df5d860b05a5218dad1ce6ef8e69238b6ec5`.

## History store

Leaves and notes are history, not state (spec 05, section 9).
`ghosttree.History` (`core/ghosttree/history.go`) keeps every leaf and note of
every tree index of both kinds on the canonical chain, in the chain database
under three key prefixes of its own (`core/rawdb/accessors_ghosttree_history.go`):

| Prefix | Key | Value |
|---|---|---|
| `ghost-tree-leaf-` | kind, tree index, position | block number, leaf, note |
| `ghost-tree-block-` | block hash | block number, positions the block wrote |
| `ghost-tree-page-` | kind, tree index, page | root of the full page |

The caller drives it. `ApplyBlock(hash, number, records)` adds the records of
a block that became canonical, in the order the block appended them;
`RevertBlock(hash)` removes those of a block that left the canonical chain,
newest block first. Each record must continue its tree: the next free
position, at a block number not below the record before it, or position 0 of
the next index after a tree that filled in an earlier block. Anything else is
refused and nothing is written, so the stored positions of a tree are always
contiguous from 0 and a reorganisation leaves the store equal to that of a
node that never saw the removed blocks. The root of a page is stored when its
last position is, and removed with it.

The store prunes nothing. Its keys are never 32 bytes long, so the offline
state pruner, which deletes 32-byte keys it takes for trie nodes, leaves them
alone; garbage collection of the trie and the limits on transaction indexes
and state history do not touch them either.

Nothing applies blocks to the store yet. The records of a block come from the
receipts of the commit and reveal transactions, whose layout belongs to that
transaction format; until that wiring exists the node's history is empty and
the methods below answer empty trees, which match the empty roots of every
header so far. The store is not derived from block bodies, and snap sync does
not download it.

## Serving

`History.Page(kind, treeIndex, page, anchor)` returns the filled positions of
one whole page as of the anchor block, each as leaf and note, and their
number. `History.PageRoots(kind, treeIndex, anchor)` returns the page roots of
pages 0 to the last page with a leaf. Both:

- require the anchor to be a known block on the canonical chain;
- count the leaves of the tree at the anchor, so that positions appended after
  it are not sent;
- recompute the tree root from the page-root list and compare it with the
  header root of that kind: the anchor's, or, for a full tree followed by the
  next index before the anchor, the root of the block that filled it;
- return an error for an unknown kind, a tree index other than 0 with no leaf
  at the anchor, a page number of 2^20 or more, a header without the root,
  a mismatch, missing or malformed history, or a database error. Uncertain
  means reject: nothing is answered that was not checked.

A page past the last filled page of an existing tree is an empty page, not an
error.

There is no lookup by commitment, single position, range other than a whole
page, marker, note or transaction, and nothing returns a witness: a wallet
fetches the page-root list and every page from its scan start, checks the list
against the header root of the anchor in its own header chain and each page
against its page root, and builds its own witness. The page root covers the
leaves only; the wallet checks each note against the receipt of its
transaction. Marker pages are not built: marker status comes from the checked
receipts alone.

The RPC methods are thin wrappers in the `ghost` namespace
(`internal/ethapi/ghosttree.go`), registered by the `eth` service when the
HTTP or WebSocket module list names it:

| Method | Parameters | Result |
|---|---|---|
| `ghost_getTreePage` | kind (`"coin"` or `"data"`), tree index, page, anchor block hash | `{kind, treeIndex, page, filled, entries: [{leaf, note}]}` |
| `ghost_getPageRoots` | kind, tree index, anchor block hash | list of page roots |

Every parameter is required, and a call with more is refused. The namespace
is opt-in, so the default module set of every endpoint is unchanged: it is
registered only when `--http.api` or `--ws.api` lists `ghost`, and it is then
also served over IPC. Pages are not served over the peer protocol.

## Eligible roots

A root is eligible for a block when it is the root field of its kind in the
header of an ancestor of that block (spec 05, section 5 and section 7, steps
1 and 2). `ghosttree.EligibleRoot(chain, parent, kind, root)`
(`core/ghosttree/roots.go`) answers it, given the parent of the including
block:

- There is no age limit: a root of any ancestor, down to genesis, counts.
- The including block's own root counts only when an ancestor carries it
  too, and a root of the other kind never counts.
- Only ancestry counts, not what the node has seen: a root that appears only
  in a block outside the ancestry is rejected, even when the node imported
  that block or followed its branch before a reorganisation.
- Uncertain means reject: a missing header, an unreadable or mismatching
  index entry, or an index that is not ready is an error, never `true`.

The answer comes from an index kept in the chain database
(`core/rawdb/accessors_ghosttree.go`):

| Key | Value |
|---|---|
| `ghost-root-` + kind + root | height of the first canonical header carrying the root |
| `GhostRootIndexHead` | number and hash of the block whose ancestry the index holds |

`ghosttree.MoveRootIndex` works out the change of the index when the
canonical head moves: it walks the indexed chain and the new head's branch
down to their common ancestor, removes the entries that start at a block
leaving the chain and adds those of the blocks joining it. `writeHeadBlock`
in `core/blockchain.go` writes that change in the same batch as the
canonical-chain pointers, so a reorganisation removes the disconnected
blocks' entries and adds the new branch's together. A rewind, the commit of a
snap-synced head and the start of the node bring the index to the head the
same way; a database without an index, or one whose index does not match
the stored headers, gets it built again from genesis along the head's
ancestry. If even that fails, the index head is removed and the index reads
as not ready until the next move of the head rebuilds it. An index that
already holds the head is not written again, so a read-only database opens
as before; if a read-only database's index is behind, it stays as it was and
answers only for blocks it covers.

`EligibleRoot` first checks that the index head is canonical. It then walks
the including block's own branch from the parent down to the first
canonical block, the fork point, and accepts a root carried on the way. Below
the fork point the index answers: the root is eligible when its entry's
height is at most the fork point's, after checking that the canonical header
at that height carries it. A fork point above the index head, as while
headers are synced ahead of the blocks, is "not ready". The chain passed in
must also implement `ghosttree.RootIndex`, as `*core.BlockChain` does;
otherwise the answer is "not ready".

The answers after a reorganisation equal those of a node that never saw the
removed branch, and so does the index.

## Decisions

- Existing headers keep their exact bytes; only a header with both roots takes
  the Ghost layout. Rejecting a header without roots is the engine's check,
  not the decoder's.
- The tree-state account holds one slot beyond the specification's table, the
  final root, because a full tree's root cannot be recovered from a frontier.
  It is derived data, zero unless the tree is full.
- The reserved accounts get nonce 1 when first written, never at genesis, so
  that the empty-account cleanup of EIP-161 does not delete them with their
  storage. They hold no code and no balance.
- Only the commit and reveal transactions will append leaves and mark markers;
  nothing in this change makes a commit or a reveal valid.
- Each header carries only the current root of each kind: no spent-marker-set
  root and no third field.
- Uncertain means reject: unreadable or corrupt tree state, a nil root or any
  mismatch is an error or `false`.
