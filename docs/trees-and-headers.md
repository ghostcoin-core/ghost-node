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
The data set also keeps the data marker-set tree, below.

## The data marker-set tree

The data spent-marker set is also the indexed tree of spec 05, section 6
(`core/ghosttree/markerset.go`): append-only, depth 40, each used leaf
`(value, nextValue, nextIndex)` linking the spent data markers in ascending
order from the sentinel leaf `(0, 0, 0)` at position 0. A leaf hashes as
`K("ghost/data-marker-set-leaf/v1", value, nextValue, nextIndex)` with
`nextIndex` 5 bytes big-endian, a node at level `l` as
`K("ghost/data-marker-set-node/v1", l, left, right)`, and an unused position
is the empty leaf. The root of the set of the sentinel alone is
`0ef484d17824d5fefb2533c70af81a3267af1169dd091395ad7607762aeee0a3`.

An insert of marker `m` finds the low leaf, the used leaf with the largest
value below `m`, writes `(m, low.nextValue, low.nextIndex)` at the next
position `n`, rewrites the low leaf to `(low.value, m, n)` and recomputes the
40 nodes on each of the two paths. `ghosttree.MarkSpent(st, Data, m)` inserts
in the same call that writes the marker slot, so a data reveal and a data
revoke both insert; the slot check that refuses a repeat runs first
(`ErrMarkerSpent`). The marker of 32 zero bytes is the sentinel's value and is
refused with `ErrZeroMarker`, and a data reveal carrying it fails check 10
with `ErrDataRevealMarker` before its proof is checked. Coin markers have no
tree.

The tree lives in the data marker account's storage, under keys
`K("ghost/data-marker-set-slot/v1", ...)`, which no marker can be:

| Key | Content |
|---|---|
| `0x00` | leaf count, zero meaning 1 (the sentinel alone) |
| `0x01`, position (5), field (1) | value, nextValue and nextIndex of a used leaf |
| `0x02`, level (1), index (5) | node at the level (0 the leaf hashes, 40 the root), zero meaning the default |
| `0x03` | root reference of the ordered index |
| `0x04`, id (5), field (1) | bit, left and right reference of an index node |

The default of node `(l, i)` is the empty subtree `Z_l`, except on the path of
position 0, whose default is the node over the sentinel leaf. So the genesis
set writes no slot, the account does not exist at genesis and the genesis
state root is unchanged; the first insert creates the account with nonce 1.
`ghosttree.DataMarkerRoot` reads the stored root node, one slot, or gives the
empty-set root.

The low leaf is found through an ordered index of the used values, a crit-bit
tree in the same storage: the node an insert adds takes the new leaf's
position as its id, and a reference is `2p` for the leaf at position `p` or
`2id + 1` for a node. A search walks at most 256 nodes, so an insert reads
and writes a bounded number of slots whatever the size of the set. The whole
tree is journaled state under the state root and rolls back with a
reorganisation; none of it is in the tree history.

`MarkerAbsenceWitness(st, m)` gives the 1,354-byte witness that `m` is not in
the set: the low leaf (32 + 32 + 5 bytes), its position (5 bytes) and the 40
siblings of its path. `VerifyMarkerAbsence(root, m, witness)` accepts it when
it is exactly that long, `m` is not zero, the low leaf folded along the
position's bits gives the root, `low.value < m` and `m < low.nextValue` or
`low.nextValue` is zero. Both are Go functions only; no RPC method serves a
witness.

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

`Header` has three fields, `CoinTreeRoot`, `DataTreeRoot` and
`DataMarkerRoot`, encoded by the hand-written `EncodeRLP` and `DecodeRLP` of
`core/types/header_ghost.go`:

- With all three roots nil, a header encodes exactly as before, with the base
  client's optional fields.
- With all three roots set, the base fee set and no withdrawals root, blob gas
  fields or parent beacon root, a header is the 19-item list of spec 05,
  section 10: fields 0 to 14, the base fee, the coin tree root, the data tree
  root and the data marker root.
- Any other combination, including one or two of the three roots, does not
  encode.

The decoder reads a list of exactly 19 items with a 32-byte string at index 18
as the Ghost layout, and anything else as before; in the base layout index 18
is the excess blob gas, an integer of at most 8 bytes. The 18-item layout
before the marker root is not a Ghost header: `DecodeGhostHeader` rejects it
with `item-count`. `DecodeGhostHeader` is the strict reference decoder of the
specification, which rejects with the reasons `non-canonical-rlp`, `trailing-bytes`, `item-count`, `field-size`,
`non-canonical-integer` and `integer-range`. The JSON encoding of
`types.Header` is unchanged.

The data marker root is the root of the data spent-marker set of spec 05,
section 6. `ghosttree.DataMarkerRoot` (`core/ghosttree/markerroot.go`)
returns it for a state, from the data marker-set tree above: it is
`ghosttree.EmptyMarkerSetRoot`
(`0ef484d17824d5fefb2533c70af81a3267af1169dd091395ad7607762aeee0a3`, vector
`marker-set-empty`) until the first data marker is spent, and changes with
every data reveal and revoke.

The RandomX engine sets the three roots from the final state in
`FinalizeAndAssemble`, after the block reward and before the state root,
requires them in every header with a base fee, and covers them with the seal
hash. Block validation recomputes the three roots after execution and rejects
a block whose roots differ. The genesis of the internal network and of
developer mode carries the empty roots and the empty marker-set root; the
genesis state root stays that of the allocation. Developer mode's configuration has no EIP-1559, so its later
blocks have no base fee and carry no roots.

The JSON header of `eth_getBlockByNumber`, `eth_getBlockByHash` and the
header methods carries `coinTreeRoot`, `dataTreeRoot` and `dataMarkerRoot`
when the header has them, and leaves them out otherwise.

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
every tree index of both kinds on the canonical chain, and every spent marker
of both kinds in the order the chain spent it, in the chain database under
key prefixes of its own (`core/rawdb/accessors_ghosttree_history.go`, and
`core/rawdb/accessors_ghosttree_markers.go` for the spent-marker index):

| Prefix | Key | Value |
|---|---|---|
| `ghost-tree-leaf-` | kind, tree index, position | block number, leaf, note, and the salt of a salted commit |
| `ghost-tree-block-` | block hash | block number, positions the block wrote |
| `ghost-tree-block-` | the zero hash | number and hash of the history's head |
| `ghost-tree-page-` | kind, tree index, page | root of the full page |
| `ghost-tree-marker-` | kind (2 or 3), marker (32 bytes) | tree index (8 bytes) and position (4 bytes) of the record that spent it |
| `ghost-tree-marked` | none (the whole key) | 1, once the history keeps the spent-marker index |

The spent-marker index finds the record that spent a marker when a block is
reverted, without a scan of a list; its keys are 51 bytes long. See
[wallet-restore-reads.md](wallet-restore-reads.md).

The kind byte is 0 for the coin tree, 1 for the data tree, 2 for the coin
marker list and 3 for the data marker list. A marker list is stored like a
tree: a marker is kept as the leaf of its record, with a zero note, and a list
index holds as many markers as a tree index holds leaves before the next
index starts. A marker list has no page roots and no header root. The head
is the block whose ancestry the store holds; no block has the zero hash.

A leaf record is 196 bytes: block number (8), leaf (32) and note (156). The
record of a salted commit or salted data commit is 16 bytes longer, with the
16-byte salt after the note; the 196-byte length still decodes, as a leaf
without a salt. A version 1 commit, a reveal remainder (whose salt is in its
note) and a marker have no salt.

`ApplyBlock(hash, number, records)` adds the records of a block that became
canonical, in the order the block appended them; `RevertBlock(hash)` removes
those of a block that left the canonical chain, newest block first. Each
record of a tree must continue it: the next free position, at a block number
not below the record before it, or position 0 of the next index after a tree
that filled in an earlier block. A marker record takes the next position of
its list, and the next list index starts at once when a list fills. Anything
else is refused and nothing is written, so the stored positions of a tree or
list are always contiguous from 0 and a reorganisation leaves the store equal
to that of a node that never saw the removed blocks. The root of a page of a
tree is stored when its last position is, and removed with it.

The store prunes nothing. Its keys are never 32 bytes long, so the offline
state pruner, which deletes 32-byte keys it takes for trie nodes, leaves them
alone; garbage collection of the trie and the limits on transaction indexes
and state history do not touch them either.

### Feeding the store

The node keeps the store at its head block. `eth/backend.go` hands the store
to the blockchain (`BlockChain.SetTreeHistory`), and from then on
`core/blockchain.go` calls `History.Sync(head, records)` whenever the head
block moves (`writeHeadBlock`, which inserts, reorganisations and
`SetCanonical` go through, the end of a rewind and the commit of a snap-synced
head). `Sync` walks the stored head's branch and the new head's branch down to
their common ancestor through the stored headers, reverts the blocks of the
old branch newest first and applies those of the new branch oldest first,
each block in one write together with the new head. While a rewind deletes
blocks from the top of the chain, `History.Unwind(hash)` reverts each deleted
block that is the history's head, before its header is gone.

The records of a block come from the logs of its receipts
(`ghostpriv.HistoryRecords`, `core/ghostpriv/commit.go`), which only the coin
and data rules write from the tree accounts:

| Receipt log | Records |
|---|---|
| commit | coin leaf at the logged tree index and position, with its note, and with its salt when the log is the 244-byte log of a salted commit |
| reveal | coin leaf of the remainder with its note, and the marker in the coin marker list |
| data commit | data leaf at the logged tree index and position, with its note, and with its salt when the log is the 212-byte log of a salted data commit |
| data reveal (and revoke) | the marker in the data marker list |

A log of a tree account that is none of these, a block without its body, or a
body without all its receipts is an error: the history stays at the block's
parent, the error is logged, and the next move of the head tries again.

At start-up, a store without a head (a database from before the store was
fed, or a new one) is built from genesis along the head block's ancestry, so a
node with an existing chain answers too. A store whose head header is gone, or
that refuses a block, is cleared (records, page roots and head) and built again
the same way; block entries of blocks no longer applied may remain and are
replaced when such a block is applied again. Nothing of this changes what a
block means: the store is a read-side index, never consulted by block
validation, and snap sync does not download it.

## Serving

`History.Page(kind, treeIndex, page, anchor)` returns the filled positions of
one whole page as of the anchor block, each as leaf, note and salt (none for a
leaf without one), and their number. `History.PageRoots(kind, treeIndex, anchor)` returns the page roots of
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
transaction.

`History.MarkerPage(kind, index, page, anchor)` returns one whole page of a
marker list as of the anchor block: the markers spent at positions `4096 p` to
`4096 p + 4095` of list `index`, in the order the canonical chain up to the
anchor spent them. No header carries a root of a marker list, so a marker page
is checked against the chain instead: the anchor must be a known canonical
block, the history's head must be canonical and at or above the anchor, and
the anchor must be applied to the history. Anything else, as while the history
is behind the head or in the middle of a reorganisation, is an error; so is a
missing record below the count. A page past the last marker of an existing
list is empty.

## Tree page methods

The RPC methods are thin wrappers in the `ghost` namespace
(`internal/ethapi/ghosttree.go`), registered by the `eth` service when the
HTTP or WebSocket module list names it. The namespace is opt-in, so the
default module set of every endpoint is unchanged: it is registered only when
`--http.api` or `--ws.api` lists `ghost`, and it is then also served over IPC.
Pages are not served over the peer protocol. Every parameter is required, and
a call with fewer or more parameters is refused.

### Parameters

| Parameter | JSON | Meaning |
|---|---|---|
| `kind` | string: `"coin"`, `"data"`, `"coin-markers"` or `"data-markers"` | the coin tree, the data tree, or the list of spent coin or data markers |
| `treeIndex` | hex quantity, for example `"0x0"` | the tree index `k`, or for a marker kind the list index; each list holds 2^32 markers |
| `page` | hex quantity below `0x100000` (2^20) | the page: positions `4096 page` to `4096 page + 4095` |
| `anchorHash` | 32-byte hex block hash | the block the answer is as of; a block number is refused |

### `ghost_getPageRoots(kind, treeIndex, anchorHash)`

For `"coin"` and `"data"`: a JSON array of 32-byte hex page roots, of pages 0
to the last page with a leaf as of the anchor; an empty tree gives `[]`. The
wallet checks `RootFromPageRoots(kind, roots)` against the `coinTreeRoot` or
`dataTreeRoot` of the anchor header. For `"coin-markers"` and
`"data-markers"` the call is refused: a marker list has no page roots.

```json
["0x06d032e35a1f30a5773c38d9631f5e4ec069786f4d22131ef0bbba75acf2b717"]
```

### `ghost_getTreePage(kind, treeIndex, page, anchorHash)`

For `"coin"` and `"data"` the result is one page of the tree, the same shape
for both kinds:

| Field | JSON | Meaning |
|---|---|---|
| `kind` | string | `"coin"` or `"data"`, as asked |
| `treeIndex` | hex quantity | as asked |
| `page` | hex quantity | as asked |
| `filled` | hex quantity | number of entries, 0 to 4096 |
| `entries` | array of `{leaf, note, salt}` | the filled positions from the first of the page, in order: `leaf` a 32-byte hex hash, `note` the 156-byte note as hex, `salt` the 16-byte salt of a salted commit as hex, left out when the leaf has none (a version 1 commit, or a reveal remainder, whose salt is in its note) |

```json
{"kind": "coin", "treeIndex": "0x0", "page": "0x0", "filled": "0x2",
 "entries": [{"leaf": "0x…", "note": "0x…", "salt": "0x…"},
             {"leaf": "0x…", "note": "0x…"}]}
```

For `"coin-markers"` and `"data-markers"` the result is one page of up to
4,096 spent markers, the same shape for both kinds:

| Field | JSON | Meaning |
|---|---|---|
| `count` | hex quantity | number of markers in this page, 0 to 4096 |
| `markers` | array of 32-byte hex hashes | the markers at the page's positions, in the order they were spent (inclusion order: block, then transaction) |

```json
{"count": "0x2", "markers": ["0x…", "0x…"]}
```

A page with fewer than 4,096 markers is the last one with markers; the pages
after it are empty (`{"count": "0x0", "markers": []}`). A wallet reads pages
0, 1, … until it gets one that is not full.

### Errors

Every failure is a JSON-RPC error, never a guess or an answer for another
block. A parameter that does not parse, an unknown kind among them (`invalid
argument 0: unknown tree kind`), is refused with code `-32602`; everything
else has code `-32000`: a page of 2^20 or more (`page number beyond the tree`), a tree or list index other than
0 with nothing at the anchor (`tree index does not exist at the anchor`), an
unknown anchor (`unknown anchor block`), an anchor off the canonical chain,
as after a reorganisation removed it (`anchor block not canonical`), a header
without the root of the kind (`header has no tree root`), a history that does
not reproduce the header root (`tree history does not match the header
root`), a history that does not hold the anchor yet (`tree history does not
cover the anchor`), corrupt history, page roots of a marker list, and
database errors.

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

- Existing headers keep their exact bytes; only a header with all three roots
  takes the Ghost layout. Rejecting a header without roots is the engine's check,
  not the decoder's.
- The tree-state account holds one slot beyond the specification's table, the
  final root, because a full tree's root cannot be recovered from a frontier.
  It is derived data, zero unless the tree is full.
- The reserved accounts get nonce 1 when first written, never at genesis, so
  that the empty-account cleanup of EIP-161 does not delete them with their
  storage. They hold no code and no balance.
- Only the commit and reveal transactions will append leaves and mark markers;
  nothing in this change makes a commit or a reveal valid.
- Each header carries only the current root of each tree kind and the root
  of the data spent-marker set; the coin spent-marker set has no root.
- Uncertain means reject: unreadable or corrupt tree state, a nil root or any
  mismatch is an error or `false`.
