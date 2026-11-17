# Wallet restore reads

A wallet restoring at scale extends the witnesses it already holds instead of
reading every page again. The node serves two reads for this, the page-root
tail and the page set (spec 05, section 8: "Reading the tail of the page
roots", "A page not yet full", "Forbidden"; TH-19, TH-20). Each has a fixed
shape, so the node never learns which page is real, and none returns a
witness: the wallet computes its own. The code is `History.PageRootTail` and
`History.PageSet` in `core/ghosttree/serve.go` and the methods of `GhostAPI` in
`internal/ethapi/ghosttree.go`.

Every read is as of an anchor block, which must be on the canonical chain:
an unknown block is `ErrUnknownAnchor`, a block off the canonical chain
`ErrNotCanonical`. `kind` is `"coin"` or `"data"`; a marker kind
(`"coin-markers"`, `"data-markers"`) is refused (`ErrUnknownKind`).

## Page-root tail

```
ghost_getPageRootTail(kind, treeIndex, start, anchorHash)
```

| Argument | Content |
|---|---|
| `kind` | `"coin"` or `"data"` |
| `treeIndex` | the tree index, hex quantity |
| `start` | the first page `s`, hex quantity |
| `anchorHash` | the canonical block the tail is as of |

The response is an array of 32-byte hashes: the page roots of pages `s` to
the last page with a leaf. `s` must be a multiple of 65,536 pages
(`ghosttree.TailPages`) below the 1,048,576 pages of a full tree; any other
`s` is refused (`ErrTailStart`). A start past the last page gives an empty
array. The tail is checked like `ghost_getPageRoots`: the whole page-root
list of the tree must reproduce the header root of the anchor (or of the
block that filled the tree), so a store that does not is refused
(`ErrRootMismatch`), never served. A wallet joins the tail to the roots it
holds below `s` and checks the list against the header root itself.

## Page set

```
ghost_getPageSet(kind, treeIndex, pages, anchorHash)
```

`pages` is an array of page numbers as hex quantities. The node accepts it
only if the tree has at least one page at the anchor and either

- the tree has 8 pages or fewer and `pages` is every page, 0 to the last, in
  order; or
- the tree has more and `pages` is exactly 8 (`ghosttree.PageSetPages`)
  distinct page numbers in ascending order, each below the page count: one
  page of the wallet read whole and 7 decoys.

Any other shape (7 or 9 pages, a repeated or descending page, a page past
the tree, an empty list, a set on an empty tree) is refused
(`ErrPageSetShape`). The response is an array of `RPCTreePage`, one per page
in request order, exactly as `ghost_getTreePage` returns a page of a tree:
`{kind, treeIndex, page, filled, entries}` with each entry
`{leaf, note, salt}`. All pages are read from one view of the tree and each
is checked against its page root, as `ghost_getTreePage` does.

## Limits

A public node must not be made to do unbounded work by one request. Every
request has a fixed shape, and a request outside it is refused before any
store read (for the page set, a shape that fits no tree; one that only
mismatches this tree's page count is refused once the page count is known,
before any page is read):

- the page set returns at most 8 pages: at most 32,768 entries, 6,160,384
  bytes of leaves and notes (plus 16 bytes of salt for a salted commit);
- the tail returns at most the 1,048,576 page roots (32 MiB) of a full tree,
  the figure spec 05 section 8 gives for the whole page-root list, so it adds
  no cost beyond `ghost_getPageRoots`.

Nor can it be made to by many requests. The ghost reads (`ghost_getTreePage`,
`ghost_getPageSet`, `ghost_getPageRoots`, `ghost_getPageRootTail`,
`ghost_getNoteBucket`, `ghost_escrowSlot`) share one limit
(`internal/ethapi/ghostlimit.go`). Each read costs page units: one, one per
page of a page set, two for a note bucket. The node works on at most 16
units at once over every caller, and each source (a client IP address, as
for the signature budget; see `docs/account-transactions.md`) may read 32
units a second, 64 at once after a quiet spell. A read waits up to two
seconds for its source's rate and then for units; past that it is refused
with JSON-RPC code `-32005`, and the caller may try again. A wallet reading
pages one after another is slowed, not refused. IPC and in-process callers
are the node's own and are held only to the units.

## Spent-marker index

The index serves the reorg and rebuild bookkeeping: it is written when a
block is applied and read when a block is reverted, so that neither scans a
marker list. The history keeps, for every
spent marker, the slot of the record that spent it:

```
"ghost-tree-marker-" + kind (1 byte: 2 coin markers, 3 data markers) + marker (32 bytes)
  -> tree index (8 bytes big endian) + position (4 bytes big endian)
```

`applyBlock` writes the entry for every marker record in the same batch as
the record, only when the marker has no entry (the chain never spends a
marker twice, so the first spend wins); `revertBlock` deletes it with each
marker record it removes, only when the entry points at the removed slot; a
reset deletes every entry. A marker is spent as of the anchor iff the index
has it and the record at its slot has a block number at or below the
anchor's. The key is 51 bytes long, so the state
pruner never takes it for a trie node.

### Rebuild

A store built before the index has none. The history head is written with a
second version marker, the key `ghost-tree-marked` (one byte, 1), beside the
tag index's `ghost-tree-tagged`. `Sync` treats a stored head without it as a
stale history and builds the history again from genesis on its first call
after the upgrade, as it does for any stale store; a reset deletes the
marker with the head.

## Private restore

A node that serves the `ghost` namespace also runs a PIR restore server
(`core/ghostpir`, `eth/ghostrestore.go`). It keeps a snapshot of its
canonical head, anchored at the last block whose number is a multiple of 20,
rebuilt when the head enters the next interval or a reorganisation replaces
the anchor. Nothing in it is keyed by a tag, a marker, a position or a note:
what every wallet reads whole says nothing about the wallet, and every other
read is a PIR query, which hides the record it fetches. The methods are those
of `GhostRestoreAPI` in `internal/ethapi/ghostrestore.go`.

| Method | Result |
|---|---|
| `ghost_restoreHeader()` | the snapshot header: anchor number and hash, roots, and every database (table, kind, tree index, record size and count, root, digest, PIR rows and columns), with its canonical encoding and identity |
| `ghost_restoreTops()` | the level-20 nodes of every coin and data tree, which fold to the anchor's tree roots |
| `ghost_restoreBlocks(after)` | every block after the anchor and after `after`, up to the head: its leaves and markers, and its lookup lists, which hash to the block's `lookupDigest` |
| `ghost_restoreQuery(entry, query)` | the PIR answer to a query to database `entry` of the snapshot |

Beside the notes, coin-tree witness records, marker lists and hint tables,
the snapshot holds the four indexed trees of decision 0004: the coin and
data lookup indices and the coin and data marker sets. Each has an `index`
database, the witness of every used leaf in key order (1,332 bytes for a
lookup index, 1,359 for the coin marker set, 1,354 for the data marker set,
the sentinel at record 0), and an `index-buckets` database of 2^b records,
record k giving the ranks of the leaves whose key starts with the b bits of
k. Both list the anchor header's root of the tree (`coinLookupRoot`,
`dataLookupRoot`, `coinMarkerRoot`, `dataMarkerRoot`), and a build whose
leaves do not fold to it fails.

A wallet finds the low leaf of its tag (the key `tag || 0^5`) or of its
marker with one bucket query and a search of the bucket's ranks, padded to a
fixed number of index queries. The witness it ends on proves the tag's first
entry (`VerifyLookupFirst`) or its absence, and the marker's membership,
with the position its reveal appended (`VerifyCoinMarker`), or its absence.
It then reads the coin's note and coin-tree witness at that position. Every
record is checked against the anchor header on the wallet's own chain; the
bucket table is not believed, a wrong one only costing queries.

A restore of one coin makes the same 20 queries whatever the chain. A PIR
answer grows with the square root of its database: the test
`TestGhostRestoreOverRPC` measures 1.9 MB for a restore at 64 coin leaves
and 67 MB at 100,000.

Every call is charged to the restore server's budget (`DefaultBudget`: 256
requests a minute a client, 4,096 from all clients) and to the ghost read
limits above, a PIR answer at half the node's read units. A request past the
budget is refused with code `-32005` and does no work.

## Not served

- a witness computed for a named leaf, tag or marker: witnesses are served
  only as records of the restore snapshot, read by PIR;
- a read keyed by a single leaf, position or marker;
- any read that names a marker, alone or among others: the marker is public
  once its coin is spent and a decoy never is, so such a read links the
  query to the spend;
- an absence witness for a marker;
- the block-range receipts request of 8 blocks (spec 05 section 12 item 5):
  the node serves receipts per block.
