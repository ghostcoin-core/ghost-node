# Wallet restore reads

A wallet restoring at scale extends the witnesses it already holds instead of
reading every page again, and asks whether its notes were spent without
telling the node which one it cares about. The node serves three reads for
this (spec 05, section 8: "Reading the tail of the page roots", "A page not
yet full", "Marker status query", "Forbidden"; TH-19, TH-20). Each has a
fixed shape, so the node never learns which page or marker is real, and none
returns a witness: the wallet computes its own. The code is
`History.PageRootTail`, `History.PageSet` and `History.MarkerStatus` in
`core/ghosttree/serve.go` and the methods of `GhostAPI` in
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

## Marker status query

```
ghost_getMarkerStatus(kind, markers, anchorHash)
```

`markers` is an array of exactly 64 (`ghosttree.StatusMarkers`) distinct
32-byte markers; any other count, or a repeated marker, is refused
(`ErrStatusQuery`). `kind` is the type: `"coin"` reads the coin spent-marker
list, `"data"` the data list, and the two are separate (a value spent as a
coin marker is not spent as a data marker). The response is an array of
`RPCMarkerStatus`, one per marker in request order:

| Field | Content |
|---|---|
| `spent` | `true` if the canonical chain up to the anchor spent the marker |
| `block` | the number of the block whose reveal spent it, hex quantity; left out when not spent |

A marker spent in a block after the anchor is not spent as of the anchor. 32
zero bytes is a valid query value and is never spent. The anchor must also be
covered by the history (its head canonical and at or above the anchor, and
the anchor applied), or the query is `ErrHistoryNotReady`, as for
`ghost_getTreePage` of a marker list.

## Limits

A public node must not be made to do unbounded work by one request. Every
request has a fixed shape, and a request outside it is refused before any
store read (for the page set, a shape that fits no tree; one that only
mismatches this tree's page count is refused once the page count is known,
before any page is read):

- the page set returns at most 8 pages: at most 32,768 entries, 6,160,384
  bytes of leaves and notes (plus 16 bytes of salt for a salted commit);
- the status query does exactly 64 index lookups;
- the tail returns at most the 1,048,576 page roots (32 MiB) of a full tree,
  the figure spec 05 section 8 gives for the whole page-root list, so it adds
  no cost beyond `ghost_getPageRoots`.

## Spent-marker index

A status query never scans a marker list. The history keeps, for every
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
anchor's; that number is `block`. The key is 51 bytes long, so the state
pruner never takes it for a trie node.

### Rebuild

A store built before the index has none. The history head is written with a
second version marker, the key `ghost-tree-marked` (one byte, 1), beside the
tag index's `ghost-tree-tagged`. `Sync` treats a stored head without it as a
stale history and builds the history again from genesis on its first call
after the upgrade, as it does for any stale store; a reset deletes the
marker with the head. Until then a status query is `ErrHistoryNotReady`.

## Not served

- a witness, or any part of one computed by the node;
- a read keyed by a single leaf, position or marker, or a status query of
  any size but 64;
- an absence witness for a marker;
- the block-range receipts request of 8 blocks (spec 05 section 12 item 5):
  the node serves receipts per block.
