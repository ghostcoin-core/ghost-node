# Note buckets

A wallet restoring from its keys does not have to read every page of a tree.
Every note starts with a 3-byte lookup tag (its nonce; spec 01 section 9,
spec 05 section 8), and the node serves, for one tree at an anchor, the notes
whose tag starts with a given bit prefix: one bucket. The node never derives a
tag, as it has no key; it only reads bytes 0 to 2 of the 156-byte note. The
code is `ghosttree.ReadNoteBucket` in `core/ghosttree/buckets.go` and the
`ghost_getNoteBucket` method in `internal/ethapi/ghostbuckets.go`.

## Request

```
ghost_getNoteBucket(kind, treeIndex, bits, prefix, anchorHash)
```

| Argument | Content |
|---|---|
| `kind` | `"coin"` or `"data"` |
| `treeIndex` | the tree index `k`, hex quantity |
| `bits` | the bucket bits `m`, hex quantity |
| `prefix` | the `m`-bit prefix, hex quantity, below `2^m` |
| `anchorHash` | the canonical block the bucket is as of |

The tag of a note is its first 3 bytes read as a big-endian 24-bit number;
the prefix of a tag at `m` bits is `tag >> (24 - m)`. For example the tag
`4d6c00` is prefix `0x4d` at `m = 8` and `0x26b60` at `m = 19`; `7c28b7` is
`0x7c` and `0x3e145`.

## The `m` rule

The bits are not the wallet's choice. With `n` the tree's leaf count at the
anchor:

```
bucket_bits(n) = clamp(floor(log2(n / 4096)), 0, 24)
```

so a tree below 8,192 leaves has one bucket (`m = 0`, prefix 0) and every
bucket holds about 4,096 to 8,192 notes once the tree is larger: 1,048,576
leaves give `m = 8`, 3,650,000,000 give `m = 19`, 2^36 leaves or more give 24.
`ghosttree.BucketBits` is the rule.

## Response

`RPCNoteBucket`:

| Field | Content |
|---|---|
| `kind` | the kind asked for |
| `treeIndex`, `bits`, `prefix` | as asked, hex quantities |
| `count` | the number of entries, hex quantity |
| `entries` | the filled positions whose note's tag starts with the prefix, in increasing position order |

Each entry is `{position, leaf, note, salt}`: the position as a hex quantity,
the leaf `C`, the 156-byte note and the 16-byte salt of a salted commit.
`salt` is left out for a leaf without one, as in a page entry. Only positions
filled at or before the anchor are returned.

The bucket is not checked against a header root: proving a returned leaf sits
at its position is the authenticated read, a later change. Like a page
result, a wallet treats it as unchecked until it has a proof.

## What is refused

Each of these is an error, and the store is unchanged:

- `bits` other than `bucket_bits(n)` of the tree at the anchor, in either
  direction, and any `bits` above 24;
- a `prefix` of `2^bits` or more;
- a marker kind (`coin-markers`, `data-markers`) or any other kind;
- an unknown anchor (`ErrUnknownAnchor`) or one off the canonical chain
  (`ErrNotCanonical`);
- an anchor the history has not applied, or a history built before the tag
  index (`ErrHistoryNotReady`);
- a tree index other than 0 without a leaf at the anchor (`ErrNoTree`).

## The tag index

A bucket read does not scan the tree. Next to each record of the coin and
data trees, `applyBlock` writes, in the same batch,

```
"ghost-tree-tag-" + kind (1 byte) + tree index (8 bytes big endian) + tag (3 bytes) + position (4 bytes big endian) -> empty
```

A marker record writes none. `revertBlock` deletes the keys of the records
it removes, and `reset` deletes every one. A read iterates the tag range of
the prefix, `prefix << (24 - m)` to `((prefix + 1) << (24 - m)) - 1`, keeps
the positions below the tree's leaf count at the anchor, sorts them by
position and reads their records. The key is 31 bytes long, so state pruning
never takes it for a trie node.

## The rebuild

A history built before the tag index has none. `writeHead` writes the marker
key `ghost-tree-tagged` (value one byte, `1`) with every head, and `Sync`
treats a stored head without it as a stale history: the first `Sync` after
the upgrade clears the store and builds it again from genesis, as it does for
any stale store. `reset` deletes the marker with the head. Until the rebuild
is done, a bucket read on a history with a head but without the marker is
refused.
