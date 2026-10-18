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
`non-canonical-integer` and `integer-range`. The JSON form of the header is
unchanged.

The RandomX engine sets both roots from the final state in
`FinalizeAndAssemble`, after the block reward and before the state root,
requires them in every header with a base fee, and covers them with the seal
hash. Block validation recomputes both roots after execution and rejects a
block whose roots differ. The genesis of the internal network and of
developer mode carries the empty roots; the genesis state root stays that of
the allocation. Developer mode's configuration has no EIP-1559, so its later
blocks have no base fee and carry no roots.

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
