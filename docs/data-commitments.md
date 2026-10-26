# Data commit and data reveal

The node records data commitments in the data tree and spends data markers
with two transactions, built on the trees, statements and hashes of the coin
rules ([commit and reveal](private-transactions.md),
[trees and headers](trees-and-headers.md)). The code is in `core/ghostpriv`
(`commit.go` and `reveal.go`), with the hooks in `core/state_transition.go`,
`core/state_processor.go`, `core/vm/evm.go` and the transaction type in
`core/types/tx_ghost_private.go`.

- A **data commit** is an ordinary transaction from a public account with
  value exactly `DATA_RESERVE`, 2.5 x 10^17 wei (`ghostpriv.DataReserve`). It
  burns that fee reserve into the hidden set and appends a data commitment
  that binds it to the data tree.
- A **data reveal** is a native transaction with no account, type `0x51`.
  Against a proof it adds one marker to the data marker set, once, and
  settles its fee from the reserve. It credits no recipient, appends to no
  tree and mints nothing.

The node never sees the file, its key, its digits, its plaintext or a
fingerprint of its content, and nothing about them is stored, derived or
checked on chain. A commit or a note carries no storage location.

`DATA`, the type of a data commitment, is two bytes that follow the
commitment format version (spec 01): `0x02 0x02` at version 2
(`ghostpriv.DataV2`) and `0x01 0x02` at version 1 (`ghostpriv.Data`); `COIN`
is `0x02 0x01` and `0x01 0x01`. No tag of the data rules is shared with a coin
rule, so no coin value can be used as a data value:

| Tag | Use |
|---|---|
| `ghost/data-commitment/v1` | the data commitment |
| `ghost/data-marker/v1` | the data marker, derived by the wallet and the proof, never by the node |
| `ghost/data-reveal-binding/v1` | the binding digest of a data reveal |
| `ghost/data-commit-receipt/v1` | the data commit's receipt log |
| `ghost/data-reveal-receipt/v1` | the data reveal's receipt log |

## Reserved address

| Address | Use |
|---|---|
| `0x67686f7374000000000000000000000000000007` | data commit entry address |

It is an internal-test value in `params/ghost/privaccounts.go`, the next free
one after the commit entry address and the totals account; the launch value
comes with the transaction-format specification in a constants-only change.
The data tree account (`…0002`) and the data marker account (`…0004`) are
those of [trees and headers](trees-and-headers.md).

## Data commit

A data commit is any transaction type the node already accepts, sent top level
to the data commit entry address with value exactly `DATA_RESERVE` and the data of a coin
commit: the 206 bytes of salted commit data, version 2
(`ghostpriv.SaltedCommitData`):

| Offset | Length | Field |
|---|---|---|
| 0 | 2 | version, `0x0002` |
| 2 | 32 | `F_d` |
| 34 | 16 | salt |
| 50 | 156 | note |

The node refuses the old 190 bytes of version 1 data without a salt from
genesis: a new chain has no version 1 leaves, and two version 1 commits to one
key would share a marker.

The salt is carried in the clear so that a wallet can read it back with the
leaf and note. The node computes the commitment itself,
`D = K("ghost/data-commitment/v1", DATA, DATA_RESERVE, F_d)`
(`ghostpriv.DataCommitmentVersion`), with `DATA` `0x02 0x02` for the 206
bytes of version 2 and `DATA_RESERVE` as a 32-byte word
(`00..0003782dace9d90000`), so the leaf binds the reserve the commit burned.
The salt is already in `F_d` and the node never uses it. The commitment never
equals a coin commitment.

The checks run in this order and stop at the first failure; each failure makes
the transaction invalid, so a block carrying it is invalid:

1. ordinary validity: nonce, sender without code, fee caps, intrinsic gas;
2. data of exactly 206 bytes with version 2 (`ErrCommitData`); anything
   else, the 190 bytes of version 1, an extra field or another version
   included, is rejected;
3. `F_d` not all zero (`ErrCommitZeroF`);
4. value exactly `DATA_RESERVE` (`ErrDataCommitValue`); 0, one wei more or
   less, or any other value is rejected;
5. the sender's funds cover the reserve and the gas
   (`core.ErrInsufficientFunds`; `ApplyDataCommit` itself refuses a sender
   below the reserve with `ErrCommitFunds`);
6. the data tree takes one more leaf (`ErrDataCommitTree`, wrapping
   `ghosttree.ErrFillingBlock` when the tree filled in this block).

Then one atomic change: the reserve is debited from the sender and credited
to nobody, it is added to `total_in`, and `D` is appended to the data tree
with the receipt log. No code runs, the entry address never holds an account,
and the coin tree stays as it was. The gas is the intrinsic gas, paid and
burned as for any transaction.

Every call to the data commit entry address from inside the EVM (`CALL`,
`CALLCODE`, `DELEGATECALL`, `STATICCALL`) fails with `vm.ErrCommitEntryCall`
and uses up the gas it was given, as for the commit entry address.

## Data reveal

A data reveal is the typed transaction `0x51 || payload`, 1,311,067 bytes, the
size of the coin reveal, with hash `keccak256(0x51 || payload)`. It is a type
of its own so that a coin reveal and a data reveal can never be taken for each
other. The payload has the coin reveal's offsets:

| Offset | Length | Field |
|---|---|---|
| 0 | 2 | version, `0x0001` |
| 2 | 8 | chain id |
| 10 | 32 | marker |
| 42 | 32 | root, a data tree root |
| 74 | 32 | purpose: 31 zero bytes, then `0x01` or `0x02` |
| 106 | 20 | verifier-or-recipient field |
| 126 | 32 | out, must be zero |
| 158 | 32 | fee, the window fee (see [fee](#fee)) |
| 190 | 1,310,720 | proof, then zeros |
| 1,310,910 | 32 | cf, the content fingerprint |
| 1,310,942 | 124 | rest of the note slot, must be all zero |

The verifier-or-recipient field names who the reveal is for; it credits
nothing and no code runs for it. A data reveal has no remainder, so the
remainder's note slot carries the content fingerprint `cf` in its first 32
bytes; the width and gas of the payload are the coin reveal's. Any 32 bytes
are a valid `cf`: the node checks it against nothing, and the proof binds it.
A data reveal with out, or with a non-zero byte in the other 124 bytes of the
slot, is rejected.

Like the coin reveal a data reveal has no sender, nonce or signature
(`types.Sender` returns `types.ErrNoSender`), takes exactly
`G_PRIV = 21,090,372` gas from the block gas pool, and has a typed receipt of
type `0x51` with status 1, the cumulative gas and one log.

### Purposes

| Purpose | Byte | Meaning |
|---|---|---|
| reveal | `0x01` | a one-time reveal of the data |
| revoke | `0x02` | a revoke: the marker is spent without a reveal |

The purpose is part of the binding digest: a proof made for a revoke does not
verify a reveal, and the other way round. Any other value of the field, a
non-zero leading byte included, is rejected at the purpose check before any
proof is verified.

### Markers

The marker is spent in the data marker set, a slot of the data marker account
keyed by the marker. A coin marker is never looked up in the data set, or the
other way round. Once a marker is in the data set, by a reveal or a revoke,
every later reveal or revoke of it is rejected, in a later block or in the
same block, and the block carrying it is invalid. A reorganisation that
removes the block makes the marker unspent again, and the reveal can be
included again on the new branch.

### Checks

The checks run in this order and stop at the first failure; any failure makes
the block invalid:

1. type `0x51` and the exact envelope length (`ErrDataRevealLength`); a coin
   reveal envelope, type `0x50`, fails here, and a data reveal sent as type
   `0x50` fails the coin checks;
2. version 1 (`ErrDataRevealVersion`);
3. out and fee have their 20 leading bytes zero (`ErrDataRevealAmount`);
4. the chain id is this chain's (`ErrDataRevealChainID`);
5. the fee (`ErrDataRevealFee`, see [fee](#fee));
6. the purpose is reveal or revoke (`ErrDataRevealPurpose`);
7. out is zero and the note slot after `cf` all zero (`ErrDataRevealShape`);
8. the node computes the binding digest itself;
9. the root is the data tree root in the header of a block of the including
   block's own ancestry, strictly below it (`ErrDataRevealRoot`); a coin tree
   root, or a root seen only on a side branch, is not eligible;
10. the marker is not in the data marker set, which holds the markers of
    earlier data reveals of the same block too (`ErrDataRevealMarker`);
    then the backstop: `DATA_RESERVE` is not more than the hidden total,
    `total_in - total_out` (`ErrDataRevealBackstop`);
11. the verifier accepts the proof for the inputs the node computed
    (`ErrDataRevealProof`).

Then one atomic change: the marker is added to the data marker set,
`DATA_RESERVE` is added to `total_out`, the fee is settled as a coin reveal's
(the burn credited to nobody, the tip to the block's coinbase), the rest of
the reserve, `DATA_RESERVE - fee`, is forfeited and credited to nobody, and the
receipt log is written. A revoke settles the same way. Nothing is appended to
either tree, nothing is minted and no other balance changes.

### Binding digest

`K("ghost/data-reveal-binding/v1", fields)` over 196 bytes: chain id (8),
version (2), domain (32, the genesis block hash), transaction type `0x51`,
statement `0x02`, statement version `0x01`, type field `0x02 0x01` (2, part
of the binding layout, not a leaf type), purpose (1), the
verifier-or-recipient field (20), root and marker (32 each), fee (32) and
`cf` (32), so a changed `cf` changes the digest. The
node fills in the chain id, version, domain, transaction type, statement and
type itself and never takes the digest from the sender; the proof field is not
covered. Its tag, statement and length differ from the coin reveal's, so a
data digest never equals a coin digest of the same fields.

### Proof verifier

The proof goes through the same `Verifier.VerifyReveal` as the coin reveal.
`VerifyInputs.Kind` is `ghosttree.Data` and `VerifyInputs.Purpose` the purpose
byte; `Recipient` holds the verifier-or-recipient field, `Cf` the reveal's
`cf`, and `Remainder`, `Out`, `Rule` and `Note` are zero. Block processing and
the pool build these inputs in one place, `DataReveal.VerifyInputs`, so they
never disagree. The linked verifier's statement, in the layout of
`ghostverifier/ghost_data.h`, is 193 bytes: the purpose (1), then the root,
marker, party, fee, rule and `cf` (32 each), `cf` at bytes 161 to 193. The
default verifier rejects every data
reveal with `ErrNoVerifier`. The stub of `core/ghostpriv/ghostprivtest`
accepts only the stub proof of the data digest, so the stub proof of a coin
reveal never verifies a data reveal.

### Fee

A data reveal or revoke pays its fee from the reserve its data commit burned
(spec 04, sections 3 and 6). The fee check is the coin reveal's (spec 07,
section 5): the fee field must equal the window fee of the including block's
window or of the window before it, and must cover `G_PRIV` times the including
block's base fee (the cover rule); any other fee, zero included, is
`ErrDataRevealFee`. A window fee above `DATA_RESERVE` cannot be paid and is
`ErrDataRevealFeeAboveReserve`, wrapped by `ErrDataRevealFee`. Both run
before the proof is verified. No public account pays a data reveal's fee and
the unused rest of the reserve is not refunded.

In the spec's worked example, files A and B are committed (`total_in`
500,000,000,000,000,000 wei), A is revealed in the first window, whose
reference base fee is 1,000,000,000 wei: fee 26,100,495,343,659,410, burned
23,727,723,039,690,372, tip 2,372,772,303,969,038, and `total_out` becomes
250,000,000,000,000,000; B is revoked in the next window and `total_out`
becomes 500,000,000,000,000,000.

The shipped ghost verifier still answers `DataFeeUnsettled` for every data
proof at the pinned revision, so a release node rejects every data reveal at
the proof check with `ErrProofDataFeeUnsettled` after its fee checks pass; the
data lifecycle tests use the stub verifier.

## Receipts

Both logs have the data tree account as address.

| Log | Topics | Data |
|---|---|---|
| data commit, version 1 | `K("ghost/data-commit-receipt/v1")` | tree index (4), position (4), leaf (32), note (156): 196 bytes |
| data commit, salted | `K("ghost/data-commit-receipt/v1")` | tree index (4), position (4), leaf (32), note (156), salt (16): 212 bytes |
| data reveal | `K("ghost/data-reveal-receipt/v1")`, marker | purpose (1), verifier-or-recipient field (20) |

The log of a salted data commit is the version 1 log with the salt appended
after the note; the logs of version 1 data commits and of data reveals do not
change. The tree history reads both lengths and keeps the salt with the leaf
and note. The layout is an internal-test value, changed with the transaction-format
specification. An append whose tree index does not fit four bytes is
rejected.

## Exported API

- `ghostpriv.DataCommitment(F_d)`, `ghostpriv.ParseDataCommit` and
  `ghostpriv.ApplyDataCommit`; a data commit's data is
  `ghostpriv.SaltedCommitData(F_d, salt, note)`, or for version 1
  `ghostpriv.CommitData(F_d, note)`;
- `ghostpriv.DataReveal` with `MarshalBinary` (the envelope), `BindingDigest`
  and `BindingInput`; `ghostpriv.DecodeDataReveal` (checks 1 to 3);
  `ghostpriv.PurposeField`, `ghostpriv.PurposeReveal` and
  `ghostpriv.PurposeRevoke`;
- `ghostpriv.CheckDataReveal` and `ghostpriv.ApplyDataReveal`, which block
  processing calls;
- `ghostpriv.DataReserve`, the reserve every data commit burns;
- `types.NewGhostDataRevealTx(envelope)`, which wraps an envelope into a
  transaction of type `0x51`, `Transaction.GhostDataRevealEnvelope` and
  `Transaction.IsGhostReveal`, true for both reveal types.

## What is not here

- Data reveals reach a block only through the chain maker of the tests
  (`core/chain_makers.go`): the transaction pool, the block builder, the RPC
  methods that send transactions and the peer protocol do not handle type
  `0x51`.
- The history store of [trees and headers](trees-and-headers.md) is not fed
  from these receipts.
- There is no real proof verifier: the default rejects every data reveal, and
  only the stub of the tests accepts one.
- No refund of the unused reserve.
- The root of the data spent-marker set is not in the block header; there is
  no header change.
- There are no remainder commitments on a data reveal, no
  application-defined data types and no rules on data.
- The proof of holding, the test-local encrypted store and any verifier-side
  challenge handling are not part of the node.
