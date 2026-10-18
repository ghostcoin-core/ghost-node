# Data commit and data reveal

The node records data commitments in the data tree and spends data markers
with two transactions, built on the trees, statements and hashes of the coin
rules ([commit and reveal](private-transactions.md),
[trees and headers](trees-and-headers.md)). The code is in `core/ghostpriv`
(`commit.go` and `reveal.go`), with the hooks in `core/state_transition.go`,
`core/state_processor.go`, `core/vm/evm.go` and the transaction type in
`core/types/tx_ghost_private.go`.

- A **data commit** is an ordinary transaction from a public account with
  value 0. It appends a data commitment to the data tree and moves no value.
- A **data reveal** is a native transaction with no account, type `0x51`.
  Against a proof it adds one marker to the data marker set, once. It moves
  no value, appends to no tree and mints nothing.

The node never sees the file, its key, its digits, its plaintext or a
fingerprint of its content, and nothing about them is stored, derived or
checked on chain. A commit or a note carries no storage location.

`DATA` is the two bytes `0x02 0x01`, the type of a data commitment; `COIN` is
`0x01 0x01`. No tag of the data rules is shared with a coin rule, so no coin
value can be used as a data value:

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
to the data commit entry address with value exactly 0 and the 190 bytes of a
coin commit (`ghostpriv.CommitData`):

| Offset | Length | Field |
|---|---|---|
| 0 | 2 | version, `0x0001` |
| 2 | 32 | `F_d` |
| 34 | 156 | note |

The node computes the commitment itself,
`D = K("ghost/data-commitment/v1", DATA, F_d)` (`ghostpriv.DataCommitment`);
it carries no amount and never equals a coin commitment.

The checks run in this order and stop at the first failure; each failure makes
the transaction invalid, so a block carrying it is invalid:

1. ordinary validity: nonce, sender without code, fee caps, intrinsic gas;
2. data of exactly 190 bytes with version 1 (`ErrCommitData`); anything else,
   an extra field included, is rejected;
3. `F_d` not all zero (`ErrCommitZeroF`);
4. value exactly 0 (`ErrDataCommitValue`);
5. the sender's funds cover the gas (`core.ErrInsufficientFunds`);
6. the data tree takes one more leaf (`ErrDataCommitTree`, wrapping
   `ghosttree.ErrFillingBlock` when the tree filled in this block).

Then one change: `D` is appended to the data tree with the receipt log. No
code runs, the entry address never holds an account, and the coin tree, the
totals account and every balance but the gas payment stay as they were. The
gas is the intrinsic gas, paid and burned as for any transaction.

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
| 158 | 32 | fee, must be zero (see [fee](#fee)) |
| 190 | 1,310,720 | proof, then zeros |
| 1,310,910 | 156 | note, must be all zero |

The verifier-or-recipient field names who the reveal is for; it credits
nothing and no code runs for it. There is no remainder: a data reveal with a
note, or with out, is rejected.

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
7. out is zero and the note all zero (`ErrDataRevealShape`);
8. the node computes the binding digest itself;
9. the root is the data tree root in the header of a block of the including
   block's own ancestry, strictly below it (`ErrDataRevealRoot`); a coin tree
   root, or a root seen only on a side branch, is not eligible;
10. the marker is not in the data marker set, which holds the markers of
    earlier data reveals of the same block too (`ErrDataRevealMarker`);
11. the verifier accepts the proof for the inputs the node computed
    (`ErrDataRevealProof`).

Then one change: the marker is added to the data marker set and the receipt
log is written. Nothing is appended to either tree, nothing is minted, no
balance and no running total changes.

### Binding digest

`K("ghost/data-reveal-binding/v1", fields)` over 164 bytes: chain id (8),
version (2), domain (32, the genesis block hash), transaction type `0x51`,
statement `0x02`, statement version `0x01`, type `DATA` (2), purpose (1), the
verifier-or-recipient field (20), root and marker (32 each) and fee (32). The
node fills in the chain id, version, domain, transaction type, statement and
type itself and never takes the digest from the sender; the proof field is not
covered. Its tag, statement and length differ from the coin reveal's, so a
data digest never equals a coin digest of the same fields.

### Proof verifier

The proof goes through the same `Verifier.VerifyReveal` as the coin reveal.
`VerifyInputs.Kind` is `ghosttree.Data` and `VerifyInputs.Purpose` the purpose
byte; `Recipient` holds the verifier-or-recipient field and `Remainder`,
`Out`, `Rule` and `Note` are zero. The default verifier rejects every data
reveal with `ErrNoVerifier`. The stub of `core/ghostpriv/ghostprivtest`
accepts only the stub proof of the data digest, so the stub proof of a coin
reveal never verifies a data reveal.

### Fee

Where a data reveal's fee comes from is not settled (spec 04, question 1).
Until it is, every data reveal is rejected at the fee check with
`ErrDataRevealFee` wrapping `ErrDataRevealFeeUnsettled`, whatever its fee
field holds, and nothing changes. A node built from this tree therefore
rejects every block that carries a data reveal.

`ghostpriv.SetDataRevealZeroFee(true)` is a switch for tests only, off by
default, like `ghostpriv.SetVerifier`: with it on, the fee is zero and any
other fee is rejected. It does not settle the fee for any network, and no
public account ever pays a data reveal's fee.

## Receipts

Both logs have the data tree account as address.

| Log | Topics | Data |
|---|---|---|
| data commit | `K("ghost/data-commit-receipt/v1")` | tree index (4), position (4), leaf (32), note (156) |
| data reveal | `K("ghost/data-reveal-receipt/v1")`, marker | purpose (1), verifier-or-recipient field (20) |

The layout is an internal-test value, changed with the transaction-format
specification. An append whose tree index does not fit four bytes is
rejected.

## Exported API

- `ghostpriv.DataCommitment(F_d)`, `ghostpriv.ParseDataCommit` and
  `ghostpriv.ApplyDataCommit`; a data commit's data is
  `ghostpriv.CommitData(F_d, note)`;
- `ghostpriv.DataReveal` with `MarshalBinary` (the envelope), `BindingDigest`
  and `BindingInput`; `ghostpriv.DecodeDataReveal` (checks 1 to 3);
  `ghostpriv.PurposeField`, `ghostpriv.PurposeReveal` and
  `ghostpriv.PurposeRevoke`;
- `ghostpriv.CheckDataReveal` and `ghostpriv.ApplyDataReveal`, which block
  processing calls;
- `ghostpriv.SetDataRevealZeroFee`, for tests only;
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
- The data reveal fee is not settled; the zero fee exists only behind the test
  switch.
- The root of the data spent-marker set is not in the block header; there is
  no header change.
- There are no remainder commitments on a data reveal, no
  application-defined data types and no rules on data.
- The proof of holding, the test-local encrypted store and any verifier-side
  challenge handling are not part of the node.
