# Commit and reveal

The node carries value into and out of the hidden set with two transactions
(spec 03, the coin rules, and spec 04, the private transaction). The code is
in `core/ghostpriv`, with the hooks in `core/state_transition.go`,
`core/state_processor.go`, `core/vm/evm.go` and the reveal type in
`core/types/tx_ghost_private.go`.

- A **commit** is an ordinary transaction from a public account. It burns
  public GHOST and records a coin commitment of exactly the burned value.
- A **reveal** is a native transaction with no account. Against a proof it
  mints public GHOST out of the hidden set, records the remainder as a new
  commitment and pays its fee from hidden value.

Hashes are `K(tag, inputs...)`, the tagged Keccak-256 of `core/ghosttree`.
Amounts are 32-byte big-endian words, valid only below `2^96`
(`V_MAX = 2^96 - 1`). `COIN` is the two bytes `0x01 0x01`.

## Reserved addresses

| Address | Use |
|---|---|
| `0x67686f7374000000000000000000000000000005` | commit entry address |
| `0x67686f7374000000000000000000000000000006` | totals account |

Both are internal-test values in `params/ghost/privaccounts.go`, like the tree
accounts of [trees and headers](trees-and-headers.md); the launch values come
with the transaction-format specification in a constants-only change.

## Commit

A commit is any transaction type the node already accepts, sent top level to
the commit entry address with value `v` and salted commit data of exactly 206
bytes, version 2:

| Offset | Length | Field |
|---|---|---|
| 0 | 2 | version, `0x0002` |
| 2 | 32 | `F` |
| 34 | 16 | salt |
| 50 | 156 | note |

The salt is the coin's 16-byte per-coin salt, carried in the clear so that a
wallet can read it back with the leaf and note. Version 1 data of exactly 190
bytes, without a salt, is still accepted unchanged, because version 1
commitments stay valid:

| Offset | Length | Field |
|---|---|---|
| 0 | 2 | version, `0x0001` |
| 2 | 32 | `F` |
| 34 | 156 | note |

The node computes the commitment itself,
`C = K("ghost/coin-commitment/v1", COIN, F, v)`, from `F` and `v` only; the
salt is already in `F` and the node never uses it. The sender chooses neither
the type nor the commitment. For `F = b44338ab…0c4d8b` and `v = 10^18` it is
`562d92a9…029458` (the test has the full values).

The checks run in this order and stop at the first failure; each failure makes
the transaction invalid, so a block carrying it is invalid:

1. ordinary validity: nonce, sender without code, fee caps, intrinsic gas;
2. data of exactly 206 bytes with version 2, or of exactly 190 bytes with
   version 1 (`ErrCommitData`); anything else, an extra field, another
   version or a version with the other length included, is rejected;
3. `F` not all zero (`ErrCommitZeroF`);
4. `1 <= v <= V_MAX` (`ErrCommitAmount`);
5. the sender's funds cover `v` plus the gas (`core.ErrInsufficientFunds`);
6. the coin tree takes one more leaf (`ErrCommitTree`, wrapping
   `ghosttree.ErrFillingBlock` when the tree filled in this block).

Then one atomic change: `v` is debited from the sender and credited to nobody,
`C` is appended to the coin tree with the receipt log, and `v` is added to the
total in. No code runs and the entry address never holds an account. The gas
is the intrinsic gas, paid and burned as for any transaction. There is no
minimum above 1 wei and no cooldown.

Every call to the entry address from inside the EVM (`CALL`, `CALLCODE`,
`DELEGATECALL`, `STATICCALL`) fails with `vm.ErrCommitEntryCall` and uses up
the gas it was given, so no contract can commit. Value reaching the address in
any other way, such as a `SELFDESTRUCT` beneficiary, is not intercepted.

## Reveal

A reveal is the typed transaction `0x50 || payload`, 1,311,067 bytes, with
hash `keccak256(0x50 || payload)`. The payload is a fixed layout, not RLP:

| Offset | Length | Field |
|---|---|---|
| 0 | 2 | version, `0x0001` |
| 2 | 8 | chain id |
| 10 | 32 | marker |
| 42 | 32 | root |
| 74 | 32 | remainder commitment |
| 106 | 20 | recipient |
| 126 | 32 | out (amount word) |
| 158 | 32 | fee (amount word) |
| 190 | 1,310,720 | proof, then zeros |
| 1,310,910 | 156 | note of the remainder |

The proof field is 1,310,720 bytes (1.25 MiB) for version 1, chosen to hold
every proof of the pinned prover (about 1.19 MB) without ever growing.

A reveal has no sender, nonce or signature: `types.Sender` returns
`types.ErrNoSender` for it under every signer, and no signer signs it. No
ordinary account can authorise one. Every reveal takes exactly
`G_PRIV = 21,090,372` gas (16 x 1,311,067 + 21,000 + 92,300) from the block
gas pool; a block whose pool holds less is invalid. At the internal network's
genesis gas limit of 30,000,000 a block holds one reveal. Its receipt is a typed receipt of type `0x50` with status 1,
the cumulative gas and one log.

The checks run in this order and stop at the first failure; any failure makes
the block invalid:

1. type `0x50` and the exact envelope length (`ErrRevealLength`);
2. version 1 (`ErrRevealVersion`);
3. out and fee have their 20 leading bytes zero (`ErrRevealAmount`);
4. the chain id is this chain's (`ErrRevealChainID`);
5. the fee equals the window fee (`ErrRevealFee`);
6. the node computes the binding digest itself;
7. the root is the coin tree root in the header of a block of the including
   block's own ancestry, strictly below it, of any tree index
   (`ErrRevealRoot`);
8. the marker is not in the coin marker set, which holds the markers of
   earlier reveals of the same block too (`ErrRevealMarker`);
9. backstop: `out + fee <= total_in - total_out` (`ErrRevealBackstop`);
10. the verifier accepts the proof for the inputs the node computed
    (`ErrRevealProof`);
11. the rule is the empty rule: the node supplies 32 zero bytes;
12. the coin tree takes the remainder (`ErrRevealTree`).

Then one atomic change: the marker is marked spent, `out` is credited to the
recipient as a plain balance credit (no code runs, even for a contract), the
base part of the fee is burned, the tip is paid to the header's coinbase, the
remainder is appended with the receipt log, and `out + fee` is added to the
total out. On any error nothing of it is written.

The ancestry is always walked by parent hash from the including block, never
through the canonical number index, so a root or base fee of a side block the
node happens to store is never used. A header the chain cannot give ends the
walk and the reveal is rejected. The walk for the root goes back to the
genesis if it has to, so its cost grows with the chain; an index of eligible
roots is left for later.

### Binding digest

`K("ghost/coin-reveal-binding/v1", fields)` over 415 bytes: chain id (8),
version (2), domain (32, the genesis block hash), statement `0x01`, statement
version `0x01`, type `COIN` (2), purpose `0x01`, root, marker and remainder
(32 each), recipient (20), out and fee (32 each), rule (32 zero bytes) and the
remainder's note (156). The node fills in the chain id, version, domain and
rule itself; the proof field is not covered.

### Fee

For an including block at height `H`, the window is `w = floor(H / 4)` and
`b_ref` is the base fee of block `4w`, found in the including block's ancestry
(the including block itself when `H = 4w`). With `U0 = b_ref` and
`U(j+1) = U(j) + floor(U(j)/8) + floor(U(j)/20000) + 1`, the price is `U3`,
the base part `G_PRIV * price`, the tip `ceil(base part / 10)` and the fee
`base part + tip`. For `b_ref = 10^9` the fee is 33036375802978007; for
`b_ref = 1.1 * 10^9` it is 36340013362396340.

## Proof verifier

`ghostpriv.Verifier` checks a proof against `VerifyInputs`, the binding digest
and public fields the node computed. Block processing uses
`ghostpriv.ActiveVerifier()`, which is `DefaultVerifier()` unless
`ghostpriv.SetVerifier` installed another. In a build without the proof
verifier the default rejects every reveal with `ErrNoVerifier`, so such a node
can process commits but rejects every block that carries a reveal. Release
builds (`ghostrelease`) and builds with the `ghostproofs` tag link the
`ghostverifier` static library instead (`core/ghostpriv/verifier_cgo.go`,
built by `go run build/ci.go ghostverifier`).

The linked verifier checks coin reveals through `ghost_proofs.h`, the pinned
ghost-proofs header, and data reveals and revokes through
`ghostverifier/ghost_data.h`, which the `ghostverifier` crate adds around the
one data verifier of ghost-proofs, `verify_data_reveal`. A data reveal and a
data revoke differ only in the purpose byte that starts the statement: `0x02`
or `0x03` in the codes of ghost-proofs, to which the node maps its own
`PurposeReveal` (`0x01`) and `PurposeRevoke` (`0x02`), then the root, marker, party (the verifier-or-recipient address
left-padded to 32 bytes), fee and rule, 32 bytes each. A kind or purpose it
does not verify is `ErrProofStatement`, without calling it; every answer but
acceptance is `ErrProofRejected`.

The data reveal fee is not settled, and the pinned ghost-proofs rejects every
data reveal and revoke with `DataFeeUnsettled`, whatever the proof. The
release node therefore rejects all of them, with `ErrProofDataFeeUnsettled`
wrapped by `ErrProofRejected` for a well-formed proof (and its own data fee
check rejects them before that by default). The accept path with real proofs
is proved only in the crate's own tests, `ghostverifier/tests/data_reveal.rs`,
with the test-only cargo feature `unsettled-points-test`, which adds
`ghost_verify_data_reveal_unsettled`. That feature is off by default, never
enabled by `build/ci.go` or the release build, and its function is not in the
release node. The data lifecycle with real proofs on a release node needs the
fee settled first.

`core/ghostpriv/ghostprivtest` holds the stub verifier for tests: it accepts
exactly a proof field whose first 32 bytes are
`K("ghost/test-proof/v1", binding digest)` and whose other bytes are zero, and
checks nothing else. Only `_test.go` files may import it.

## Accounting

The totals account holds `total_in` in slot 0 and `total_out` in slot 1, 32-byte
big-endian, and gets nonce 1 when first written so that the empty-account
cleanup never deletes it. The hidden total is `total_in - total_out`
(`ghostpriv.Hidden`). After every block:

    sum of public balances + hidden total
      = sum of block rewards and genesis allocations
        - (base fee * gas used of every ordinary transaction
           + base part of every reveal)

`TestAccountingInvariantRandomized` checks this after every block of a seeded
random run of transfers, commits and reveals. The seed is fixed by default,
printed, and set with `GHOST_INVARIANT_SEED`.

## Receipts

Both logs have the coin tree account as address.

| Log | Topics | Data |
|---|---|---|
| commit, version 1 | `K("ghost/commit-receipt/v1")` | tree index (4), position (4), leaf (32), `v` (32), note (156): 228 bytes |
| commit, salted | `K("ghost/commit-receipt/v1")` | tree index (4), position (4), leaf (32), `v` (32), note (156), salt (16): 244 bytes |
| reveal | `K("ghost/reveal-receipt/v1")`, marker | tree index (4), position (4), remainder (32), note (156), recipient (20), out (32) |

The log of a salted commit is the version 1 log with the salt appended after
the note; the logs of version 1 commits and of reveals do not change. The
tree history reads both commit lengths and keeps the salt with the leaf and
note ([trees and headers](trees-and-headers.md)); a reveal remainder has no
salt there, its salt is in its note. The layout is an internal-test value,
changed with the transaction-format specification. An append whose tree
index does not fit four bytes is rejected.

## Exported API

For the wallet and the tests that build on this:

- `ghostpriv.Reveal` with `MarshalBinary` (the envelope), `BindingDigest` and
  `BindingInput`; `ghostpriv.DecodeReveal` (checks 1 to 3);
- `ghostpriv.SaltedCommitData(F, salt, note)`, the 206 bytes of a salted
  commit (`SaltedCommitVersion`, `SaltedCommitDataSize`), and
  `ghostpriv.CommitData(F, note)`, the 190 bytes of a version 1 commit;
- `ghostpriv.Commitment(F, v)`;
- `ghostpriv.WindowFee(b_ref)` and `ghostpriv.WindowStart(H)`;
- `ghostpriv.CheckReveal` and `ghostpriv.ApplyReveal`, which block processing
  calls;
- `types.NewGhostRevealTx(envelope)`, which wraps an envelope into a
  transaction of type `0x50`;
- `ghostprivtest.Verifier` and `ghostprivtest.Proof(binding digest)`.

## What is not here

Reveals reach a block only through the chain maker of the tests
(`core/chain_makers.go`): the pool, the miner, the RPC submission methods and
the peer protocol do not handle type `0x50` yet. The history store of
[trees and headers](trees-and-headers.md) is not fed from these receipts yet.
The only rule is the empty one. The data tree has its own commit and its own
reveal, type `0x51`, in [data commit and data reveal](data-commitments.md);
a coin reveal is never checked as a data reveal, or the other way round.
