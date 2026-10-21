# Account transactions

An account on Ghost is held with a quantum-safe signature from genesis
(spec 09 of the Ghost repository, `docs/spec/09-quantum-safe-accounts.md`).
This node takes the account transaction, a native transaction type of its
own, in blocks and in the transaction pool. This document describes what the
node does; the spec is the authority on the format.

## The type byte

The account transaction is type `0x52`. Spec 09 proposes `0x51`, but `0x51`
is the data reveal in this node (`core/types/tx_ghost_private.go`,
docs/data-commitments.md) and keeps that meaning.

## Encoding

The envelope is the type byte followed by an RLP list of exactly twelve
items (`core/types/tx_ghost_account.go`):

| # | Field | Encoding |
|---|---|---|
| 1 | `chain_id` | integer |
| 2 | `nonce` | integer, 64 bits |
| 3 | `max_priority_fee_per_gas` | integer |
| 4 | `max_fee_per_gas` | integer |
| 5 | `gas_limit` | integer, 64 bits |
| 6 | `to` | 20 bytes, or the empty string for a contract creation |
| 7 | `value` | integer |
| 8 | `data` | bytes |
| 9 | `access_list` | EIP-2930 list |
| 10 | `scheme` | exactly 2 bytes, big-endian |
| 11 | `public_key` | bytes, the scheme's exact length |
| 12 | `signature` | bytes, the scheme's exact length |

Decoding is strict, and nothing is repaired: an envelope is refused for any
other number of items, an integer with a leading zero byte or of more than
256 bits, a non-canonical size, any byte after the list, an unknown scheme or
a key or signature of the wrong length. The transaction hash is
`keccak256(0x52 || rlp(list))`. Receipts of account transactions are typed
receipts with type byte `0x52`. In JSON the transaction carries the fields of
a type `0x02` transaction, without `v`, `r` and `s`, and `scheme`,
`publicKey` and `signature`.

## Schemes

| Scheme | Algorithm | Public key | Signature | Accepted |
|---|---|---|---|---|
| `0x0001` | ML-DSA-44 (FIPS 204, pure mode) | 1,312 bytes | 2,420 bytes | yes |
| `0x0002` | the hash-based scheme of spec 09 | 32 bytes | 7,856 bytes | no: decoded by its lengths, refused by the signer |

Scheme `0x0000` and every other value are refused when the transaction is
decoded, before any signature is verified.

The ML-DSA-44 verifier and signer are those of
`github.com/cloudflare/circl` v1.6.1, package `sign/mldsa/mldsa44`, with the
context string `ghost/tx/v1`. Signatures are hedged.

## Sender and signature

`K(tag, parts...)` is Keccak-256 over one byte holding the tag's length, the
ASCII tag and the parts in order (spec 01, section 2).

```
sender   = first 20 bytes of K("ghost/account-address/v1", scheme, public_key)
unsigned = rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas,
                gas_limit, to, value, data, access_list, scheme, public_key])
sighash  = K("ghost/account-tx/v1", 0x52, genesis_hash, keccak256(unsigned))
```

The signature is ML-DSA-44 over the 32-byte `sighash`. There is no key
registry and no public key recovery: the sender is derived from the key the
transaction carries. The vectors of `TestGhostAccountTxSenderVectors` are
computed independently of the node by the pure Keccak-256 of
`scripts/test_ghost_account_vectors.py`, which also checks them against the
Go test.

The signer is `types.NewGhostAccountSigner(base, genesisHash)`. It handles
type `0x52` itself and passes every other type to the base signer. Its
checks run in order and stop at the first failure: the scheme is accepted,
the key and signature have its lengths, the chain ID is the signer's, the
sender is derived, and the signature is verified last. A signer with a zero
genesis hash refuses every account transaction. Block processing, the chain
makers and the miner use the chain's genesis hash; `core.ApplyTransaction`
does when it is given the chain, and refuses account transactions otherwise.

## Intrinsic gas

```
intrinsic_gas = type 0x02 intrinsic gas
              + 16 * (2 + len(public_key) + len(signature))
              + VERIFY_GAS[scheme]
```

For ML-DSA-44 the extra part is 16 * 3,734 + 3,000 = 62,744 gas, so a plain
transfer takes 83,744 gas. The extra part is carried as
`core.Message.ExtraIntrinsicGas`, set by `core.TransactionToMessage` and
added where the state transition adds the intrinsic gas. The constants are in
`params/ghost/accounttx.go`.

A scheme whose `VERIFY_GAS` is zero has no transaction accepted (spec 09,
section 13): `core.GhostAccountExtraIntrinsicGas` refuses it.

### Measuring VERIFY_GAS

`VERIFY_GAS = ceil(t_ms * 10,000)` rounded up to the next multiple of 1,000
gas, where `t_ms` is the slowest of at least 1,000 verifications, of valid
and invalid signatures, measured in the work area (spec 09, section 8.2).
`BenchmarkGhostAccountTxVerifySlowest` in `core/types` is that measurement:
2,000 verifications, 1,000 of valid signatures and 1,000 of signatures with
one bit changed, each over a different key and transaction and timed one by
one, the public key decoding included.

| | |
|---|---|
| Scheme | `0x0001`, ML-DSA-44 |
| Machine | linux/arm64 virtual machine, 16 CPUs, implementer `0x61` (Apple silicon) |
| Go | go1.26.9 |
| circl | v1.6.1 |
| Verifications | 2,000 (1,000 valid, 1,000 invalid) |
| Fastest | 0.0448 ms |
| Median | 0.0454 ms |
| Slowest, `t_ms` | 0.2865 ms |
| `ceil(t_ms * 10,000)` | 2,866 |
| `VERIFY_GAS[0x0001]` | **3,000** |

The slowest verification is about six times the median: it is a scheduling
or memory outlier of the machine, which the rule takes on purpose. The value
should be measured again on the slowest machine Ghost means to support before
launch; it is a consensus constant and changes only with a network upgrade.
`BenchmarkGhostAccountTxVerify` measures the typical verification.

## The transaction pool

The legacy pool admits type `0x52` when its chain gives its genesis block
(`core.BlockChain` does): it then wraps its signer with the genesis hash and
lists the type in `Filter` and in the accepted types of its validation. A
pool whose chain gives no genesis block keeps the plain signer and refuses
every account transaction.

The cheap checks run before the signature check: the type, the size, the
canonical decoding, the scheme and the lengths, the chain ID, the derived
sender, no code at the sender (EIP-3607), the nonce, the balance and the
intrinsic gas. The signature is verified last, in
`txpool.ValidateTransactionWithState`, and the sender is then cached in the
transaction.

## Bounded signature checks

A signature check costs far more than any other check of a transaction, so
the node bounds them (spec 09, sections 8.3 and 8.4): a peer or an RPC client
sending transactions with invalid signatures cannot make the node verify more
than it can afford.

### Order of the checks

The cheap checks of the pool, above, run first: the stateless ones in
`txpool.ValidateTransaction`, then the state checks under the pool lock. A
transaction that fails one is refused before it takes a slot of the
signature queue, and its signature is never verified. Only then is the
signature verified, on the verifier's workers and outside the pool lock; the
sender is cached in the transaction, so adding it to the pool afterwards does
not verify it again.

### The verifier

`txpool.SigVerifier` (`core/txpool/sigcheck.go`) verifies the signatures of
the legacy pool on a fixed number of workers, from a bounded queue. The queue
is split: 3 slots in 4 are for transactions from peers, 1 in 4 for
transactions submitted locally by RPC (the pool's local transactions). A
slot is held while the check waits or runs. When a transaction finds its
share full:

- from a peer, it is dropped unverified;
- from RPC, the submission fails with the error `signature queue busy`,
  JSON-RPC code `-32005`.

A batch that already has checks of its own in the queue waits for one of them
to free a slot instead; it drops a transaction only when the share is full
without it.

A signature that fails is kept in a bounded cache of recent failures, keyed
by the signature hash and the public key, and the signature itself: the same
failing transaction is refused from the cache, not verified again. The
signature is part of the key because ML-DSA signatures are hedged: another
signature of the same key over the same hash may be valid, and is verified.

### Budgets

Each peer has a budget of account transactions it may have verified per
second, a token bucket refilled every second (`eth/handler.go`). A
transaction beyond it is dropped unverified, and an announcement is fetched
only for as many unknown account transactions as the budget has left. A
transaction already in the pool costs nothing. A transaction from a peer the
node cannot identify is dropped before it takes a slot.

RPC has two budgets, token buckets refilled every second as well
(`internal/ethapi/api.go`): one for each connection, told apart by its remote
address (`rpc.PeerInfoFromContext`), and one for all connections together.
A submission beyond either fails with the error `signature budget exceeded`,
JSON-RPC code `-32005`, before it reaches the pool.

### Peers

A peer that sends a transaction whose signature fails, verified or found in
the failure cache, is disconnected. A transaction refused by the state, a
stale nonce or a balance already spent, is not held against the peer.

### The bounds and their measurement

The bounds are node settings, not consensus constants, in
`params/ghost/accounttx.go`. None is zero (`TestSignatureLimitsAreSet`).
They are derived from the measurement of ML-DSA-44 verification recorded
above for `VERIFY_GAS` (`BenchmarkGhostAccountTxVerifySlowest`: 2,000
verifications on the linux/arm64 machine of 16 CPUs; median 0.0454 ms,
slowest 0.2865 ms), taking the slowest verification as the cost of every
one:

| Constant | Value | Derivation |
|---|---|---|
| `SigVerifyWorkers` | 4 | a quarter of the 16 CPUs, leaving the rest to block processing and the network: 4 / 0.2865 ms = 13,961 verifications per second at worst, 88,105 at the median |
| `SigVerifyQueue` | 256 | the last check of a full queue waits 256 × 0.2865 ms / 4 = 18.3 ms at worst, 2.9 ms at the median; 192 slots for peers, 64 for RPC |
| `SigPeerBudget` | 200 per second | the peers' 3 quarters of the workers, 10,471 per second at worst, over the default 50 peers is 209, rounded down |
| `SigRPCBudget` | 3,000 per second | the RPC quarter of the workers, 3,490 per second at worst, rounded down |
| `SigRPCConnBudget` | 300 per second | a tenth of the RPC budget, so that one connection cannot take it all |
| `SigFailureCacheSize` | 4,096 | entries of 96 bytes, well under 1 MiB; a peer that sends a failure is disconnected, so the cache serves the same failure sent again by other peers |

The values should be measured again on the slowest machine Ghost means to
support before launch, as `VERIFY_GAS` is. `TestSignatureFloodStaysWithinWorkers`
floods the pool from 24 peers at once and checks that no more signatures are
verified at once than there are workers, that a transaction beyond the
peers' share is dropped unverified, and that none is verified twice.

## Signatures in a block

A block's signatures are checked only after its seal and header checks pass
(spec 09, section 8.3, item 7). On import (`core/blockchain.go`), the sender
recovery of a block, which verifies the signatures of its account
transactions, starts only once the engine's result for the block's header,
the seal check included, came back clean; a block whose header fails has
none of its signatures verified. The signatures of a block are verified in
parallel on the workers of `core.SenderCacher`, one per CPU, with the
block's own signer bound to the chain's genesis, and the senders are cached
in the transactions, so executing the block does not verify them again.
`TestBlockSignaturesVerifiedOnlyAfterSeal` holds the header results back and
checks that no signature is verified before a block's result, that the
signatures of a block whose header passed are, and that none of a block
whose seal failed is.

## Block gas limit and message size

The consensus maximum block gas limit is 30,000,000 gas, `MaxBlockGasLimit`
in `params/ghost/gaslimit.go`. Spec 09, section 8.4, asks for a limit under
41,943,040 (10 MiB at 4 gas per zero calldata byte) minus the header and RLP
overhead; 30,000,000 is also the default gas limit of the internal network.

- The Ghost engine (`consensus/randomx`) refuses a header whose gas limit is
  above it (`TestGasLimitAboveConsensusMaximumRejected`), whatever the step
  from its parent. The older engines keep their own rule.
- The miner clamps its target gas ceiling to it when it prepares a block
  (`miner/worker.go`), so a block it builds never votes the limit above it,
  whatever `--miner.gaslimit` asks for (`TestMinerNeverVotesAboveMaxGasLimit`).

QS-9 (`TestMaxBlockFitsMessageCap`, `eth/protocols/eth`) builds the block
with the most bytes at that limit: a zero calldata byte costs 4 gas, less per
byte than any other part of a transaction, and each transaction costs 83,744
gas of overhead for some 3,800 bytes, so the most bytes come from one account
transaction whose calldata is all zeros and fills the block. It checks every
message that carries the block, and the pooled transactions reply, against
the message cap of 10 MiB (10,485,760 bytes). Measured sizes:

| Message | Bytes | Under the cap by |
|---|---|---|
| The block: 30,000,000 gas used, 7,479,064 calldata bytes | 7,483,375 | |
| New block message, the largest total difficulty a peer accepts (100 bits) | 7,483,393 | 3,002,367 |
| Block bodies response, the largest body alone | 7,482,880 | 3,002,880 |
| Block bodies response, the largest body after one of 2 MiB less one byte | 9,580,031 | 905,729 |
| Pooled transactions reply, transactions of 128 KiB, the largest the pool takes | 2,097,233 | 8,388,527 |

The serving handler stops adding bodies or transactions to a reply once it
holds 2 MiB, so its largest reply is the largest item after just under
2 MiB: the second bodies response above. Any larger block gas limit narrows
the 905,729-byte margin by a quarter byte per gas.

## Not yet in this node

Refusing the secp256k1 transaction types, the signature-verify contract,
the node's own signing and its remote procedure calls, and scheme `0x0002`
are separate pieces of work.
