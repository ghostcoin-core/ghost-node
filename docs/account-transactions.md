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
| `0x0002` | SLH-DSA-SHAKE-128s (FIPS 205, pure mode) | 32 bytes | 7,856 bytes | yes |

Scheme `0x0000` and every other value are refused when the transaction is
decoded, before any signature is verified.

The key and signature lengths are checked against the scheme before any
signature is verified, when the transaction is decoded and again by the
signer: an ML-DSA-44 key or signature under `0x0002`, or an SLH-DSA key or
signature under `0x0001`, is refused with the length error and never reaches
a verifier (QS-4, `TestGhostAccountTxSLHDSA` and `TestGhostPoolSLHDSA`).

Both schemes come from `github.com/cloudflare/circl` v1.6.5, with the
context string `ghost/tx/v1`:

- ML-DSA-44: package `sign/mldsa/mldsa44`. Signatures are hedged.
- SLH-DSA-SHAKE-128s: package `sign/slhdsa`, parameter set `SHAKE_128s`
  only, pure mode: signing is FIPS 205 algorithm 22 and verification
  algorithm 24, over the 32-byte `sighash` as the message. A signature in
  prehash mode (HashSLH-DSA) or with any other context does not verify.
  `types.SignGhostAccountTxSLHDSA` signs with randomized signatures, and
  refuses a key of any other parameter set.

## Sender and signature

`K(tag, parts...)` is Keccak-256 over one byte holding the tag's length, the
ASCII tag and the parts in order (spec 01, section 2).

```
sender   = first 20 bytes of K("ghost/account-address/v1", scheme, public_key)
unsigned = rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas,
                gas_limit, to, value, data, access_list, scheme, public_key])
sighash  = K("ghost/account-tx/v1", 0x52, genesis_hash, keccak256(unsigned))
```

The signature is of the transaction's scheme over the 32-byte `sighash`. There is no key
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
transfer takes 83,744 gas. For SLH-DSA-SHAKE-128s it is
16 * (2 + 32 + 7,856) = 126,240 byte gas plus 12,000, 138,240 gas, so a
plain transfer takes 159,240 gas. The extra part is carried as
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

`BenchmarkGhostAccountTxSLHDSAVerifySlowest`, beside it, is the same
measurement for SLH-DSA-SHAKE-128s. Signing takes some 0.55 s, so it signs
10 transactions with 10 keys and verifies them in turn: 1,000 verifications
of valid signatures and 1,000 of signatures with one bit changed, a
different bit each time, timed one by one, the public key decoding included.
It was run three times; the table takes the slowest of the 6,000.

| | |
|---|---|
| Scheme | `0x0002`, SLH-DSA-SHAKE-128s |
| Machine | linux/arm64 virtual machine, 16 CPUs, implementer `0x61` (Apple silicon), the machine of the ML-DSA-44 measurement |
| Go | go1.26.9 |
| circl | v1.6.5 |
| Verifications | 3 runs of 2,000 (1,000 valid, 1,000 invalid) |
| Fastest | 0.4565 ms |
| Median | 0.5359, 0.5390 and 0.5372 ms |
| Slowest of each run | 0.9998, 1.1932 and 0.9968 ms |
| Slowest, `t_ms` | 1.1932 ms |
| `ceil(t_ms * 10,000)` | 11,932 |
| `VERIFY_GAS[0x0002]` | **12,000** |

On the same runs ML-DSA-44 verified with a median of 0.046 to 0.048 ms and a
slowest of 0.24 to 0.32 ms, as recorded above: `VERIFY_GAS[0x0001]` stays
3,000.

### Measuring SIGVERIFY_WORD_GAS

The signature-verify precompile at `0x51`
([EVM profile](ghost-evm-profile.md#the-signature-verify-precompile)) charges
`VERIFY_GAS[scheme]` plus `SIGVERIFY_WORD_GAS` for each 32-byte word of the
message. `SIGVERIFY_WORD_GAS = ceil(t_ms * 10,000)`, and at least 1, where
`t_ms` is the slowest of at least 1,000 measured costs of one extra word of
message, of valid and invalid signatures, the same way as `VERIFY_GAS`.
`BenchmarkSignatureVerifyWordGasSlowest` in `core/vm` is that measurement:
for 1,000 valid signatures and 1,000 signatures with one bit changed, each
over a different key, it times the verification of a one-word message and of
a message 1,024 words longer; the cost of one extra word is the difference
divided by 1,024.

| | |
|---|---|
| Scheme | `0x0001`, ML-DSA-44 |
| Machine | linux/arm64 virtual machine, 16 CPUs (the same machine as above) |
| Go | go1.26.9 |
| circl | v1.6.1 |
| Measured costs | 2,000 (1,000 valid, 1,000 invalid) |
| Median | 0.000047 ms per word |
| Slowest, `t_ms` | 0.000398 ms per word |
| `ceil(t_ms * 10,000)` | 4 |
| `SIGVERIFY_WORD_GAS` | **4** |

The value is in `params/ghost/accounttx.go` as `SigVerifyWordGas`, and a test
there keeps it above zero. Like `VERIFY_GAS`, it should be measured again on
the slowest machine Ghost means to support before launch.

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
They are derived from the slower of the two schemes' slowest verification,
recorded above for `VERIFY_GAS`: SLH-DSA-SHAKE-128s, slowest 1.1932 ms
(`BenchmarkGhostAccountTxSLHDSAVerifySlowest`, 6,000 verifications on the
linux/arm64 machine of 16 CPUs; median 0.537 ms), against 0.2865 ms for
ML-DSA-44. Any transaction may carry the dearer scheme, so every slot of the
queue is paid at that cost:

| Constant | Value | Derivation |
|---|---|---|
| `SigVerifyWorkers` | 4 | a quarter of the 16 CPUs, leaving the rest to block processing and the network: 4 / 1.1932 ms = 3,352 verifications per second at worst, 7,449 at the SLH-DSA median, 88,105 at the ML-DSA-44 median |
| `SigVerifyQueue` | 256 | the last check of a full queue waits 256 × 1.1932 ms / 4 = 76.4 ms at worst, 34.4 ms at the SLH-DSA median; 192 slots for peers, 64 for RPC |
| `SigPeerBudget` | 50 per second | the peers' 3 quarters of the workers, 2,514 per second at worst, over the default 50 peers is 50.3, rounded down |
| `SigRPCBudget` | 800 per second | the RPC quarter of the workers, 838 per second at worst, rounded down |
| `SigRPCConnBudget` | 80 per second | a tenth of the RPC budget, so that one connection cannot take it all |
| `SigFailureCacheSize` | 4,096 | entries of 96 bytes, well under 1 MiB; a peer that sends a failure is disconnected, so the cache serves the same failure sent again by other peers |

`TestSignatureLimitsAreSet` checks the peer and RPC budgets against the
dearest scheme's `VERIFY_GAS`, which bounds its slowest verification from
above. An SLH-DSA transaction carries 7,890 bytes of scheme, key and
signature; a plain transfer is some 8 KB, far under the pool's cap of
128 KiB a transaction (`TestGhostPoolSLHDSA`).

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

## Node records

A quantum-safe node record (spec 09, section 10.3) is
`rlp([seq, scheme, public_key, ip, tcp_port, udp_port, fork_id, signature])`,
signed by the node's ML-DSA-44 key over
`K("ghost/node-record/v1", rlp of the fields before the signature)`; its node
ID is the `p2p/qsconn` node ID of its scheme and public key. The type, its
decoding and its verification are `enode.QSRecord` (`p2p/enode/qsrecord.go`);
the signing is `qsconn.Identity.SignRecord` (`p2p/qsconn/record.go`). It is
a type of its own next to the secp256k1 ENR of `p2p/enr`, and neither turns
into the other.

A record over 4,096 bytes (`QSRecordMaxSize`) is dropped before it is
decoded; one with an unknown scheme, a public key or signature of the wrong
length, or an IP of neither 4 nor 16 bytes is dropped before its signature
is verified; one whose signature fails is dropped (`TestQSRecordDropped`).

`enode.QSRecordCache` holds verified records, one per node ID, the one of
the highest `seq`, and is the only place records are handed out from, so a
node never relays one that has not verified. A record is verified once
(`TestQSRecordCacheVerifiesOnce`):

- a record whose node ID and `seq` are cached is answered from the cache,
  whatever its signature bytes; an older `seq` is dropped unverified;
- copies of the same record that arrive while it is verified wait for that
  verification;
- a record whose signature failed is remembered by the hash of its encoding,
  in a bounded memory as large as the cache, and refused without verifying
  it again.

The cache drops its least recently used record when full, and verifies a
bounded number of records per second over all sources, a token bucket
refilled every second; a record beyond it is dropped unverified and not
cached (`TestQSRecordCacheBounds`). The limits are node settings in
`p2p/enode/qsrecord.go` (`TestQSRecordCacheLimitsAreSet`):

| Constant | Value | Derivation |
|---|---|---|
| `QSRecordCacheSize` | 4,096 records | 18.0 MB of heap measured for a full cache (`BenchmarkQSRecordCacheMemory`: 17,976,888 bytes, some 4,390 bytes for each record of 3,764 encoded bytes) |
| `QSRecordVerifyRate` | 100 per second | one verification measured at 0.053 ms (`BenchmarkQSRecordVerify`); over 2,000 verifications the median was 0.049 ms and the slowest 0.565 ms, so the budget costs at most 57 ms of one CPU a second, under 6%, and 5 ms at the median |

Measured on the linux/arm64 machine of 16 CPUs used for the signature bounds
above; they should be measured again on the slowest machine Ghost means to
support before launch.

## Peer discovery

`p2p/qsdisc` finds peers by node ID over UDP (spec 09, section 10.3). It is
built on `qsconn.NodeID` and `enode.QSRecord` alone, with no secp256k1 key
and nothing of the old discovery. Four packets, one type byte and an RLP
body: ping and pong, findnode and neighbors. A ping and a findnode each
carry a random 16-byte token that the pong or neighbors answer echoes. They
carry node IDs and UDP endpoints only, never a record or a
signature, so nothing in them is trusted on its own:

- A packet over 1,280 bytes is dropped before it is decoded, and a neighbors
  packet of more than 16 entries is refused.
- An endpoint is proven when it answers a ping we sent with a pong carrying
  our token, from the same address; a pong is accepted only for a pending
  ping to that address with that token. A node answers a findnode only from
  a proven endpoint, and sends an unproven one nothing larger than its
  request: a ping gets a pong of the same size, and a ping back to prove it.
- Every pong carries a 16-byte cookie for the endpoint and node ID of the
  ping it answers: a keyed hash of the endpoint, the ID and a 6-hour period
  under a secret of the node. It is accepted in its period and the next, so
  it expires at most 12 hours after it was given, with the proof, and the
  requester fetches a new one after 3 hours. The endpoint puts it in its
  later pings and findnodes to the node. A pong gives a cookie only when it
  answers our ping with our token, and it is kept with the endpoint and
  with the table node.
- A findnode is answered only when it carries the cookie the node gave that
  endpoint and ID and the cookie has not expired; any other findnode is
  dropped before it is charged or answered. A proven endpoint alone is not
  enough: a findnode forged from a proven peer's address cannot carry the
  peer's cookie, so it cannot make the node send the peer neighbors packets
  it did not ask for. A neighbors answer is also never larger than twice
  the findnode it answers (`MaxAmplification`); it holds fewer nodes when a
  full one would be larger. A findnode is padded to 640 bytes
  (`FindnodeSize`) so that a full answer of 16 IPv6 endpoints, 921 bytes,
  fits.
- Every ping and findnode of a source IP is charged to its one token bucket,
  whatever its port and cookie, so one source IP gets at most 10 requests a
  second with a burst of 20 however it mixes them. The last 10 packets of
  the bucket (`CookieReserve`) are taken only by a request with the right
  cookie, which packets forged from the address do not carry, so they
  cannot use up the allowance of the peer's live checks of the node and so
  cannot make the peer evict it.
- A neighbors answer completes a lookup's findnode only when it echoes that
  findnode's token and comes from the endpoint asked; a forged answer,
  empty or not, is ignored and the findnode stays pending for the real one.
- A node trusts an endpoint for an ID only after it has proven the endpoint
  (its pong names that ID) and the `RecordVerifier` has fetched the ID's
  record from it and verified it. The record is accepted only when it is of
  the ID asked for and its IP and UDP port are the endpoint that answered;
  anything else is refused, never guessed at. A ping from an unknown ID and
  every entry of a neighbors answer go through this before they enter the
  table, a lookup result or an answer. The real verifier fetches the record
  over qsconn and passes it through `enode.QSRecordCache`, so the signature
  budget is still the 100 verifications a second of `QSRecordVerifyRate`.
- A verification in progress, the one-minute wait between two
  verifications and a failed verification are all kept per node ID and
  endpoint, not per ID alone. Anyone can claim any ID at their own
  endpoint, so a peer that claims an honest ID there and fails cannot hold
  up, or get refused, the honest node at its own endpoint. This does not
  widen the budget: each start still takes one of the at most 8 running
  verifications and one of the at most 1,024 starts a minute, over all IDs
  and endpoints, and the record cache still verifies at most 100
  signatures a second.
- A verification a peer triggers while all 8 slots are busy is queued, at
  most 64 queued with the oldest dropped first, and started once a slot is
  free under the same budgets.

The table holds verified nodes in 17 buckets by log distance, checks the
node checked longest ago every second when it was last checked over 10
seconds ago, and replaces a node that does not answer with the newest of the
bucket's replacement candidates. A node is removed when the pong to its live
check named another ID, or when 3 live checks in a row were sent and no pong
came: one lost pong does not evict a live node. A check that could
not be sent, for example because no ping slot was free, removes nothing and
is tried again. Of the 512 pending pings at most 448 can be pings that a
peer triggered (a ping back to an unproven endpoint, or the ping of a
verification it caused) and at most 32 can be challenge pings, so the
rest are always free for the node's own live checks and lookups. A table
node's endpoint proof can be pushed out of the 1,024 endpoints a node
keeps by pings from new sources; when that node pings again, the node
sends it one challenge ping, and answers its findnodes only once the
pong with that ping's token has proven the endpoint again. Challenge
pings have their own 32 slots, so a flood filling the 448 cannot stop
them, and at most one is pending for an endpoint. A lookup asks the closest verified nodes a
few at a time, verifies every node they name and returns verified nodes
only (`TestQSDiscovery`).

Everything a remote peer can make a node hold or do is bounded, by node
settings in `p2p/qsdisc/limits.go` (`TestQSDiscoveryLimitsAreSet`):

| Constant | Value | What it bounds |
|---|---|---|
| `MaxPacketSize` | 1,280 bytes | a packet; the largest a node sends, a neighbors packet of 16 IPv6 endpoints, is 921 bytes |
| `MaxNeighbors` | 16 | entries in a neighbors packet, the bucket size |
| `MaxAmplification`, `FindnodeSize` | 2 times, 640 bytes | a neighbors answer is at most twice the bytes of its findnode; a findnode is padded to 640 bytes so that a full answer fits |
| `NumBuckets`, `BucketSize` | 17 buckets of 16 nodes | the table, as in the old table |
| `MaxReplacements` | 10 per bucket | replacement candidates |
| `BucketIPLimit`, `TableIPLimit` | 2 per /24 in a bucket, 10 in the table | addresses of one subnet, LAN addresses not counted, as in the old table |
| `ProvenTime` | 12 hours | how long an endpoint stays proven |
| `PingTimeout` | 5 seconds | how long a ping waits for its pong |
| `MaxPendingPings` | 512 | pings waiting for a pong |
| `MaxRemotePings` | 448 | of those, pings a peer can trigger |
| `MaxChallengePings` | 32 | of those, challenge pings that prove again the endpoint of a table node whose proof was pushed out; the other 32 stay for the node's own live checks and lookups |
| `MaxVerifications` | 8 | record verifications running at once; one a peer triggers beyond it is queued for a retry |
| `VerifyInterval` | 1 minute | the least time between two verifications started for one ID at one endpoint |
| `MaxVerifyStarts` | 1,024 | starts remembered, and so the most that start in a minute over all IDs and endpoints |
| `MaxVerifyRetries` | 64 | verifications a peer triggered queued for a free slot, the oldest dropped first |
| `MaxFailed` | 1,024 | the memory of failed verifications, the oldest dropped first |
| `SourceRate`, `SourceBurst` | 10 packets a second, burst 20 | pings and findnodes from one source IP, a token bucket; a packet over it is dropped without an answer. Every request of the source IP, with or without the cookie and from any port, is charged to that one bucket. A findnode without that cookie is dropped and charges nothing. A packet that does not decode is dropped and charges nothing, and a pong or neighbors packet is handled only when it answers a request we sent to that endpoint with its token, and charges nothing, so packets forged from a peer's address can neither stop its answers to our live checks and lookups nor its own live checks and lookups of us |
| `CookieReserve` | 10 packets | the last packets of a source's bucket, taken only by requests carrying the cookie the node gave their endpoint and ID, so that packets forged from the address leave the peer's own live checks of the node an allowance |
| `MaxRevalidateFails` | 3 | live checks in a row a table node may leave unanswered before it is removed |
| `MaxSources` | 1,024 | source IPs with a token bucket and endpoints with a proof, each the least recently seen dropped first; a dropped bucket starts full again, so pushing one out never takes from its peer |
| `LookupAlpha`, `LookupTimeout`, `LookupResults` | 3 at a time, 5 seconds each, 16 nodes | a lookup |

Measured on the linux/arm64 machine of 16 CPUs used for the bounds above:

- `BenchmarkTableMemory`: 3,084,248 bytes of heap (3.08 MB) for a node with
  every bucket and replacement list full (442 nodes), each holding a record
  of full size that nothing else references, 1,024 token buckets, 1,024
  proven endpoints, 1,024 failures, 1,024 remembered starts, 64 queued
  retries and 512 pending pings. A table node's record is the one the record cache holds, so in a
  running node most of it is shared with the 18.0 MB of the cache.
- `BenchmarkPacketDecode`: the largest packet, 921 bytes, decodes in
  2.1 µs with 4,076 bytes in 30 allocations. A packet is decoded before it
  is charged to its source, so decoding costs 2.1 µs a packet received, some
  21 ms of one CPU a second for 10,000 packets a second, about the cost of
  receiving them.

They should be measured again on the slowest machine Ghost means to support
before launch. Fetching a record over qsconn and starting discovery in the
p2p server are separate work.

## Not yet in this node

Refusing the secp256k1 transaction types, the node's own signing and its
remote procedure calls, and signing with SLH-DSA keys outside tests are
separate pieces of work.
