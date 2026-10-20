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

## Not yet in this node

Refusing the secp256k1 transaction types, the signature-verify contract,
bounds on signature checks in the pool and on the wire, the node's own
signing and RPC, and scheme `0x0002` are separate pieces of work.
