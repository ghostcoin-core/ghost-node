# The Ghost EVM profile

This page says which parts of the Ethereum execution layer a Ghost chain runs.
It is the published support matrix for contract authors, wallet and tool
builders, and node operators.

The tables are not only documentation. `params/ghost/evmprofile_test.go`
reads the first four tables and checks every row against the chain
configuration of the internal test network (`ghost.InternalNetGenesis()`) and
against the EVM, and it fails if the configuration or the EVM has something
these tables do not list. `tests/ghostprofile_test.go` reads the last table
and checks that every fixture fork it names exists. When the launch genesis
exists, the same tests are pointed at it.

Every status is one of these words:

* `on`: the chain runs it from block 0.
* `off`: the node has the code, as upstream does, but the chain configuration
  does not switch it on, and `params/ghost.CheckProfile` refuses a
  configuration that does.
* `absent`: the node has no way to switch it on. For an opcode, the byte is an
  invalid opcode on a Ghost chain.
* `failing`: only for a precompile Ghost removes. The address stays a
  precompile in every configuration, so it is warm from the start of every
  transaction, but every call to it fails and uses all the gas given to it,
  and a call that sends value fails and moves nothing.

## Forks and EIPs

A fork row stands for every execution change in that fork. The difficulty
bomb delays and difficulty formulas of those forks do not apply: blocks are
sealed with RandomX and its own difficulty rule. The BN254 precompiles that
Byzantium adds (EIP-196 and EIP-197, transitions EIP-212 and EIP-213) and
Istanbul reprices (EIP-1108) are not among them: on Ghost the addresses fail
in every configuration, whatever those transitions say (see
[Precompiles](#precompiles)). Shanghai and Cancun are only
partly on, so they are listed EIP by EIP rather than as forks. The fixture
fork is the execution-fixture configuration that exercises the row; see
[Execution fixtures](#execution-fixtures).

| EIP or fork | Status | Fixture fork |
|---|---|---|
| Frontier | on | Frontier |
| Homestead | on | Homestead |
| Tangerine Whistle (EIP-150) | on | EIP150 |
| Spurious Dragon (EIP-155, EIP-158/161, EIP-160, EIP-170) | on | EIP158 |
| Byzantium | on | Byzantium |
| Constantinople | on | Constantinople |
| Petersburg (removes EIP-1283) | on | ConstantinopleFix |
| Istanbul | on | Istanbul |
| Berlin | on | Berlin |
| London | on | London |
| EIP-1559 (fee market; the base fee is burned) | on | London |
| EIP-3651 (warm COINBASE) | on | Shanghai |
| EIP-3855 (PUSH0) | on | Shanghai |
| EIP-3860 (initcode limit and metering) | on | Shanghai |
| EIP-6049 (SELFDESTRUCT deprecation notice; no change in behaviour) | on | Shanghai |
| EIP-1153 (transient storage) | on | Cancun |
| EIP-5656 (MCOPY) | on | Cancun |
| EIP-6780 (SELFDESTRUCT only in the creating transaction) | on | Cancun |
| EIP-4895 (withdrawals) | off | none |
| EIP-4844 (blob transactions) | off | none |
| EIP-4788 (beacon block root contract) | off | none |
| EIP-7516 (BLOBBASEFEE) | off | none |
| EIP-4399 (PREVRANDAO) | off | none |
| EIP-2537 (BLS12-381 precompiles; the node has no code for them, so the transition switches nothing on) | off | none |
| EIP-2315 (subroutines) | off | none |
| EIP-7702 (set code for externally owned accounts) | absent | none |
| EIP-2935 (historical block hashes in state) | absent | none |
| EIP-6110 (deposits in the execution layer) | absent | none |
| EIP-7002 (execution-layer exits) | absent | none |
| EIP-7251 (higher maximum effective balance) | absent | none |
| EIP-7623 (higher calldata cost) | absent | none |
| EIP-7685 (execution-layer requests) | absent | none |
| EIP-7691 (more blobs per block) | absent | none |
| EIP-7840 (blob schedule in the configuration) | absent | none |
| EIP-7951 (secp256r1 signature precompile) | absent | none |
| Prague | absent | none |
| Osaka | absent | none |

EIP-7702 and the execution changes after Cancun are tracked items, not
assumptions: none of them is on, and adding one is a change to this profile
and to these tables.

## Opcodes

These are the opcodes added after Frontier, and the opcodes whose meaning on
a Ghost chain differs from Ethereum's. Every other Frontier opcode behaves as
in Frontier with the gas rules of the forks above.

| Opcode | Byte | Status | Note |
|---|---|---|---|
| DELEGATECALL | 0xf4 | on | Homestead |
| REVERT | 0xfd | on | Byzantium |
| RETURNDATASIZE | 0x3d | on | Byzantium |
| RETURNDATACOPY | 0x3e | on | Byzantium |
| STATICCALL | 0xfa | on | Byzantium |
| SHL | 0x1b | on | Constantinople |
| SHR | 0x1c | on | Constantinople |
| SAR | 0x1d | on | Constantinople |
| CREATE2 | 0xf5 | on | Constantinople |
| EXTCODEHASH | 0x3f | on | Constantinople |
| CHAINID | 0x46 | on | Istanbul |
| SELFBALANCE | 0x47 | on | Istanbul |
| BASEFEE | 0x48 | on | London |
| PUSH0 | 0x5f | on | EIP-3855 |
| TLOAD | 0x5c | on | EIP-1153 |
| TSTORE | 0x5d | on | EIP-1153 |
| MCOPY | 0x5e | on | EIP-5656 |
| DIFFICULTY | 0x44 | on | Also read as PREVRANDAO by compilers. Returns the block's difficulty, not randomness. |
| SELFDESTRUCT | 0xff | on | EIP-6780 meaning: deletes the account only if it was created in the same transaction; otherwise it only moves the balance. |
| BLOBHASH | 0x49 | absent | No blob transactions. |
| BLOBBASEFEE | 0x4a | absent | No blob transactions. |

## Precompiles

Ghost removes the elliptic-curve precompiles, which a quantum computer
breaks, and adds a quantum-safe signature-verify precompile (spec 09,
section 7). The removed ones are `failing`, not absent: a call to them fails
the same way in every configuration, and their addresses keep their warm
status.

| Address | Name | Status |
|---|---|---|
| 0x01 | ECRECOVER | failing |
| 0x02 | SHA256 | on |
| 0x03 | RIPEMD160 | on |
| 0x04 | IDENTITY | on |
| 0x05 | MODEXP (EIP-2565 pricing) | on |
| 0x06 | BN254 ADD | failing |
| 0x07 | BN254 MUL | failing |
| 0x08 | BN254 PAIRING | failing |
| 0x09 | BLAKE2F | on |
| 0x0a | POINT EVALUATION (EIP-4844) | failing |
| 0x0b | BLS12-381 (EIP-2537) | absent |
| 0x0c | BLS12-381 (EIP-2537) | absent |
| 0x0d | BLS12-381 (EIP-2537) | absent |
| 0x0e | BLS12-381 (EIP-2537) | absent |
| 0x0f | BLS12-381 (EIP-2537) | absent |
| 0x10 | BLS12-381 (EIP-2537) | absent |
| 0x11 | BLS12-381 (EIP-2537) | absent |
| 0x51 | SIGVERIFY (quantum-safe signature verify) | on |
| 0x0100 | P256VERIFY (EIP-7951) | absent |

### The signature-verify precompile

The precompile at `0x0000000000000000000000000000000000000051` verifies a
signature of one of the account transaction's schemes
([account transactions](account-transactions.md)). Its input is

```
scheme (2 bytes, big-endian) || ctx_len (1 byte) || ctx || public_key || signature || message
```

The public key and the signature have the exact lengths of the scheme, and
the message is the rest of the input. The output is 32 bytes: 1 for a valid
signature, 0 for an invalid one.

The call fails, and uses all the gas given to it, for a scheme that is not
accepted, for an input too short for its header, context, key and signature,
and for a context that begins with `ghost/tx/`, which is reserved for
transaction signatures. Only scheme `0x0001`, ML-DSA-44, is accepted: the
precompile takes the schemes and their verification gas from the account
transaction, so the two accept the same schemes. Scheme `0x0002` fails until
the node verifies it.

The gas is charged before the signature is verified:

```
gas = VERIFY_GAS[scheme] + SIGVERIFY_WORD_GAS * ceil(len(message) / 32)
```

with `VERIFY_GAS[0x0001] = 3,000` and `SIGVERIFY_WORD_GAS = 4`, both in
`params/ghost/accounttx.go` and measured as described in
[account transactions](account-transactions.md).

## Frozen policies

A frozen policy (spec 10, section 6) is a contract whose behaviour depends
only on its code and its input, and which never holds a balance. Only the
policy factory creates one. The rules are in `core/vm/frozen_policy.go`, the
addresses, hashes and registry helpers in `params/ghost/policy.go`.

### The factory

The factory is a native at `0x0000000000000000000000000000000000000062`. It
is not a precompile: it is not in the precompile set and its address is not
warm. A `CALL` with no value reaches it; a `CALL` with value fails and moves
nothing, and a `STATICCALL`, `CALLCODE` or `DELEGATECALL` to it fails and
uses up its gas. A call to it inside a static frame fails as a write would.

Its input is a 32-byte salt followed by the init code; its output is the
policy address as a 32-byte word. The policy is created at

```
address = K("ghost/policy-address/v1", salt, keccak256(init_code))[12:]
```

where `K` is the tagged hash of the trees: Keccak-256 over the tag's length
as one byte, the tag, then the inputs. The sender is not an input, so the
same code and salt give the same address whoever creates it. The factory
refuses an address that is reserved (below), an address that already has a
nonce or code, and, as `CREATE2` does, init code over 49,152 bytes, runtime
code over 24,576 bytes and runtime code that begins with `0xef`. A balance
already at the address is burned when the policy is created; it is not a
reason to fail.

The gas is charged before the constructor runs:

```
gas = 32,000 + (6 + 2) * ceil(len(init_code) / 32) + REGISTRY_GAS
```

the gas of a `CREATE2` of the init code (the 2 per word is EIP-3860's
initcode gas) plus `REGISTRY_GAS = 40,000` for the registry entry. The
constructor gets the rest of the call's gas and pays the code deposit of 200
per byte, as for `CREATE2`. A constructor that fails leaves nothing: no
account, no code, no registry entry, and the balance at the address stays.

### The registry

The registry is the storage of the system account
`0x67686f7374000000000000000000000000000009`, which gets nonce 1 when it is
first written. Each policy has two words:

| Word | Key | Value |
|---|---|---|
| 0 | `K("ghost/policy-registry/v1", address, 0x00)` | byte 0 is `0x01` (frozen); bytes 24 to 31 are the creation height, big-endian |
| 1 | `K("ghost/policy-registry/v1", address, 0x01)` | Keccak-256 of the runtime code |

An address is a policy exactly when its word 0 begins with `0x01`
(`ghost.IsRegisteredPolicy`).

### The frozen context

A frame is frozen when the address it runs as is a registered policy, or
when it is the constructor the factory runs. The flag is read once when the
frame starts. A `DELEGATECALL` or `CALLCODE` frame runs as its caller, so
policy code reached by `DELEGATECALL` from a contract that is not frozen runs
unfrozen, without the frozen context's access to the natives.

A frozen frame halts, using up its gas, on any of these opcodes, when the
opcode runs:

| Opcodes | Why |
|---|---|
| BALANCE, SELFBALANCE, EXTCODESIZE, EXTCODECOPY, EXTCODEHASH, SLOAD, SSTORE, TLOAD, TSTORE | state |
| ORIGIN, CALLER, GASPRICE, GAS | the transaction, the caller and the remaining gas |
| BLOCKHASH, COINBASE, TIMESTAMP, NUMBER, DIFFICULTY, GASLIMIT, CHAINID, BASEFEE, BLOBHASH, BLOBBASEFEE | the block and the chain |
| LOG0 to LOG4 | logs |
| CREATE, CREATE2, CALLCODE, DELEGATECALL, SELFDESTRUCT | creation, delegation and destruction |

Its `CALL` and `STATICCALL` halt unless the target is SHA256 (0x02),
RIPEMD160 (0x03), IDENTITY (0x04), signature verify (0x51), 0x60, 0x61, or a
policy created in an earlier block. MODEXP, BLAKE2F, the removed
precompiles, the factory, any contract that is not a policy and a policy
created in the same block are refused. The natives at 0x60 and 0x61 do not
exist yet: a call to them is allowed and, with no code there, succeeds as a
call to an empty account.

### No balance

A policy's balance is always zero:

* a `CALL` with value to a policy fails as a call without the balance would,
  and nothing moves;
* a transaction with value to a policy is invalid; with value zero it runs
  the policy;
* a `SELFDESTRUCT` that would move a non-zero balance to a policy halts;
* a block whose coinbase is a policy in its post-state is invalid, including
  a policy that block creates;
* the factory burns a balance sent to the address before the policy exists.

The reserved addresses (`ghost.IsReservedAddress`) are every address below
`0x10000`, which holds the precompiles and the natives, and the system
accounts, `ghost` in ASCII followed by zero bytes and a two-byte counter.

## JSON-RPC

These are the namespaces a node with the Ethereum service registers. Here
`off` means the node has the namespace but registers it only when an opt-in
flag asks for it. The IPC endpoint serves every registered namespace; HTTP and
WebSocket serve only the namespaces named with `--http.api` and `--ws.api`.

| Namespace | Status | Note |
|---|---|---|
| eth | on | Chain, state, transaction and log filter methods. |
| net | on | |
| web3 | on | |
| txpool | on | |
| miner | on | |
| ethash | on | Served by the RandomX engine under the proof-of-work name; reports the local hash rate only. |
| admin | on | |
| debug | on | Includes the tracers. |
| trace | on | Parity-style tracing. |
| personal | off | Deprecated; registered only with `--rpc.enabledeprecatedpersonal`. |
| rpc | on | `rpc_modules`. |
| engine | absent | No proof-of-stake consensus client; the Engine API is removed. |
| graphql | absent | The GraphQL server is removed. |
| les | absent | No light server. |
| clique | absent | The chain is proof of work. |

## Deviations from Ethereum

* **PREVRANDAO is difficulty.** Opcode 0x44 returns the block's difficulty, as
  before the Merge. It is not randomness, and miners influence it. Contracts
  must not rely on `block.prevrandao` (or `block.difficulty`) for randomness.
* **No blobs.** There are no blob transactions: `BLOBHASH` and `BLOBBASEFEE`
  are invalid opcodes and the point-evaluation precompile fails.
* **The precompile set** is exactly the one listed above: 0x01 to 0x0a and
  0x51. Of these, ECRECOVER (0x01), the BN254 precompiles (0x06 to 0x08) and
  point evaluation (0x0a) always fail, so contracts that recover secp256k1
  signers or verify BN254 proofs do not work on Ghost. Signatures are checked
  with the signature-verify precompile at 0x51 instead.
* **No withdrawals and no beacon block root.** Blocks carry no withdrawals and
  there is no EIP-4788 contract.
* **The commit entry address cannot be called.** Every `CALL`, `CALLCODE`,
  `DELEGATECALL` and `STATICCALL` to the commit entry address fails and uses
  up the gas it was given. Only a top-level transaction to it commits, and it
  runs no code ([commit and reveal](private-transactions.md)).
* **Frozen policies.** The native at 0x62 creates frozen policies, contracts
  that may not read state or the environment, may call only a short list of
  targets, and never hold a balance. Value sent to one fails, and a block
  paying one as coinbase is invalid ([frozen policies](#frozen-policies)).
* **The reveal transaction has no sender.** Type `0x50` is a native
  transaction without an account, nonce or signature; it runs no EVM code and
  credits its recipient without running the recipient's code. Blocks accept
  it only with a proof the node's verifier accepts, and the node has no
  verifier linked in yet, so no chain the node runs today includes one. No
  contract or tool may assume a sender, `tx.origin` or a call for it.
* **`evmVersion: cancun` is compiler guidance only.** Compiling with
  `evmVersion: cancun` gives bytecode that uses only opcodes this profile has
  on (PUSH0, MCOPY, TLOAD and TSTORE included), as long as it does not use
  `blobhash`, `blobbasefee` or `block.prevrandao` as randomness. It does not
  promise that every contract written for Cancun on Ethereum behaves the same
  here: anything that depends on blobs, withdrawals, the beacon root or
  PREVRANDAO randomness does not.

## Execution fixtures

Each fork and EIP that is on is exercised by Ethereum's execution test
fixtures, under the fixture fork named below. The name is a key of
`tests.Forks`, and the GitHub `fixtures` CI job runs the state and blockchain
fixtures for it (`go test -run '^TestState$' ./tests` and
`go test -run '^TestBlockchain$' ./tests`) before any merge.

| Profile fork | Fixture fork name | Run by |
|---|---|---|
| Frontier | Frontier | `fixtures` CI job |
| Homestead | Homestead | `fixtures` CI job |
| Tangerine Whistle | EIP150 | `fixtures` CI job |
| Spurious Dragon | EIP158 | `fixtures` CI job |
| Byzantium | Byzantium | `fixtures` CI job |
| Constantinople | Constantinople | `fixtures` CI job |
| Petersburg | ConstantinopleFix | `fixtures` CI job |
| Istanbul | Istanbul | `fixtures` CI job |
| Berlin | Berlin | `fixtures` CI job |
| London | London | `fixtures` CI job |
| EIP-3651, EIP-3855, EIP-3860, EIP-6049 | Shanghai | `fixtures` CI job |
| EIP-1153, EIP-5656, EIP-6780 | Cancun | `fixtures` CI job |

What this proves, honestly: the fixtures run with upstream's fork
configurations, not with Ghost's. The Shanghai fixtures also switch on
withdrawals, and the Cancun fixtures also switch on blobs, the beacon block
root contract and PREVRANDAO. A pass therefore shows that the EVM code paths
Ghost shares with Ethereum are right; it says nothing about the features Ghost
turns off, and it does not run any fixture under the exact Ghost
configuration. That a Ghost chain has those features off, and what it runs
instead, is checked by the tests named at the top of this page.

Not done yet: checks with MetaMask, Foundry, Hardhat and a block explorer,
the check of a block that contains a reveal transaction through those tools,
and a run of the fee behaviour through a live chain. They need outside tools
and a node that can submit reveals, and they are still required before
launch.
