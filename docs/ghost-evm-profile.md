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

Every status is one of three words:

* `on`: the chain runs it from block 0.
* `off`: the node has the code, as upstream does, but the chain configuration
  does not switch it on, and `params/ghost.CheckProfile` refuses a
  configuration that does.
* `absent`: the node has no way to switch it on. For an opcode, the byte is an
  invalid opcode on a Ghost chain.

## Forks and EIPs

A fork row stands for every execution change in that fork. The difficulty
bomb delays and difficulty formulas of those forks do not apply: blocks are
sealed with RandomX and its own difficulty rule. Shanghai and Cancun are only
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
| EIP-2537 (BLS12-381 precompiles) | off | none |
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

| Address | Name | Status |
|---|---|---|
| 0x01 | ECRECOVER | on |
| 0x02 | SHA256 | on |
| 0x03 | RIPEMD160 | on |
| 0x04 | IDENTITY | on |
| 0x05 | MODEXP (EIP-2565 pricing) | on |
| 0x06 | BN254 ADD | on |
| 0x07 | BN254 MUL | on |
| 0x08 | BN254 PAIRING | on |
| 0x09 | BLAKE2F | on |
| 0x0a | POINT EVALUATION (EIP-4844); the draft EIP-2537 code also uses this address | off |
| 0x0b | BLS12-381 (EIP-2537 draft) | off |
| 0x0c | BLS12-381 (EIP-2537 draft) | off |
| 0x0d | BLS12-381 (EIP-2537 draft) | off |
| 0x0e | BLS12-381 (EIP-2537 draft) | off |
| 0x0f | BLS12-381 (EIP-2537 draft) | off |
| 0x10 | BLS12-381 (EIP-2537 draft) | off |
| 0x11 | BLS12-381 (EIP-2537 draft) | off |
| 0x12 | BLS12-381 (EIP-2537 draft) | off |
| 0x0100 | P256VERIFY (EIP-7951) | absent |

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
  are invalid opcodes and the point-evaluation precompile is off.
* **The precompile set** is exactly the one listed above: 0x01 to 0x09.
* **No withdrawals and no beacon block root.** Blocks carry no withdrawals and
  there is no EIP-4788 contract.
* **The Reveal transaction is planned, not implemented.** A sender-less Reveal
  transaction type is planned for Ghost. It does not exist on any chain the
  node runs today, it is not in these tables as supported, and no contract or
  tool may assume it.
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
the check of a block that contains a Reveal transaction, and a run of the fee
behaviour through a live chain. They need outside tools and a Reveal type that
does not exist yet, and they are still required before launch.
