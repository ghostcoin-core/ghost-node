# What this fork removes and turns off

The Ghost node starts from Core-Geth (see
[decision 0001](decisions/0001-fork-point.md)). Following the base client
plan, unwanted parts are turned off first, and code is deleted only where that
clearly reduces attack surface or maintenance, so upstream fixes stay easy to
carry over.

## Removed

| Part | Where it was |
|---|---|
| Ethereum Classic, Mordor, MintMe, Sepolia and Holesky networks, the `--mainnet` flag, and every built-in bootnode and DNS node list | `params`, `cmd/utils`, `core/genesis.go` |
| Falling back to Ethereum mainnet's genesis when a data directory has none | `core/genesis.go`; until Ghost's genesis is built in as the default, the node refuses to start on an empty data directory (developer mode and `geth init` still work) |
| Replacing a stored chain configuration with a default one at block zero when the chain IDs matched | `core/genesis.go` |
| The MintMe Lyra2 engine and its contract-address rule in the EVM, receipts and RPC | `consensus/lyra2`, `core`, `internal/ethapi` |
| The Engine API, its authenticated RPC endpoints and the full-sync tester | `eth/catalyst` |
| The beacon chain types and light client, and the miner's payload building | `beacon/`, `miner/payload_building.go` |
| The proof-of-stake developer mode: `--dev` is now the proof-of-work developer mode | `cmd/geth`, `params/genesis.go` |
| The simulated backends built on the Engine API | `ethclient/simulated`, `accounts/abi/bind/backends` |
| The GraphQL server | `graphql/` |
| The OpenRPC discovery service, which parsed the node's source at run time | `node/openrpc.go` |
| The switches that turn Ethereum Classic's rules on at run time: `--ecbp1100`, `--override.ecbp1100.deactivate`, `--ecbp1100.nodisable` and `admin_ecbp1100` | `cmd`, `eth` |
| The fork override flags `--override.shanghai`, `--override.cancun` and `--override.verkle` | `cmd`, `eth/ethconfig` |
| The fake proof-of-work flags `--fakepow` and `--fakepow.poisson` | `cmd/utils` |
| The blob transaction pool and its flags | `eth/backend.go`, `cmd/utils` |
| Core-Geth's CI, documentation site, release scripts, chain-spec tool and Ethereum Classic test fixtures | repository root, `cmd/echainspec`, `tests` |

## Turned off, and how that is enforced

The code below stays, as in upstream, but no chain the node runs may switch it
on. `params/ghost.CheckProfile` names every such feature in a chain
configuration; `geth init` refuses the genesis, and the node refuses to start
or to import, if any is switched on.

| Feature | Enforced by |
|---|---|
| The proof-of-stake transition (a terminal total difficulty) | `CheckProfile`, and `core.CheckProofOfWorkOnly` when the Ethereum service starts |
| ECBP-1100 artificial finality (MESS) | `CheckProfile` |
| The ECIP-1017 reward schedule | `CheckProfile` |
| The ECIP-1010 difficulty bomb delay and ECIP-1099 (Etchash) | `CheckProfile` |
| Withdrawals (EIP-4895) | `CheckProfile` |
| Blob transactions (EIP-4844) and the BLOBBASEFEE opcode (EIP-7516) | `CheckProfile`; there is also no blob pool |
| The beacon block root contract (EIP-4788) | `CheckProfile` |
| PREVRANDAO (EIP-4399): DIFFICULTY returns the block's difficulty | `CheckProfile` |
| Fake proof-of-work modes, also through the config file | Release builds use the `ghostrelease` build tag, which compiles them out; the engine refuses them, and `TestReleaseHasNoFakeSeals` checks it in CI |
| The proof-of-stake beacon wrapper | The node no longer wraps its engine in it. The package stays only because upstream tests and the evm test runner build post-merge test chains with it; a CI step fails if `geth` links it |

## Left for later phases

- **Ghost's network as the default.** Running a node must take one pasted
  line, with no flags or config. When the genesis is frozen (phase 5), it and
  the bootstrap nodes are built in as the default network, so `geth` alone
  runs a Ghost node. Until then no Ghost network is built in: the node mines
  with RandomX only on the internal test network (chain ID 6777971, see
  [internal-network.md](internal-network.md)) and in developer mode (chain
  ID 1337), and refuses to start on a proof-of-work chain whose chain ID has
  no consensus parameters. The launch genesis adds its own entry.

- **Uncles, uncle rewards and the difficulty bomb** are rules of the ethash
  engine. The RandomX engine replaces ethash for every proof-of-work chain
  and has none of them.
- **Ethash and Clique** stay: ethash is the model for the RandomX engine, the
  engine upstream tests use, and the engine of the test modes outside release
  builds; Clique is kept for internal test networks. The consensus type in a
  chain configuration stays `ethash`, the proof-of-work marker; the node runs
  RandomX for it.
- **Remote mining and fast mode.** The RandomX engine mines on the node's
  own CPU in light mode only; work for external miners and the 2 GiB
  fast-mode dataset come later.
- **Post-Cancun execution features** and the Ghost EVM profile matrix are
  phase 3 work.
- **Upstream fixes since go-ethereum 1.13.15** and the dependency advisories
  are the security catch-up (phase 1), which must finish before any Ghost node
  is exposed to a public network.
