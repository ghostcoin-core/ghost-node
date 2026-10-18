# The internal test network

The internal network is a private proof-of-work chain for testing the node:
two `geth` processes on one machine, one mining blocks with RandomX and the
other syncing them. It is not a Ghost network and never will be; the launch
genesis comes with the built-in network in phase 5.

## One command

```sh
make geth                      # or: go run build/ci.go install ./cmd/geth
scripts/internal-net.sh 1000   # mine until both nodes reach block 1000
scripts/internal-net.sh        # mine until interrupted with Ctrl-C
```

The script chooses everything itself, so there is no flag to pick: it makes a
temporary directory, writes the genesis, initialises two data directories,
imports the miner's key into the first, starts both nodes with ports chosen
by the operating system and discovery off, peers them, and starts mining on
the first. It prints the height of both nodes every second. When both reach
the requested height, or on Ctrl-C, it stops mining, waits for the nodes to
agree, prints both heads and exits 0 if they are equal, 1 otherwise. On exit
it stops the nodes and removes the directory.

`GETH` selects the binary (default `build/bin/geth`):

```sh
GETH=/path/to/geth scripts/internal-net.sh 25
```

While it runs, the script prints the IPC path of the mining node, so you can
attach a console (`geth attach <path>`). The miner account is unlocked there,
so its mined funds can be sent with `eth.sendTransaction`.

## The chain

| | |
|---|---|
| Chain ID and network ID | 6777971 (ASCII "ghs"), not a launch value |
| Genesis | `params/ghost.InternalNetGenesis()`: fixed timestamp 2026-10-01 00:00:00 UTC, difficulty 1, gas limit 30,000,000, the EIP-1559 initial base fee, no allocation |
| EVM | The Ghost profile from block 0: Frontier through Shanghai without withdrawals, London, and Cancun's EIP-1153, EIP-5656 and EIP-6780 |
| Consensus | `params/ghost.InternalNetParams()`: 1-second blocks, ASERT half-life 3,600 s, starting and minimum difficulty 1, 3,600 s future drift, and the reward constants of the 30-second launch preset |
| Funds | None in the genesis; test funds come only from mined block rewards |
| Miner account | The fixed test key 6777971 (the private key is that number), never a launch key |

The consensus values are internal-test values. They exist only so that a
thousand blocks mine in seconds on one machine with light-mode RandomX (about
23 ms a hash), and they never appear in a launch preset. Developer mode
(`geth --dev`, chain ID 1337) uses the same consensus values with its own
genesis.

Because the genesis time is in the past and the difficulty is at its minimum,
the miner first runs ahead of the one-second schedule, giving each block the
parent's time plus one second. It never seals a block more than the future
drift ahead of its clock, which peers would hold back, so once its blocks
are an hour ahead it slows to one block a second.

## How the node picks its engine

For every proof-of-work chain (consensus type `ethash` in the chain
configuration) the node runs the RandomX engine, with the consensus
parameters of the chain's ID. The internal network and developer mode are the
only chain IDs with parameters; on any other chain the node refuses to start
with a one-line message:

```
Fatal: Failed to register the Ethereum service: no consensus parameters for chain ID 7: this node runs only the internal network (6777971) and developer mode (1337)
```

A chain configuration without a chain ID is identified by its network ID. The
ethash test modes keep their ethash engines in non-release builds only.

## Tests

`cmd/geth/internalnet_test.go` runs the network as separate `geth` processes:
two nodes mine and sync 1,000 blocks and agree on the head; the miner
account's balance equals the sum of `BlockReward(h)` for h = 1..1000 on both
nodes; ordinary transfers between public accounts are mined and change the
receiver's balance on both nodes; a node refuses a chain ID without
parameters; and developer mode still mines.
