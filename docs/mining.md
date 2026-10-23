# Solo mining with an external RandomX miner

A Ghost node hands out work to a miner program running beside it and takes
back the solutions, over its JSON-RPC interface. The miner never talks to
other nodes and nothing is shared: every block it finds pays its whole
reward to the node's mining address.

## Starting the node

```sh
geth --mine --miner.threads=-1 --miner.etherbase=0xYOUR_ADDRESS \
     --http --http.addr 127.0.0.1 --http.api eth
```

- `--mine` makes the node build blocks to be sealed.
- `--miner.threads=-1` turns off the node's own CPU sealer, so only the
  external miner seals. Leave it out to have both search at once.
- `--miner.etherbase` is the address the block reward is paid to.
- `--http.api eth` serves the two calls below. Keep the HTTP endpoint on
  localhost or behind a firewall: anyone who can reach it can ask for work.

## The two calls

### `eth_getWork`

No parameters. Returns four hex strings:

| | field | meaning |
|---|---|---|
| 0 | seal hash | 32 bytes: the block header to seal, with nonce and mix digest left out |
| 1 | key | 32 bytes: the RandomX key, which is the hash of the key block |
| 2 | target | 32 bytes: the largest hash that seals the block |
| 3 | number | the height of the block |

It fails with "no mining work available yet" until the node has built its
first block. The work changes when the head moves and when the node rebuilds
the block with new transactions, so poll it often (every second or two).

### `eth_submitWork`

Three parameters:

1. the nonce, 8 bytes as hex (`0x` and 16 hex digits),
2. the seal hash of the work it solves (field 0 of the work),
3. the RandomX hash the miner computed for that nonce (32 bytes).

Returns `true` when the node accepted the block, `false` otherwise. The node
computes the RandomX hash itself, under the work's key, and checks the whole
block header before it accepts anything. It refuses:

- a nonce whose hash is above the target,
- a hash in parameter 3 that is not the hash of the work and nonce,
- a seal hash it never handed out,
- work for a block 7 or more blocks below the newest work (stale work).

Work handed out earlier for the same height stays valid, so a solution found
just after the node rebuilt the block is still taken.

`eth_submitHashrate` (rate, a 32-byte id of the miner's choosing) is also
served; the node adds the rates miners report within the last 10 seconds to
its own in `eth_hashrate`.

## What the miner computes

For each nonce:

1. Input: the 32 bytes of the seal hash followed by the nonce as 8 bytes,
   most significant byte first (40 bytes in all).
2. Hash the input with RandomX keyed by the 32 bytes of the key field.
3. Read the 32-byte hash as a number, most significant byte first. If it is
   at most the target, submit the nonce and the hash.

Things to set in an existing RandomX miner:

- **Ghost's RandomX.** Ghost changes one constant of the RandomX library:
  the Argon2 salt is `Ghost-RandomX` followed by the byte `0x01`
  (`RANDOMX_ARGON_SALT` in `configuration.h`). Everything else is the
  standard RandomX v1. A miner built with another salt computes different
  hashes and every submission is refused.
- **The key.** Rebuild the RandomX cache (or dataset) when the key field
  changes. The key moves rarely, on a fixed schedule, so the miner can keep
  the current one between work packages.
- **Byte order.** The nonce goes into the input big-endian, and the hash is
  compared with the target big-endian. Miners written for other RandomX
  chains often use little-endian for both; that must be changed.
- **The nonce space.** All 8 bytes are the miner's; there is no extra nonce.

Full or light mode, the JIT and huge pages are the miner's choice; they
change only its speed, not the hash.
