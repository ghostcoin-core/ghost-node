# Scale benchmark: one block of 3,500 reveals and 3,500 public transactions

Measured: block execution without root proof verification. The record is [`block-3500.json`](block-3500.json), written by `TestScaleBlock` in `core/ghostscale` when `GHOST_SCALE_BENCH_OUT` names this folder. `GHOST_SCALE_BENCH_TXS` sets the number of reveals and of public transactions (3,500 by default) and `GHOST_SCALE_BENCH_RUNS` the number of timed imports (5 by default).

Machine: `lima-kipp`, Apple (CPU implementer 0x61, part 0x000; /proc/cpuinfo has no model name), 16 cores, linux/arm64, 46.9 GiB of memory, go1.26.9, 2026-11-07.

The block holds 3 bundles of reveals, one public root and 3,500 binding transactions: 3,504 transactions, 74,947,880,000 gas, 8,026,104 bytes.

| Measure | Value |
|---|---|
| Block execution, median of 5 runs | 268.5 ms |
| Block execution, slowest run | 273.8 ms |
| Budget of spec 07, section 4 | 3,000 ms |
| Share of the budget, median / slowest | 9.0% / 9.1% |
| Database growth for the block | 10,986,053 bytes |
| Disk growth a day, 2,880 blocks | 31.64 GB |

What the time covers: Each run opens a fresh pebble database holding only that genesis and times core.BlockChain.InsertChain of the block: the header checks of the benchmark engine (parent link, gas used, header MMR root), the body checks, the state processor running the bundles, the public root and the binding transactions with their coin tree appends and spent markers, the receipt, bloom, tree root and state root checks, the state commit and the block, receipt and header MMR writes. The state cache writes every block's state trie to the database (hash scheme, no dirty trie cache, no snapshot); no transaction index is kept.

What it does not cover: root proof verification. The root proofs of the bundles and the public root are checked by the stub verifier of the tests, which compares one hash: no root proof is verified here and no root proof time is given. The real root proof verifier waits for the stage 2 prover. The budget is for verifying the block with its root proofs, so the share above is that of execution alone and does not show the budget is met. See [root verification time](../private-transactions.md#root-verification-time).

The block's gas limit is above the consensus maximum of 30,000,000, which holds a bundle of at most one reveal, so the benchmark engine does not check it; nor the difficulty, the timestamp or the RandomX seal, which take the same time for any block.

Disk growth is the growth of the database's table files, after compaction, from the genesis to the imported block; median of the runs. It counts the 4 stub root proof fields, zeros past 32 bytes, as the database compresses them. Real root proofs do not compress: their fields, 5,242,880 bytes a block, would add up to 15.10 GB a day (computed from their size, not measured).
