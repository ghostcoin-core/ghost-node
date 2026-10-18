# Decision 0002: the RandomX binding

Status: settled, 2026-10-17.

## Decision

Ghost's proof of work is RandomX v1 with Ghost's own Argon2 salt, computed by
the reference C++ implementation, vendored unmodified (apart from the salt)
into `consensus/randomx/librandomx/` and compiled from source by a thin cgo
wrapper in `consensus/randomx`. The engine in that package seals and verifies
blocks in light mode.

| | |
|---|---|
| Library | `tevador/RandomX`, the reference implementation |
| Pin | `418f5497e60215fcd8a7cff2a16be835135833e5` (master, 2026-10-17) |
| Version | RandomX v1; the v2 flag is never set |
| Salt | the 14 bytes `Ghost-RandomX` followed by the byte `0x01` |
| Mode | light mode (256 MiB cache) for sealing and verification; no large pages |
| Key | the hash of the block at `SeedHeight(h)`, E = 8192, L = 256 |

## Why vendor the reference and write our own wrapper

The RandomX survey compared the Go options; none could be used as it is.

- **The mining-pool Go binding** links static libraries that are shipped in
  its repository as prebuilt binary files, which defeats reproducible builds
  and cannot be reviewed. It wraps RandomX v1.2.1 only and cannot take another
  salt.
- **P2Pool's pure-Go RandomX** is BSD-3 and configurable, but has one author,
  a self-hosted origin and a JIT for amd64 only. It is kept as a possible
  second implementation for cross-checks later, not as a dependency.
- The other bindings found were rejected for the same reasons or for being
  unmaintained.

Vendoring the reference keeps the code that decides consensus the code Monero
and the RandomX authors run and audit, builds it from source with the Go
toolchain alone (no CMake, no prebuilt library), and lets the one change Ghost
needs live in one reviewed line.

## Why this pin

Commit `418f5497e602` on master carries fixes that no release tag has yet: the
use-after-free fix in `randomx_vm_set_cache`, the JIT page-protection fixes
and a signed-overflow fix. When a tag with them appears, the pin moves in a
separate change. `librandomx/VENDORED.md` lists every vendored file with its
upstream git blob hash, so the copy can be checked against upstream file by
file. One upstream file is left out, `src/tests/tests.cpp`, the library's own
test program: an upper-case word in its output messages matches a pattern the
repository's publishing checks refuse. It is not compiled by Ghost, and the Go
tests cover the library instead.

## How it is built

- The `rx_*.c`, `rx_*.cpp` and `rx_*.S` files in `consensus/randomx` each
  `#include` one vendored source, so cgo compiles the library as part of the
  package (a unity build per source file; one file per source keeps the
  sources' file-local names apart). The file list and flags follow upstream's
  `CMakeLists.txt`: `-maes` on amd64, `-march=armv8-a+crypto` on arm64,
  `HAVE_HWCAP` on Linux arm64, C++11. The x86 JIT is built on amd64 and the
  ARMv8 JIT on arm64; other architectures get the library's portable
  interpreter. RISC-V is not built: its JIT needs per-file `-march` flags,
  which cgo cannot give.
- The SSSE3 and AVX2 Argon2 sources are compiled without `-mssse3`/`-mavx2`
  (cgo flags apply to the whole package) and so contribute no code; the
  engine uses the portable Argon2. The cache is identical either way; only
  building it is slower.
- Linux links libstdc++ and libgcc statically (`-static-libstdc++
  -static-libgcc`), Windows links statically (`-static`), and macOS uses only
  its system libraries. No `#cgo` flag holds an absolute path.
- Built without cgo, the package compiles and `New` returns `ErrCgoRequired`.
- If the C++ does not build on a platform in CI, the exact compiler error is
  reported in the pull request; no platform is dropped.

## Library modes

- **Light mode only.** Sealing and verification share one 256 MiB cache per
  key. The 2 GiB dataset of fast mode is out of scope for now.
- **JIT and hardware AES where the library reports them**, and W^X pages
  where it asks for them (Apple arm64). The interpreter with software AES
  gives the same hashes; `TestHashVectors` checks both.
- **No large pages**, and never the v2 flag.

## The salt

`Ghost-RandomX` followed by `0x01`, 14 bytes, the value the survey measured.
The salt keys every cache, so Ghost hashes cannot be reused on Monero or on
any other RandomX chain, nor theirs on Ghost. It is the only change to the
library: one line of `src/configuration.h`, recorded in
`librandomx/ghost-salt.patch`. The Go constant `randomx.Salt` holds the same
bytes, and `TestSaltMatchesVendoredHeader` keeps the two equal.

`TestHashVectors` checks key `test key 000` and input `Ghost survey test
input` against `253de6bf1004419ac11fdb08b5a8efd7fa0269d82ea8bb39db173ba43d6cf8ee`,
the value the survey measured with the C++ reference and the pure-Go library.

## The seal

- The RandomX input is the block's seal hash (32 bytes) followed by its nonce
  (8 bytes, big-endian). The seal hash is the Keccak-256 of the RLP header
  with `MixDigest` and `Nonce` zeroed, so it covers every other header field,
  including any added later; a reflection test checks every field.
- The 32-byte output, read big-endian, must be at most `M // difficulty`
  (`ghostrules.SealValid`).
- `MixDigest` must be all zero. RandomX has no mix digest to commit to, and a
  free field would let one sealed block be rewritten into many block hashes.
- Verification runs the cheap checks first (parent link, timestamp,
  difficulty, gas limit and base fee, uncle hash, mix digest) and the RandomX
  hash last. Blocks carry no uncles, and the whole block reward goes to the
  coinbase.

## The key constants

The key of a block at height `h` is the hash of its ancestor at
`SeedHeight(h)`: 0 while `h <= E + L`, else `(h - L - 1)` rounded down to a
multiple of E. The ancestor is found by following parent hashes on the
block's own branch, never by number, so a side branch is checked with its own
key; results are remembered per header hash.

- **E = 8192 blocks.** At 30 seconds a block that is 68 hours, the key
  lifetime Monero has (2048 blocks of 2 minutes); at 60 seconds, 137 hours. A
  long key lifetime keeps cache builds rare for verifiers; a key that never
  changed would let precomputed work carry over.
- **L = 256 blocks.** At 30 seconds that is 2 hours 8 minutes, Monero's delay
  (64 blocks of 2 minutes): time to build the next cache before it is needed,
  and far deeper than any expected reorganisation, so the key block of a
  branch is settled before the key is used.

Both are `Config` fields, must be powers of two, and default to these values.
Tests use E = 8 and L = 4.

## Memory

At most three caches (3 × 256 MiB) are resident in the process, shared by
every engine: the current key, the next one around a key change, and one for a
side branch. The least recently used free cache is evicted and freed through
the library. A cache in use by a verification or a sealer is never evicted; a
caller that needs a fourth key while all three are in use waits. All
verifications and sealing threads share one cache per key, each with its own
VM.

## How it was checked

- `go test ./consensus/randomx` on linux/arm64 with Go 1.26.9 and GCC: the
  hash vector in both modes, the key rule against the survey's table, sealing
  and inserting into a real `core.BlockChain`, rejection of bad seals, the
  block reward and the cache limit. Linux amd64, Windows and macOS are built
  and tested by GitHub CI.
- Every vendored file was compared with upstream by git blob hash.
