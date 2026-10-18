# Vendored RandomX

This directory is a copy of the RandomX reference implementation, built from
source by the cgo wrapper in `consensus/randomx`. See
`docs/decisions/0002-randomx-binding.md` for why it is vendored and how it is
used.

| | |
|---|---|
| Upstream | https://github.com/tevador/RandomX |
| Commit | `418f5497e60215fcd8a7cff2a16be835135833e5` (master, 2026-10-17) |
| Copied | `LICENSE` and the `src/` tree but one file, nothing else |
| License | BSD 3-Clause, `LICENSE` |
| Changes | one line, `src/configuration.h`, in `ghost-salt.patch` |

## The one change

`ghost-salt.patch` replaces the Argon2 salt in `src/configuration.h`:

```
-#define RANDOMX_ARGON_SALT         "RandomX\x03"
+#define RANDOMX_ARGON_SALT         "Ghost-RandomX\x01"
```

Every other file is byte for byte the upstream file. The Go constant `Salt`
in `consensus/randomx` holds the same 14 bytes, and
`TestSaltMatchesVendoredHeader` keeps the constant, this header line and the
patch equal.

## How to check the copy

Each file's git blob hash below is the blob in the upstream tree at the pinned
commit (`git ls-tree -r 418f5497e602 LICENSE src` in a clone of upstream). In
this repository, `git ls-files -s consensus/randomx/librandomx` prints the same
hashes for every file but `src/configuration.h`, whose patched blob is
`03f5bbf7a4b2e3f8dfec4cf7aa7ec0dcc192a019`. Reversing `ghost-salt.patch`
restores upstream's `aac8914e0e8a52319600169bcc64b6cd9c967565`.

Some upstream files have no final newline, trailing whitespace or CRLF line
endings (`src/jit_compiler_rv64_vector_static.h`); they are kept exactly. The
`.gitattributes` here turns off line-ending conversion so git stores them as
they are.

## What is compiled

The `rx_*` files in `consensus/randomx` each include one of these sources, so
cgo compiles them with the package's flags. The list follows upstream's
`CMakeLists.txt`.

- On every platform: `aes_hash.cpp`, `allocator.cpp`, `argon2_avx2.c`,
  `argon2_core.c`, `argon2_ref.c`, `argon2_ssse3.c`,
  `assembly_generator_x86.cpp`, `blake2/blake2b.c`, `blake2_generator.cpp`,
  `bytecode_machine.cpp`, `cpu.cpp`, `dataset.cpp`, `instruction.cpp`,
  `instructions_portable.cpp`, `randomx.cpp`, `reciprocal.c`, `soft_aes.cpp`,
  `superscalar.cpp`, `virtual_machine.cpp`, `virtual_memory.c`,
  `vm_compiled.cpp`, `vm_compiled_light.cpp`, `vm_interpreted.cpp`,
  `vm_interpreted_light.cpp`.
- amd64 also: `jit_compiler_x86.cpp`, `jit_compiler_x86_static.S` (which
  includes the `asm/*.inc` files).
- arm64 also: `jit_compiler_a64.cpp`, `jit_compiler_a64_static.S`.

Not compiled: `src/tests/`, the RISC-V sources (`*rv64*`, `cpu_rv64.S`), the
MSVC assembly `jit_compiler_x86_static.asm` and `asm/configuration.asm`. They
are kept so the copy is the upstream `src/` tree.

## The one file left out

`src/tests/tests.cpp` (blob `7e91a43d2f7ed51cc4de78d294912eadedba99e4`),
upstream's own test program, is not copied: an upper-case word in two of its
output messages matches a pattern this repository's publishing checks refuse.
It is never compiled here and nothing includes it; the Go tests check the
library instead. Fetch it from upstream at the pinned commit to run it.

## Files

| File | Git blob |
|---|---|
| `LICENSE` | `b1572ae82433af4b6985acc80f8fdc7c8d1768b4` |
| `src/aes_hash.cpp` | `deca16d14e7c2c5a24843b8cedd790000693131b` |
| `src/aes_hash.hpp` | `9f75f73ae706043e9e57a667cbe5e381f622338d` |
| `src/aes_hash_rv64_vector.cpp` | `a49ae3e3bcd53952e1b80bc09548778aa006ded6` |
| `src/aes_hash_rv64_vector.hpp` | `5026832dad3d29f7269fc7295dae8b49b03d8fc0` |
| `src/aes_hash_rv64_zvkned.cpp` | `abb0dff5353d7ac2728e5aebc0e504c8dae73b4f` |
| `src/aes_hash_rv64_zvkned.hpp` | `c630a7ff1259b7c2bda27b06d00dff193ad82f0a` |
| `src/allocator.cpp` | `bcee0f6b648a23f62f3c1c2182ee5890d686016a` |
| `src/allocator.hpp` | `d7aa3f95d7b8776c874dae3582d25d4c889a16b1` |
| `src/argon2.h` | `9052f42a5bd86864c4a2a981b88bb3268b59ebb8` |
| `src/argon2_avx2.c` | `2135303262754299347918703c02e91ee02153cd` |
| `src/argon2_core.c` | `f2e7f3d1a8c5398b9509f0877bd46a4630e28ca9` |
| `src/argon2_core.h` | `def27c6dace74a73f42553ecafd4ece44706e99d` |
| `src/argon2_ref.c` | `dc4a8049b5e1c76aeba0d602a7fb8163e79e2647` |
| `src/argon2_ssse3.c` | `778edd7de6c76e65b78b04ea523fdb6bd64769f3` |
| `src/asm/configuration.asm` | `a403c44a2311048e87fdcf024723d4b006cae67b` |
| `src/asm/program_epilogue_linux.inc` | `0dc838bd15e15376bbede7eb459615210b7f7544` |
| `src/asm/program_epilogue_store.inc` | `5fe0e4a4c9ca790b8650614d18041b42bb6e7f2e` |
| `src/asm/program_epilogue_win64.inc` | `727f006859f612cf771af9e0d6e184bb02874920` |
| `src/asm/program_loop_load.inc` | `f872d07122b3184e3fbc33d7970570f02237dbf8` |
| `src/asm/program_loop_store.inc` | `a894e3eb95b11ff9845013c1293e4ffe2094b228` |
| `src/asm/program_loop_store_hard_aes.inc` | `f916de331c65ee0cf98b17aa04ebe7af91f2ef35` |
| `src/asm/program_loop_store_soft_aes.inc` | `b4e62499bb5be367f7d1ee46f824d40066b4395c` |
| `src/asm/program_prologue_linux.inc` | `563a822ec74570df5980cbc93b526e28814e2a09` |
| `src/asm/program_prologue_win64.inc` | `c3d90fa9decbc291ae153d54dd78e2de198362f0` |
| `src/asm/program_read_dataset.inc` | `9c61092f9c63cd20b974317bd6bd12e251336fc9` |
| `src/asm/program_read_dataset_sshash_fin.inc` | `da008d1597dcbbfa884e1c06fbeb7673dfe2531e` |
| `src/asm/program_read_dataset_sshash_init.inc` | `da49621de29e012e02e22a4c245f0ffa5a877891` |
| `src/asm/program_read_dataset_sshash_init_v2.inc` | `51cddb1e262f529e90e7bbc297c3d68c9f56b62d` |
| `src/asm/program_read_dataset_v2.inc` | `f5e1e765d7185d333275a78f2b62b9a6aef1f3be` |
| `src/asm/program_soft_aes_dec.inc` | `77975485418223b83b8d227c549a6306346a2c5b` |
| `src/asm/program_soft_aes_enc.inc` | `c4c27b90a84c80028ec113e11eeaf181e88d9e1a` |
| `src/asm/program_sshash_constants.inc` | `53dc1755cb78bc7cff0cb63bfdd1e66646453dd0` |
| `src/asm/program_sshash_load.inc` | `535135691c3f0bc21c9060a57c5257c44991b112` |
| `src/asm/program_sshash_prefetch.inc` | `26efb51590e17416a81a5bca110fe164a3501622` |
| `src/asm/program_xmm_constants.inc` | `296237a45c9d4cffa99754c6b2c68093046b5cdb` |
| `src/asm/randomx_reciprocal.inc` | `e1f22fdc64d5afa0ad37314adc9d9eea75adb429` |
| `src/assembly_generator_x86.cpp` | `2262e40da3a46376ba8873c939f00963a12a13b1` |
| `src/assembly_generator_x86.hpp` | `9348f61736c3422e099a217b79f52a1bf997b728` |
| `src/blake2/blake2-impl.h` | `617f7c8a3db78074864479c8d55dea625d67ec71` |
| `src/blake2/blake2.h` | `3d15be13687a561477e7653fe06f1fb3ce9de389` |
| `src/blake2/blake2b.c` | `b9f1b565c3be53d6d1ebd0a5434ddf5a4f7a3ff4` |
| `src/blake2/blamka-round-avx2.h` | `4838261790ffdaeb30542d38914b06658fb6fc46` |
| `src/blake2/blamka-round-ref.h` | `f1fb50bf8d4b16afb7dced5cdd4c28399ba4aece` |
| `src/blake2/blamka-round-ssse3.h` | `f2d3b5d05b8df28ab10f75930f0eac09742281f0` |
| `src/blake2/endian.h` | `c7afed261abe664561797418b88b787fcc8d2227` |
| `src/blake2_generator.cpp` | `3f2d028c3d7db6cad99034af07b924a5b241e4e7` |
| `src/blake2_generator.hpp` | `5e7f61f25041ff8ccadbfc825508551e3a6b079c` |
| `src/bytecode_machine.cpp` | `d7698e87bce296fd9774b684949862407cc6f688` |
| `src/bytecode_machine.hpp` | `aa6454b046fe2929b61b4a24d6709cddf469856e` |
| `src/common.hpp` | `579752d97bfdd411effdf35f54b65adb304fbf47` |
| `src/configuration.h` | `aac8914e0e8a52319600169bcc64b6cd9c967565` upstream, patched here |
| `src/cpu.cpp` | `070aba7b5aa26fed56e710ac3e6566d66ddb9b43` |
| `src/cpu.hpp` | `7db033117db1966ec50befbf04ff1b250aaad90e` |
| `src/cpu_rv64.S` | `41647c900f0aff467168efad2927dc1ebf3c1e82` |
| `src/dataset.cpp` | `7ebf1bca42afc851fc757a7e55ce99e211d851c2` |
| `src/dataset.hpp` | `26bc0b283a5193241a5b3edbd42efef266012b44` |
| `src/instruction.cpp` | `12e6f49b971c24a73c1a826dbc616204056ee161` |
| `src/instruction.hpp` | `b1863b5edb2ce6ff8f2b85612ba6bc21f58e328f` |
| `src/instruction_weights.hpp` | `f6c887349db2381a7f77110d8dbcdf60c42cc21c` |
| `src/instructions_portable.cpp` | `5d5921feae0dff6b56bdedac4605a222dc998546` |
| `src/intrin_portable.h` | `1bf7452acdeb4c80cb12ba4d40057f07f87c0603` |
| `src/jit_compiler.hpp` | `56c0655c1297226549d8e21af65ccdac52a9a226` |
| `src/jit_compiler_a64.cpp` | `ec879da9f4963d762dd5c5abed753bdef1bead98` |
| `src/jit_compiler_a64.hpp` | `69dbcaaf0657ab1b1915376f368b52c1cc5cbe05` |
| `src/jit_compiler_a64_static.S` | `2082643e719730aa626d6286da4fb6ac8a9ac2e1` |
| `src/jit_compiler_a64_static.hpp` | `c32147e89965ee11ccf0c902c24622ffeb044c97` |
| `src/jit_compiler_fallback.hpp` | `86d8b4e627f0d68eb3564f4338779ccb5552c27f` |
| `src/jit_compiler_rv64.cpp` | `050aa29db14065ff68d12469428123922376d7d5` |
| `src/jit_compiler_rv64.hpp` | `f61dcb49cf46576f21a29c09a29a77db54742020` |
| `src/jit_compiler_rv64_static.S` | `89724c88c092872457c914e73594d57db17ba6c4` |
| `src/jit_compiler_rv64_static.hpp` | `26b79caec924c23bb40728064cf838f32282b4e5` |
| `src/jit_compiler_rv64_vector.cpp` | `db8d3e5622c6d36c0db9ed8ffda39a2385b21318` |
| `src/jit_compiler_rv64_vector.h` | `2e8aa23857bfe89b99ff47e3976d775f736600a3` |
| `src/jit_compiler_rv64_vector_static.S` | `72906d12883053bdf1809e51c948f5d497bae0fa` |
| `src/jit_compiler_rv64_vector_static.h` | `441888f967f4e6002e5aa0f938b1f3c691d1fdbc` |
| `src/jit_compiler_x86.cpp` | `b44bba47adadb454ffd13136f607b471d3e5e48e` |
| `src/jit_compiler_x86.hpp` | `c892ab93755f66d521e8f3ac913ad80e45655a81` |
| `src/jit_compiler_x86_static.S` | `6150af2272637470246240ccca5e24ce9b336e64` |
| `src/jit_compiler_x86_static.asm` | `04a59ad00094107577ec3a549f714c52eb5e4ba7` |
| `src/jit_compiler_x86_static.hpp` | `1696596e74c47b50d2b11bd158e5c768cadfb924` |
| `src/program.hpp` | `ff9a52f6cff2770ddb2dca40df57d6e5e8f004ab` |
| `src/randomx.cpp` | `be05d5504e777dc55ab90fc0a71f76647c515c85` |
| `src/randomx.h` | `661a5a6ac52543d11788cf6014ca70160a1ec9f8` |
| `src/reciprocal.c` | `074d1846ba74a550d814599c2231c09e26915df6` |
| `src/reciprocal.h` | `90bd9b6be19882bc70d484fd561930b45d1ce8b7` |
| `src/soft_aes.cpp` | `2963f32103335fb943d4a1c763aec666f45bb8cc` |
| `src/soft_aes.h` | `a20dba28a77141a76d6b6fe99c8e399e00562967` |
| `src/superscalar.cpp` | `4e9fd78d3f712d4cf8833b224dcb604f2dd3894d` |
| `src/superscalar.hpp` | `bc101c453110f45ce5e81996f5c9f9ff2ae8ba68` |
| `src/superscalar_program.hpp` | `7bcd484ba060efef5823ae61b997ca894eac2b72` |
| `src/tests/affinity.cpp` | `b090d479912d04b7910c8ffe63cc7c4989fd8642` |
| `src/tests/affinity.hpp` | `db9e9a972e94c837ce6b86b59f90c3e3cd0991ee` |
| `src/tests/api-example1.c` | `e5f85267f14c5ce21b5747e0b9efab247b8c7f47` |
| `src/tests/api-example2.cpp` | `610aaa896b5da93a8879ddec12f28814ea0ed896` |
| `src/tests/benchmark.cpp` | `d4e6e8d24742868a7bd49933694da14fe16e72e5` |
| `src/tests/code-generator.cpp` | `2f9ea66557353a764565b05dc0d3a2d803955805` |
| `src/tests/jit-performance.cpp` | `71c0169c486916ae4786701cf9ae3284ade1d946` |
| `src/tests/perf-simulation.cpp` | `27f34d8c4ffc8eb937197cb26d0ad7b23fd6441c` |
| `src/tests/riscv64_vector.s` | `1b4681a6f8c642e861f509c85c0bc3e80161fe7e` |
| `src/tests/riscv64_zba.s` | `e1947e7a6a2a66d83917e94b1a41f12d7b55baf1` |
| `src/tests/riscv64_zbb.s` | `d922043f0d3ac791d3a47d895eb3a9ce4d789fc5` |
| `src/tests/riscv64_zicbop.s` | `e64b57d6edf46b2dcdc77105cc17ea9ce967626d` |
| `src/tests/riscv64_zvkb.s` | `ba6de4d6004c2bc2a88ec93ee4d192296a5789f2` |
| `src/tests/riscv64_zvkned.s` | `f99af1acfddd03211e5f8af87a5d928ae425b890` |
| `src/tests/rng-tests.cpp` | `fed47614476797f35e1491258898756015708143` |
| `src/tests/runtime-distr.cpp` | `b7663d07e1706666ab1d1d9f55dd5f5523402c94` |
| `src/tests/scratchpad-entropy.cpp` | `ecb3c7d6c2e63a1b6125661def484459414992f1` |
| `src/tests/stopwatch.hpp` | `d1e4912c510d1a4f8821d2f155e86f0f2420aa92` |
| `src/tests/superscalar-avalanche.cpp` | `d9f916cddf1b82a7b78eadc3296651069a325d8b` |
| `src/tests/superscalar-init.cpp` | `15554bbd67693d90ffcf3391bb2a28af4a6518bd` |
| `src/tests/superscalar-stats.cpp` | `50924e5ba65b20f02ca827a86bb95d2ff39074b2` |
| `src/tests/utility.hpp` | `0250a5b3998b183137ab7142263a1e7fe20954c4` |
| `src/vm_compiled.cpp` | `5b16ecbf98c5fa87361abee9e556e112124932f8` |
| `src/vm_compiled.hpp` | `a69bdf309ea8cd3601a969389a4c8bbb741e49c9` |
| `src/vm_compiled_light.cpp` | `98dff34cad6e51df6748b04adfc6ef7d845eb2a0` |
| `src/vm_compiled_light.hpp` | `0211f1e8824b4f8172352150d1d64e13cbf505ab` |
| `src/vm_interpreted.cpp` | `0645e6962a05b2bed2fe764bcfa09a7b4c4bbcda` |
| `src/vm_interpreted.hpp` | `7c26b513663298e31609fd0cd05307c4e623aed4` |
| `src/vm_interpreted_light.cpp` | `c54b32f6465a3ba7c4e51c3931ba6fbb6d60ba45` |
| `src/vm_interpreted_light.hpp` | `0705dbc4717493d3e6fefd0f567423d7935a242a` |
| `src/virtual_machine.cpp` | `bae1c7c07fbc1ef975c0c3231d25664ab86fd7dd` |
| `src/virtual_machine.hpp` | `de613e591a2f8258e5356cd9e713a3a9912f98bf` |
| `src/virtual_memory.c` | `7a4c8695961249361f0b202d17007b724755c461` |
| `src/virtual_memory.h` | `6eba4c5bd8ed48162b72e37f7992f79f89090e51` |
