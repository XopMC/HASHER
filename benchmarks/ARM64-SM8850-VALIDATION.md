# ARM64 SM8850 validation

Physical stand: Qualcomm SM8850, AArch64, 8 cores, Android 17/Termux.

Detected CPU features include ASIMD, SHA1, SHA2, SHA3, SHA512, SM3, SM4,
SVE, SVE2 and SME. The build used Clang 21.1.8 and mold 2.42.0.

Accepted changes:

- SHA-1/SHA-224/SHA-256 now use the ARM hardware message-schedule instructions in addition to the round instructions. Core throughput improved roughly 2.5-2.8x over the previous ARM native implementation.
- SHA3/Keccak/SHAKE short-record batching uses two XKCP ARM SHA3 x2 permutations for four independent lines.
- ARM auto scheduling no longer applies the x86 AVX four-worker cap to the ARM x2+x2 backend.
- ARM64 hexadecimal encoding and decoding use NEON, with scalar tails and byte-identical output.
- A device-local PGO profile was generated from all algorithms, file/PIPE input and 1/2/4/8 workers. Interleaved representative A/B measurements showed about 4.0% geometric-mean improvement.

Rejected candidates:

- xxHash SVE: slower than official NEON by roughly 2.0-3.3x for 64-1024-byte records.
- Alternative single-state SHA3 intrinsic permutation: isolated permutation was faster, but complete hashes were 6.6% slower geometrically.
- ThinLTO with Termux mold: unavailable because the Termux LLVM package does not ship the LLVMgold plugin required by mold. No linker substitution was accepted.

Large-input verification used 4,259,840 records and a 260 MiB input file:

- SHA-256 median file time: 0.198 seconds, about 21.5M lines/s.
- SHA-256 median PIPE time: 0.238 seconds, about 17.9M lines/s.
- Real 276,889,600-byte output completed in 0.344 seconds and ended with byte `0x0a`.
- All 73 algorithms together: 18.718 seconds from file and 21.614 seconds from PIPE.

Raw CSV files and the profile are stored under `benchmark-data/arm-sm8850/`.
The Termux binary is a benchmark artifact, not a Linux ARM64 release: it depends
on Termux's system `libc++_shared.so`.
