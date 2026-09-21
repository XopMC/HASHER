# Per-algorithm optimization audit

This matrix tracks the fastest implementation allowed by the project rule: C11 source and compiler intrinsics are allowed; handwritten assembly and runtime crypto DLLs are not.

The nine `pbkdf2-*` names are intentionally non-standard compatibility chains;
standards-compatible PBKDF2 is exposed only as `pbkdf2-hmac-*`. No upstream
project provides the requested direct-hash construction as a distinct optimized
primitive. It therefore reuses HASHER's audited native digest backends. The
unchanged password prefix is pre-absorbed and the hash state is cloned only for
the platform/algorithm combinations where real high-round benchmarks improved;
other combinations retain the faster reusable-buffer path. RHash handles MD5/RIPEMD-160,
SHA intrinsics handle SHA-1/224/256, the optimized SHA-512 core handles
SHA-384/512, and XKCP handles Keccak-256/512. Runtime selection remains safe,
with portable/native equality covered by backend-parity tests.

| Algorithm | Selected implementation | Alternatives checked | Status |
|---|---|---|---|
| SHA-1 | LibTomCrypt SHA-NI / ARM SHA1 / LTC fallback | SHA-Intrinsics, OpenSSL, Intel multi-buffer | Full ARM hardware message schedule added; SM8850 core throughput improved ~2.5x over the previous native path |
| SHA-224 | LibTomCrypt SHA-NI / ARM SHA2 / LTC fallback | SHA-Intrinsics, OpenSSL, Intel multi-buffer | Full ARM hardware message schedule added; SM8850 core throughput improved ~2.8x |
| SHA-256 | LibTomCrypt SHA-NI / ARM SHA2 / LTC fallback | SHA-Intrinsics, AWS sample, OpenSSL | Full ARM hardware message schedule added; SM8850 core throughput improved ~2.7x |
| SHA-384 | x86 SHA512NI or AWS AVX C / ARM SHA512 / LTC | OpenSSL, RHash, Intel multi-buffer | Current compliant backend retained |
| SHA-512 | x86 SHA512NI or AWS AVX C / ARM SHA512 / LTC | OpenSSL, RHash, Intel multi-buffer | Current compliant backend retained |
| SHA-512/224 | Shared optimized SHA-512 core | OpenSSL, LibTomCrypt | Retained |
| SHA-512/256 | Shared optimized SHA-512 core | OpenSSL, LibTomCrypt | Retained |
| SHA3-224 | XKCP x4 AVX2/AVX-512 + x1/ARM SHA3 fallback | XKCP x1/x4/x8, OpenSSL | x4 added; parity/throughput verified |
| SHA3-256 | XKCP x4 AVX2/AVX-512 + ARM SHA3 x2+x2 batching | XKCP x1/x2/x4/x8, OpenSSL | ARM four-line API implemented as two hardware x2 permutations; parity and real-hardware throughput verified |
| SHA3-384 | XKCP x4 AVX2/AVX-512 + x1/ARM SHA3 fallback | XKCP x1/x4/x8, OpenSSL | x4 added; parity/throughput verified |
| SHA3-512 | XKCP x4 AVX2/AVX-512 + x1/ARM SHA3 fallback | XKCP x1/x4/x8, OpenSSL | x4 added; parity/throughput verified |
| Keccak-224 | XKCP x4 AVX2/AVX-512 + x1/ARM SHA3 fallback | XKCP variants | x4 added; parity/throughput verified |
| Keccak-256 | XKCP x4 AVX2/AVX-512 + x1/ARM SHA3 fallback | XKCP variants | x4 added; parity/throughput verified |
| Keccak-384 | XKCP x4 AVX2/AVX-512 + x1/ARM SHA3 fallback | XKCP variants | x4 added; parity/throughput verified |
| Keccak-512 | XKCP x4 AVX2/AVX-512 + x1/ARM SHA3 fallback | XKCP variants | x4 added; parity/throughput verified |
| SHAKE128 | XKCP x4 for one-block input/output; x1 fallback | XKCP, Intel crypto primitives | x4 added; variable-output fallback retained |
| SHAKE256 | XKCP x4 for one-block input/output; x1 fallback | XKCP, Intel crypto primitives | x4 added; variable-output fallback retained |
| cSHAKE128 | x4 when N/S empty; prepared XKCP sponge otherwise | XKCP SP 800-185 | Prepared/x4 paths verified |
| cSHAKE256 | x4 when N/S empty; prepared XKCP sponge otherwise | XKCP SP 800-185 | Prepared/x4 paths verified |
| MD2 | LibTomCrypt scalar + line-level parallelism | sphlib, RFC reference | sphlib was slower; retained |
| MD4 | RHash pure C + line-level parallelism | LibTomCrypt, sphlib | RHash core faster; selected |
| MD5 | RHash pure C + line-level parallelism | LibTomCrypt, sphlib, Intel MB | RHash core faster; selected |
| RIPEMD-128 | LibTomCrypt unrolled C | sphlib, PHP, Crypto++ | sphlib slower; retained |
| RIPEMD-160 | RHash pure C | LibTomCrypt, sphlib, Botan | RHash substantially faster; selected |
| RIPEMD-256 | LibTomCrypt unrolled C | PHP, Crypto++, reference implementations | PHP C was slower at 64/1024 bytes; retained |
| RIPEMD-320 | LibTomCrypt unrolled C | PHP, Crypto++, reference implementations | PHP C was slower at 64/1024 bytes; retained |
| BLAKE2b | Official SSE/NEON C | official reference, LibTomCrypt, OpenSSL | Official optimized C retained |
| BLAKE2s | Official SSE/NEON C | official reference, LibTomCrypt, OpenSSL | Official optimized C retained |
| BLAKE3 | Official C runtime SSE2/SSE4.1/AVX2/AVX-512/NEON | official portable path | Official backend retained |
| XXH128 | Official xxHash runtime SIMD/NEON | scalar and SVE official paths | NEON retained; official SVE path was 2.0-3.3x slower for 64-1024-byte records on SM8850 |
| SM3 | LibTomCrypt scalar fallback / x86 SM3-NI / ARM SM3 / GmSSL NEON | GmSSL SSE, Intel IPP SM3-NI, gmsm ARM SM3, OpenSSL | Native ARM KAT and real SM8850 timing passed; ~4.2M 64-byte hashes/s single-core and ~9.8M lines/s with 8 workers |
| KMAC128 | Prepared SP 800-185 state over optimized Keccak | XKCP, Intel primitives | Prepared path retained |
| KMAC256 | Prepared SP 800-185 state over optimized Keccak | XKCP, Intel primitives | Prepared path retained |
| KMACXOF128 | Prepared SP 800-185 state over optimized Keccak | XKCP | Prepared path retained |
| KMACXOF256 | Prepared SP 800-185 state over optimized Keccak | XKCP | Prepared path retained |
| TupleHash128 | Prepared SP 800-185 state over optimized Keccak | XKCP | Prepared path retained |
| TupleHash256 | Prepared SP 800-185 state over optimized Keccak | XKCP | Prepared path retained |
| TupleHashXOF128 | Prepared SP 800-185 state over optimized Keccak | XKCP | Prepared path retained |
| TupleHashXOF256 | Prepared SP 800-185 state over optimized Keccak | XKCP | Prepared path retained |
| ParallelHash128 | Prepared SP 800-185 + XKCP x4 inner blocks | XKCP | x4 multi-block path ~2.2x faster at B=8 |
| ParallelHash256 | Prepared SP 800-185 + XKCP x4 inner blocks | XKCP | x4 multi-block path ~1.9x faster at B=8 |
| ParallelHashXOF128 | Prepared SP 800-185 + XKCP x4 inner blocks | XKCP | x4 multi-block path ~2.2x faster at B=8 |
| ParallelHashXOF256 | Prepared SP 800-185 + XKCP x4 inner blocks | XKCP | x4 multi-block path ~1.9x faster at B=8 |
| HMAC-MD5 | Precomputed RHash/LTC ipad/opad contexts | OpenSSL, RHash, Intel multi-buffer | Per-OS x64/ARM selection benchmarked |
| HMAC-SHA1 | Precomputed or ARM one-shot HMAC | OpenSSL, Intel multi-buffer | Per-OS x64/ARM selection benchmarked |
| HMAC-SHA224 | Precomputed or ARM SHA2 one-shot HMAC | OpenSSL, Intel multi-buffer | ARM native path retained after benchmark |
| HMAC-SHA256 | Precomputed or ARM SHA2 one-shot HMAC | OpenSSL, Intel multi-buffer | Per-OS native selection benchmarked |
| HMAC-SHA384 | Precomputed SHA contexts + 8-line workers on x64 | OpenSSL, Intel multi-buffer | ARM one-shot rejected; fresh x64 1/2/4/8 tuning selected 8 |
| HMAC-SHA512 | Precomputed SHA contexts + 8-line workers on x64 | OpenSSL, Intel multi-buffer | Stale 2-thread cap removed; ~3.5M -> 9.4M Win / 8.1M Linux |
| PBKDF-MD5 | Direct chain over RHash MD5 | OpenSSL PBKDF1, LibTomCrypt | KAT and x64/ARM file/PIPE verified |
| PBKDF-SHA1 | Direct chain over runtime-selected SHA-1 | OpenSSL PBKDF1, LibTomCrypt | KAT and x64/ARM file/PIPE verified |
| PBKDF-SHA224 | Extended chain over runtime-selected SHA-224 | LibTomCrypt/OpenSSL primitives | KAT and x64/ARM file/PIPE verified |
| PBKDF-SHA256 | Extended chain over runtime-selected SHA-256 | LibTomCrypt/OpenSSL primitives | KAT and x64/ARM file/PIPE verified |
| PBKDF-SHA384 | Extended chain over runtime-selected SHA-384 | LibTomCrypt/OpenSSL primitives | KAT and x64/ARM file/PIPE verified |
| PBKDF-SHA512 | Extended chain over runtime-selected SHA-512 | LibTomCrypt/OpenSSL primitives | KAT and x64/ARM file/PIPE verified |
| PBKDF-RIPEMD160 | Extended chain over RHash RIPEMD-160 | RHash/LibTomCrypt/OpenSSL primitives | KAT and x64/ARM file/PIPE verified |
| PBKDF-Keccak256 | Extended chain over optimized Keccak | XKCP | KAT and x64/ARM file/PIPE verified |
| PBKDF-Keccak512 | Extended chain over optimized Keccak | XKCP | KAT and x64/ARM file/PIPE verified |
| direct-PBKDF2-MD5 | Reused message buffer + RHash MD5 | RHash, LibTomCrypt primitives | Independent KAT; x64/ARM thread scaling |
| direct-PBKDF2-SHA1 | Reused message buffer + selected SHA-1 backend | AWS SHA intrinsics, ARM ACLE | Independent KAT; x64/ARM thread scaling |
| direct-PBKDF2-SHA224 | Reused message buffer + selected SHA-224 backend | AWS SHA intrinsics, ARM ACLE | Independent KAT; x64/ARM thread scaling |
| direct-PBKDF2-SHA256 | Reused message buffer + selected SHA-256 backend | AWS SHA intrinsics, ARM ACLE | Independent KAT; x64/ARM thread scaling |
| direct-PBKDF2-SHA384 | Reused message buffer + selected SHA-384 backend | optimized SHA-512 core, ARM ACLE | Independent KAT; x64/ARM thread scaling |
| direct-PBKDF2-SHA512 | Reused message buffer + selected SHA-512 backend | optimized SHA-512 core, ARM ACLE | Independent KAT; x64/ARM thread scaling |
| direct-PBKDF2-RIPEMD160 | Reused message buffer + RHash RIPEMD-160 | RHash | Independent KAT; x64/ARM thread scaling |
| direct-PBKDF2-Keccak256 | Reused message buffer + runtime XKCP backend | XKCP | Independent KAT; x64/ARM thread scaling |
| direct-PBKDF2-Keccak512 | Reused message buffer + runtime XKCP backend | XKCP | Independent KAT; x64/ARM thread scaling |
| PBKDF2-HMAC-MD5 | Prepared RHash HMAC states | OpenSSL, LibTomCrypt | Independent vectors and x64/ARM E2E verified |
| PBKDF2-HMAC-SHA1 | Prepared/ARM HMAC states | OpenSSL, LibTomCrypt | RFC-compatible vectors and x64/ARM E2E verified |
| PBKDF2-HMAC-SHA224 | Prepared/ARM HMAC states | OpenSSL, LibTomCrypt | Independent vectors and x64/ARM E2E verified |
| PBKDF2-HMAC-SHA256 | Prepared/ARM HMAC states | OpenSSL, LibTomCrypt | Independent vectors and x64/ARM E2E verified |
| PBKDF2-HMAC-SHA384 | Prepared SHA contexts | OpenSSL, LibTomCrypt | Independent vectors and x64/ARM E2E verified |
| PBKDF2-HMAC-SHA512 | Per-OS prepared/ARM HMAC path | OpenSSL, LibTomCrypt | Independent vectors and x64/ARM E2E verified |
| EvpKDF-MD5 | CryptoJS/OpenSSL digest chain | CryptoJS, OpenSSL EVP_BytesToKey | Online-tools vector and x64/ARM E2E verified |
| EvpKDF-SHA1 | CryptoJS/OpenSSL digest chain | CryptoJS, OpenSSL EVP_BytesToKey | Independent vector and x64/ARM E2E verified |
| EvpKDF-SHA224 | CryptoJS/OpenSSL digest chain | CryptoJS, OpenSSL primitives | Independent vector and x64/ARM E2E verified |
| EvpKDF-SHA256 | CryptoJS/OpenSSL digest chain | CryptoJS, OpenSSL EVP_BytesToKey | Independent vector and x64/ARM E2E verified |
| EvpKDF-SHA384 | CryptoJS/OpenSSL digest chain | CryptoJS, OpenSSL primitives | Independent vector and x64/ARM E2E verified |
| EvpKDF-SHA512 | CryptoJS/OpenSSL digest chain | CryptoJS, OpenSSL primitives | Independent vector and x64/ARM E2E verified |
| EvpKDF-RIPEMD160 | CryptoJS-compatible digest chain | CryptoJS, LibTomCrypt | Independent vector and x64/ARM E2E verified |
| EvpKDF-Keccak256 | CryptoJS-compatible chain over optimized Keccak | CryptoJS, XKCP | Independent vector and x64/ARM E2E verified |
| EvpKDF-Keccak512 | CryptoJS-compatible chain over optimized Keccak | CryptoJS, XKCP | Independent vector and x64/ARM E2E verified |

Raw comparison evidence is stored in the `research-*`, `tuned-*`, and `kdf-*.csv` benchmark files in this directory.
The final all-73 reruns are `final2-*-all-file-pipe-260m-r3.csv`; fresh HMAC/KDF scaling is in `final2-kdf-thread-scaling-*-260m-r3.csv`.
