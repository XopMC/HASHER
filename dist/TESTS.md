# HASHER verification report

| Target | Release tests | Additional verification |
|---|---:|---|
| Windows x64 | 5/5 passed | PE imports, SHA-NI/AVX-512/SM3-NI disassembly, Intel SDE SM3-NI KAT, large file and native PIPE |
| WSL Linux x64 | 6/6 passed | ASan+UBSan 6/6, TSan 6/6, ELF dependencies, large file and native PIPE |
| Linux ARM64 | 6/6 passed | Native SSH build/run, portable parity, ELF/mold checks, ARM SM3 QEMU KAT, large file and PIPE |
| macOS ARM64 | 6/6 passed | Native SSH build/run, portable parity, Mach-O/otool checks, large file and PIPE |
| Android/Termux ARM64 SM8850 | 6/6 passed | Native SM3/SHA3/SHA512 execution, 260 MiB file/PIPE, real output, all-algorithm scenario |
| Windows ARM64 | Cross-build passed | PE/COFF ARM64 and imports verified; runtime not available |

The release suite contains:

- KAT/smoke checks for every registered algorithm;
- official SHA/SHA-3/SP 800-185/BLAKE/XXH/SM3/HMAC/PBKDF2 vectors, independent direct-PBKDF2 vectors, and EvpKDF compatibility vectors;
- prepared HMAC and SP 800-185 parity against one-shot computation;
- auto versus forced-portable parity for 49 hash/HMAC algorithms plus separate parity for all 33 KDF variants;
- CLI help, aliases, deduplication, binary iterations, UTF-8/hex, CRLF/LF, empty/final lines, 1024-byte truncation, multi-file input, deterministic 1/8-thread output, and one-digest-per-line checks;
- broken-pipe exit-code and no-hang checks on Linux/macOS.

Optional-instruction objects were compiled separately from baseline objects. Disassembly confirmed x86 `sha256rnds2`, x86 AVX-512, ARM SHA3, and ARM SHA512 instructions. `HASHER_FORCE_IMPL=portable` passes the same parity suite without entering those backends.

SM3 optional backends are isolated too: baseline objects contain no SM3 instructions; dedicated objects contain x86 `vsm3*` or ARM `sm3*`. Native KATs cover official vectors, padding boundaries, and every input length 0..1025 against an independent scalar implementation.

All 82 registered algorithms pass smoke/KAT execution in auto, forced-portable, and native test runs. Linux x64 ASan+UBSan also passes 6/6 targets. Final Linux ARM64 and macOS ARM64 sources were rebuilt and tested natively over SSH after the ARM message-schedule, SHA3 batching and NEON codec changes. Windows ARM64 was cross-built successfully from the same source.
