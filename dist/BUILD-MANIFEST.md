# HASHER build manifest

Build date: 2026-09-21

| Artifact | Target | Compiler | Linker | LTO | Runtime verification |
|---|---|---|---|---|---|
| HASHER-win-x64.exe | x86_64-pc-windows-msvc | Clang 21.1.8 | lld-link 21.1.8 | ThinLTO | Passed |
| HASHER-win-arm64.exe | aarch64-pc-windows-msvc | Clang 21.1.8 | lld-link 21.1.8 | ThinLTO | Cross-built; runtime unverified |
| HASHER-linux-x64 | x86_64-linux-gnu | Clang 21.1.8 | mold 2.40.4 | ThinLTO | Passed in WSL |
| HASHER-linux-arm64 | aarch64-linux-gnu | Clang 21.1.8 | mold 1.0.3 | Disabled* | Passed on ARM64 host |
| HASHER-macos-arm64 | arm64-apple-darwin | AppleClang 21.0.0 | Apple ld64 | ThinLTO | Passed on ARM64 host |
| HASHER-android-arm64-termux | aarch64-linux-android24 | Clang 21.1.8 | mold 2.42.0 | PGO, no LTO* | Passed on SM8850 Termux host |

*The available Linux/Termux ARM64 LLVM packages have no `LLVMgold.so`; mold cannot consume ThinLTO objects. These builds use `-O3` plus per-file ISA flags; Termux additionally uses a freshly generated device-native PGO profile.

Pinned dependencies:

- LibTomCrypt: `6c6d5104de66f3ca0dfd7b68540ef86869982b07`
- BLAKE2: `ed1974ea83433eba7b2d95c5dcd9ac33cb847913`
- BLAKE3: `6aab490a26124663329dfd3961b8469f8fdb158b`
- xxHash: `1798053afaa7ee83ae21adee5649238be8a66197`
- XKCP: `eb5244d6b95fb1c434b211bac293093e18aa8fd1`
- AWS SHA-512 intrinsics: `35156390899935c8a00b82eebd9ebc0fa8069348`
- GmSSL SM3 ARM64: `24ae482701a7b124826c382fffc55c19f76d475d`
- RHash: `3dbba4baa3cbdc3baf06d3ba086d8094bd98cd88`
- Intel Cryptography Primitives SM3-NI schedule: `653e5086f9fefd30b7e18867478fda0ba4ce2c46`
- gmsm ARM SM3 schedule: `baf7885864e0fc4b9c31a12340043d7741515c0c`

Runtime acceleration:

- x64 SHA-1/SHA-224/SHA-256: SHA-NI; portable fallback.
- x64 SHA-384/SHA-512 family: SHA512 extension when present, otherwise AVX C or portable.
- ARM64 SHA-1/SHA-224/SHA-256: full hardware round and message-schedule instructions; portable fallback. SHA-512 uses its optional ARM backend when advertised.
- SHA-3/Keccak/SHAKE/SP 800-185: XKCP unrolled C, x64 AVX-512 C, ARM SHA3 C plus x2+x2 four-line batching.
- BLAKE2: official SSE4.1/NEON C; BLAKE3: official runtime SSE2/SSE4.1/AVX2/AVX-512/NEON C.
- XXH128: official x64 runtime SIMD dispatcher and ARM64 NEON.
- SM3: x86 SM3-NI and ARM SM3 instructions when advertised at runtime; LibTomCrypt/GmSSL fallbacks otherwise.
- Legacy MD/RIPEMD implementations scale across independent lines through the bounded worker pool.
- HMAC/PBKDF/direct-PBKDF2/PBKDF2-HMAC/EvpKDF reuse the selected digest backend; prepared HMAC states and per-OS ARM dispatch are benchmark-selected.
- x64 HMAC/KDF automatic worker counts are selected from fresh 1/2/4/8-thread matrices; stale two-thread caps were removed.
- ParallelHash uses XKCP x4 for eligible inner blocks on AVX2/AVX-512 systems.

All release third-party code is linked into the executable. Windows imports only `KERNEL32.dll`; Linux, macOS and Termux releases depend only on their normal system runtime libraries. No companion DLL, `.so`, `.dylib`, configuration, or data file is required beside a release executable.

Verification includes all 82 registered algorithms, official/independent KATs, prepared/one-shot parity, auto/forced-portable backend parity over boundary lengths, CLI golden tests, broken-pipe handling, ASan/UBSan, PE/ELF/Mach-O checks, and ISA disassembly. x86 SM3-NI passed Intel SDE emulation but remains in the physical-hardware backlog. ARM SM3 passed QEMU and direct execution on Qualcomm SM8850 hardware.
