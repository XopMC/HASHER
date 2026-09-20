# SM3-NI validation

- Source design: Intel Cryptography Primitives `653e5086f9fefd30b7e18867478fda0ba4ce2c46`, `pcpsm3l9_ni_as.asm` (Apache-2.0).
- Implementation: pure C11 intrinsics in `src/hash/sm3_x86_ni.c`; separate `-msm3 -mssse3` object.
- Dispatch: `CPUID.(EAX=7,ECX=1):EAX[1]`, SSSE3 and OS-enabled AVX; portable fallback otherwise.
- Static verification: Clang 21 Windows/Linux builds contain `vsm3msg1`, `vsm3msg2`, and `vsm3rnds2`; baseline `hasher_core` contains none.
- Semantic verification: scalar emulation of the Intel/Clang intrinsic pseudocode matched the independent scalar SM3 core for lengths 0..1025 including every padding boundary tested.
- Native-backend KAT target: `sm3_ni_kat` covers official vectors, padding boundaries, and every deterministic length 0..1025 against an independent scalar core.
- Intel SDE 10.13.1 `-arl` passed the native KAT and the full hash test executable; runtime dispatch reported `x86-sm3ni`.
- Pending/backlog: benchmark on real x64 SM3-NI hardware. Emulator timing is intentionally not accepted as performance evidence.

ARM64:

- Source design: gmsm `baf7885864e0fc4b9c31a12340043d7741515c0c`, MIT license.
- Implementation: pure C11 ACLE intrinsics in `src/hash/sm3_arm_ni.c`; separate `-march=armv8.4-a+sm4` object.
- Dispatch: Linux `HWCAP_SM3` and macOS `hw.optional.arm.FEAT_SM3`; unknown Windows capability safely falls back.
- `sm3ss1`, `sm3tt1a/b`, `sm3tt2a/b`, and `sm3partw1/2` were confirmed by disassembly.
- The native-instruction KAT passed under QEMU 7.2 `-cpu max`, including official and padding-boundary vectors.
- Qualcomm SM8850 real hardware exposes `HWCAP_SM3`; native instructions were executed directly and the complete SM3 KAT passed.
- Median core measurements on SM8850: about 4.2M hashes/s for 64-byte records and 0.56M hashes/s for 1024-byte records.
- 64 MiB end-to-end input reached about 9.8M lines/s with 8 workers. GmSSL NEON and portable fallbacks were measured separately; neither produced a stable >=5% win across the 0-1024-byte matrix.
