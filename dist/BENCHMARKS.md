# HASHER benchmark summary

Large SHA-256 workload, 16+ million 64-byte lines (median of three; actual output includes every digest):

| Platform | File to null | Native PIPE to null | File to real output |
|---|---:|---:|---:|
| Windows x64 | 22.6 M lines/s | 24.3 M lines/s | 17.6 M lines/s |
| WSL Linux x64 | 21.0 M lines/s | 19.2 M lines/s | 11.0 M lines/s |
| Linux ARM64 | 8.58 M lines/s | 7.13 M lines/s | 6.30 M lines/s |
| macOS ARM64 | 31.98 M lines/s | 25.97 M lines/s | 30.49 M lines/s |

The real-output files were about 1 GiB, had the expected line count, and ended in byte `0x0a`.

Final all-algorithm rerun on a 260 MiB corpus (4,194,304 lines, 64 input bytes per line, median of three):

| Algorithm | Win x64 file | Win x64 PIPE | Linux x64 file | Linux x64 PIPE |
|---|---:|---:|---:|---:|
| SHA-1 | 20.28 M | 21.15 M | 17.68 M | 16.82 M |
| SHA-256 | 20.98 M | 23.14 M | 18.63 M | 17.02 M |
| SHA-512 | 14.56 M | 15.06 M | 11.69 M | 11.32 M |
| SHA3-256 | 24.02 M | 23.41 M | 18.97 M | 17.79 M |
| Keccak-256 | 23.85 M | 23.03 M | 19.29 M | 17.24 M |
| MD2 | 1.16 M | 1.15 M | 1.10 M | 1.10 M |
| MD5 | 16.56 M | 17.57 M | 14.01 M | 13.27 M |
| RIPEMD-160 | 15.32 M | 14.78 M | 12.48 M | 11.81 M |
| BLAKE3 | 20.86 M | 21.18 M | 17.36 M | 17.01 M |
| XXH128 | 25.80 M | 26.79 M | 23.52 M | 23.48 M |
| SM3 fallback | 13.51 M | 13.65 M | 11.33 M | 10.76 M |
| HMAC-SHA256 | 15.41 M | 15.84 M | 14.35 M | 13.70 M |
| HMAC-SHA512 | 9.42 M | 9.44 M | 8.12 M | 7.98 M |
| PBKDF2-HMAC-SHA256 (`-kiter 1`) | 14.77 M | 15.54 M | 13.08 M | 12.24 M |
| direct-PBKDF2-SHA256 (`-kiter 1`) | 19.44 M | 19.52 M | 12.37 M | 11.69 M |

Units are output lines per second. The v1.0 baseline CSV files contain its 73 algorithms in both modes: `final2-win-x64-all-file-pipe-260m-r3.csv` and `final2-linux-x64-all-file-pipe-260m-r3.csv`. Windows uses native `cmd > NUL`; Linux input is on native WSL ext4. PowerShell-redirection and `/mnt` measurements were rejected because they benchmarked the host bridge rather than HASHER.

Fresh 1/2/4/8-thread matrices cover all HMAC/KDF variants. The original 30-variant evidence is in `final2-kdf-thread-scaling-*.csv`; the nine direct-PBKDF2 additions have dedicated `pbkdf2-direct-*-thread-*.csv` matrices. They exposed and corrected stale worker limits; for example HMAC-SHA512 improved from about 3.5 M to 9.4 M lines/s on Windows and from about 3.5 M to 8.1 M on Linux.

Earlier baseline scenarios (before the KDF expansion), Windows x64, 260 MiB / 4,194,304 input lines:

| Workload | File | Native PIPE |
|---|---:|---:|
| SHA-256 + SHA-512 | 0.357 s | 0.343 s |
| Ten algorithms | 1.235 s | 1.250 s |
| SHA-256 iteration 10 | 0.565 s | 0.533 s |
| SHA-256 iterations 1,3-5 | 0.568 s | 0.548 s |

The current registry contains 82 algorithms. Each HMAC/PBKDF/direct-PBKDF2/PBKDF2-HMAC/EvpKDF variant is measured separately with file and native PIPE input and with 1/2/4/8 workers. Direct-PBKDF2 also has a higher-round matrix to prevent tuning only for one-round benchmarks.

Direct-PBKDF2-SHA256, one KDF round, full 260 MiB file/PIPE path:

| Platform | File | PIPE |
|---|---:|---:|
| Windows x64 | 19.44 M lines/s | 19.52 M lines/s |
| WSL Linux x64 | 12.37 M lines/s | 11.69 M lines/s |
| Linux ARM64 | 8.58 M lines/s | 8.56 M lines/s |
| macOS ARM64 | 30.87 M lines/s | 31.38 M lines/s |
| Android/Termux ARM64 | 19.90 M lines/s | 18.44 M lines/s |

Notable accepted optimizations:

- RHash-backed MD5/RIPEMD KDF paths improved selected x64 workloads by roughly 27–50%.
- Selective password-prefix state cloning improved high-round direct-PBKDF2 MD5/RIPEMD-160 by roughly 61–91%, while per-platform measurements kept the faster non-cloned path for regressing SHA/Keccak combinations.
- ParallelHash x4 inner-block batching improved `-bsize 8` workloads by about 1.9–2.2x.
- PBKDF2-HMAC-SHA256 at 10,000 KDF rounds scaled from 8.50 s at one worker to 1.38 s at eight workers on Linux x64.
- ARM HMAC/KDF backends are selected per algorithm and OS; paths that regressed on real Linux/macOS ARM64 hardware were disabled.
- PGO candidates were rejected for release because representative HMAC/KDF workloads regressed despite isolated gains.
- On x64 without SM3-NI, LibTomCrypt SM3 measured about 1.82x faster than the tested GmSSL SSE implementation at both 64 and 1024 bytes. SM3 hardware timing awaits a physical SM3-capable host; emulator timings are excluded.
- Full ARM SHA-1/SHA-256 message scheduling improved the native core by roughly 2.3-3.2x across Qualcomm SM8850, Linux ARM64 and macOS ARM64 measurements.
- Qualcomm SM8850 native SM3 reached about 4.2M 64-byte hashes/s per worker and about 9.8M end-to-end lines/s with eight workers.
- On the SM8850 260 MiB corpus, SHA-256 reached about 21.5M file lines/s, 17.9M PIPE lines/s and produced the complete 276,889,600-byte output in 0.344 seconds.
- The v1.0 73-algorithm baseline processed that corpus in 18.718 seconds from a file and 21.614 seconds from PIPE.
- ARM SHA3 uses x2+x2 batching for four short records. xxHash SVE and an alternative SHA3 x1 intrinsic core were benchmarked and rejected because they regressed real complete-hash workloads.

x64 SM3-NI, SHA512-NI and potential SM4 work is explicitly deferred until a physical capable x64 stand is available; see `benchmarks/X64-NATIVE-BACKLOG.md`.

Detailed evidence is in `benchmarks/kdf-*.csv`, `benchmarks/arm/`, `benchmarks/tuned-*.csv`, and `benchmarks/research-*.csv`. Timings include reading, line splitting, hashing, hexadecimal conversion, and buffered output to the selected sink.
