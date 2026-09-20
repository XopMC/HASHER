# HASHER v1.0.0

## English

The first verified release of HASHER: a deterministic streaming multi-hasher
for Windows, Linux, macOS, and Android/Termux.

Highlights:

- 73 hash, XOF, MAC, PBKDF/PBKDF2-HMAC, and EvpKDF algorithms;
- runtime native-instruction dispatch with safe portable fallbacks;
- SHA-NI/AVX/AVX-512 on x64 and SHA/SM3/NEON acceleration on ARM64;
- files of any size and native stdin/PIPE processing with bounded memory;
- deterministic ordered output with up to eight workers;
- permissive high-throughput `-hex` input and optimized buffered output;
- Clang/LLVM-only portable builds;
- full KAT, backend parity, CLI, large-file, and PIPE validation.

Representative SHA-256 throughput exceeded 20 M lines/s on Windows/Linux x64,
31 M lines/s on macOS ARM64, and 21 M lines/s on Qualcomm SM8850 for the
measured file workloads. Exact methodology and complete results are documented
in `BENCHMARKS.md` in the repository.

Windows ARM64 is cross-built and PE/COFF-verified but remains runtime-unverified
until native hardware is available. The Termux build uses the standard Termux
system runtime and requires no companion file beside the executable.

Verify every downloaded archive with the attached `SHA256SUMS.txt`.

## Русский

Первый проверенный релиз HASHER — детерминированного потокового
мультихешировщика для Windows, Linux, macOS и Android/Termux.

Главное:

- 73 алгоритма hash, XOF, MAC, PBKDF/PBKDF2-HMAC и EvpKDF;
- runtime-выбор нативных инструкций с безопасным portable fallback;
- SHA-NI/AVX/AVX-512 на x64 и SHA/SM3/NEON ускорение на ARM64;
- файлы любого размера и нативная работа с stdin/PIPE при bounded memory;
- детерминированный упорядоченный вывод при использовании до восьми workers;
- permissive `-hex` без остановки потока и быстрый буферизированный вывод;
- portable-сборки только через Clang/LLVM;
- KAT, backend parity, CLI, large-file и PIPE проверки.

В измеренных file workloads SHA-256 превысил 20 M строк/с на Windows/Linux
x64, 31 M строк/с на macOS ARM64 и 21 M строк/с на Qualcomm SM8850. Полная
методика и результаты находятся в `BENCHMARKS.md` репозитория.

Windows ARM64 собран кросс-компиляцией и проверен как PE/COFF, но для полной
runtime-проверки ещё нужен нативный стенд. Termux-сборка использует стандартный
системный runtime Termux; рядом с бинарником дополнительные файлы не нужны.

Проверяйте скачанные архивы по приложенному `SHA256SUMS.txt`.
