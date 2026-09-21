<p align="center">
  <a href="#english"><strong>English</strong></a> |
  <a href="#russian"><strong>Русский</strong></a>
</p>

<a id="english"></a>

# HASHER

Author: Mikhail Khoroshavin, also known as `XopMC`

`HASHER` is a deterministic, high-throughput command-line hashing engine for
large files and continuous pipelines. It reads input line by line, never loads
the entire source into memory, computes one or many algorithms, and writes each
digest on its own output line.

The project is optimized for Windows x64/ARM64, Linux x64/ARM64, macOS ARM64,
and Android ARM64 under Termux. A single executable contains baseline code and
all supported native backends. At startup, HASHER detects CPU and OS features,
selects the fastest safe implementation, and keeps feature checks out of the
hot loop.

## Why HASHER

- deterministic output across supported operating systems, backends, and
  worker counts;
- runtime SHA-NI, AVX, AVX2, AVX-512, ARM SHA1/SHA2/SHA3/SHA512/SM3, and NEON
  dispatch with portable fallbacks;
- streaming input with bounded memory for files of any size;
- native `stdin`/PIPE processing when no `-i` option is supplied;
- up to eight persistent workers while preserving input order;
- one pass through each iteration chain instead of recalculating checkpoints;
- fast buffered `fwrite` output with one lowercase hexadecimal digest per line;
- pure C hash implementations and adapters; the CLI orchestration is C++ in a
  C-style subset;
- Clang/LLVM-only builds with mold on Linux/Termux, lld-link on Windows, and
  Apple ld64 on macOS;
- no configuration, data, or algorithm files are required beside a release
  executable.

## Download Builds

Verified binaries are published in the private
[`v1.1.0` release](https://github.com/XopMC/HASHER/releases/tag/v1.1.0):

```text
HASHER-v1.1.0-win-x64.zip
HASHER-v1.1.0-win-arm64.zip
HASHER-v1.1.0-linux-x64.tar.gz
HASHER-v1.1.0-linux-arm64.tar.gz
HASHER-v1.1.0-macos-arm64.tar.gz
HASHER-v1.1.0-android-arm64-termux.tar.gz
SHA256SUMS.txt
```

Each platform archive contains exactly one executable. Windows ARM64 is
cross-built and PE/COFF-verified; native runtime verification requires a
Windows ARM64 machine.

## Quick Start

Default mode is SHA-256, iteration 1, automatic workers, and `stdin`:

```bash
printf 'abc\n' | ./HASHER
```

Hash several files in order with several algorithms:

```bash
./HASHER -sha256 -sha512 -rmd256 -i first.txt -i second.txt
```

Select iteration checkpoints without recalculating the chain:

```bash
./HASHER -sha256 -iter 1,3-5 -i input.txt
```

Use hexadecimal input:

```bash
printf '616263\n' | ./HASHER -sha256 -hex
```

`-hex` is intentionally permissive for uninterrupted high-load pipelines.
Malformed lines are never rejected. An odd line is padded with zero on the
left, so `123` is decoded as `0123`.

HMAC with the default empty key or an explicit key:

```bash
printf 'abc\n' | ./HASHER -hmac-sha256
printf 'abc\n' | ./HASHER -hmac-sha256 -key secret
```

PBKDF2-HMAC-SHA256:

```bash
./HASHER -pbkdf2-hmac-sha256 -salt saltsalt -kiter 10000 -len 32 -i passwords.txt
```

## Input and Output Contract

- `-i FILE` can be repeated; files are processed in command-line order.
- With no `-i`, input is read continuously from `stdin` until EOF.
- Sources are opened in binary mode.
- LF is removed; a directly preceding CR is also removed.
- The first 1024 input bytes of each line are used; the rest is drained and
  ignored without growing memory usage.
- The last line is processed even without a trailing newline.
- An empty line hashes the zero-length message.
- UTF-8 mode hashes bytes exactly as received without normalization.
- Every digest is lowercase hexadecimal followed by `\n`.
- Output order is input line → algorithm CLI order → ascending iteration.
- There are no labels, spaces, tabs, headers, or blank separators.

Iterations use binary digests:

```text
digest1 = H(input)
digest2 = H(binary digest1)
digest3 = H(binary digest2)
```

The hexadecimal text is never fed into the next iteration.

## Main Options

```text
-h / -help           Full built-in help.
-i FILE              Input file; repeatable. Default: stdin.
-hex                 Permissive hexadecimal line decoding.
-iter LIST           Checkpoints such as 1,3-5. Default: 1.
-key TEXT            HMAC/KMAC key. Default: empty, zero bytes.
-key-hex HEX         HMAC/KMAC key as hexadecimal bytes.
-func TEXT           cSHAKE function name.
-custom TEXT         cSHAKE/KMAC/TupleHash/ParallelHash customization.
-len BYTES           Variable output size, maximum 1,048,576 bytes.
-bsize BYTES         ParallelHash block size. Default: 1024.
-seed HEX            XXH128 seed. Default: 0.
-salt TEXT           KDF salt. Default: empty.
-salt-hex HEX        KDF salt as hexadecimal bytes.
-kiter N             KDF rounds; PBKDF2 default: 10000, others: 1.
-t N                 Workers: 0=automatic, 1..8 explicit.
```

Run `HASHER -help` for aliases, defaults, examples, and error codes.

## Supported Algorithms

The registry contains 82 independently selectable algorithms.

### SHA and Keccak families

```text
sha1
sha224  sha256  sha384  sha512  sha512/224  sha512/256
sha3-224  sha3-256  sha3-384  sha3-512
keccak-224  keccak-256  keccak-384  keccak-512
shake128  shake256  cshake128  cshake256
```

### MD, RIPEMD, BLAKE, XXH and SM3

```text
md2  md4  md5
rmd-128  rmd-160  rmd-256  rmd-320
blake2b  blake2s  blake3
xxh128  sm3
```

### SP 800-185

```text
kmac128  kmac256  kmacxof128  kmacxof256
tuplehash128  tuplehash256  tuplehashxof128  tuplehashxof256
parallelhash128  parallelhash256
parallelhashxof128  parallelhashxof256
```

### HMAC

```text
hmac-md5  hmac-sha1  hmac-sha224
hmac-sha256  hmac-sha384  hmac-sha512
```

### PBKDF direct chains

```text
pbkdf-md5  pbkdf-sha1  pbkdf-sha224  pbkdf-sha256  pbkdf-sha384
pbkdf-sha512  pbkdf-rmd160  pbkdf-keccak256  pbkdf-keccak512
```

### PBKDF2-HMAC

```text
pbkdf2-hmac-md5  pbkdf2-hmac-sha1  pbkdf2-hmac-sha224
pbkdf2-hmac-sha256  pbkdf2-hmac-sha384  pbkdf2-hmac-sha512
```

### Direct PBKDF2 chains

```text
pbkdf2-md5  pbkdf2-sha1  pbkdf2-sha224  pbkdf2-sha256  pbkdf2-sha384
pbkdf2-sha512  pbkdf2-rmd160  pbkdf2-keccak256  pbkdf2-keccak512
```

These compatibility variants use the selected digest directly as the PBKDF2
round function: `U1=H(password||salt||counter)`, `Uj=H(password||Uj-1)`, with
the usual per-block XOR. Use `pbkdf2-hmac-*` for standards-compatible PBKDF2-HMAC.

### OpenSSL/CryptoJS-compatible EvpKDF

```text
evpkdf-md5  evpkdf-sha1  evpkdf-sha224  evpkdf-sha256  evpkdf-sha384
evpkdf-sha512  evpkdf-rmd160  evpkdf-keccak256  evpkdf-keccak512
```

## Native Acceleration

| Family | x64 | ARM64 |
|---|---|---|
| SHA-1/SHA-224/SHA-256 | SHA-NI, portable fallback | ARM SHA1/SHA2 full rounds and schedule |
| SHA-384/SHA-512 | AVX core, optional SHA512 extension | ARM SHA512 when advertised |
| SHA-3/Keccak/XOF | scalar, AVX2/AVX-512 multi-buffer | ARM SHA3 and NEON x2+x2 batching |
| BLAKE2 | official SSE backend | official NEON backend |
| BLAKE3 | SSE2/SSE4.1/AVX2/AVX-512 | NEON |
| XXH128 | official runtime SIMD dispatcher | NEON |
| SM3 | SM3-NI when available | ARM SM3 instructions |
| MD/RIPEMD/KDF | independent-line worker scaling | independent-line worker scaling |

Feature detection runs once. Unsupported or unconfirmed instructions always
fall back to a safe baseline implementation.

## Performance

Large SHA-256 workload, more than 16 million 64-byte lines, median of three:

| Platform | File → null | Native PIPE → null | File → real output |
|---|---:|---:|---:|
| Windows x64 | 22.6 M lines/s | 24.3 M lines/s | 17.6 M lines/s |
| WSL Linux x64 | 21.0 M lines/s | 19.2 M lines/s | 11.0 M lines/s |
| Linux ARM64 | 8.58 M lines/s | 7.13 M lines/s | 6.30 M lines/s |
| macOS ARM64 | 31.98 M lines/s | 25.97 M lines/s | 30.49 M lines/s |

Selected 260 MiB corpus results, 4,194,304 lines:

| Algorithm | Windows x64 file | Windows x64 PIPE | Linux x64 file | Linux x64 PIPE |
|---|---:|---:|---:|---:|
| SHA-256 | 20.98 M | 23.14 M | 18.63 M | 17.02 M |
| SHA-512 | 14.56 M | 15.06 M | 11.69 M | 11.32 M |
| SHA3-256 | 24.02 M | 23.41 M | 18.97 M | 17.79 M |
| XXH128 | 25.80 M | 26.79 M | 23.52 M | 23.48 M |
| HMAC-SHA256 | 15.41 M | 15.84 M | 14.35 M | 13.70 M |
| PBKDF2-HMAC-SHA256, one KDF round | 14.77 M | 15.54 M | 13.08 M | 12.24 M |
| direct-PBKDF2-SHA256, one KDF round | 19.44 M | 19.52 M | 12.37 M | 11.69 M |

On Qualcomm SM8850, SHA-256 reached approximately 21.5 M file lines/s and
17.9 M PIPE lines/s. The v1.0 73-algorithm baseline processed the 260 MiB
corpus in 18.718 seconds from a file and 21.614 seconds from PIPE.

Measurements include input, splitting, hashing, hexadecimal conversion, and
buffered output. Full CSV evidence is kept in `benchmarks/` and summarized in
`dist/BENCHMARKS.md`.

## Building From Source

Requirements:

- GNU Make 4.x;
- CMake and Ninja;
- Clang/LLVM 21.x;
- mold on Linux and Termux;
- Windows SDK/UCRT for Windows targets;
- Xcode Command Line Tools on macOS.

The normal command is deliberately simple:

```bash
make
```

The Makefile detects the current OS and architecture, selects the accepted
optimization policy, builds, tests, and stages one executable under
`build/<platform>/`.

Useful commands:

```bash
make detect
make test
make debug
make pgo
make package VERSION=v1.1.0
make package-all VERSION=v1.1.0
make help
```

Overrides (`TARGET`, `JOBS`, `CC`, `CXX`, `CMAKE`, `CTEST`, `NINJA`, and
`LLVM_PROFDATA`) are available for unusual installations:

```bash
make TARGET=linux-arm64 CC=/opt/llvm/bin/clang CXX=/opt/llvm/bin/clang++ JOBS=8
```

Termux uses a fresh native PGO profile automatically. PGO is not enabled by
default on platforms where the measured representative workload regressed.

## Verification

- all 82 registry entries have smoke/KAT coverage;
- official SHA, SHA-3, SP 800-185, BLAKE, XXH, SM3, HMAC and PBKDF2 vectors;
- one-shot/prepared and portable/native parity;
- boundary inputs, binary data, streaming chunks and unaligned buffers;
- CLI golden tests for files, PIPE, iterations, aliases, CRLF/LF, permissive
  hex input, truncation, deterministic threads, and one-digest-per-line output;
- Windows x64: 5/5 release tests;
- Linux x64, Linux ARM64, macOS ARM64 and Termux ARM64: 6/6 release tests;
- sanitizer, dependency, binary-format and ISA disassembly checks.

See `dist/TESTS.md` and `dist/BUILD-MANIFEST.md` for the full record.

## Limitations and Backlog

- Each source line is limited to its first 1024 input bytes.
- The worker count is intentionally capped at eight.
- Windows ARM64 is cross-built until native hardware is available.
- Physical x64 validation of SM3-NI and SHA512-NI remains in the backlog.
- Termux uses the normal system `libc++_shared.so`; no library needs to be
  copied beside HASHER inside a standard Termux installation.

## License

Original HASHER code is available under the MIT License. Third-party code keeps
its own license; see `THIRD_PARTY_NOTICES.md` and `dist/licenses/`.

---

<a id="russian"></a>

# HASHER — Русская версия

Автор: Михаил Хорошавин, также известный как `XopMC`

`HASHER` — детерминированный высокопроизводительный консольный хешировщик для
огромных файлов и непрерывных PIPE-потоков. Он читает данные построчно, не
загружает исходный файл целиком в память, выполняет один или сразу несколько
алгоритмов и печатает каждый результат отдельной строкой.

Проект оптимизирован для Windows x64/ARM64, Linux x64/ARM64, macOS ARM64 и
Android ARM64 в Termux. В одном бинарнике находятся baseline-код и доступные
нативные backend'ы. При запуске программа один раз определяет возможности CPU
и ОС, выбирает самый быстрый безопасный вариант и больше не выполняет feature
checks в горячем цикле.

## Зачем нужен HASHER

- одинаковый результат на всех поддерживаемых ОС, backend'ах и количествах
  потоков;
- runtime-переключение SHA-NI, AVX, AVX2, AVX-512, ARM
  SHA1/SHA2/SHA3/SHA512/SM3 и NEON с portable fallback;
- потоковое чтение и ограниченное потребление памяти для файлов любого размера;
- чтение `stdin`/PIPE по умолчанию, если не указан `-i`;
- до восьми постоянных workers с сохранением исходного порядка строк;
- одна цепочка вычислений для всех выбранных iteration checkpoints;
- быстрый буферизированный вывод через `fwrite`;
- каждый digest печатается lowercase hex на новой строке с обязательным `\n`;
- реализации алгоритмов и adapters написаны на чистом C;
- сборка только Clang/LLVM: mold на Linux/Termux, lld-link на Windows и Apple
  ld64 на macOS;
- рядом с релизным бинарником не нужны конфиги, таблицы или файлы алгоритмов.

## Скачать готовые сборки

Проверенные бинарники находятся в приватном
[`Release v1.1.0`](https://github.com/XopMC/HASHER/releases/tag/v1.1.0):

```text
HASHER-v1.1.0-win-x64.zip
HASHER-v1.1.0-win-arm64.zip
HASHER-v1.1.0-linux-x64.tar.gz
HASHER-v1.1.0-linux-arm64.tar.gz
HASHER-v1.1.0-macos-arm64.tar.gz
HASHER-v1.1.0-android-arm64-termux.tar.gz
SHA256SUMS.txt
```

В каждом архиве находится ровно один бинарник. Windows ARM64 собран
кросс-компиляцией и проверен как PE/COFF; для полной runtime-проверки нужен
реальный Windows ARM64 компьютер.

## Быстрый старт

По умолчанию используется SHA-256, одна итерация, автоматическое количество
потоков и `stdin`:

```bash
printf 'abc\n' | ./HASHER
```

Несколько файлов и несколько алгоритмов:

```bash
./HASHER -sha256 -sha512 -rmd256 -i first.txt -i second.txt
```

Выбранные итерации без повторного пересчёта цепочки:

```bash
./HASHER -sha256 -iter 1,3-5 -i input.txt
```

Hex-ввод:

```bash
printf '616263\n' | ./HASHER -sha256 -hex
```

`-hex` специально сделан permissive для долгой работы в высоконагруженном
потоке: некорректная строка никогда не останавливает программу. Нечётная строка
дополняется нулём слева: `123` превращается в `0123`.

HMAC с пустым ключом по умолчанию или явным ключом:

```bash
printf 'abc\n' | ./HASHER -hmac-sha256
printf 'abc\n' | ./HASHER -hmac-sha256 -key secret
```

PBKDF2-HMAC-SHA256:

```bash
./HASHER -pbkdf2-hmac-sha256 -salt saltsalt -kiter 10000 -len 32 -i passwords.txt
```

## Контракт ввода и вывода

- `-i FILE` можно указывать несколько раз; файлы читаются в порядке CLI.
- Без `-i` программа читает `stdin` до EOF.
- Все источники открываются в binary mode.
- `LF` не хешируется; непосредственно стоящий перед ним `CR` тоже удаляется.
- Используются первые 1024 байта строки; остаток дочитывается и отбрасывается.
- Последняя строка обрабатывается даже без завершающего newline.
- Пустая строка хешируется как сообщение длиной 0 байт.
- UTF-8 не нормализуется и не перекодируется.
- Каждый результат — lowercase hex с `\n` в конце.
- Порядок: входная строка → алгоритм в порядке CLI → итерация по возрастанию.
- Labels, пробелы, табы, заголовки и пустые разделители отсутствуют.

Итерации используют бинарный digest:

```text
digest1 = H(input)
digest2 = H(binary digest1)
digest3 = H(binary digest2)
```

Hex-текст никогда не становится входом следующей итерации.

## Основные параметры

```text
-h / -help           Полная встроенная справка.
-i FILE              Входной файл; можно повторять. По умолчанию stdin.
-hex                 Быстрое permissive hex-декодирование строк.
-iter LIST           Итерации, например 1,3-5. По умолчанию 1.
-key TEXT            Ключ HMAC/KMAC. По умолчанию пустой, 0 байт.
-key-hex HEX         Ключ HMAC/KMAC в hex.
-func TEXT           Function name для cSHAKE.
-custom TEXT         Customization для cSHAKE/KMAC/TupleHash/ParallelHash.
-len BYTES           Размер variable output, максимум 1 048 576 байт.
-bsize BYTES         Размер блока ParallelHash. По умолчанию 1024.
-seed HEX            Seed для XXH128. По умолчанию 0.
-salt TEXT           Salt для KDF. По умолчанию пустой.
-salt-hex HEX        Salt для KDF в hex.
-kiter N             KDF rounds: PBKDF2 — 10000, остальные — 1.
-t N                 Потоки: 0=автоматически, 1..8 явно.
```

Полный список aliases, defaults, примеров и кодов ошибок доступен через
`HASHER -help`.

## Поддерживаемые алгоритмы

В registry находятся 82 независимо выбираемых алгоритма.

### SHA и Keccak

```text
sha1
sha224  sha256  sha384  sha512  sha512/224  sha512/256
sha3-224  sha3-256  sha3-384  sha3-512
keccak-224  keccak-256  keccak-384  keccak-512
shake128  shake256  cshake128  cshake256
```

### MD, RIPEMD, BLAKE, XXH и SM3

```text
md2  md4  md5
rmd-128  rmd-160  rmd-256  rmd-320
blake2b  blake2s  blake3
xxh128  sm3
```

### SP 800-185

```text
kmac128  kmac256  kmacxof128  kmacxof256
tuplehash128  tuplehash256  tuplehashxof128  tuplehashxof256
parallelhash128  parallelhash256
parallelhashxof128  parallelhashxof256
```

### HMAC

```text
hmac-md5  hmac-sha1  hmac-sha224
hmac-sha256  hmac-sha384  hmac-sha512
```

### PBKDF direct chains

```text
pbkdf-md5  pbkdf-sha1  pbkdf-sha224  pbkdf-sha256  pbkdf-sha384
pbkdf-sha512  pbkdf-rmd160  pbkdf-keccak256  pbkdf-keccak512
```

### PBKDF2-HMAC

```text
pbkdf2-hmac-md5  pbkdf2-hmac-sha1  pbkdf2-hmac-sha224
pbkdf2-hmac-sha256  pbkdf2-hmac-sha384  pbkdf2-hmac-sha512
```

### Прямые цепочки PBKDF2

```text
pbkdf2-md5  pbkdf2-sha1  pbkdf2-sha224  pbkdf2-sha256  pbkdf2-sha384
pbkdf2-sha512  pbkdf2-rmd160  pbkdf2-keccak256  pbkdf2-keccak512
```

Эти compatibility-варианты используют выбранный digest напрямую как round
function: `U1=H(password||salt||counter)`, `Uj=H(password||Uj-1)`, затем XOR
внутри блока. Для стандартного PBKDF2-HMAC используйте `pbkdf2-hmac-*`.

### EvpKDF, совместимый с OpenSSL/CryptoJS

```text
evpkdf-md5  evpkdf-sha1  evpkdf-sha224  evpkdf-sha256  evpkdf-sha384
evpkdf-sha512  evpkdf-rmd160  evpkdf-keccak256  evpkdf-keccak512
```

## Нативное ускорение

| Семейство | x64 | ARM64 |
|---|---|---|
| SHA-1/SHA-224/SHA-256 | SHA-NI и portable fallback | ARM SHA1/SHA2, включая hardware schedule |
| SHA-384/SHA-512 | AVX core, optional SHA512 | ARM SHA512 при наличии |
| SHA-3/Keccak/XOF | scalar, AVX2/AVX-512 multi-buffer | ARM SHA3 и NEON x2+x2 batching |
| BLAKE2 | официальный SSE backend | официальный NEON backend |
| BLAKE3 | SSE2/SSE4.1/AVX2/AVX-512 | NEON |
| XXH128 | официальный runtime SIMD dispatcher | NEON |
| SM3 | SM3-NI при наличии | ARM SM3 instructions |
| MD/RIPEMD/KDF | параллельная обработка строк | параллельная обработка строк |

Возможности CPU проверяются один раз. Если инструкцию нельзя достоверно
подтвердить, автоматически используется безопасный baseline backend.

## Производительность

Большой SHA-256 workload, более 16 миллионов строк по 64 байта, median из трёх:

| Платформа | Файл → null | PIPE → null | Файл → реальный output |
|---|---:|---:|---:|
| Windows x64 | 22.6 M строк/с | 24.3 M строк/с | 17.6 M строк/с |
| WSL Linux x64 | 21.0 M строк/с | 19.2 M строк/с | 11.0 M строк/с |
| Linux ARM64 | 8.58 M строк/с | 7.13 M строк/с | 6.30 M строк/с |
| macOS ARM64 | 31.98 M строк/с | 25.97 M строк/с | 30.49 M строк/с |

Выбранные результаты на корпусе 260 МиБ / 4 194 304 строки:

| Алгоритм | Windows x64 файл | Windows x64 PIPE | Linux x64 файл | Linux x64 PIPE |
|---|---:|---:|---:|---:|
| SHA-256 | 20.98 M | 23.14 M | 18.63 M | 17.02 M |
| SHA-512 | 14.56 M | 15.06 M | 11.69 M | 11.32 M |
| SHA3-256 | 24.02 M | 23.41 M | 18.97 M | 17.79 M |
| XXH128 | 25.80 M | 26.79 M | 23.52 M | 23.48 M |
| HMAC-SHA256 | 15.41 M | 15.84 M | 14.35 M | 13.70 M |
| PBKDF2-HMAC-SHA256, один KDF round | 14.77 M | 15.54 M | 13.08 M | 12.24 M |
| direct-PBKDF2-SHA256, один KDF round | 19.44 M | 19.52 M | 12.37 M | 11.69 M |

На Qualcomm SM8850 SHA-256 достиг примерно 21.5 M строк/с из файла и 17.9 M
строк/с из PIPE. Базовая v1.0-матрица из 73 алгоритмов обработала корпус
260 МиБ за 18.718 секунды из файла и 21.614 секунды из PIPE.

В измерения входят чтение, разбор строк, хеширование, hex-кодирование и
буферизированный вывод. Полные CSV находятся в `benchmarks/`, сводка — в
`dist/BENCHMARKS.md`.

## Сборка из исходников

Требования:

- GNU Make 4.x;
- CMake и Ninja;
- Clang/LLVM 21.x;
- mold на Linux и Termux;
- Windows SDK/UCRT для Windows;
- Xcode Command Line Tools для macOS.

Обычная сборка выполняется одной командой:

```bash
make
```

Makefile сам определяет ОС и архитектуру, выбирает проверенную оптимальную
конфигурацию, собирает проект, запускает доступные тесты и оставляет один
бинарник в `build/<platform>/`.

```bash
make detect
make test
make debug
make pgo
make package VERSION=v1.1.0
make package-all VERSION=v1.1.0
make help
```

Для нестандартного расположения toolchain доступны overrides `TARGET`, `JOBS`,
`CC`, `CXX`, `CMAKE`, `CTEST`, `NINJA` и `LLVM_PROFDATA`:

```bash
make TARGET=linux-arm64 CC=/opt/llvm/bin/clang CXX=/opt/llvm/bin/clang++ JOBS=8
```

На Termux автоматически создаётся свежий PGO-профиль. На платформах, где PGO
ухудшил representative workload, он по умолчанию не используется.

## Проверка корректности

- smoke/KAT для всех 82 registry entries;
- официальные vectors SHA, SHA-3, SP 800-185, BLAKE, XXH, SM3, HMAC и PBKDF2;
- parity one-shot/prepared и portable/native;
- boundary lengths, binary input, streaming chunks и unaligned buffers;
- CLI golden tests для файлов, PIPE, iterations, aliases, CRLF/LF, permissive
  hex, truncation, детерминизма потоков и one-digest-per-line;
- Windows x64: 5/5 release tests;
- Linux x64, Linux ARM64, macOS ARM64 и Termux ARM64: 6/6 release tests;
- sanitizer, dependency, binary-format и ISA disassembly checks.

Подробности находятся в `dist/TESTS.md` и `dist/BUILD-MANIFEST.md`.

## Ограничения и backlog

- Используются первые 1024 байта каждой входной строки.
- Количество worker threads специально ограничено восемью.
- Windows ARM64 пока проверен как cross-build.
- Физическая x64-проверка SM3-NI и SHA512-NI остаётся в backlog.
- Termux использует системный `libc++_shared.so`; в стандартной установке
  Termux ничего копировать рядом с HASHER не требуется.

## Лицензия

Оригинальный код HASHER распространяется по MIT License. Сторонний код
сохраняет собственные лицензии — см. `THIRD_PARTY_NOTICES.md` и
`dist/licenses/`.
