# x64 native-instruction backlog

Deferred until physical x64 hardware is available:

- Intel SM3-NI throughput and end-to-end file/PIPE tuning;
- Intel SHA512-NI throughput and backend-selection tuning;
- SM4 instruction evaluation if an SM4 algorithm is added to HASHER later.

The existing x64 SM3 implementation has semantic/KAT coverage under Intel SDE,
but emulator timing is not accepted as performance evidence. No claim that the
x64 SM3-NI or SHA512-NI paths are maximally tuned will be made until the real
hardware matrix is completed.

Required future stand evidence:

- forced portable/native parity;
- individual core hashes/s for every affected algorithm and record size;
- 260 MiB file and PIPE lines/s;
- 1/2/4/8-worker scaling;
- instruction disassembly and illegal-instruction fallback checks;
- interleaved candidate/baseline medians before accepting changes.
