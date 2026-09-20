#include "keccak_x4.h"
#include "KeccakP-1600-times4-AVX512.h"

int hasher_keccak_x4_avx512(size_t rate, uint8_t suffix,
    const uint8_t* const input[4], const size_t input_size[4],
    uint8_t* const output[4], size_t output_size) {
    KeccakP1600times4_align512SIMD256_states states;
    unsigned i;
    if (!rate || rate > 200 || output_size > rate) return -1;
    for (i=0;i<4;++i) if (input_size[i] >= rate || (!input[i] && input_size[i]) || !output[i]) return -1;
    KeccakP1600times4_AVX512_InitializeAll(&states);
    for (i=0;i<4;++i) {
        if (input_size[i]) KeccakP1600times4_AVX512_AddBytes(&states,i,input[i],0,(unsigned)input_size[i]);
        KeccakP1600times4_AVX512_AddByte(&states,i,suffix,(unsigned)input_size[i]);
        KeccakP1600times4_AVX512_AddByte(&states,i,0x80,(unsigned)rate-1);
    }
    KeccakP1600times4_AVX512_PermuteAll_24rounds(&states);
    for (i=0;i<4;++i) KeccakP1600times4_AVX512_ExtractBytes(&states,i,output[i],0,(unsigned)output_size);
    return 0;
}
