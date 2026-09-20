/* ARM SHA3 backend from XKCP's pure-C ARMv8A x2 implementation (CC0). */
#include <stdint.h>
#include <arm_neon.h>
#include "keccak_x4.h"
#include "KeccakP-1600-times2-armv8a-neon.c"

void KeccakP1600times2_AddLanesAll(KeccakP1600times2_states* states,
                                   const unsigned char* data,
                                   unsigned lane_count, unsigned lane_offset) {
    uint64_t* packed = (uint64_t*)states->A;
    unsigned instance, lane;
    for (instance = 0; instance < 2; ++instance) {
        for (lane = 0; lane < lane_count; ++lane) {
            uint64_t word;
            memcpy(&word, data + (instance * lane_offset + lane) * 8u, 8u);
            packed[lane * 2u + instance] ^= word;
        }
    }
}

void KeccakP1600times2_PermuteAll_12rounds(KeccakP1600times2_states* states) {
    V128 lanes[25];
    KeccakP1600times2_LoadState(lanes, states->A);
    KeccakP1600times2_SHA3_Round(lanes, CONST128_RC(12));
    KeccakP1600times2_SHA3_Round(lanes, CONST128_RC(13));
    KeccakP1600times2_SHA3_Round(lanes, CONST128_RC(14));
    KeccakP1600times2_SHA3_Round(lanes, CONST128_RC(15));
    KeccakP1600times2_SHA3_Round(lanes, CONST128_RC(16));
    KeccakP1600times2_SHA3_Round(lanes, CONST128_RC(17));
    KeccakP1600times2_SHA3_Round(lanes, CONST128_RC(18));
    KeccakP1600times2_SHA3_Round(lanes, CONST128_RC(19));
    KeccakP1600times2_SHA3_Round(lanes, CONST128_RC(20));
    KeccakP1600times2_SHA3_Round(lanes, CONST128_RC(21));
    KeccakP1600times2_SHA3_Round(lanes, CONST128_RC(22));
    KeccakP1600times2_SHA3_Round(lanes, CONST128_RC(23));
    KeccakP1600times2_StoreState(states->A, lanes);
}

void KeccakP1600times2_PermuteAll_24rounds(KeccakP1600times2_states* states) {
    V128 lanes[25];
    KeccakP1600times2_LoadState(lanes, states->A);
    KeccakP1600times2_SHA3_Rounds24(lanes);
    KeccakP1600times2_StoreState(states->A, lanes);
}

void hasher_keccak_arm_sha3_permute(void* opaque) {
    uint64_t* state = (uint64_t*)opaque;
    KeccakP1600times2_states pair;
    unsigned i;
    for (i = 0; i < 25; ++i) pair.A[i] = vdupq_n_u64(state[i]);
    KeccakP1600times2_PermuteAll_24rounds(&pair);
    for (i = 0; i < 25; ++i) state[i] = vgetq_lane_u64(pair.A[i], 0);
}

static void pair_add_bytes(KeccakP1600times2_states* states, unsigned instance,
                           const uint8_t* input, size_t size) {
    uint64_t* packed = (uint64_t*)states->A;
    size_t offset = 0;
    while (offset + 8 <= size) {
        uint64_t word;
        memcpy(&word, input + offset, sizeof(word));
        packed[(offset >> 3) * 2u + instance] ^= word;
        offset += 8;
    }
    while (offset < size) {
        uint8_t* lane = (uint8_t*)&packed[(offset >> 3) * 2u + instance];
        lane[offset & 7u] ^= input[offset];
        ++offset;
    }
}

static void pair_add_byte(KeccakP1600times2_states* states, unsigned instance,
                          size_t offset, uint8_t byte) {
    uint64_t* packed = (uint64_t*)states->A;
    uint8_t* lane = (uint8_t*)&packed[(offset >> 3) * 2u + instance];
    lane[offset & 7u] ^= byte;
}

static void pair_extract(const KeccakP1600times2_states* states, unsigned instance,
                         uint8_t* output, size_t size) {
    const uint64_t* packed = (const uint64_t*)states->A;
    size_t offset = 0;
    while (offset + 8 <= size) {
        memcpy(output + offset, &packed[(offset >> 3) * 2u + instance], 8);
        offset += 8;
    }
    if (offset < size) memcpy(output + offset, &packed[(offset >> 3) * 2u + instance], size - offset);
}

int hasher_keccak_x4_arm_sha3(size_t rate, uint8_t suffix,
    const uint8_t* const input[4], const size_t input_size[4],
    uint8_t* const output[4], size_t output_size) {
    unsigned base, instance;
    if (!rate || rate > 200 || output_size > rate) return -1;
    for (base = 0; base < 4; ++base)
        if (input_size[base] >= rate || (!input[base] && input_size[base]) || !output[base]) return -1;
    for (base = 0; base < 4; base += 2) {
        KeccakP1600times2_states states;
        memset(&states, 0, sizeof(states));
        for (instance = 0; instance < 2; ++instance) {
            unsigned index = base + instance;
            pair_add_bytes(&states, instance, input[index], input_size[index]);
            pair_add_byte(&states, instance, input_size[index], suffix);
            pair_add_byte(&states, instance, rate - 1, 0x80);
        }
        KeccakP1600times2_PermuteAll_24rounds(&states);
        for (instance = 0; instance < 2; ++instance)
            pair_extract(&states, instance, output[base + instance], output_size);
    }
    return 0;
}
