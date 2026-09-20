#include "keccak_core.h"
#include "keccak_x4.h"
#include <string.h>
#include <KeccakP-1600-plain64.h>

typedef void (*permute_fn)(void* state);
static void permute_plain(void* state) { KeccakP1600_plain64_Permute_24rounds((KeccakP1600_plain64_state*)state); }
#if defined(HASHER_XKCP_AVX512)
extern void KeccakP1600_Permute_24rounds(void* state);
#endif
#if defined(HASHER_XKCP_ARM_SHA3)
extern void hasher_keccak_arm_sha3_permute(void* state);
#endif
static permute_fn selected_permute = permute_plain;
static hasher_keccak_x4_fn selected_x4;
static const char* selected_backend = "xkcp-unrolled-c";

void hasher_keccak_select_backend(int use_avx512, int use_avx2, int use_arm_sha3) {
    (void)use_avx2;
#if defined(HASHER_XKCP_X4_AVX512)
    if (use_avx512) selected_x4 = hasher_keccak_x4_avx512;
    else
#endif
#if defined(HASHER_XKCP_X4_AVX2)
    if (use_avx2) selected_x4 = hasher_keccak_x4_avx2;
    else
#endif
#if defined(HASHER_XKCP_ARM_SHA3)
    if (use_arm_sha3) selected_x4 = hasher_keccak_x4_arm_sha3;
    else
#endif
    selected_x4 = 0;
#if defined(HASHER_XKCP_AVX512)
    if (use_avx512) { selected_permute = KeccakP1600_Permute_24rounds; selected_backend = "xkcp-avx512-c+x4"; return; }
#else
    (void)use_avx512;
#endif
#if defined(HASHER_XKCP_ARM_SHA3)
    if (use_arm_sha3) { selected_permute = hasher_keccak_arm_sha3_permute; selected_backend = "arm-sha3-c+x4-via-x2"; return; }
#else
    (void)use_arm_sha3;
#endif
    selected_permute = permute_plain;
    selected_backend = selected_x4 ? "xkcp-unrolled-c+x4-avx2" : "xkcp-unrolled-c";
}
const char* hasher_keccak_backend(void) { return selected_backend; }
int hasher_keccak_hash4(size_t rate, uint8_t suffix,
    const uint8_t* const input[4], const size_t input_size[4],
    uint8_t* const output[4], size_t output_size) {
    return selected_x4 ? selected_x4(rate,suffix,input,input_size,output,output_size) : -1;
}
static void permute(hasher_keccak_ctx* ctx) { selected_permute(ctx->lanes); }

int hasher_keccak_init(hasher_keccak_ctx* ctx, size_t rate) {
    if (!ctx || rate == 0 || rate >= sizeof(ctx->lanes)) return -1;
    memset(ctx, 0, sizeof(*ctx));
    ctx->rate = rate;
    return 0;
}

int hasher_keccak_update(hasher_keccak_ctx* ctx, const uint8_t* input, size_t size) {
    uint8_t* state;
    if (!ctx || (!input && size)) return -1;
    state = (uint8_t*)ctx->lanes;
    while (size) {
        size_t take = ctx->rate - ctx->position;
        size_t i = 0;
        if (take > size) take = size;
        while (i < take && ((ctx->position + i) & 7u)) {
            state[ctx->position + i] ^= input[i];
            ++i;
        }
        while (i + 8 <= take) {
            uint64_t word;
            memcpy(&word, input + i, sizeof(word));
            ctx->lanes[(ctx->position + i) >> 3] ^= word;
            i += 8;
        }
        while (i < take) {
            state[ctx->position + i] ^= input[i];
            ++i;
        }
        ctx->position += take;
        input += take;
        size -= take;
        if (ctx->position == ctx->rate) {
            permute(ctx);
            ctx->position = 0;
        }
    }
    return 0;
}

int hasher_keccak_final(hasher_keccak_ctx* ctx, uint8_t suffix, uint8_t* output, size_t output_size) {
    uint8_t* state;
    if (!ctx || (!output && output_size)) return -1;
    state = (uint8_t*)ctx->lanes;
    state[ctx->position] ^= suffix;
    state[ctx->rate - 1] ^= 0x80;
    permute(ctx);
    while (output_size) {
        size_t take = output_size < ctx->rate ? output_size : ctx->rate;
        memcpy(output, state, take);
        output += take;
        output_size -= take;
        if (output_size) permute(ctx);
    }
    return 0;
}

int hasher_keccak_hash(size_t rate, uint8_t suffix, const uint8_t* input, size_t input_size,
                       uint8_t* output, size_t output_size) {
    hasher_keccak_ctx ctx;
    if (hasher_keccak_init(&ctx, rate) != 0) return -1;
    if (hasher_keccak_update(&ctx, input, input_size) != 0) return -1;
    return hasher_keccak_final(&ctx, suffix, output, output_size);
}
