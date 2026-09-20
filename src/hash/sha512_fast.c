#include "sha512_fast.h"
#include <string.h>
#if defined(HASHER_HAVE_SHA512_AVX)
#include "sha512_defs.h"
#endif
#if defined(HASHER_HAVE_SHA512_ARM)
#include "sha512_arm.h"
#endif

static int selected_avx, selected_arm;

void hasher_sha512_fast_select(int use_avx, int use_arm_sha512) {
#if defined(HASHER_HAVE_SHA512_AVX)
    selected_avx = use_avx;
#else
    (void)use_avx;
    selected_avx = 0;
#endif
#if defined(HASHER_HAVE_SHA512_ARM)
    selected_arm = use_arm_sha512;
#else
    (void)use_arm_sha512;
    selected_arm = 0;
#endif
}
const char* hasher_sha512_fast_backend(void) { return selected_avx ? "avx-c" : selected_arm ? "arm-sha512" : "portable"; }

#if defined(HASHER_HAVE_SHA512_AVX) || defined(HASHER_HAVE_SHA512_ARM)
static void store_be64(uint8_t* out, uint64_t x) {
    out[0]=(uint8_t)(x>>56);out[1]=(uint8_t)(x>>48);out[2]=(uint8_t)(x>>40);out[3]=(uint8_t)(x>>32);
    out[4]=(uint8_t)(x>>24);out[5]=(uint8_t)(x>>16);out[6]=(uint8_t)(x>>8);out[7]=(uint8_t)x;
}
#if defined(HASHER_HAVE_SHA512_AVX)
typedef sha512_state_t fast_state;
#else
typedef struct { uint64_t w[8]; } fast_state;
#endif
static void compress(fast_state* state,const uint8_t* data,size_t blocks) {
#if defined(HASHER_HAVE_SHA512_AVX)
    if(selected_avx){sha512_compress_x86_64_avx(state,data,blocks);return;}
#endif
#if defined(HASHER_HAVE_SHA512_ARM)
    if(selected_arm)hasher_sha512_arm_compress(state->w,data,blocks);
#else
    (void)state;(void)data;(void)blocks;
#endif
}
#endif

int hasher_sha512_fast(const uint8_t* input, size_t size, uint8_t* output, size_t output_size, int variant) {
#if defined(HASHER_HAVE_SHA512_AVX) || defined(HASHER_HAVE_SHA512_ARM)
    static const uint64_t iv384[8]={0xcbbb9d5dc1059ed8ULL,0x629a292a367cd507ULL,0x9159015a3070dd17ULL,0x152fecd8f70e5939ULL,0x67332667ffc00b31ULL,0x8eb44a8768581511ULL,0xdb0c2e0d64f98fa7ULL,0x47b5481dbefa4fa4ULL};
    static const uint64_t iv512[8]={0x6a09e667f3bcc908ULL,0xbb67ae8584caa73bULL,0x3c6ef372fe94f82bULL,0xa54ff53a5f1d36f1ULL,0x510e527fade682d1ULL,0x9b05688c2b3e6c1fULL,0x1f83d9abfb41bd6bULL,0x5be0cd19137e2179ULL};
    static const uint64_t iv224[8]={0x8c3d37c819544da2ULL,0x73e1996689dcd4d6ULL,0x1dfab7ae32ff9c82ULL,0x679dd514582f9fcfULL,0x0f6d2b697bd44da8ULL,0x77e36f7304c48942ULL,0x3f9d85a86a1d36c8ULL,0x1112e6ad91d692a1ULL};
    static const uint64_t iv256[8]={0x22312194fc2bf72cULL,0x9f555fa3c84c64c2ULL,0x2393b86b6f53b151ULL,0x963877195940eabdULL,0x96283ee2a88effe3ULL,0xbe5e1e2553863992ULL,0x2b0199fc2c85b8aaULL,0x0eb72ddc81c52ca2ULL};
    fast_state state;uint8_t tail[256]={0};const uint64_t* iv;size_t full=size&~(size_t)127,left=size-full,pad=left<112?128:256;uint64_t bits=(uint64_t)size*8;size_t i;
    if((!selected_avx&&!selected_arm)||(!input&&size)||!output||size>UINT64_MAX/8)return -1;
    iv=variant==HASHER_SHA384_VARIANT?iv384:variant==HASHER_SHA512_VARIANT?iv512:variant==HASHER_SHA512_224_VARIANT?iv224:iv256;
    memcpy(state.w,iv,sizeof(state.w));if(full)compress(&state,input,full/128);
    if(left)memcpy(tail,input+full,left);tail[left]=0x80;store_be64(tail+pad-8,bits);compress(&state,tail,pad/128);
    for(i=0;i<output_size/8;++i)store_be64(output+i*8,state.w[i]);if(output_size&7){uint8_t last[8];store_be64(last,state.w[i]);memcpy(output+i*8,last,output_size&7);}return 0;
#else
    (void)input;(void)size;(void)output;(void)output_size;(void)variant;return -1;
#endif
}
