/* SHA-512 ARMv8.2 compression adapted from Mbed TLS 3.6.4 (Apache-2.0). */
#include "sha512_arm.h"
#include <arm_neon.h>

static const uint64_t k[80] = {
0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL};

#define ROUND2(S,I,H,E,C,A,T,ADD) do { \
    initial=vaddq_u64((S),vld1q_u64(k+(I))); \
    sum=vaddq_u64(vextq_u64(initial,initial,1),(H)); \
    mid=vsha512hq_u64(sum,vextq_u64((E),(H),1),vextq_u64((C),(E),1)); \
    (T)=vsha512h2q_u64(mid,(C),(A)); (ADD)=vaddq_u64((ADD),mid); \
} while(0)

void hasher_sha512_arm_compress(uint64_t state[8], const uint8_t* data, size_t blocks) {
    uint64x2_t ab=vld1q_u64(state),cd=vld1q_u64(state+2),ef=vld1q_u64(state+4),gh=vld1q_u64(state+6);
    while(blocks--){
        uint64x2_t abo=ab,cdo=cd,efo=ef,gho=gh,initial,sum,mid;
        uint64x2_t s0=(uint64x2_t)vrev64q_u8(vld1q_u8(data));
        uint64x2_t s1=(uint64x2_t)vrev64q_u8(vld1q_u8(data+16));
        uint64x2_t s2=(uint64x2_t)vrev64q_u8(vld1q_u8(data+32));
        uint64x2_t s3=(uint64x2_t)vrev64q_u8(vld1q_u8(data+48));
        uint64x2_t s4=(uint64x2_t)vrev64q_u8(vld1q_u8(data+64));
        uint64x2_t s5=(uint64x2_t)vrev64q_u8(vld1q_u8(data+80));
        uint64x2_t s6=(uint64x2_t)vrev64q_u8(vld1q_u8(data+96));
        uint64x2_t s7=(uint64x2_t)vrev64q_u8(vld1q_u8(data+112));
        ROUND2(s0,0,gh,ef,cd,ab,gh,cd); ROUND2(s1,2,ef,cd,ab,gh,ef,ab);
        ROUND2(s2,4,cd,ab,gh,ef,cd,gh); ROUND2(s3,6,ab,gh,ef,cd,ab,ef);
        ROUND2(s4,8,gh,ef,cd,ab,gh,cd); ROUND2(s5,10,ef,cd,ab,gh,ef,ab);
        ROUND2(s6,12,cd,ab,gh,ef,cd,gh); ROUND2(s7,14,ab,gh,ef,cd,ab,ef);
        for(unsigned t=16;t<80;t+=16){
            s0=vsha512su1q_u64(vsha512su0q_u64(s0,s1),s7,vextq_u64(s4,s5,1)); ROUND2(s0,t,gh,ef,cd,ab,gh,cd);
            s1=vsha512su1q_u64(vsha512su0q_u64(s1,s2),s0,vextq_u64(s5,s6,1)); ROUND2(s1,t+2,ef,cd,ab,gh,ef,ab);
            s2=vsha512su1q_u64(vsha512su0q_u64(s2,s3),s1,vextq_u64(s6,s7,1)); ROUND2(s2,t+4,cd,ab,gh,ef,cd,gh);
            s3=vsha512su1q_u64(vsha512su0q_u64(s3,s4),s2,vextq_u64(s7,s0,1)); ROUND2(s3,t+6,ab,gh,ef,cd,ab,ef);
            s4=vsha512su1q_u64(vsha512su0q_u64(s4,s5),s3,vextq_u64(s0,s1,1)); ROUND2(s4,t+8,gh,ef,cd,ab,gh,cd);
            s5=vsha512su1q_u64(vsha512su0q_u64(s5,s6),s4,vextq_u64(s1,s2,1)); ROUND2(s5,t+10,ef,cd,ab,gh,ef,ab);
            s6=vsha512su1q_u64(vsha512su0q_u64(s6,s7),s5,vextq_u64(s2,s3,1)); ROUND2(s6,t+12,cd,ab,gh,ef,cd,gh);
            s7=vsha512su1q_u64(vsha512su0q_u64(s7,s0),s6,vextq_u64(s3,s4,1)); ROUND2(s7,t+14,ab,gh,ef,cd,ab,ef);
        }
        ab=vaddq_u64(ab,abo);cd=vaddq_u64(cd,cdo);ef=vaddq_u64(ef,efo);gh=vaddq_u64(gh,gho);data+=128;
    }
    vst1q_u64(state,ab);vst1q_u64(state+2,cd);vst1q_u64(state+4,ef);vst1q_u64(state+6,gh);
}
