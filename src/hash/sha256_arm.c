#include "sha256_arm.h"
#include <arm_neon.h>
#include <string.h>

static const uint32_t k[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
static uint32x4_t load_be128(const uint8_t* p){return vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p)));}

#define SHA1_ROUND(FN,STATE,E,MSG,KI) do { \
  uint32x4_t wk=vaddq_u32((MSG),vdupq_n_u32((KI))); \
  uint32_t next=vsha1h_u32(vgetq_lane_u32((STATE),0)); \
  (STATE)=FN((STATE),(E),wk);(E)=next; \
} while(0)
#define SHA1_SCHEDULE(A,B,C,D) do { \
  (A)=vsha1su0q_u32((A),(B),(C));(A)=vsha1su1q_u32((A),(D)); \
} while(0)
static void compress_sha1(uint32_t state[5],const uint8_t block[64]){
  uint32_t e=state[4],saved_e=e;uint32x4_t abcd=vld1q_u32(state),saved=abcd;
  uint32x4_t m0=load_be128(block),m1=load_be128(block+16),m2=load_be128(block+32),m3=load_be128(block+48);
  SHA1_ROUND(vsha1cq_u32,abcd,e,m0,0x5a827999u);SHA1_SCHEDULE(m0,m1,m2,m3);
  SHA1_ROUND(vsha1cq_u32,abcd,e,m1,0x5a827999u);SHA1_SCHEDULE(m1,m2,m3,m0);
  SHA1_ROUND(vsha1cq_u32,abcd,e,m2,0x5a827999u);SHA1_SCHEDULE(m2,m3,m0,m1);
  SHA1_ROUND(vsha1cq_u32,abcd,e,m3,0x5a827999u);SHA1_SCHEDULE(m3,m0,m1,m2);
  SHA1_ROUND(vsha1cq_u32,abcd,e,m0,0x5a827999u);SHA1_SCHEDULE(m0,m1,m2,m3);
  SHA1_ROUND(vsha1pq_u32,abcd,e,m1,0x6ed9eba1u);SHA1_SCHEDULE(m1,m2,m3,m0);
  SHA1_ROUND(vsha1pq_u32,abcd,e,m2,0x6ed9eba1u);SHA1_SCHEDULE(m2,m3,m0,m1);
  SHA1_ROUND(vsha1pq_u32,abcd,e,m3,0x6ed9eba1u);SHA1_SCHEDULE(m3,m0,m1,m2);
  SHA1_ROUND(vsha1pq_u32,abcd,e,m0,0x6ed9eba1u);SHA1_SCHEDULE(m0,m1,m2,m3);
  SHA1_ROUND(vsha1pq_u32,abcd,e,m1,0x6ed9eba1u);SHA1_SCHEDULE(m1,m2,m3,m0);
  SHA1_ROUND(vsha1mq_u32,abcd,e,m2,0x8f1bbcdcu);SHA1_SCHEDULE(m2,m3,m0,m1);
  SHA1_ROUND(vsha1mq_u32,abcd,e,m3,0x8f1bbcdcu);SHA1_SCHEDULE(m3,m0,m1,m2);
  SHA1_ROUND(vsha1mq_u32,abcd,e,m0,0x8f1bbcdcu);SHA1_SCHEDULE(m0,m1,m2,m3);
  SHA1_ROUND(vsha1mq_u32,abcd,e,m1,0x8f1bbcdcu);SHA1_SCHEDULE(m1,m2,m3,m0);
  SHA1_ROUND(vsha1mq_u32,abcd,e,m2,0x8f1bbcdcu);SHA1_SCHEDULE(m2,m3,m0,m1);
  SHA1_ROUND(vsha1pq_u32,abcd,e,m3,0xca62c1d6u);SHA1_SCHEDULE(m3,m0,m1,m2);
  SHA1_ROUND(vsha1pq_u32,abcd,e,m0,0xca62c1d6u);
  SHA1_ROUND(vsha1pq_u32,abcd,e,m1,0xca62c1d6u);
  SHA1_ROUND(vsha1pq_u32,abcd,e,m2,0xca62c1d6u);
  SHA1_ROUND(vsha1pq_u32,abcd,e,m3,0xca62c1d6u);
  vst1q_u32(state,vaddq_u32(abcd,saved));state[4]=e+saved_e;
}

#define SHA256_ROUND(MSG,I) do { \
  uint32x4_t old=abcd,wk=vaddq_u32((MSG),vld1q_u32(k+(I))); \
  abcd=vsha256hq_u32(abcd,efgh,wk);efgh=vsha256h2q_u32(efgh,old,wk); \
} while(0)
#define SHA256_SCHEDULE(A,B,C,D) do { \
  (A)=vsha256su0q_u32((A),(B));(A)=vsha256su1q_u32((A),(C),(D)); \
} while(0)
static void compress(uint32_t state[8],const uint8_t block[64]){
  uint32x4_t abcd=vld1q_u32(state),efgh=vld1q_u32(state+4),sa=abcd,se=efgh;
  uint32x4_t m0=load_be128(block),m1=load_be128(block+16),m2=load_be128(block+32),m3=load_be128(block+48);
  SHA256_ROUND(m0,0);SHA256_SCHEDULE(m0,m1,m2,m3);
  SHA256_ROUND(m1,4);SHA256_SCHEDULE(m1,m2,m3,m0);
  SHA256_ROUND(m2,8);SHA256_SCHEDULE(m2,m3,m0,m1);
  SHA256_ROUND(m3,12);SHA256_SCHEDULE(m3,m0,m1,m2);
  SHA256_ROUND(m0,16);SHA256_SCHEDULE(m0,m1,m2,m3);
  SHA256_ROUND(m1,20);SHA256_SCHEDULE(m1,m2,m3,m0);
  SHA256_ROUND(m2,24);SHA256_SCHEDULE(m2,m3,m0,m1);
  SHA256_ROUND(m3,28);SHA256_SCHEDULE(m3,m0,m1,m2);
  SHA256_ROUND(m0,32);SHA256_SCHEDULE(m0,m1,m2,m3);
  SHA256_ROUND(m1,36);SHA256_SCHEDULE(m1,m2,m3,m0);
  SHA256_ROUND(m2,40);SHA256_SCHEDULE(m2,m3,m0,m1);
  SHA256_ROUND(m3,44);SHA256_SCHEDULE(m3,m0,m1,m2);
  SHA256_ROUND(m0,48);SHA256_ROUND(m1,52);SHA256_ROUND(m2,56);SHA256_ROUND(m3,60);
  vst1q_u32(state,vaddq_u32(abcd,sa));vst1q_u32(state+4,vaddq_u32(efgh,se));
}
void hasher_sha256_arm(const uint8_t* input,size_t size,uint8_t output[32],int sha224){
  static const uint32_t iv256[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
  static const uint32_t iv224[8]={0xc1059ed8,0x367cd507,0x3070dd17,0xf70e5939,0xffc00b31,0x68581511,0x64f98fa7,0xbefa4fa4};
  uint32_t state[8];uint8_t tail[128]={0};size_t full=size&~(size_t)63,left=size-full,pad=left<56?64:128,block;uint64_t bits=(uint64_t)size*8;unsigned i,words=sha224?7:8;
  memcpy(state,sha224?iv224:iv256,sizeof(state));for(block=0;block<full;block+=64)compress(state,input+block);
  if(left)memcpy(tail,input+full,left);tail[left]=0x80;for(i=0;i<8;++i)tail[pad-1-i]=(uint8_t)(bits>>(8*i));compress(state,tail);if(pad==128)compress(state,tail+64);
  for(i=0;i<words;++i){output[4*i]=(uint8_t)(state[i]>>24);output[4*i+1]=(uint8_t)(state[i]>>16);output[4*i+2]=(uint8_t)(state[i]>>8);output[4*i+3]=(uint8_t)state[i];}
}
void hasher_sha1_arm(const uint8_t* input,size_t size,uint8_t output[20]){
  uint32_t state[5]={0x67452301,0xefcdab89,0x98badcfe,0x10325476,0xc3d2e1f0};uint8_t tail[128]={0};size_t full=size&~(size_t)63,left=size-full,pad=left<56?64:128,block;uint64_t bits=(uint64_t)size*8;unsigned i;
  for(block=0;block<full;block+=64)compress_sha1(state,input+block);if(left)memcpy(tail,input+full,left);tail[left]=0x80;for(i=0;i<8;++i)tail[pad-1-i]=(uint8_t)(bits>>(8*i));compress_sha1(state,tail);if(pad==128)compress_sha1(state,tail+64);
  for(i=0;i<5;++i){output[4*i]=(uint8_t)(state[i]>>24);output[4*i+1]=(uint8_t)(state[i]>>16);output[4*i+2]=(uint8_t)(state[i]>>8);output[4*i+3]=(uint8_t)state[i];}
}
