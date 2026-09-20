/* Pure-C ACLE port of the ARM SM3 instruction schedule used by gmsm.
 * Copyright (c) 2020 Sun Yimin. MIT License.
 * The source is compiled in a separate +sm4 translation unit because ACLE
 * groups the ARM SM3 and SM4 instruction extensions under that target flag. */
#include "sm3_arm_ni.h"
#include <arm_neon.h>
#include <string.h>

#define ROT1(X) vorrq_u32(vshlq_n_u32((X),1),vshrq_n_u32((X),31))

#define ROUND_A(I,ST1,ST2,W,WT,TC,TN) do { \
    uint32x4_t ss=vsm3ss1q_u32((ST1),(TC),(ST2)); \
    (TN)=ROT1(TC); \
    (ST1)=vsm3tt1aq_u32((ST1),ss,(WT),(I)); \
    (ST2)=vsm3tt2aq_u32((ST2),ss,(W),(I)); \
} while(0)

#define ROUND_B(I,ST1,ST2,W,WT,TC,TN) do { \
    uint32x4_t ss=vsm3ss1q_u32((ST1),(TC),(ST2)); \
    (TN)=ROT1(TC); \
    (ST1)=vsm3tt1bq_u32((ST1),ss,(WT),(I)); \
    (ST2)=vsm3tt2bq_u32((ST2),ss,(W),(I)); \
} while(0)

#define EXPAND(S0,S1,S2,S3,OUT) do { \
    uint32x4_t e6=vextq_u32((S0),(S1),3); \
    uint32x4_t e7=vextq_u32((S2),(S3),2); \
    (OUT)=vextq_u32((S1),(S2),3); \
    (OUT)=vsm3partw1q_u32((OUT),(S0),(S3)); \
    (OUT)=vsm3partw2q_u32((OUT),e7,e6); \
} while(0)

#define QROUND_A(ST1,ST2,S0,S1,S2,S3,OUT,T0,T1) do { \
    uint32x4_t wt; EXPAND(S0,S1,S2,S3,OUT); wt=veorq_u32((S0),(S1)); \
    ROUND_A(0,ST1,ST2,S0,wt,T0,T1); ROUND_A(1,ST1,ST2,S0,wt,T1,T0); \
    ROUND_A(2,ST1,ST2,S0,wt,T0,T1); ROUND_A(3,ST1,ST2,S0,wt,T1,T0); \
} while(0)

#define QROUND_B(ST1,ST2,S0,S1,S2,S3,OUT,T0,T1) do { \
    uint32x4_t wt; EXPAND(S0,S1,S2,S3,OUT); wt=veorq_u32((S0),(S1)); \
    ROUND_B(0,ST1,ST2,S0,wt,T0,T1); ROUND_B(1,ST1,ST2,S0,wt,T1,T0); \
    ROUND_B(2,ST1,ST2,S0,wt,T0,T1); ROUND_B(3,ST1,ST2,S0,wt,T1,T0); \
} while(0)

#define QROUND_B_LAST(ST1,ST2,S0,S1,T0,T1) do { \
    uint32x4_t wt=veorq_u32((S0),(S1)); \
    ROUND_B(0,ST1,ST2,S0,wt,T0,T1); ROUND_B(1,ST1,ST2,S0,wt,T1,T0); \
    ROUND_B(2,ST1,ST2,S0,wt,T0,T1); ROUND_B(3,ST1,ST2,S0,wt,T1,T0); \
} while(0)

static uint32x4_t load_message(const uint8_t* p) {
    return vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p)));
}

static void sm3_arm_ni_compress(uint32_t state[8],const uint8_t* data,size_t blocks) {
    uint32x4_t st1=vld1q_u32(state),st2=vld1q_u32(state+4);
    st1=vextq_u32(vrev64q_u32(st1),vrev64q_u32(st1),2);
    st2=vextq_u32(vrev64q_u32(st2),vrev64q_u32(st2),2);
    while(blocks--) {
        uint32x4_t old1=st1,old2=st2;
        uint32x4_t s0=load_message(data),s1=load_message(data+16);
        uint32x4_t s2=load_message(data+32),s3=load_message(data+48),s4;
        uint32x4_t t0=vsetq_lane_u32(0x79cc4519u,vdupq_n_u32(0),3);
        uint32x4_t t1=vsetq_lane_u32(0xf3988a32u,vdupq_n_u32(0),3);
        QROUND_A(st1,st2,s0,s1,s2,s3,s4,t0,t1);
        QROUND_A(st1,st2,s1,s2,s3,s4,s0,t0,t1);
        QROUND_A(st1,st2,s2,s3,s4,s0,s1,t0,t1);
        QROUND_A(st1,st2,s3,s4,s0,s1,s2,t0,t1);
        t0=vsetq_lane_u32(0x9d8a7a87u,vdupq_n_u32(0),3);
        t1=vsetq_lane_u32(0x3b14f50fu,vdupq_n_u32(0),3);
        QROUND_B(st1,st2,s4,s0,s1,s2,s3,t0,t1);
        QROUND_B(st1,st2,s0,s1,s2,s3,s4,t0,t1);
        QROUND_B(st1,st2,s1,s2,s3,s4,s0,t0,t1);
        QROUND_B(st1,st2,s2,s3,s4,s0,s1,t0,t1);
        QROUND_B(st1,st2,s3,s4,s0,s1,s2,t0,t1);
        QROUND_B(st1,st2,s4,s0,s1,s2,s3,t0,t1);
        QROUND_B(st1,st2,s0,s1,s2,s3,s4,t0,t1);
        QROUND_B(st1,st2,s1,s2,s3,s4,s0,t0,t1);
        QROUND_B(st1,st2,s2,s3,s4,s0,s1,t0,t1);
        QROUND_B_LAST(st1,st2,s3,s4,t0,t1);
        QROUND_B_LAST(st1,st2,s4,s0,t0,t1);
        QROUND_B_LAST(st1,st2,s0,s1,t0,t1);
        st1=veorq_u32(st1,old1); st2=veorq_u32(st2,old2);
        data+=64;
    }
    st1=vextq_u32(vrev64q_u32(st1),vrev64q_u32(st1),2);
    st2=vextq_u32(vrev64q_u32(st2),vrev64q_u32(st2),2);
    vst1q_u32(state,st1);vst1q_u32(state+4,st2);
}

static void store_be32(uint8_t* p,uint32_t x) {
    p[0]=(uint8_t)(x>>24);p[1]=(uint8_t)(x>>16);p[2]=(uint8_t)(x>>8);p[3]=(uint8_t)x;
}

void hasher_sm3_arm_ni(const uint8_t* input,size_t size,uint8_t output[32]) {
    uint32_t state[8]={0x7380166fu,0x4914b2b9u,0x172442d7u,0xda8a0600u,
                       0xa96f30bcu,0x163138aau,0xe38dee4du,0xb0fb0e4eu};
    uint8_t tail[128]={0};size_t blocks=size/64,rem=size&63,pad_blocks,i;
    uint64_t bits=(uint64_t)size<<3;
    if(blocks)sm3_arm_ni_compress(state,input,blocks);
    if(rem)memcpy(tail,input+blocks*64,rem);
    tail[rem]=0x80;pad_blocks=rem<56?1:2;
    for(i=0;i<8;i++)tail[pad_blocks*64-1-i]=(uint8_t)(bits>>(i*8));
    sm3_arm_ni_compress(state,tail,pad_blocks);
    for(i=0;i<8;i++)store_be32(output+i*4,state[i]);
}
