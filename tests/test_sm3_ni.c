#ifndef HASHER_SM3_TEST_HEADER
#define HASHER_SM3_TEST_HEADER "sm3_x86_ni.h"
#define HASHER_SM3_TEST_FN hasher_sm3_x86_ni
#endif
#include HASHER_SM3_TEST_HEADER
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static uint32_t rol32(uint32_t x,unsigned n) { return n?((x<<n)|(x>>(32-n))):x; }
static uint32_t load_be32(const uint8_t* p) {
    return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];
}
static void store_be32(uint8_t* p,uint32_t x) {
    p[0]=(uint8_t)(x>>24);p[1]=(uint8_t)(x>>16);p[2]=(uint8_t)(x>>8);p[3]=(uint8_t)x;
}
static void reference_block(uint32_t s[8],const uint8_t b[64]) {
    uint32_t w[68],a=s[0],bb=s[1],c=s[2],d=s[3],e=s[4],f=s[5],g=s[6],h=s[7];unsigned j;
    for(j=0;j<16;j++)w[j]=load_be32(b+j*4);
    for(j=16;j<68;j++){uint32_t x=w[j-16]^w[j-9]^rol32(w[j-3],15);w[j]=x^rol32(x,15)^rol32(x,23)^rol32(w[j-13],7)^w[j-6];}
    for(j=0;j<64;j++){
        uint32_t k=j<16?0x79cc4519u:0x7a879d8au;
        uint32_t s1=rol32(rol32(a,12)+e+rol32(k,j&31),7),s2=s1^rol32(a,12);
        uint32_t ff=j<16?a^bb^c:(a&bb)|(a&c)|(bb&c);
        uint32_t gg=j<16?e^f^g:(e&f)|((~e)&g);
        uint32_t t1=ff+d+s2+(w[j]^w[j+4]),t2=gg+h+s1+w[j];
        d=c;c=rol32(bb,9);bb=a;a=t1;h=g;g=rol32(f,19);f=e;e=t2^rol32(t2,9)^rol32(t2,17);
    }
    s[0]^=a;s[1]^=bb;s[2]^=c;s[3]^=d;s[4]^=e;s[5]^=f;s[6]^=g;s[7]^=h;
}
static void reference_sm3(const uint8_t* in,size_t size,uint8_t out[32]) {
    uint32_t s[8]={0x7380166fu,0x4914b2b9u,0x172442d7u,0xda8a0600u,0xa96f30bcu,0x163138aau,0xe38dee4du,0xb0fb0e4eu};
    uint8_t tail[128]={0};size_t blocks=size/64,rem=size&63,pads,i;uint64_t bits=(uint64_t)size<<3;
    for(i=0;i<blocks;i++)reference_block(s,in+i*64);
    if(rem)memcpy(tail,in+blocks*64,rem);tail[rem]=0x80;pads=rem<56?1:2;
    for(i=0;i<8;i++)tail[pads*64-1-i]=(uint8_t)(bits>>(i*8));
    for(i=0;i<pads;i++)reference_block(s,tail+i*64);
    for(i=0;i<8;i++)store_be32(out+i*4,s[i]);
}

static int hex_value(char c) {
    return c >= '0' && c <= '9' ? c-'0' : c >= 'a' && c <= 'f' ? c-'a'+10 : -1;
}

static int check(const uint8_t* input, size_t size, const char* hex) {
    uint8_t got[32], expected[32];
    size_t i;
    for (i=0;i<32;i++) expected[i]=(uint8_t)((hex_value(hex[i*2])<<4)|hex_value(hex[i*2+1]));
    HASHER_SM3_TEST_FN(input,size,got);
    if(memcmp(got,expected,32)!=0){
        static const char digits[]="0123456789abcdef";char line[65];
        for(i=0;i<32;i++){line[i*2]=digits[got[i]>>4];line[i*2+1]=digits[got[i]&15];}
        line[64]='\n';fwrite(line,1,65,stderr);return 0;
    }
    return 1;
}

int main(void) {
    static const struct { size_t size; const char* digest; } zeros[] = {
        {0,"1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"},
        {1,"2daef60e7a0b8f5e024c81cd2ab3109f2b4f155cf83adeb2ae5532f74a157fdf"},
        {55,"2cdce3d697af3716a9b3cdf068b43e513846e17cc9fd427929aad70165f21dda"},
        {56,"87b81af2b2b22cbdf268e211d012d604892d3c948ff298d61d6c942eee847f86"},
        {63,"5241dc10cb3c700e46446943d27b971fefa7e88115f866d6f83d502ff1bc06c2"},
        {64,"46b58571be41685c253194d20ec7f82b659cc8c6b753f26d4e9ec85bc91c231e"},
        {65,"b1f76e2d1d41d6f1bb3b09c09b8219dafbad700df2482220c892be41445a22ff"},
        {1024,"62edd1c6c4542572f68a2a687af44e5cd809a5a72cacaa00b07b38581f23e515"}
    };
    uint8_t zero[1024]={0},random_input[1025],got[32],expected[32];
    uint8_t repeated[64];
    size_t i;
    if (!check((const uint8_t*)"abc",3,"66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0")) return 1;
    for(i=0;i<64;i++) repeated[i]=(uint8_t)"abcd"[i&3];
    if (!check(repeated,64,"debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732")) return 2;
    for(i=0;i<sizeof(zeros)/sizeof(zeros[0]);i++) if(!check(zero,zeros[i].size,zeros[i].digest)) return (int)i+3;
    for(i=0;i<sizeof(random_input);i++)random_input[i]=(uint8_t)(i*131u+17u);
    for(i=0;i<=sizeof(random_input);i++){
        HASHER_SM3_TEST_FN(random_input,i,got);reference_sm3(random_input,i,expected);
        if(memcmp(got,expected,32)!=0)return 32;
    }
    return 0;
}
