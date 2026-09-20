#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void sm3_digest(const uint8_t* msg, size_t msglen, uint8_t dgst[32]);

static double now_seconds(void) {
#if defined(_WIN32)
    return (double)clock() / (double)CLOCKS_PER_SEC;
#else
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC,&t);
    return (double)t.tv_sec + (double)t.tv_nsec * 1e-9;
#endif
}

int main(int argc,char** argv) {
    size_t size=argc>1?(size_t)strtoull(argv[1],0,10):64;
    size_t rounds=argc>2?(size_t)strtoull(argv[2],0,10):1000000;
    uint8_t* in=(uint8_t*)malloc(size?size:1); uint8_t out[32];
    volatile unsigned sink=0; double begin,end; size_t i;
    if(!in||!rounds)return 1;
    for(i=0;i<size;i++)in[i]=(uint8_t)(i*131u+17u);
    begin=now_seconds();
    for(i=0;i<rounds;i++){sm3_digest(in,size,out);sink^=out[i&31];}
    end=now_seconds();
    printf("gmssl-sse,%zu,%zu,%.6f,%.3f,%.0f,%u\n",size,rounds,end-begin,
           (double)size*(double)rounds/(1048576.0*(end-begin)),(double)rounds/(end-begin),(unsigned)sink);
    free(in);return 0;
}
