#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif
#ifdef __linux__
#include <fcntl.h>
#include <unistd.h>
#endif
int main(int argc,char** argv){
    unsigned char* buffer;FILE* input;size_t n;if(argc!=2)return 1;
#ifdef _WIN32
    _setmode(_fileno(stdout),_O_BINARY);
#elif defined(__linux__)
    (void)fcntl(STDOUT_FILENO,F_SETPIPE_SZ,1<<20);
#endif
    input=fopen(argv[1],"rb");if(!input)return 2;buffer=(unsigned char*)malloc(1u<<20);if(!buffer){fclose(input);return 3;}
    while((n=fread(buffer,1,1u<<20,input))!=0)if(fwrite(buffer,1,n,stdout)!=n){free(buffer);fclose(input);return 4;}
    n=ferror(input)?2:0;free(buffer);fclose(input);return (int)n;
}
