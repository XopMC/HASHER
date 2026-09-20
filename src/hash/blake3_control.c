#include "blake3_control.h"

#if defined(__x86_64__) || defined(_M_X64)
#if defined(_WIN32)
extern long g_cpu_features;
#else
#include <stdatomic.h>
extern _Atomic int g_cpu_features;
#endif

void hasher_blake3_force_portable(void) {
    g_cpu_features = 0;
}
#else
void hasher_blake3_force_portable(void) {}
#endif
