#pragma once
#include <stdint.h>

#define __SHA__ //Comment for use legacy sha256 (if CPU not have SHA-NI intrinsics)

#ifdef __cplusplus
extern "C" {
#endif

	void sha256(uint8_t in[], uint32_t size, uint8_t out[]);

#ifdef __cplusplus
}
#endif
