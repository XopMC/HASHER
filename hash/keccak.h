#pragma once

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>


void keccak(const char* message, int message_len, unsigned char* output, int output_len);
void sha3_256(const char* message, int message_len, unsigned char* output, int output_len);
void keccak256_batch(const uint8_t* messages, const unsigned long long* lengths, unsigned long long count, uint8_t* out);
void sha3_256_batch(const uint8_t* messages, const unsigned long long* lengths, unsigned long long count, uint8_t* out);