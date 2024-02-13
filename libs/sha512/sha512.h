#pragma once

#include <stdio.h>

#define BLOCK_WORD_SIZE 16
#define BLOCK_BYTE_SIZE 128
#define BUFFER_WORD_SIZE 80
#define REGISTER_SIZE 8

typedef unsigned long long u64;
typedef char u8;

u64* _sha512(FILE* stream, u64* registers);
unsigned char* sha512(char const *buffer, int const len, unsigned char* registers);