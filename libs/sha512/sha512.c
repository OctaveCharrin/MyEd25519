#include <string.h>
#include <stdint.h>
#include <string.h>
#include "sha512.h"

static u64 K[] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 
    0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 
    0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 
    0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 
    0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 
    0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 
    0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 
    0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 
    0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

static u64 IV[] = {
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179
};

static inline u64 swap_endianness(u64 x) {
    return __builtin_bswap64(x);
}

size_t read_block(FILE* stream, u8* buffer) {
    // This assumes the buffer is exactly 128 bytes long.
    return fread(buffer, sizeof(u8), BLOCK_BYTE_SIZE, stream);
}

void pad_block(u8* buffer, size_t buffer_content_size) {
    // This assumes the buffer has at least 17 bytes of empty spaces to be padded

    buffer[buffer_content_size] = 0b10000000;
    for (size_t i = buffer_content_size + 1; i < BLOCK_BYTE_SIZE; i++) {
        buffer[i] = 0;
    }
}

void seal_block(u8* buffer, u64 message_content_size) {
    u64* padding_cursor = (u64*)(buffer + BLOCK_BYTE_SIZE - 8);
    *padding_cursor = swap_endianness(message_content_size * 8);
}

void swap_endianness_block(u64* buffer) {
    for (size_t i = 0; i < BLOCK_WORD_SIZE; i++) {
        buffer[i] = swap_endianness(buffer[i]);
    }
}

static inline u64 rotate_right(u64 x, size_t n_bits) {
    return (x >> n_bits) | (x << (64 - n_bits));
}

static inline u64 sigma_0(u64 x) {
    return rotate_right(x, 1) ^ rotate_right(x, 8) ^ (x >> 7);
}

static inline u64 sigma_1(u64 x) {
    return rotate_right(x, 19) ^ rotate_right(x, 61) ^ (x >> 6);
}

static inline u64 ch(u64 x, u64 y, u64 z) {
    return (x & y) ^ ((~x) & z);
}

static inline u64 maj(u64 x, u64 y, u64 z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

static inline u64 big_sigma_0(u64 x) {
    return rotate_right(x, 28) ^ rotate_right(x, 34) ^ rotate_right(x, 39);
}

static inline u64 big_sigma_1(u64 x) {
    return rotate_right(x, 14) ^ rotate_right(x, 18) ^ rotate_right(x, 41);
}

void extend_block(u64* buffer) {
    for (size_t i = BLOCK_WORD_SIZE; i < BUFFER_WORD_SIZE; i++) {
        buffer[i] = sigma_1(buffer[i - 2]) + buffer[i - 7] + sigma_0(buffer[i - 15]) + buffer[i - 16];
    }
}

void compress_block(u64* buffer, u64* registers) {
    u64 working_registers[REGISTER_SIZE];
    for (size_t i = 0; i < REGISTER_SIZE; i++) {
        working_registers[i] = registers[i];
    }
    
    for (size_t i = 0; i < BUFFER_WORD_SIZE; i++) {
        u64 t1 = working_registers[7] 
            + big_sigma_1(working_registers[4]) 
            + ch(working_registers[4], working_registers[5], working_registers[6])
            + K[i]
            + buffer[i];
        
        u64 t2 = big_sigma_0(working_registers[0]) 
            + maj(working_registers[0], working_registers[1], working_registers[2]);

        working_registers[7] = working_registers[6];
        working_registers[6] = working_registers[5];
        working_registers[5] = working_registers[4];
        working_registers[4] = working_registers[3] + t1;
        working_registers[3] = working_registers[2];
        working_registers[2] = working_registers[1];
        working_registers[1] = working_registers[0];
        working_registers[0] = t1 + t2;
    }

    for (size_t i = 0; i < REGISTER_SIZE; i++) {
        registers[i] += working_registers[i];
    }
}

u64* sha512(FILE* stream, u64* registers) {
    u64 buffer[80];
    for (size_t i = 0; i < REGISTER_SIZE; i++) {
        registers[i] = IV[i];
    }

    u64 message_content_size = 0;
    int sealed_block = 0;
    int padded_block = 0;

    while (!feof(stream)) {
        size_t buffer_content_size = read_block(stream, (u8*) buffer);
        message_content_size += (u64) buffer_content_size;

        if (buffer_content_size < BLOCK_BYTE_SIZE) {
            pad_block((u8*) buffer, buffer_content_size);
            padded_block = 1;
        }
        
        if (buffer_content_size < BLOCK_BYTE_SIZE - 16) {
            seal_block((u8*) buffer, message_content_size);
            sealed_block = 1;
        }

        swap_endianness_block(buffer);
        extend_block(buffer);
        compress_block(buffer, registers);
    }

    if ((sealed_block == 0) && (padded_block == 1)) memset(buffer, 0, BLOCK_BYTE_SIZE);
    if (padded_block == 0) pad_block((u8*) buffer, 0);
    if (sealed_block == 0) seal_block((u8*) buffer, message_content_size);
    if ((sealed_block == 0) || (padded_block == 0)) {
        swap_endianness_block(buffer);
        extend_block(buffer);
        compress_block(buffer, registers);
    }

    return registers;
}