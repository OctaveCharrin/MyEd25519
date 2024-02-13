#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>

#include "libs/utils/utils.h"
#include "libs/sha512/sha512.h"

#include "ed25519.h"

int main(int argc, char *argv[]){
    
    if (argc != 2){
        fprintf(stderr, "Usage: %s <prefix>\n", argv[0]);
        return 1;
    }

    char *input_string = argv[1];
    size_t input_length = strlen(input_string);
    if (input_length != 64){
        fprintf(stderr, "Input must be 32-bytes (ie 64 hexadecimal characters)\n");
        return 1;
    }
    // Process input
    char input_bytes[32];
    HexStringToBytes(input_string, (unsigned char *)input_bytes);

    // Write k as secret key
    char const *prefixsecFileName = "prefix.sk";
    FILE *secfile;
    secfile = fopen(prefixsecFileName, "wb");
    if(secfile == NULL){
        perror("Error creating prefix.sk");
        return 1;
    }
    if (fwrite(input_bytes, 1, 32, secfile) != 32) {
        perror("Error writing to tmpfile\n");
        fclose(secfile);
        return 1;
    }
    fclose(secfile);

    // Compute H(input)
    unsigned char key_buffer[64];
    sha512(input_bytes, 32, key_buffer);

    // Prune the lower 32 bytes
    key_buffer[0]  &= 0xf8;
    key_buffer[31] &= 0x7f;
    key_buffer[31] |= 0x40;


    //******** KEY GENERATION *********
    beginEd25519();
    mpz_t a;
    mpz_init(a);
    LeByteToMPZ(key_buffer, 32, a); // Convert key to mpz_t

    Point G, out;
    initPoint(&out);
    initPoint(&G);
    setBasePoint(&G);
    point_mul(a, G, &out);
    unsigned char public_buffer[32];
    point_compress(out, public_buffer);

    mpz_clear(a);
    clearPoint(&G);
    clearPoint(&out);
    endEd25519();
    //***** END OF KEY GENERATION *****


    // Write the public key to prefix.pk
    char const *prefixpubFileName = "prefix.pk";
    FILE *pubfile;
    pubfile = fopen(prefixpubFileName, "wb");
    if (pubfile == NULL){
        perror("Error creating prefix.pk");
        return 1;
    }
    if (fwrite(public_buffer, 1, 32, pubfile) != 32) {
        perror("Error writing to tmpfile\n");
        fclose(pubfile);
        return 1;
    }
    fclose(pubfile);

    return 0;
}