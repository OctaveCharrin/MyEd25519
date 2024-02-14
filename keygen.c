#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>
#include <time.h>

#include "libs/utils/utils.h"
#include "libs/sha512/sha512.h"
#include "ed25519.h"

#define DEBUG 0
#define VERBOSE 0

int main(int argc, char *argv[]){
    
    if (argc != 2){
        fprintf(stderr, "Usage: %s <prefix>\n", argv[0]);
        return 1;
    }

    char *prefix = argv[1];
    size_t prefix_len = strlen(prefix);
    if (prefix_len > 252){
        fprintf(stderr, "Prefix is too long: maximum length of prefix is 252 characters\n");
        return 1;
    }

    char secfilename[256];
    char pubfilename[256];
    strcpy(secfilename, prefix);
    strcpy(pubfilename, prefix);
    strcat(secfilename, ".sk");
    strcat(pubfilename, ".pk");

    char sec_key[32];

#if DEBUG
    // Use user specified private key
    char input_string[] = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    size_t input_length = strlen(input_string);
    if (input_length != 64){
        fprintf(stderr, "Input string must be 32-bytes (ie 64 hexadecimal characters)\n");
        return 1;
    }
    HexStringToBytes(input_string, (unsigned char *)sec_key);
#else
    // Generate random private key
    srand(time(NULL));
    for (int i=0; i<32; i+=1){
        sec_key[i] = rand();
    }
#endif

    // Write k as secret key
    FILE *secfile;
    secfile = fopen(secfilename, "wb");
    if(secfile == NULL){
        perror("Error creating prefix.sk");
        return 1;
    }
    if (fwrite(sec_key, 1, 32, secfile) != 32) {
        perror("Error writing to tmpfile\n");
        fclose(secfile);
        return 1;
    }
    fclose(secfile);

    // Compute H(sec_key)
    unsigned char a_prefix[64];
    sha512(sec_key, 32, a_prefix);

    // Prune the lower 32 bytes
    a_prefix[0]  &= 0xf8;
    a_prefix[31] &= 0x7f;
    a_prefix[31] |= 0x40;


    //******** KEY GENERATION *********
    beginEd25519();
    mpz_t a;
    mpz_init(a);
    LeByteToMPZ(a_prefix, 32, a); // Convert a to mpz_t

    Point G, out;
    initPoint(&out);
    initPoint(&G);
    asBasePoint(&G);
    point_mul(a, G, &out);
    unsigned char pub_key[32];
    point_compress(out, pub_key);

    mpz_clear(a);
    clearPoint(&G);
    clearPoint(&out);
    endEd25519();
    //***** END OF KEY GENERATION *****


    // Write the public key to prefix.pk
    FILE *pubfile;
    pubfile = fopen(pubfilename, "wb");
    if (pubfile == NULL){
        perror("Error creating prefix.pk");
        return 1;
    }
    if (fwrite(pub_key, 1, 32, pubfile) != 32) {
        perror("Error writing to tmpfile\n");
        fclose(pubfile);
        return 1;
    }
    fclose(pubfile);

#if VERBOSE
    printf("sec = ");
    printBytes((unsigned char *)sec_key, 32, "");
    printf("pub = ");
    printBytes(pub_key, 32, "");
#endif

    return 0;
}