#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>

#include "libs/utils/utils.h"
#include "libs/sha512/sha512.h"
#include "ed25519.h"

#define DEBUG 1

int main(int argc, char *argv[]){
    
    if (argc != 4){
        fprintf(stderr, "Usage: %s <prefix> <datafile> <sigfile>\n", argv[0]);
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

    // Read secret key
    FILE *secfile;
    int seclen;
    char sec_key[32];
    secfile = fopen(secfilename, "rb");
    if (secfile == NULL){
        perror("Error opening secfile\n");
        return 1;
    }
    fseek(secfile, 0, SEEK_END);
    seclen = ftell(secfile);
    if (seclen != 32){
        fprintf(stderr, "Wrong length for secret key: %d instead of 32 bytes\n", seclen);
        return 1;
    }
    rewind(secfile);
    fread(sec_key, 1, seclen, secfile);
    fclose(secfile);

    // Read public key
    FILE *pubfile;
    int publen;
    char pub_key[32];
    pubfile = fopen(pubfilename, "rb");
    if (pubfile == NULL){
        perror("Error opening pubfile\n");
        return 1;
    }
    fseek(pubfile, 0, SEEK_END);
    publen = ftell(pubfile);
    if (publen != 32){
        fprintf(stderr, "Wrong length for secret key: %d instead of 32 bytes\n", publen);
        return 1;
    }
    rewind(pubfile);
    fread(pub_key, 1, publen, pubfile);
    fclose(pubfile);

    // Compute H(sec_key) to generate a and prefix
    unsigned char a_prefix[64];
    sha512(sec_key, 32, a_prefix);
    // Prune the lower 32 bytes
    a_prefix[0]  &= 0xf8;
    a_prefix[31] &= 0x7f;
    a_prefix[31] |= 0x40;

    // Process the message and store it in a buffer
    FILE *datafile;
    char *msg;
    char *datafilename = argv[2];
    long msglen;
    datafile = fopen(datafilename, "rb");
    if (datafile == NULL){
        perror("Error opening datafile\n");
        return 1;
    }
    fseek(datafile, 0, SEEK_END);
    msglen = ftell(datafile);
    rewind(datafile);
    msg = (char *)malloc(msglen * sizeof(char));
    fread(msg, 1, msglen, datafile);
    fclose(datafile);

    //***** SIGNATURE COMPUTATION *****
    beginEd25519();

    mpz_t r, h, a, s, q;
    mpz_inits(r, h, a, s, q, NULL);
    Point G, R;
    initPoint(&G);
    asBasePoint(&G);
    initPoint(&R);

    char *buffer = malloc((64 + msglen)*sizeof(char));
    memcpy(buffer, a_prefix+32, 32); // Put (prefix || msg) in buffer
    memcpy(buffer+32, msg, msglen);

    sha512_modq(buffer, 32 + msglen, r);
    point_mul(r, G, &R);
    unsigned char Rs[32];
    point_compress(R, Rs);

    memcpy(buffer, Rs, 32); //Put (Rs || pub_key || msg) in buffer
    memcpy(buffer+32, pub_key, 32);
    memcpy(buffer+64, msg, msglen);

    sha512_modq(buffer, 64 + msglen, h);
    LeByteToMPZ(a_prefix, 32, a);
    mpz_mul(s, h, a);
    mpz_add(s, r, s);
    getq(q);
    mpz_mod(s, s, q);

    endEd25519();
    //******* END OF COMPUTATION *******

    // Generate signature from computation
    unsigned char signature[64];
    memcpy(signature, Rs, 32);
    char tmp_str[65];
    MPZToLeHexString(s, tmp_str, 32);
    HexStringToBytes(tmp_str, signature+32);

    // Write signature to sigfile
    FILE *sigfile;
    sigfile = fopen(argv[3], "wb");
    if (sigfile == NULL){
        perror("Error opening sigfile\n");
        return 1;
    }
    fwrite(signature, 1, 64, sigfile);
    fclose(sigfile);
    
#if DEBUG
    printf("signature = ");
    printBytes(signature, 64, "");
#endif

    free(msg);
    free(buffer);
    clearPoint(&G);
    clearPoint(&R);
    mpz_clears(r, h, a, s, q, NULL);

    return 0;
}