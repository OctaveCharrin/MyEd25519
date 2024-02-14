#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>

#include "libs/utils/utils.h"
#include "libs/sha512/sha512.h"

#include "ed25519.h"

int main(int argc, char *argv[]){
    
    if (argc != 4){
        fprintf(stderr, "Usage: %s <pkfile> <datafile> <sigfile>\n", argv[0]);
        return 1;
    }

    // Read public key
    FILE *pkfile;
    int pklen;
    unsigned char pub_key[32];
    pkfile = fopen(argv[1], "rb");
    if (pkfile == NULL){
        perror("Error opening pkfile\n");
        return 1;
    }
    fseek(pkfile, 0, SEEK_END);
    pklen = ftell(pkfile);
    if (pklen != 32){
        perror("Bad public key length\n");
        return 1;
    }
    rewind(pkfile);
    fread(pub_key, 1, pklen, pkfile);
    fclose(pkfile);

    printf("pub = ");
    printBytes(pub_key, 32, "");

    // Read signature
    FILE *sigfile;
    int siglen;
    unsigned char signature[64];
    sigfile = fopen(argv[3], "rb");
    if (sigfile == NULL){
        perror("Error opening sigfile\n");
        return 1;
    }
    fseek(sigfile, 0, SEEK_END);
    siglen = ftell(sigfile);
    if (siglen != 64){
        perror("Bad signature length\n");
        return 1;
    }
    rewind(sigfile);
    fread(signature, 1, siglen, sigfile);
    fclose(sigfile);

    // Read message
    FILE *msgfile;
    long msglen;
    char *msg;
    msgfile = fopen(argv[2], "rb");
    if (msgfile == NULL){
        perror("Error opening datafile\n");
        return 1;
    }
    fseek(msgfile, 0, SEEK_END);
    msglen = ftell(msgfile);
    msg = malloc(msglen * sizeof(*msg));
    rewind(msgfile);
    fread(msg, 1, msglen, msgfile);
    fclose(msgfile);

    //***** VERIFICATION *****
    beginEd25519();

    char *buffer = malloc((64 + msglen)*sizeof(char));

    mpz_t s, q, h;
    mpz_inits(s, q, h, NULL);
    Point G, A, R, sB, hA, RhA;
    initPoint(&G);
    asBasePoint(&G);
    initPoint(&A);
    initPoint(&R);
    initPoint(&sB);
    initPoint(&hA);
    initPoint(&RhA);

    point_decompress(pub_key, &A);
    if (isNullPoint(A)){
        printf("REJECT 1\n");
        goto clear;
    }


    point_decompress(signature, &R);
    PrintPoint(R, "R sig");

    if (isNullPoint(R)){
        printf("REJECT 2\n");
        goto clear;
    }

    LeByteToMPZ(signature+32, 32, s);
    getq(q);
    if (mpz_cmp(s, q) >= 0){
        printf("REJECT 3\n");
        goto clear;
    }

    memcpy(buffer, signature, 32);
    memcpy(buffer+32, pub_key, 32);
    memcpy(buffer+64, msg, msglen);
    sha512_modq(buffer, msglen + 64, h);

    point_mul(s, G, &sB);
    point_mul(h, A, &hA);
    point_add(R, hA, &RhA);

    int valid = point_equal(sB, RhA);

    PrintPoint(R, "R final");
    PrintPoint(sB, "sB");
    PrintPoint(RhA, "RhA");

    if (valid){
        printf("ACCEPT 4\n");
    } else {
        printf("REJECT 4\n");
    }

clear:
    free(msg);
    free(buffer);
    mpz_clears(s, q, h, NULL);
    clearPoint(&G);
    clearPoint(&A);
    clearPoint(&R);
    clearPoint(&sB);
    clearPoint(&hA);
    clearPoint(&RhA);
    endEd25519();

    return 0;
}