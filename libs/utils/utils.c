#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>

#include "utils.h"


void printBytes(unsigned char const *key, int const n, char const *s){
    for (int i=0; i<n-1; ++i){
        printf("%02x%s", key[i], s);
    }
    printf("%02x\n", key[n-1]);
}


char HexCharacterToByte(char const hexDigit) {
    if (hexDigit >= '0' && hexDigit <= '9') {
        return hexDigit - '0';
    } else if (hexDigit >= 'a' && hexDigit <= 'f') {
        return hexDigit - 'a' + 10;
    } else if (hexDigit >= 'A' && hexDigit <= 'F') {
        return hexDigit - 'A' + 10;
    } else {
        fprintf(stderr, "Invalid hexadecimal digit in key: %c\n", hexDigit);
        return 1;
    }
}


void HexStringToBytes(char const *input, unsigned char *output){
    int n = strlen(input);
    if (n%2 != 0){
        fprintf(stderr, "Input string has uneven length.\n");
        return;
    }
    for (int i=0; i<n/2; ++i){
        output[i] = (unsigned char)((HexCharacterToByte(input[2*i]) << 4) | HexCharacterToByte(input[2*i+1]));
    }
}


unsigned int LeByteToUInt32(unsigned char const *p){
    return ((unsigned int)p[0]) | ((unsigned int)p[1])<<8 | ((unsigned int)p[2])<<16 | ((unsigned int)p[3])<<24;
}


void UInt32ToLeByte(unsigned int const n, unsigned char *p){
    unsigned int mask = 0xff;
    for (int i=0; i<4; i+=1){
        p[i] = (unsigned char)(n>>(24 - 8*i) & mask);
    }
}


void UInt64ToLeByte(unsigned long long const n, unsigned char *p){
    unsigned int mask = 0xff;
    for (int i=0; i<8; i+=1){
        p[i] = (unsigned char)(n>>(56 - 8*i) & mask);
    }
}


void LeByteToMPZ(unsigned char const *in, int const n, mpz_t out){
    char reversed[2*n+1];
    for (int i=0; i<2*n+1; i+=1){
        reversed[i]=0;
    }
    for (int i=0; i<2*n; i+=2){
        snprintf((reversed+i), 3, "%02x", in[n-1-i/2]);
    }
    reversed[2*n] = '\0';
    if (mpz_set_str(out, reversed, 16) == -1) {
        fprintf(stderr, "Error: Invalid hexadecimal string.\n");
    }
}

void MPZToLeHexString(mpz_t in, char *out, int const n){
    int len2 = n*2;
    int size = (int)mpz_sizeinbase(in, 16);
    char hexString[size+2];

    if (size%2 == 0) {
        mpz_get_str(hexString, 16, in);
    } else {
        hexString[0] = '0';
        mpz_get_str(hexString+1, 16, in);
        size++;
    }

#define min(a, b) ((a) < (b) ? (a) : (b))
    
    int l = min(size, len2);
    for(int i=0; i<l; i+=2){
        out[i] = hexString[size-2-i];
        out[i+1] = hexString[size-1-i];
    }
    for(int i=l; i<len2; ++i){
        out[i] = '0';
    }
    out[len2] = '\0';
}


char *readNBytesFromFile(char const *filename, int const n, char const *type){
    FILE *file;
    file = fopen(filename, "rb");
    if (file == NULL) {
        perror("Error opening keyfile");
        return NULL;
    }

    char *bytes = malloc(n*sizeof(*bytes));
    int len = 0;
    char byte = fgetc(file);
    while ((byte != EOF) && (len<n)){
        bytes[len] = byte;
        len += 1;
        byte = fgetc(file);
    }
    fclose(file);
    if (len < n){
        fprintf(stderr, "Error: Your %s file is %d-byte long but you try to read %d bytes from it.\n", type, len, n);
        return NULL;
    }
    return bytes;
}


unsigned int RotL(unsigned int const n, int const d){
    int l = 8 * sizeof(n);
    int s = d % (8 * sizeof(n));
    return (n << s) | (n >> (l - s));
}