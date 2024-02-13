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

    char input_bytes[input_length/2];
    HexStringToBytes(input_string, (unsigned char *)input_bytes);

    FILE *temp_file = tmpfile();
    if (temp_file == NULL) {
        perror("Error creating tmpfile\n");
        return 1;
    }

    if (fwrite(input_bytes, 1, input_length/2, temp_file) != input_length/2) {
        perror("Error writing to tmpfile\n");
        fclose(temp_file);
        return 1;
    }

    // Compute H(k);
    rewind(temp_file);
    u64 hash_register[8];
    sha512(temp_file, hash_register);
    fclose(temp_file);

    unsigned char key_buffer[64];
    for (int i=0; i<=8; i+=1){
        UInt64ToLeByte(hash_register[i], key_buffer + (8*i));
    }



    printf("key buffer before prune\n");
    printBytes(key_buffer, 64);


    // Prune the lower 32 bytes
    key_buffer[31] &= 0x7f;
    key_buffer[31] |= 0x40;
    key_buffer[0]  &= 0xf8;


    printf("byte read:\n");
    printBytes((unsigned char *)input_bytes, input_length/2);
    printf("SHA512 sum is %016llx%016llx%016llx%016llx%016llx%016llx%016llx%016llx\n",
            hash_register[0], hash_register[1], hash_register[2], hash_register[3], hash_register[4], hash_register[5], hash_register[6], hash_register[7]);
    printf("key buffer after\n");
    printBytes(key_buffer, 64);

    mpz_t s;
    mpz_init(s);
    LeByteToMPZ(key_buffer, 32, s);
    char string[33];
    unsigned char another[32];
    MPZToLeHexString(s, string, 32);
    printf("string = %s\n", string);

    HexStringToBytes(string, another);
    printBytes(another, 32);

    gmp_printf("s = %Zx\n", s);



    // char const *prefixsecFileName = "prefix.sk";
    // char const *prefixpubFileName = "prefix.pk";

    // FILE *secfile;
    // secfile = fopen(prefixsecFileName, "wb");
    // if(secfile == NULL){
    //     perror("Error creating prefix.sk");
    //     return 1;
    // }

    // FILE *pubfile;
    // pubfile = fopen(prefixpubFileName, "wb");
    // if (pubfile == NULL){
    //     perror("Error creating prefix.pk");
    //     return 1;
    // }

    // fclose(pubfile);
    // fclose(secfile);

    mpz_clear(s);
    return 0;
}