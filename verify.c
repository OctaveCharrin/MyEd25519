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

    return 0;
}