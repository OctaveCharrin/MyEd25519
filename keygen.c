#include <stdio.h>
#include <stdlib.h>

#include "lib/utils.h"

int main(int argc, char *argv[]){
    
    if (argc != 1){
        fprintf(stderr, "Usage: %s <prefix>\n", argv[0]);
        return 1;
    }

    char const *prefixsecFileName = "prefix.sk";
    char const *prefixpubFileName = "prefix.pk";



    FILE *secfile;
    secfile = fopen(prefixsecFileName, 'wb');
    if(secfile == NULL){
        perror("Error creating prefix.sk");
        return 1;
    }

    FILE *pubfile;
    pubfile = fopen(prefixpubFileName, 'wb');
    if (pubfile == NULL){
        perror("Error creating prefix.pk");
        return 1;
    }

    fclose(pubfile);
    fclose(secfile);
    return 0;
}