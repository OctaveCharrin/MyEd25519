#include "sha512.h"
#include "assert.h"

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Missing input file.\n");
        return -1;
    }

    u64 registers[8];

    FILE* stream = fopen(argv[1], "r");
    assert(stream != 0x0);

    sha512(stream, registers);

    fclose(stream);

    printf("SHA512 sum is %016llx%016llx%016llx%016llx%016llx%016llx%016llx%016llx\n", registers[0], registers[1], registers[2], registers[3], registers[4], registers[5], registers[6], registers[7]);
    
    return 0;
}