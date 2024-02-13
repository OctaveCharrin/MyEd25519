
#include <gmp.h>

#include "../utils/utils.h"

#include "curve25519.h"


void decodeLittleEndian(unsigned char const *b, int const bits, mpz_t out){
    LeByteToMPZ(b, (bits+7)/8, out);
}


void decodeUCoordinate(char const *u, int const bits, mpz_t out){
    unsigned char tmp[32];
    HexStringToBytes(u, tmp);
    if (bits%8 != 0)
        tmp[31] &= (1<<(bits%8))-1;
    decodeLittleEndian(tmp, bits, out);
}


void encodeUCoordinate(mpz_t u, mpz_t p, int const bits, char *out){
    mpz_mod(u, u, p);
    MPZToLeHexString(u, out, (bits+7)/8);
}


void decodeScalar25519(char const *k, mpz_t out){
    unsigned char k_list[32];
    HexStringToBytes(k, k_list);
    k_list[0] &= 248;
    k_list[31] &= 127;
    k_list[31] |= 64;
    decodeLittleEndian(k_list, 255, out);
}


void xADD(mpz_t const p, mpz_t const x_p, mpz_t const z_p, mpz_t const x_q, mpz_t const z_q, mpz_t const x_m, mpz_t const z_m, mpz_t x_out, mpz_t z_out){
    mpz_t U, V, tmp;
    mpz_inits(U, V, tmp, NULL);

    // U = ( (x_p - z_p) * (x_q + z_q) )
    mpz_sub(U, x_p, z_p);
    mpz_add(tmp, x_q, z_q);
    mpz_mul(U, U, tmp);
    mpz_mod(U, U, p);

    // V = ( (x_p + z_p) * (x_q - z_q) )
    mpz_add(V, x_p, z_p);
    mpz_sub(tmp, x_q, z_q);
    mpz_mul(V, V, tmp);
    mpz_mod(V, V, p);

    mpz_set_ui(tmp, 2);

    // x_out = z_m * (U + V) ^ 2
    mpz_add(x_out, U, V);
    mpz_powm_sec(x_out, x_out, tmp, p);
    mpz_mul(x_out, z_m, x_out);
    mpz_mod(x_out, x_out, p);

    // z_out = x_m * (U - V) ^ 2
    mpz_sub(z_out, U, V);
    mpz_powm_sec(z_out, z_out, tmp, p);
    mpz_mul(z_out, x_m, z_out);
    mpz_mod(z_out, z_out, p);

    mpz_clears(U, V, tmp, NULL);
}


void xDBL(mpz_t const p, mpz_t const x_in, mpz_t const z_in, mpz_t x_out, mpz_t z_out){
    mpz_t Q, R, S, a24;
    mpz_inits(Q, R, S, a24, NULL);
    
    mpz_set_ui(a24, 2);

    mpz_add(Q, x_in, z_in);
    mpz_powm_sec(Q, Q, a24, p);
    mpz_sub(R, x_in, z_in);
    mpz_powm_sec(R, R, a24, p);
    mpz_sub(S, Q, R);
    mpz_mod(S, S, p);

    mpz_set_ui(a24, 121666);
    
    mpz_mul(x_out, Q, R);
    mpz_mod(x_out, x_out, p);

    mpz_mul(z_out, a24, S);
    mpz_add(z_out, R, z_out);
    mpz_mul(z_out, S, z_out);
    mpz_mod(z_out, z_out, p);

    mpz_clears(Q, R, S, a24, NULL);
}


void cswap(int swap, mpz_t a, mpz_t b){
    mpz_t mask, dummy;
    mpz_inits(mask, dummy, NULL);

    mpz_ui_pow_ui(mask, 2, 256);
    mpz_sub_ui(mask, mask, 1);
    mpz_mul_ui(mask, mask, swap);

    mpz_xor(dummy, a, b);
    mpz_and(dummy, mask, dummy);
    mpz_xor(a, a, dummy);
    mpz_xor(b, b, dummy);

    mpz_clears(mask, dummy, NULL);
}


void X25519(char const *k, char const *u, mpz_t out){
    int swap = 0;
    int kt;

    mpz_t p, K, u_x, u_z, x_0, z_0, x_1, z_1, x_0out, z_0out, x_1out, z_1out;

    mpz_init_set_ui(p, 2);
    mpz_pow_ui(p, p, 255);
    mpz_sub_ui(p, p, 19);

    mpz_init(K);
    decodeScalar25519(k, K);
    mpz_init(u_x);
    decodeUCoordinate(u, 255, u_x);
    mpz_init_set_ui(u_z, 1);
    mpz_init_set_ui(x_0, 1);
    mpz_init_set_ui(z_0, 0);
    mpz_init_set(x_1, u_x);
    mpz_init_set(z_1, u_z);

    mpz_inits(x_0out, z_0out, x_1out, z_1out, NULL);
    for (int i = 255; i>=0; i-=1){
        kt = mpz_tstbit(K, i);
        swap ^= kt;
        cswap(swap, x_0, x_1);
        cswap(swap, z_0, z_1);
        swap = kt;

        xDBL(p, x_0, z_0, x_0out, z_0out);
        xADD(p, x_0, z_0, x_1, z_1, u_x, u_z, x_1out, z_1out);
        mpz_set(x_0, x_0out);
        mpz_set(z_0, z_0out);
        mpz_set(x_1, x_1out);
        mpz_set(z_1, z_1out);
    }

    mpz_sub_ui(K, p, 2);
    mpz_powm_sec(out, z_0, K, p);
    mpz_mul(out, x_0, out);
    mpz_mod(out, out, p);

    mpz_clears(p, K, u_x, u_z, x_0, z_0, x_1, z_1, x_0out, z_0out, x_1out, z_1out, NULL);
}