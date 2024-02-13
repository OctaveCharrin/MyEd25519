#include <stdio.h>
#include <gmp.h>

#include "ed25519.h"
#include "libs/utils/utils.h"

mpz_t p, d; // Prime generator, curve constant
Point B; // Base point

void modp_inv(const mpz_t x, mpz_t out) {
    mpz_t exponent;
    mpz_init(exponent);
    mpz_sub_ui(exponent, p, 2);
    mpz_powm(out, x, exponent, p);
    mpz_clear(exponent);
}

void initCurve(){
    // Set p
    mpz_init_set_ui(p, 2);
    mpz_pow_ui(p, p, 255);
    mpz_sub_ui(p, p, 19);
    // Set d
    mpz_set_ui(d, 121666);
    modp_inv(d, d);
    mpz_mul_si(d, d, -121665);
    mpz_mod(d, d, p);
    // Set B
    initPoint(B);
    mpz_t x, y, tmp;
    mpz_inits(x, y, tmp, NULL);
    mpz_set_ui(tmp, 5);
    modp_inv(tmp, y);
    mpz_mul_ui(y, y, 4);
    mpz_mod(y, y, p);
    recover_x(y, 0, x);
    setPoint(x, y, B);
    mpz_clears(x, y, tmp, NULL);
}

inline void clearCurve(){
    mpz_clears(p, d, NULL);
    clearPoint(B);
}

inline void initPoint(Point P){
    mpz_inits(P.X, P.Y, P.Z, P.T, NULL);
}

void setPoint(mpz_t x, mpz_t y, Point P){
    mpz_set(P.X, x);
    mpz_set(P.Y, y);
    mpz_set_ui(P.Z, 1);
    mpz_mul(P.T, P.X, P.Y);
    mpz_mod(P.T, P.T, p);
}

void setPointInt(int x, int y, Point P){
    mpz_set_si(P.X, x);
    mpz_set_si(P.Y, y);
    mpz_set_ui(P.Z, 1);
    mpz_mul(P.T, P.X, P.Y);
    mpz_mod(P.T, P.T, p);
}

void setPointP(Point src, Point dst){
    mpz_set(dst.X, src.X);
    mpz_set(dst.Y, src.Y);
    mpz_set(dst.Z, src.Z);
    mpz_set(dst.T, src.T);
}

inline void clearPoint(Point P){
    mpz_clears(P.X, P.Y, P.Z, P.T, NULL);
}

void point_add(Point P, Point Q, Point out){
    mpz_t A, B, C, D, E, F, G, H, t;
    mpz_inits(A, B, C, D, E, F, G, H, t, NULL);

    mpz_sub(A, P.Y, P.X);
    mpz_sub(t, Q.Y, Q.X);
    mpz_mul(A, A, t);
    mpz_mod(A, A, p);

    mpz_add(B, P.Y, P.X);
    mpz_add(t, Q.Y, Q.X);
    mpz_mul(B, B, t);
    mpz_mod(B, B, p);

    mpz_mul_ui(C, P.T, 2);
    mpz_mul(C, C, Q.T);
    mpz_mul(C, C, d);
    mpz_mod(C, C, p);

    mpz_mul_ui(D, P.Z, 2);
    mpz_mul(D, D, Q.Z);
    mpz_mod(D, D, p);

    mpz_sub(E, B, A);
    mpz_sub(F, D, C);
    mpz_add(G, D, C);
    mpz_add(H, B, A);

    mpz_mul(out.X, E, F);
    mpz_mul(out.Y, G, H);
    mpz_mul(out.Z, F, G);
    mpz_mul(out.T, E, H);

    mpz_clears(A, B, C, D, E, F, G, H, t, NULL);
}

void point_mul(mpz_t s, Point P, Point out){
    Point Q;
    initPoint(Q);
    setPointInt(0, 1, Q);

    while(mpz_cmp_ui(s, 0)>0){
        int bit = mpz_tstbit(s, 0);
        if (bit == 1){
            point_add(P, Q, Q);
            mpz_sub_ui(s, s, 1);
        }
        point_add(P, P, P);
        mpz_tdiv_q_ui(s, s, 2);
    }
    setPointP(Q, out);
    clearPoint(Q);
}

int point_equal(Point P, Point Q){
    mpz_t t1, t2;
    mpz_inits(t1, t2, NULL);

    mpz_mul(t1, P.X, Q.Z);
    mpz_mul(t2, Q.X, P.Z);
    mpz_sub(t1, t1, t2);
    mpz_mod(t1, t1, p);
    if (mpz_cmp_ui(t1, 0) != 0){
        return 0;
    }

    mpz_mul(t1, P.Y, Q.Z);
    mpz_mul(t2, Q.Y, P.Z);
    mpz_sub(t1, t1, t2);
    mpz_mod(t1, t1, p);
    if (mpz_cmp_ui(t1, 0) != 0){
        return 0;
    }

    mpz_clears(t1, t2, NULL);
    return 1;
}

void recover_x(mpz_t y, int sign, mpz_t x){
    if (mpz_cmp(y, p)>=0){
        fprintf(stderr, "Y too large, cannot recover x\n");
        return;
    }
    mpz_t x2, tmp, sqrt_m1;
    mpz_inits(x2, tmp, sqrt_m1, NULL);
    mpz_mul(x2, y, y);
    mpz_sub_ui(x2, x2, 1);

    mpz_mul(tmp, d, y);
    mpz_mul(tmp, tmp, y);
    mpz_add_ui(tmp, tmp, 1);
    modp_inv(tmp, tmp);

    mpz_mul(x2, x2, tmp);

    if (mpz_cmp_ui(x2, 0) == 0){
        if (sign == 1){
            fprintf(stderr, "Cannot recover x\n");
            return;
        } else {
            mpz_set_ui(x, 0);
            goto clean;
        }
    }

    // Compute square root of x2
    mpz_add_ui(tmp, p, 3);
    mpz_tdiv_q_ui(tmp, tmp, 8); // tmp = (p+3) // 8
    mpz_powm(x, x2, tmp, p);

    mpz_mul(tmp, x, x);
    mpz_sub(tmp, tmp, x2);
    mpz_mod(tmp, tmp, p);

    if (mpz_cmp_ui(tmp, 0) != 0){
        mpz_set_ui(sqrt_m1, 2);
        mpz_sub_ui(tmp, p, 1);
        mpz_tdiv_q_ui(tmp, tmp, 4);
        mpz_powm(sqrt_m1, sqrt_m1, tmp, p);
        mpz_mul(x, x, sqrt_m1);
        mpz_mod(x, x, p);
    }

    mpz_mul(tmp, x, x);
    mpz_sub(tmp, tmp, x2);
    mpz_mod(tmp, tmp, p);

    if (mpz_cmp_ui(tmp, 0) != 0){
        fprintf(stderr, "Cannot recover x\n");
        return;
    }

    int bit = mpz_tstbit(x, 0);
    if (bit != sign){
        mpz_sub(x, p, x);
    }
    
    clean:
    mpz_clears(x2, tmp, sqrt_m1, NULL);
}

void point_compress(Point P, unsigned char *out){
    mpz_t zinv, x, y;
    mpz_inits(zinv, x, y, NULL);
    modp_inv(P.Z, zinv);
    mpz_mul(x, P.X, zinv);
    mpz_mod(x, x, p);
    mpz_mul(y, P.Y, zinv);
    mpz_mod(y, y, p);
    int bit = mpz_tstbit(x, 0);
    mpz_ui_pow_ui(x, bit, 255);
    mpz_ior(y, y, x);
    char string[33];
    MPZToLeHexString(y, string, 32);
    HexStringToBytes(string, out);
    mpz_clears(zinv, x, y, NULL);
}

void point_decompress(unsigned char *s, Point out){
    mpz_t x, y;
    mpz_inits(x, y, NULL);
    LeByteToMPZ(s, 32, y);
    int sign = mpz_tstbit(y, 255);
    
    mpz_ui_pow_ui(x, 1, 255);
    mpz_sub_ui(x, x, 1);
    mpz_and(y, y, x);

    recover_x(y, sign, x);
    setPoint(x, y, out);
}