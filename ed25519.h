#pragma once

#include <gmp.h>

typedef struct Point{
    mpz_t X;
    mpz_t Y;
    mpz_t Z;
    mpz_t T;
} Point;

void PrintPoint(Point P, char *name);
void seeCurve();

void initPoint(Point *P);
void setPoint(mpz_t x, mpz_t y, Point *P);
void clearPoint(Point *P);
void asBasePoint(Point *B);
int isNullPoint(Point const P);

void getp(mpz_t _p);
void getq(mpz_t _q);
void getd(mpz_t _d);

void beginEd25519();
void endEd25519();

void point_add(Point const P, Point const Q, Point *out);
void point_mul(mpz_t const _s, Point const _P, Point *out);
int point_equal(Point const P, Point const Q);
void recover_x(mpz_t y, int sign, mpz_t x);
void point_compress(Point P, unsigned char *out);
void point_decompress(unsigned char *s, Point *out);

void sha512_modq(char const *input, int const len, mpz_t output);