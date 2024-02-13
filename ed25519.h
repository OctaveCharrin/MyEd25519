#pragma once

#include <gmp.h>

typedef struct Point{
    mpz_t X;
    mpz_t Y;
    mpz_t Z;
    mpz_t T;
} Point;

void initPoint(Point P);
void setPoint(mpz_t x, mpz_t y, Point P);
void clearPoint(Point P);

void point_add(Point P, Point Q, Point out);
void point_mul(mpz_t s, Point P, Point out);
int point_equal(Point P, Point Q);
void recover_x(mpz_t y, int sign, mpz_t x);
void point_compress(Point P, unsigned char *out);
void point_decompress(unsigned char *s, Point out);