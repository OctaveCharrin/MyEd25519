#pragma once

#include <gmp.h>

typedef struct Point{
    mpz_t X;
    mpz_t Y;
    mpz_t Z;
    mpz_t T;
} Point;

/**
 * Initalizes the values of p, d, q and base point B.
 */
void beginEd25519();

/**
 * Clears and frees p, d, q and B.
 */
void endEd25519();

/**
 * Prints the coordinates of a point.
 * @param P The point to be printed.
 * @param name A string to indentify the printed point.
 */
void PrintPoint(Point const P, char *name);

/**
 * Initializes a point and allocate memory for its coordinates.
 */
void initPoint(Point *P);

/**
 * Clears and frees the point P.
 */
void clearPoint(Point *P);

/**
 * Set the corrdinate of the point P to be:
 * X = x, Y = y, Z = 1, T = x*y
 */
void setPoint(mpz_t x, mpz_t y, Point *P);

/**
 * Copies the point src to the point dst.
 */
void setPointP(Point const src, Point *dst);

/**
 * Set a point from integers as in function setPoint(...).
 */
void setPointInt(int const x, int const y, Point *P);

/**
 * Set B to be the base point of the curve edwards25519.
 */
void asBasePoint(Point *B);

/**
 * Test wether a point is null of not.
 * @return 1 if the point is null and 0 otherwise.
 */
int isNullPoint(Point const P);

/**
 * Rescales the point P to have Z = 1.
 */
void rescalePoint(Point *P);

/**
 * DOES NOT WORK
 * Compute -P using the transformation (x, y) -> (x, -y)
 */
void negPoint(Point *P);

void getp(mpz_t _p);
void getq(mpz_t _q);
void getd(mpz_t _d);

// Functions from the python implementation of Ed25519 from RFC8032
void point_add(Point const P, Point const Q, Point *out);
void point_mul(mpz_t const _s, Point const _P, Point *out);
int point_equal(Point const P, Point const Q);
void recover_x(mpz_t y, int const sign, mpz_t x);
void point_compress(Point const P, unsigned char *out);
void point_decompress(unsigned char const *s, Point *out);

/**
 * Computes SHA512(input) % p.
 * @param input The input to be hashed.
 * @param len The length of the input in bytes.
 * @param output Stores the result.
 */
void sha512_modq(char const *input, int const len, mpz_t output);