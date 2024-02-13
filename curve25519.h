// curve25519.h

#pragma once

#include <gmp.h>

/**
 * Performs X25519 on two strings representing the 32-byte scalar and
 * the secret, then store the result in out.
 */
void X25519(char const *k, char const *u, mpz_t out);