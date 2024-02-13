//utils.h

#pragma once

#include <gmp.h>

/**
 * Prints the hexadecimal representation of a buffer bytes per bytes.
 * @param key The buffer to print.
 * @param n The number of bytes to print.
 * @param s The separator between bytes.
 */
void printBytes(unsigned char const *buffer, int const n, char const *s);

/**
 * Converts a hexadecimal character to its char representation in C.
 * @param hexDigit a hexadecimal character.
 * @return The char representation of the digit.
 */
char HexCharacterToByte(char const hexDigit);

/**
 * Converts a hexadecimal string into an array of bytes of length strlen(input)/2.
 * @param input The input string to be converted.
 * @param output The pointer to the output buffer.
 */
void HexStringToBytes(char const *input, unsigned char *output);

/**
 * Converts an unsigned char array to an unsigned int.
 * @param p The array to be converted. Only the 4 first entry of the array are considered
 * in little endian order.
 * @return The unsigned int representation of p.
 */
unsigned int LeByteToUInt32(unsigned char const *p);

/**
 * Converts an unsigned int into an unsigned char array.
 * @param n The integer to be converted.
 * @param p The pointer in which the result is stored. The result is char[4].
 */
void UInt32ToLeByte(unsigned int const n, unsigned char *p);

/**
 * Converts an unsigned long long into an unsigned char array.
 * @param n The integer to be converted.
 * @param p The pointer in which the result is stored. The result is char[8].
 */
void UInt64ToLeByte(unsigned long long const n, unsigned char *p);

/**
 * Converts a buffer of bytes stored in little endian to mpz_t integer.
 * @param in The input bytes buffer.
 * @param n The input buffer length.
 * @param out The output mpz_t integer.
 */
void LeByteToMPZ(unsigned char const *in, int const n, mpz_t out);

/**
 * Converts an mpz_t integer to it hexadecimal little endian representation.
 * @param in The input mpz_t integer.
 * @param out The output string.
 * @param n The output will represent n-byte integer.
 */
void MPZToLeHexString(mpz_t in, char *out, int const n);

/**
 * Reads n bytes from the file.
 * @param filename The name of the input file.
 * @param n The number of bytes to read.
 * @param type String to customize the error message. For debug purpose.
 * @return The n bytes as a char*.
 */
char *readNBytesFromFile(char const *filename, int const n, char const *type);

/**
 * Rotate the bits of n to the left by d.
 * @param n The integer to rotate.
 * @param d The length of the rotation.
 * @return The rotated integer.
 * @example RotL(b1110, 2) returns b1011.
 */
unsigned int RotL(unsigned int const n, int const d);
