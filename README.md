# MyX25519
C implementation of the "Ed25519" signature scheme following RFC 8032

## Initialization

Run `make` to build the project.

Alternatively you can run `make keygen`, `make sign` or `make verify` to build a specific part of the project.

## Usage

### Key Generation

To generate a random private/public keypair run the `keygen` program:
```bash
./keygen <prefix>
```

This will store the random private (resp. public) key in the file `prefix.sk` (resp. `prefix.pk`).

*Note that this keygen is not suited for intensive use (more than one call per second) because it uses the time library from C to set the seed of the random generator.*

For example, run the following command to generate two 32 byte files `my_key.sk` and `my_key.pk`.
```bash
./keygen my_key
```

You can also go inside the code of `keygen.c` and set `DEBUG` to `1` to generate the public key corresponding to the specified hexadecimal secret key.

### Signature

To get the signature of a file and write it in a file run the following command line:
```bash
./sign <prefix> <datafile> <sigfile>
```

For example, run the following command to sign your `data.bin` file with the key stored in `my_key` files and store the signature in `sigfile.bin`:
```bash
./sign my_key data.bin sigfile.bin
```

### Verification

To verify the signature stored in `sigfile` of a datafile with respect to a public key stored in `pkfile` run the following command:
```bash
./verify <pkfile> <datafile> <sigfile>
```
This will print `ACCEPT` if and only if the signature is valid.

## Notes

- I was not able to implement the multiexponentiation because of a lack of time and because I was not able to compute the opposite of a point on the curve and thus was not able to compute `[-h]A`.
- You can modify the `DEBUG` macro in both `keygen.c` and `sign.c` to test and debug the code more simply.
- This code uses the C implementation of `SHA512` that was released under the *MIT License* in the github page of [kevin-zhou-1](https://github.com/kevin-zhou-1/sha512-c). 

### Author
Octave Charrin