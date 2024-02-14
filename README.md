# MyX25519
C implementation of the "Ed25519" signature scheme following RFC 8032

## Initialization

Run `make` to build the project.
For now the project was just initialized to import necessary functions.

Note that this keygen is not suited for intensive use (more than one call per second) because it uses the time library from C to set the seed of the random generator.

### Author
Octave Charrin