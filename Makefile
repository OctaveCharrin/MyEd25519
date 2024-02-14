CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g
LDFLAGS = -L./libs/utils -L./libs/sha512
LIBS = -lutils -lsha512 -lgmp
SRC = keygen.c ed25519.c sign.c verify.c
OBJ = $(SRC:.c=.o)
TARGETS = keygen sign verify

all: $(TARGETS)

keygen: keygen.o ed25519.o | lib
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

sign: sign.o ed25519.o | lib
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

verify: verify.o ed25519.o | lib
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

lib:
	$(MAKE) -C libs

clean:
	rm -f $(OBJ) $(TARGETS)
	$(MAKE) -C libs clean