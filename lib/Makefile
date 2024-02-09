CC = gcc
CFLAGS = -Wall -Wextra -std=c99
SRC = utils.c
OBJ = $(SRC:.c=.o)
LIB = libutils.a
LDFLAGS = -lgmp

all: $(LIB) lib/shake256/libshake256.a

$(LIB): $(OBJ)
	ar rcs $@ $^ $(LDFLAGS)

lib/shake256/libshake256.a:
	$(MAKE) -C shake256

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJ) $(LIB)
	$(MAKE) -C shake256 clean
