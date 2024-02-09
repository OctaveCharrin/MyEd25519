CC = gcc
CFLAGS = -Wall -Wextra -std=c99

LIB = libshake128.a
SRC = utils.c padding.c keccakp.c
OBJ = $(SRC:.c=.o)

all: $(LIB)

$(LIB): $(OBJ)
	ar rcs $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJ) $(LIB)
