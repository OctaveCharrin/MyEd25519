CC = gcc
CFLAGS = -Wall -Wextra -std=c99

LIB = libsha512.a
SRC = sha512.c
OBJ = $(SRC:.c=.o)

all: $(LIB)

$(LIB): sha512.o
	ar rcs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJ) $(LIB)
