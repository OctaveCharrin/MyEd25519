CC = gcc
CFLAGS = -Wall -Wextra -std=c99
SRC = utils.c
OBJ = $(SRC:.c=.o)
LIB = libutils.a
LDFLAGS = -lgmp

all: $(LIB)

$(LIB): $(OBJ)
	ar rcs $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJ) $(LIB)
