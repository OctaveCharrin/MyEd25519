CC = gcc
CFLAGS = -Wall -Wextra -std=c99
SRC = utils.c
OBJ = $(SRC:.c=.o)
LIB = libutils.a
LDFLAGS = 

all: $(LIB)

$(LIB): $(OBJ)
	ar rcs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJ) $(LIB)
