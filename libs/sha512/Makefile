CC = gcc
CFLAGS = -Wall -Wextra -std=c99

LIB = libsha512.a
TARGET = main
SRC = main.c sha512.c
OBJ = $(SRC:.c=.o)

all: $(LIB)

test: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

$(LIB): sha512.o
	ar rcs $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJ) $(LIB) $(TARGET)
