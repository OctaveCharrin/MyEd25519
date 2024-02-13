CC = gcc
CFLAGS = -Wall -Wextra -std=c99
LDFLAGS = -L./libs/utils -L./libs/sha512
LIBS = -lutils -lsha512 -lgmp
SRC = keygen.c
OBJ = $(SRC:.c=.o)
TARGET = keygen

all: $(TARGET)

$(TARGET): $(OBJ) | lib
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

lib:
	$(MAKE) -C libs

clean:
	rm -f $(OBJ) $(TARGET)
	$(MAKE) -C libs clean