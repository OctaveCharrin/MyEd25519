CC = gcc
CFLAGS = -Wall -Wextra -std=c99
LDFLAGS = -L./lib -L./lib/shake256
LIBS = -lutils -lgmp -lshake128
SRC = keygen.c
OBJ = $(SRC:.c=.o)
TARGET = keygen

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ) | lib/libutils.a lib/shake256
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

lib/libutils.a:
	$(MAKE) -C lib

lib/shake256:
	$(MAKE) -C lib/shake256

clean:
	rm -f $(OBJ) $(TARGET)
	$(MAKE) -C lib clean
	$(MAKE) -C lib/shake256 clean
