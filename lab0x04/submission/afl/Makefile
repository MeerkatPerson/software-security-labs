CC = afl-clang
override CFLAGS += -g -w -O3

all: libpngparser size

clean:
	rm -f libpngparser.a size *.o

.PHONY: all clean

libpngparser: pngparser.h pngparser.c crc.c crc.h
	$(CC) $(CFLAGS) -c pngparser.c crc.c
	ar rcs libpngparser.a pngparser.o crc.o

size: libpngparser size.c
	$(CC) $(CFLAGS) -o size size.c libpngparser.a -lz
