CC = gcc
CFLAGS = -Wall -Werror -fsanitize=address,undefined -b -O2 -fPIC -shared
LIBS = -lpthread

all: libscanner.so

libscanner.so: core/scanner/connect_scanner.c
	$(CC) $(CFLAGS) -o core/scanner/libscanner.so core/scanner/connect_scanner.c $(LIBS)

clean:
	rm -f core/scanner/libscanner.so
