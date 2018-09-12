.POSIX:
.SUFFIXES:

CC = gcc
LIB_CFLAGS = -pedantic -Wall -Wextra -Werror -fPIC
LIB_CFLAGS += -DFORTIFY_SOURCE=2 -fstack-protector-strong
LIB_LDFLAGS = -lcrypto -fPIC -Wl,-z,relro,-z,now

all: lib

lib: ecies.o
	ar rcs ecies.a ecies.o

test: LIB_CFLAGS = -DDEBUG -g3 -fsanitize=address -fno-omit-frame-pointer
test: LIB_LDFLAGS = -lasan -lcrypto
test: ecies.o
	$(CC) -o test $(LIB_CFLAGS) ecies.o $(LIB_LDFLAGS)

clean:
	rm -f *.o *.a test

.SUFFIXES: .c .o
.c.o:
	$(CC) -c $(LIB_CFLAGS) $<

