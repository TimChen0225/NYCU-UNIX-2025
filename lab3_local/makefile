CC = gcc
CFLAGS = -Wall -fPIC -shared

all: libgotoku.so gotoku.local libsolver.so

libgotoku.so: libgotoku_dummy.c gops.c libgotoku.h
	$(CC) -o $@ -shared -fPIC libgotoku_dummy.c

gotoku.local: gotoku.c libgotoku.so gops.c libgotoku.h
	$(CC) -o $@ gotoku.c -L. -lgotoku -Wl,-rpath,.

libsolver.so: libsolver.c libgotoku.h
	$(CC) -o $@ $(CFLAGS) libsolver.c

clean:
	rm -f *.so gotoku.local

run: gotoku.local
	LD_PRELOAD=./libsolver.so ./gotoku.local
