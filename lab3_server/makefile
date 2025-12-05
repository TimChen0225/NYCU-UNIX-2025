CC = gcc
CFLAGS = -Wall -fPIC -shared

all: libsolver.so

libsolver.so: libsolver.c libgotoku.h
	$(CC) -o $@ $(CFLAGS) libsolver.c

clean:
	rm -f *.so 

run: libsolver.so
	python3 submit.py ./libsolver.so
