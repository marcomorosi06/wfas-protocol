CC      ?= cc
CFLAGS  ?= -std=c99 -Wall -Wextra -Wpedantic -O2

all: example

example: example.c wfas.c wfas.h
	$(CC) $(CFLAGS) -o example example.c wfas.c

run: example
	./example

clean:
	rm -f example

.PHONY: all run clean
