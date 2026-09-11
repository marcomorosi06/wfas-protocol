# WFAS v2 — C reference implementation
#
#     wfas.h  wfas.c     the protocol library (vendor these two into firmware)
#     wfascli.c          command line client/server built on the library
#
# `make` builds ./wfascli.

CC      ?= cc
CFLAGS  ?= -std=c99 -Wall -Wextra -Wpedantic -O2
LDLIBS  ?=
PREFIX  ?= /usr/local

all: wfascli

wfascli: wfascli.c wfas.c wfas.h
	$(CC) $(CFLAGS) -o $@ wfascli.c wfas.c $(LDLIBS)

# Static build — handy for dropping the binary onto an SBC that has a
# different libc version from the machine that compiled it.
static: wfascli.c wfas.c wfas.h
	$(CC) $(CFLAGS) -static -o wfascli wfascli.c wfas.c $(LDLIBS)

install: wfascli
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 wfascli $(DESTDIR)$(PREFIX)/bin/wfascli

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/wfascli

clean:
	rm -f wfascli

.PHONY: all static install uninstall clean
