CC=gcc
LD=gcc
CFLAGS=-O2
LDFLAGS=-O2

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

all: dumpathrom

dumpathrom: dumpathrom.o
	$(LD) $(LDFLAGS) -o $@ $<

