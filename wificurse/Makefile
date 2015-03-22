PREFIX ?= /usr/local
CC = $(CROSS_COMPILE)gcc
CFLAGS ?= -O2

SRCS = $(wildcard src/*.c)
HDRS = $(wildcard src/*.h)

OBJS = $(SRCS:%.c=%.o)
LIBS = -lpthread

.PHONY: clean all install

ifneq ($(DESTDIR),)
    INSTALLDIR = $(subst //,/,$(DESTDIR)/$(PREFIX))
else
    INSTALLDIR = $(PREFIX)
endif


all: wificurse

wificurse: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) $(LIBS) -o $@

%.o: %.c $(HDRS)
	$(CC) $(CFLAGS) -c $< -o $@

install: all
	@mkdir -p $(INSTALLDIR)/bin
	cp wificurse $(INSTALLDIR)/bin/wificurse

clean:
	@rm -f src/*~ src/\#*\# src/*.o *~ \#*\# wificurse
