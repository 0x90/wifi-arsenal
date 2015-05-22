-include .config

MAKEFLAGS += --no-print-directory

PREFIX ?= /usr
SBINDIR ?= $(PREFIX)/sbin
MANDIR ?= $(PREFIX)/share/man
PKG_CONFIG ?= pkg-config

MKDIR ?= mkdir -p
INSTALL ?= install
CC ?= "gcc"

CFLAGS ?= -O2 -g
CFLAGS += -Wall -Wundef -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -Werror-implicit-function-declaration

OBJS = acs.o \
	genl.o \
	survey.o \
	event.o \
	version.o
ALL = acs 

NL1FOUND := $(shell $(PKG_CONFIG) --atleast-version=1 libnl-1 && echo Y)
NL2FOUND := $(shell $(PKG_CONFIG) --atleast-version=2 libnl-2.0 && echo Y)
NL3FOUND := $(shell $(PKG_CONFIG) --atleast-version=3 libnl-3.0 && echo Y)


ifeq ($(NL1FOUND),Y)
CFLAGS += -DCONFIG_LIBNL1
NLLIBNAME = libnl-1
endif

ifeq ($(NL2FOUND),Y)
CFLAGS += -DCONFIG_LIBNL20
LIBS += -lnl-genl
LIBS += -lm
NLLIBNAME = libnl-2.0
endif

ifeq ($(NL3FOUND),Y)
CFLAGS += -DCONFIG_LIBNL30
LIBS += -lm
NLLIBNAME = libnl-3.0 libnl-genl-3.0
endif

ifeq ($(NLLIBNAME),)
$(error Cannot find development files for any supported version of libnl)
endif

LIBS += $(shell $(PKG_CONFIG) --libs $(NLLIBNAME))
CFLAGS += $(shell $(PKG_CONFIG) --cflags $(NLLIBNAME))

ifeq ($(V),1)
Q=
NQ=true
else
Q=@
NQ=echo
endif

all: version_check $(ALL)

version_check:
ifeq ($(NL3FOUND),Y)
else
ifeq ($(NL2FOUND),Y)
else
ifeq ($(NL1FOUND),Y)
else
	$(error No libnl found)
endif
endif
endif


VERSION_OBJS := $(filter-out version.o, $(OBJS))

version.c: version.sh $(patsubst %.o,%.c,$(VERSION_OBJS)) nl80211.h acs.h Makefile \
		$(wildcard .git/index .git/refs/tags)
	@$(NQ) ' GEN ' $@
	$(Q)./version.sh $@

%.o: %.c acs.h nl80211.h
	@$(NQ) ' CC  ' $@
	$(Q)$(CC) $(CFLAGS) -c -o $@ $<

acs:	$(OBJS)
	@$(NQ) ' CC  ' acs
	$(Q)$(CC) $(LDFLAGS) $(OBJS) $(LIBS) -o acs

check:
	$(Q)$(MAKE) all CC="REAL_CC=$(CC) CHECK=\"sparse -Wall\" cgcc"

%.gz: %
	@$(NQ) ' GZIP' $<
	$(Q)gzip < $< > $@

install: acs acs.8.gz
	@$(NQ) ' INST acs'
	$(Q)$(MKDIR) $(DESTDIR)$(SBINDIR)
	$(Q)$(INSTALL) -m 755 acs $(DESTDIR)$(SBINDIR)
	@$(NQ) ' INST acs.8'
	$(Q)$(MKDIR) $(DESTDIR)$(MANDIR)/man8/
	$(Q)$(INSTALL) -m 644 acs.8.gz $(DESTDIR)$(MANDIR)/man8/

clean:
	$(Q)rm -f acs *.o *~ *.gz version.c *-stamp
