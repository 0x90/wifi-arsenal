CC			?= gcc
CFLAGS		?= -O0 -g3 -Wall -Werror

prefix		= /usr/local
sbindir		= $(prefix)/sbin
bindir		= $(prefix)/bin
confdir		= $(prefix)/etc/openwips-ng/
mandir		= $(prefix)/man/man1
datadir		= $(prefix)/share
docdir		= $(datadir)/doc/openwips-ng

REVISION	= $(shell ../evalrev)
REV_DEFINE	= -D_REVISION=$(REVISION)

ifndef OSNAME
OSNAME		= $(shell uname -s | sed -e 's/.*CYGWIN.*/cygwin/g' -e 's,/,-,g')
endif

ifeq ($(OSNAME), Darwin)
	CC		= gcc
endif

ifeq ($(OSNAME), cygwin)
	CC		= gcc-4
	LIBS	= -lwpcap -I/usr/include/pcap -I/usr/include -I ~/airpcap_dev/Airpcap_Devpack/include -L~/airpcap_dev/Airpcap_Devpack/lib  -I ~/airpcap_dev/WinPcap_Devpack/include -L~/airpcap_dev/WinPcap_Devpack/lib
else
	LIBS	= -pthread -lpcap
endif