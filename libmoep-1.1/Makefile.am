
AM_DISTCHECK_CONFIGURE_FLAGS = --enable-examples

AM_CFLAGS = -O2 -Wall -Wstrict-prototypes -Wmissing-prototypes -Wno-unused-function

lib_LTLIBRARIES = libmoep80211.la

libmoep80211_la_SOURCES  = src/dev.c
libmoep80211_la_SOURCES += src/dev.h
libmoep80211_la_SOURCES += src/frame.c
libmoep80211_la_SOURCES += src/interfaces.c
libmoep80211_la_SOURCES += src/interfaces.h
libmoep80211_la_SOURCES += src/list.h
libmoep80211_la_SOURCES += src/moep_hdr_ext.c
libmoep80211_la_SOURCES += src/moep_hdr_ext.h
libmoep80211_la_SOURCES += src/system.c
libmoep80211_la_SOURCES += src/util.h

libmoep80211_la_SOURCES += src/ieee80211/addr.c

libmoep80211_la_SOURCES += src/netlink/attr.h
libmoep80211_la_SOURCES += src/netlink/error.c
libmoep80211_la_SOURCES += src/netlink/error.h
libmoep80211_la_SOURCES += src/netlink/util.c
libmoep80211_la_SOURCES += src/netlink/util.h

libmoep80211_la_SOURCES += src/modules/moep80211/moep80211.c

libmoep80211_la_SOURCES += src/modules/moep8023/moep8023.c

libmoep80211_la_SOURCES += src/modules/ieee80211/ieee80211.c

libmoep80211_la_SOURCES += src/modules/ieee8023/ieee8023.c

libmoep80211_la_SOURCES += src/modules/radio/nl80211.c
libmoep80211_la_SOURCES += src/modules/radio/nl80211.h
libmoep80211_la_SOURCES += src/modules/radio/radio.c
libmoep80211_la_SOURCES += src/modules/radio/radiotap.c
libmoep80211_la_SOURCES += src/modules/radio/radiotap.h
libmoep80211_la_SOURCES += src/modules/radio/radiotap_parser.c
libmoep80211_la_SOURCES += src/modules/radio/radiotap_parser.h

libmoep80211_la_SOURCES += src/modules/eth/eth.c

libmoep80211_la_SOURCES += src/modules/tap/tap.c

libmoep80211_la_SOURCES += src/modules/unix/unix.c

libmoep80211_la_CPPFLAGS = -I$(top_srcdir)/include $(LIBNL_CFLAGS)

libmoep80211_la_LIBADD = $(LIBNL_LIBS)

libmoep80211_la_LDFLAGS = -version-info 1:0:0

libmoep80211_la_includedir = $(includedir)/moep80211

libmoep80211_la_include_HEADERS  = include/moep80211/dev.h
libmoep80211_la_include_HEADERS += include/moep80211/frame.h
libmoep80211_la_include_HEADERS += include/moep80211/ieee80211_addr.h
libmoep80211_la_include_HEADERS += include/moep80211/ieee80211_frametypes.h
libmoep80211_la_include_HEADERS += include/moep80211/ieee80211_radiotap.h
libmoep80211_la_include_HEADERS += include/moep80211/module.h
libmoep80211_la_include_HEADERS += include/moep80211/moep_hdr_ext.h
libmoep80211_la_include_HEADERS += include/moep80211/radiotap.h
libmoep80211_la_include_HEADERS += include/moep80211/system.h
libmoep80211_la_include_HEADERS += include/moep80211/types.h

libmoep80211_la_include_modulesdir = $(includedir)/moep80211/modules

libmoep80211_la_include_modules_HEADERS  = include/moep80211/modules/moep80211.h
libmoep80211_la_include_modules_HEADERS += include/moep80211/modules/moep8023.h
libmoep80211_la_include_modules_HEADERS += include/moep80211/modules/ieee80211.h
libmoep80211_la_include_modules_HEADERS += include/moep80211/modules/ieee8023.h
libmoep80211_la_include_modules_HEADERS += include/moep80211/modules/radio.h
libmoep80211_la_include_modules_HEADERS += include/moep80211/modules/eth.h
libmoep80211_la_include_modules_HEADERS += include/moep80211/modules/tap.h
libmoep80211_la_include_modules_HEADERS += include/moep80211/modules/unix.h


bin_PROGRAMS =

EXTRA_DIST =


dist_man_MANS =


if WANT_EXAMPLES
bin_PROGRAMS += examples/moepeval examples/ptmsimple examples/ptmbeacon

examples_moepeval_SOURCES = examples/moepeval.c
examples_moepeval_LDADD = libmoep80211.la
examples_moepeval_CPPFLAGS = -I$(top_srcdir)/include

examples_ptmsimple_SOURCES = examples/ptmsimple.c
examples_ptmsimple_LDADD = libmoep80211.la
examples_ptmsimple_CPPFLAGS = -I$(top_srcdir)/include

examples_ptmbeacon_SOURCES = examples/ptmbeacon.c
examples_ptmbeacon_LDADD = libmoep80211.la
examples_ptmbeacon_CPPFLAGS = -I$(top_srcdir)/include

dist_man_MANS += examples/moepeval.1
dist_man_MANS += examples/ptmsimple.1
dist_man_MANS += examples/ptmbeacon.1
else
EXTRA_DIST += examples/moepeval.1
EXTRA_DIST += examples/ptmsimple.1
EXTRA_DIST += examples/ptmbeacon.1
endif


dist_noinst_DATA = doc/html

doc/html: doc

if HAVE_DOXYGEN
doc: Doxyfile $(libmoep80211_la_include_HEADERS) $(libmoep80211_la_include_modules_HEADERS)
	@echo "  DOXYGEN"
	@$(DOXYGEN)

clean-local: clean-doc
else
doc:

maintainer-clean-local: clean-doc
endif

.PHONY: clean-doc
clean-doc:
	-rm -rf doc


install-data-hook: doc/html
	mkdir -p "$(DESTDIR)$(docdir)"
	cp --no-preserve=ownership,mode -r $< "$(DESTDIR)$(docdir)"

uninstall-hook:
	-rm -rf "$(DESTDIR)$(docdir)"


pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libmoep80211.pc
