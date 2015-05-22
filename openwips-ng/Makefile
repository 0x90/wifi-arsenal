$(shell chmod 755 evalrev)
include		common.mak

DOCFILES	= INSTALL LICENSE AUTHORS VERSION FAQ LICENSE.OpenSSL RELEASE_NOTES

default: all

all:
	$(MAKE) -C sensor $(@)
	$(MAKE) -C server $(@)

install:
	$(MAKE) -C sensor $(@)
	$(MAKE) -C server $(@)
	$(MAKE) -C manpages $(@)

uninstall:
	$(MAKE) -C sensor $(@)
	$(MAKE) -C server $(@)
	$(MAKE) -C manpages $(@)

strip:
	$(MAKE) -C sensor $(@)
	$(MAKE) -C server $(@)

clean:
	$(MAKE) -C sensor $(@)
	$(MAKE) -C server $(@)

doc:
	install -d $(DESTDIR)$(docdir)
	install -m 644 $(DOCFILES) $(DESTDIR)$(docdir)

distclean: clean
