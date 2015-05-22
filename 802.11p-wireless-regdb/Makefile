# Install prefix
PREFIX ?= /usr
CRDA_PATH ?= $(PREFIX)/lib/crda
CRDA_KEY_PATH ?= $(CRDA_PATH)/pubkeys

MANDIR ?= $(PREFIX)/share/man/

SHA1SUM ?= /usr/bin/sha1sum
LSB_RELEASE ?= /usr/bin/lsb_release
WHOAMI ?= /usr/bin/whoami

# Distro name: Ubuntu, Debian, Fedora, if not present you get
# "custom-distro", if your distribution does not have the LSB stuff,
# then set this variable when calling make if you don't want "custom-distro"
LSB_ID ?= $(shell if [ -f $(LSB_RELEASE) ]; then \
			$(LSB_RELEASE) -i -s; \
		else \
			echo custom-distro; \
		fi)

DISTRO_PRIVKEY ?= ~/.wireless-regdb-$(LSB_ID).key.priv.pem
DISTRO_PUBKEY ?= ~/.wireless-regdb-$(LSB_ID).key.priv.pem

REGDB_AUTHOR ?= $(shell if [ -f $(DISTRO_PRIVKEY) ]; then \
			echo $(LSB_ID) ; \
		elif [ -f $(WHOAMI) ]; then \
			$(WHOAMI); \
		else \
			echo custom-user; \
		fi)

REGDB_PRIVKEY ?= ~/.wireless-regdb-$(REGDB_AUTHOR).key.priv.pem
REGDB_PUBKEY ?= $(REGDB_AUTHOR).key.pub.pem

REGDB_UPSTREAM_PUBKEY ?= linville.key.pub.pem

REGDB_CHANGED = $(shell $(SHA1SUM) -c --status sha1sum.txt >/dev/null 2>&1; \
        if [ $$? -ne 0 ]; then \
                echo maintainer-clean $(REGDB_PUBKEY); \
        fi)

.PHONY: all clean mrproper install maintainer-clean install-distro-key

all: $(REGDB_CHANGED) regulatory.bin sha1sum.txt

clean:
	@rm -f *.pyc *.gz

maintainer-clean: clean
	@rm -f regulatory.bin

mrproper: clean maintainer-clean
	@echo Removed public key, regulatory.bin and compresed man pages
	@rm -f $(REGDB_PUBKEY) .custom

regulatory.bin: db.txt $(REGDB_PRIVKEY) $(REGDB_PUBKEY)
	@echo Generating $@ digitally signed by $(REGDB_AUTHOR)...
	./db2bin.py regulatory.bin db.txt $(REGDB_PRIVKEY)

sha1sum.txt: db.txt
	sha1sum $< > $@

$(REGDB_PUBKEY): $(REGDB_PRIVKEY)
	@echo "Generating public key for $(REGDB_AUTHOR)..."
	openssl rsa -in $(REGDB_PRIVKEY) -out $(REGDB_PUBKEY) -pubout -outform PEM
	@echo $(REGDB_PUBKEY) > .custom


$(REGDB_PRIVKEY):
	@echo "Generating private key for $(REGDB_AUTHOR)..."
	openssl genrsa -out $(REGDB_PRIVKEY) 2048

ifneq ($(shell test -e $(DISTRO_PRIVKEY) && echo yes),yes)
$(DISTRO_PRIVKEY):
	@echo "Generating private key for $(LSB_ID) packager..."
	openssl genrsa -out $(DISTRO_PRIVKEY) 2048
endif

install-distro-key: maintainer-clean $(DISTRO_PRIVKEY)

%.gz: %
	gzip < $< > $@

# Users should just do:
#	sudo make install
#
# Developers should do:
#	make maintainer-clean
#	make
#	sudo make install
#
# Distributions packagers should do only once:
#	make install-distro-key
# This will create a private key for you and install it into
# ~/.wireless-regdb-$(LSB_ID).key.priv.pem
# To make new releaes just do:
#	make maintainer-clean
#	make
#	sudo make install
install: regulatory.bin.5.gz
	install -m 755 -d $(DESTDIR)/$(CRDA_PATH)
	install -m 755 -d $(DESTDIR)/$(CRDA_KEY_PATH)
	if [ -f .custom ]; then \
		install -m 644 -t $(DESTDIR)/$(CRDA_KEY_PATH)/ $(shell cat .custom); \
	fi
	@# In linville we trust
	install -m 644 -t $(DESTDIR)/$(CRDA_KEY_PATH)/ $(REGDB_UPSTREAM_PUBKEY)
	install -m 644 -t $(DESTDIR)/$(CRDA_PATH)/ regulatory.bin
	install -m 755 -d $(DESTDIR)/$(MANDIR)/man5/
	install -m 644 -t $(DESTDIR)/$(MANDIR)/man5/ regulatory.bin.5.gz

uninstall:
	rm -rf $(DESTDIR)/$(CRDA_PATH)/
