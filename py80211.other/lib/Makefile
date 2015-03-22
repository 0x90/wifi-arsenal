#
# py80211 netlink api creation
#
# Copyright 2013 Arend van Spriel <aspriel@gmail.com>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
TMPDIR = /tmp/py80211.$(shell echo $$PPID)
TOPDIR = $(abspath ..)
DESTDIR = $(abspath ./generated)
UTILDIR = $(abspath $(TOPDIR)/util)
GITREPO = $(abspath $(GITTREE))
TARGETS = nl80211_extract

ifeq ($(GITTREE),)
$(error "need to specify a git repository, ie. make GITTREE=<dir>")
endif
ifeq ($(wildcard $(GITTREE)/.git/*),)
$(error "specified GITTREE is not a git repository")
endif

all: $(TARGETS)

.PHONY: nl80211_extract
nl80211_extract:
	mkdir -p $(TMPDIR)
	mkdir -p $(DESTDIR)
	cp $(UTILDIR)/extract.h $(TMPDIR)
	cd $(TMPDIR) && python $(UTILDIR)/extract.py $(GITREPO) $(DESTDIR)

.PHONY: clean
clean:
	rm -rf /tmp/py80211.*
	rm -rf $(DESTDIR)
