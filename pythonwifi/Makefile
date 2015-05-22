# -*- coding: utf-8 -*-
#
# Makefile for Python WiFi
#
# Copyright 2015 Sean Robinson <robinson@tuxfamily.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# `GNU General Public License <LICENSE.GPL.html>`_ for more details.
#

# Binaries needed in this file...
PEP8=pep8-py2.7
PYFLAKES=pyflakes-py2.7
PYTHON2=python2
PYTHON3=python3
SHELL=/bin/sh

package = python-wifi

TOPDIR := $(CURDIR)

VERSION = $(shell cat $(TOPDIR)/docs/VERSION)

TESTCASES = pymnl.tests.nlsocket,pymnl.tests.attributes,pymnl.tests.message,pymnl.tests.genl

.PHONY: targets clean pep8 pep-verbose pyflakes sdist

targets:
	@echo "Available make targets:"
	@echo "    clean        - remove caches and reports (e.g. coverage)"
	@echo "    pep8         - check entire project for PEP8 compliance"
	@echo "    pep8-verbose - include many details about PEP8 check"
	@echo "    pyflakes     - statically analyze entire project for common errors"
	@echo "    sdist        - make a source distribution with checksum and PGP signature"
	@echo ""

clean:
	rm -fr tmp/ dist/ build/ MANIFEST
	rm -fr `find $(TOPDIR) -type f -a -name "*.pyc"`
	rm -fr `find $(TOPDIR) -type d -a -name "__pycache__"`

pep8:
	$(PEP8) --statistics pythonwifi/ examples/ tests/

pep8-verbose:
	$(PEP8) --show-source --show-pep8 --statistics pythonwifi/ examples/ tests/

pyflakes:
	$(PYFLAKES) pythonwifi/ examples/ tests/

sdist:	clean $(TOPDIR)/dist/${package}-$(VERSION).tar.bz2.sha256 $(TOPDIR)/dist/${package}-$(VERSION).tar.bz2.sign
	chmod 644 $(TOPDIR)/dist/${package}-$(VERSION).*

$(TOPDIR)/dist/${package}-$(VERSION).tar.bz2.sha256: $(TOPDIR)/dist/${package}-$(VERSION).tar.bz2
	cd $(TOPDIR)/dist && \
		sha256sum ${package}-$(VERSION).tar.bz2 \
			> ${package}-$(VERSION).tar.bz2.sha256

$(TOPDIR)/dist/${package}-$(VERSION).tar.bz2.sign: $(TOPDIR)/dist/${package}-$(VERSION).tar.bz2
	cd $(TOPDIR)/dist && \
		gpg --detach-sign -a --output \
			${package}-$(VERSION).tar.bz2.asc \
			${package}-$(VERSION).tar.bz2
	cd $(TOPDIR)/dist && \
		gpg --verify $(TOPDIR)/dist/${package}-$(VERSION).tar.bz2.asc

$(TOPDIR)/dist/${package}-$(VERSION).tar.bz2:
	PYTHONPATH=$(TOPDIR) $(PYTHON2) ./setup.py sdist --force-manifest --formats=bztar
