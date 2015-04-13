# -*- Makefile -*-

.PHONY: gendoc api_ref asciidoc

ASCIIDOCOPTS=-a pygments -a language=c -a icons \
	     -a toc2 \
	     -a numbered \
	     -a imagesdir="./images/" \
	     -a iconsdir="./images/icons" \
	     -a stylesdir="${abs_srcdir}/stylesheets/"

EXTRA_DIST = \
	core.txt \
	core.html \
	route.txt \
	route.html \
	index.txt \
	index.html \
	libnl.css \
	stylesheets \
	images \
	api

dist-hook:
	rm -f $(distdir)/aclocal.m4
	rm -f $(distdir)/configure
	rm -f $(distdir)/configure.in
	rm -rf $(distdir)/m4
	rm -f $(distdir)/README
	rm -f $(distdir)/missing
	rm -f $(distdir)/Doxyfile.in
	rm -f $(distdir)/Makefile.am
	rm -f $(distdir)/Makefile.in

link_doc:
if LINK_DOC
	./gen-tags.sh > libnl.dict
else
	@echo "Warning: Linking to API reference is disabled, check configure output"
endif
	

%.html: %.txt link_doc
	./resolve-asciidoc-refs.py $< > asciidoc.tmp
	asciidoc $(ASCIIDOCOPTS) -o $@ asciidoc.tmp
if LINK_DOC
	./doxygen-link.py libnl.dict $@ > asciidoc.tmp
	mv asciidoc.tmp $@
endif

asciidoc: core.html route.html index.html

api_ref:
	doxygen Doxyfile;

gendoc:
if GENERATE_DOC
if HAVE_DOXYGEN
	$(MAKE) api_ref
else
	@echo "Warning: Building of API reference (doxygen) is disabled, check autoconf logs"
endif
if HAVE_ASCIIDOC
	$(MAKE) asciidoc
else
	@echo "Warning: Building of asciidoc files is disabled, check autoconf logs"
endif
else
	@echo "Warning: Building of documentation disabled by user or autoconf"
endif

clean-local:
	rm -f api/* libnl.dict *.html;
