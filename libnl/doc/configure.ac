#
# configure.in
#
# 	This library is free software; you can redistribute it and/or
#	modify it under the terms of the GNU Lesser General Public
#	License as published by the Free Software Foundation version 2.1
#	of the License.
#
# Copyright (c) 2003-2013 Thomas Graf <tgraf@suug.ch>
#

AC_INIT(libnl-doc, [3.2.26-rc1], [http://www.infradead.org/~tgr/libnl/])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES(yes)], [])

m4_include([m4/ax_python.m4])

#
# Generating the documentation
#
AC_ARG_ENABLE([doc],
	      AS_HELP_STRING([--disable-doc], [Do not generate documentation]),
	      [generate_doc="$enableval"], [generate_doc=auto])

AX_PYTHON

if test "x$generate_doc" != "xno"; then
	AC_PROG_SED
	AC_PROG_EGREP

	AC_CHECK_PROG(HAVE_DOXYGEN, [doxygen], yes, no)
	if test "x$HAVE_DOXYGEN" = "xno" -a "x$generate_doc" = "xyes"; then
		AC_MSG_ERROR([*** doxygen package required to generate documentation])
	fi

	AC_CHECK_PROG(HAVE_DOT, [dot], yes, no)
	if test "x$HAVE_DOT" = "xno"; then
		if test "x$generate_doc" = "xyes"; then
			AC_MSG_ERROR([*** graphviz package required to generate documentation])
		else
			AC_MSG_WARN([*** graphviz not found, disabling building of API reference])
			HAVE_DOXYGEN=no
		fi
	fi

	AC_CHECK_PROG(HAVE_ASCIIDOC, [asciidoc], yes, no)
	if test "x$HAVE_ASCIIDOC" = "xno"; then
		if test "x$generate_doc" = "xyes"; then
			AC_MSG_ERROR([*** asciidoc package required to generate documentation])
		else
			AC_MSG_WARN([*** asciidoc not found, disabling building of guides])
		fi
	fi

	AC_CHECK_PROG(HAVE_SOURCE_HIGHLIGHT, [source-highlight], yes, no)
	if test "x$HAVE_SOURCE_HIGHLIGHT" = "xno"; then
		if test "x$generate_doc" = "xyes"; then
			AC_MSG_ERROR([*** source-highlight required to generate documentation])
		else
			AC_MSG_WARN([*** source-highlight not found, disabling building of guides])
			HAVE_ASCIIDOC=no
		fi
	fi

	AC_CHECK_PROG(HAVE_MSCGEN, [mscgen], yes, no)
	if test "x$HAVE_MSCGEN" = "xno"; then
		AC_MSG_WARN([*** mscgen not found, get it at http://www.mcternan.me.uk/mscgen/])
		if test "x$generate_doc" = "xyes"; then
			AC_MSG_ERROR([*** mscgen package required to generate documentation])
		else
			AC_MSG_WARN([*** Disabling building of guides])
			HAVE_ASCIIDOC=no
			HAVE_DOXYGEN=no
		fi
	fi

	AC_CHECK_PROG(HAVE_PYGMENTIZE, [pygmentize], yes, no)
	if test "x$HAVE_PYGMENTIZE" = "xno"; then
		if test "x$generate_doc" = "xyes"; then
			AC_MSG_ERROR([*** pygmentize package required to generate documentation])
		else
			AC_MSG_WARN([*** Disabling building of guides])
			HAVE_ASCIIDOC=no
		fi
	fi

	link_doc=yes
	if test "x$HAVE_DOXYGEN" = "xno"; then
		AC_MSG_WARN([*** Disabling API linking due to missing doxygen package])
		link_doc=no
	fi
fi

AM_CONDITIONAL([LINK_DOC], [test "x$link_doc" = "xyes"])
AM_CONDITIONAL([HAVE_DOXYGEN], [test "x$HAVE_DOXYGEN" = "xyes"])
AM_CONDITIONAL([HAVE_ASCIIDOC], [test "x$HAVE_ASCIIDOC" = "xyes"])

AM_CONDITIONAL([GENERATE_DOC], [test "x$generate_doc" != "xno"])

AC_CONFIG_FILES([
Doxyfile
Makefile
])

AC_OUTPUT
