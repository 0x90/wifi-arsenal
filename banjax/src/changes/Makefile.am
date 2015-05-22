# Copyright 2011 NICTA
# 

bin_PROGRAMS = changes

changes_SOURCES = \
	changes.cpp 

changes_CPPFLAGS = -I@top_srcdir@/lib

changes_LDADD = @top_srcdir@/lib/libbanjax.la -lpcap -lboost_program_options
