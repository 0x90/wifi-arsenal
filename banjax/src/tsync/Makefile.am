# Copyright 2011 NICTA
# 

bin_PROGRAMS = tsync

tsync_SOURCES = \
	tsync.cpp 

tsync_CPPFLAGS = -I@top_srcdir@/lib

tsync_LDADD = @top_srcdir@/lib/libbanjax.la -lpcap -lboost_program_options
