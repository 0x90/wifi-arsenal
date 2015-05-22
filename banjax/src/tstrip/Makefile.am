# Copyright 2011 NICTA
# 

bin_PROGRAMS = tstrip

tstrip_SOURCES = \
	strip.cpp 

tstrip_CPPFLAGS = -I@top_srcdir@/lib

tstrip_LDADD = @top_srcdir@/lib/libbanjax.la -lpcap -lboost_program_options
