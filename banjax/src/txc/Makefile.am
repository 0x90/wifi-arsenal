# Copyright 2011 NICTA
# 

bin_PROGRAMS = txc

txc_SOURCES = \
	txc.cpp

txc_CPPFLAGS = -I@top_srcdir@/lib

txc_LDADD = @top_srcdir@/lib/libbanjax.la -lpcap -lboost_program_options
