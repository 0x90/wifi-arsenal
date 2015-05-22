# Copyright 2011 NICTA
# 

bin_PROGRAMS = verify

verify_SOURCES = \
	verify.cpp

verify_CPPFLAGS = -I@top_srcdir@/lib

verify_LDADD = @top_srcdir@/lib/libbanjax.la -lpcap -lboost_program_options
