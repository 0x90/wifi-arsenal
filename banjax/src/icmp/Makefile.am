# Copyright 2011 NICTA
# 

bin_PROGRAMS = icmp

icmp_SOURCES = \
	icmp.cpp

icmp_CPPFLAGS = -I@top_srcdir@/lib

icmp_LDADD = @top_srcdir@/lib/libbanjax.la -lpcap -lboost_program_options
