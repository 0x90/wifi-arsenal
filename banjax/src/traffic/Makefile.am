# Copyright 2011 NICTA
# 

bin_PROGRAMS = traffic

traffic_SOURCES = \
	traffic.cpp

traffic_CPPFLAGS = -I@top_srcdir@/lib

traffic_LDADD = @top_srcdir@/lib/libbanjax.la -lpcap -lboost_program_options
