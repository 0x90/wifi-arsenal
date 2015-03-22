# Copyright 2011 NICTA
# 

bin_PROGRAMS = beacons

beacons_SOURCES = \
	beacons.cpp

beacons_CPPFLAGS = -I@top_srcdir@/lib

beacons_LDADD = @top_srcdir@/lib/libbanjax.la -lpcap -lboost_program_options
