# Copyright 2013 NICTA
# 

bin_PROGRAMS = monitor

monitor_SOURCES = \
	main.cpp

monitor_CPPFLAGS = -I@top_srcdir@/lib

monitor_LDADD = @top_srcdir@/lib/libbanjax.la -lpcap -lboost_program_options
