# Copyright 2011 NICTA
# 

bin_PROGRAMS = sender

sender_SOURCES = \
	main.cpp

sender_CPPFLAGS = -I@top_srcdir@/lib

sender_LDADD = @top_srcdir@/lib/libbanjax.la -lpcap -lboost_program_options
