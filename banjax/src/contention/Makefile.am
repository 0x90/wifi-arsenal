# Copyright 2011 NICTA
# 

bin_PROGRAMS = analyse

analyse_SOURCES = \
	main.cpp

analyse_CPPFLAGS = -I@top_srcdir@/lib

analyse_LDADD = @top_srcdir@/lib/libbanjax.la -lpcap -lboost_program_options
