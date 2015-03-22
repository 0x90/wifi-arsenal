# Copyright 2011 NICTA
# 

bin_PROGRAMS = probe

probe_SOURCES = \
	main.cpp \
	wireless_link.cpp \
	wireless_link_monitor.cpp \
	timespec.cpp

probe_CPPFLAGS = -I@top_srcdir@/lib

probe_LDADD = @top_srcdir@/lib/libbanjax.la -lpcap -lboost_program_options -lboost_thread -lrt
