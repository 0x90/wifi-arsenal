ifndef OSNAME
OSNAME		= $(shell uname -s | sed -e 's/.*CYGWIN.*/cygwin/g' -e 's,/,-,g')
endif

ifeq ($(OSNAME), Darwin)
	include Makefile.Darwin
else
	include Makefile.nix
endif