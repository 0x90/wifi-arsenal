###############################################################################
## Makefile
##
## Rusty Lynch <rusty.lynch@intel.com>
###############################################################################
##   Copyright (c) Intel Corp., 2001
##   License: BSD 
###############################################################################
ifeq ($(TET_ROOT),)
	TET_ROOT := /usr/tet
else
	TET_ROOT := /usr/tet
endif
export TET_ROOT

all: build

build:
	echo "Building `pwd`"
	if [ ! -f ${TET_ROOT}/bin/tcc ]; then \
	   echo "ERROR: tet not install!"; \
           echo "       or manually set TET_ROOT to your tet root dir"; \
	   exit -1; \
	else \
		make -C ./src/Framework; \
	fi


install:
	echo "Installing `pwd`"
	if [ ! -f ${TET_ROOT}/bin/tcc ]; then \
	   echo "ERROR: tet not install!"; \
           echo "       or manually set TET_ROOT to your tet root dir"; \
	   exit -1; \
	else \
		make -C ./src/Framework install; \
	fi


clean:  
	echo "Cleaning `pwd`"
	rm -f core *~ *.o
	make -C ./src/Framework clean















