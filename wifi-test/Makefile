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
	   exit -1; \
	else \
		make -C tvs; \
		make -C TestSuites; \
	fi


install:
	echo "Installing `pwd`"
	if [ ! -f ${TET_ROOT}/bin/tcc ]; then \
	   echo "ERROR: tet not install!"; \
	   exit -1; \
	else \
		make -C tvs install; \
		make -C TestSuites install; \
		mkdir -p /usr/tet/TVS; \
		cd tvs/src; \
		cp -r bin documentation inc lib tsets etc ${TET_ROOT}/TVS; \
		cp etc/TVSEnvironment /etc; \
	fi


clean:  
	echo "Cleaning `pwd`"
	rm -f core *~ *.o
	make -C tvs clean
	make -C TestSuites clean















