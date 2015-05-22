#!/bin/sh -x
# Modified build for Cygwin DLL
make # build .o's
gcc -shared -o orcon.dll ifcontrol_linux.o iwcontrol.o wtinject.o mwoldinject.o mwnginject.o ajinject.o p54inject.o wginject.o hapinject.o rt2500inject.o rtlinject.o rt2570inject.o airpinject.o rt73inject.o tx80211.o lorcon_packasm.o lorcon_forge.o -lairpcap -L../../../AirPcap_Devpack_2_0_0_708/Airpcap_Devpack/lib/ -mno-cygwin -ggdb -g3 

gcc -o tx tx.c -L ./ -L ../../../AirPcap_Devpack_2_0_0_708/Airpcap_Devpack/lib -lorcon -lairpcap -I. -ggdb -g3 

