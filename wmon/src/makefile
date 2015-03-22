#   Wireless Network Monitor
# 
#   Copyright 2011 David Garcia Villalba, Daniel López Rovira, Marc Portoles Comeras and Albert Cabellos Aparicio
# 
#   This file is part of wmon.
# 
#   wmon is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
# 
#   wmon is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
# 
#   You should have received a copy of the GNU General Public License
#   along with wmon.  If not, see <http://www.gnu.org/licenses/>.

## Variables definition

CC=g++
CXXFLAGS=-Iinclude -ansi -O2 -DNDEBUG -Wall -Wextra -Werror -Wno-uninitialized -Wno-sign-compare -Wno-unused-parameter -Wno-unused-result
LDFLAGS=-lncurses -ltrace -lpcap -liw -lpthread # Dynamic-link compilation
#LDFLAGS=-static -lncurses -ltrace -lpcap -liw -lpthread -lz -lgpm # Static-link compilation

PROGS=wmon
OBJECTS=main.o NetManager.o NetID.o NetInfo.o CaptureStorage.o Utils.o AirmonNG.o FileGUI.o ConsoleGUI.o GUI.o GUIEvent.o GUIEventDispatcher.o UpdateChannelEvent.o ChangeChannelEvent.o RemainingChannelTimeEvent.o

# DEBCONFIG
HOMEPAGE=http://cba.upc.edu/developed-tools/wireless-network-monitor
MAINTAINER=David Garcia <dagavi@gmail.com>
VERSION=1.1
#ARCH=i386
ARCH=amd64

## Rules

all: $(PROGS)

wmon: $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $? $(LDFLAGS)

wmonGUI: Makefile
	make -f Makefile

Makefile: wmon.pro
	qmake

doc:
	doxygen configuration.dox

deb: wmon.deb

wmon.deb: $(PROGS)
	rm -rf DEB
	mkdir -p DEB/DEBIAN
	mkdir -p DEB/usr/sbin
	mkdir -p DEB/usr/share/man/man1
	cp wmon DEB/usr/sbin/wmon
	gzip -c DEBFILES/wmon.1 > DEB/usr/share/man/man1/wmon.1.gz
	
	echo "Package: wmon\nVersion: $(VERSION)\nSection: net\nPriority: optional\nArchitecture: $(ARCH)\nDepends: libpthread-stubs0, libtrace3 (>= 3), libncurses5 (>= 5), libiw30, libpcap0.8 (>= 1), iw\nInstalled-Size: 100\nMaintainer: $(MAINTAINER)\nHomepage: $(HOMEPAGE)\nDescription: Wireless Network Monitor\n A Wireless Network Monitor." > DEB/DEBIAN/control
	
	cd DEB; rm -f DEBIAN/md5sums; md5sum `find . -type f | awk '/.\// { print substr($$0, 3) }'` > DEBIAN/md5sums
	fakeroot dpkg-deb --build DEB
	mv DEB.deb wmon.deb
	rm -rf DEB

wmonGUI.deb: wmonGUI
	rm -rf DEB
	mkdir -p DEB/DEBIAN
	mkdir -p DEB/usr/sbin
	mkdir -p DEB/usr/share/applications
	mkdir -p DEB/usr/share/man/man1
	cp wmonGUI DEB/usr/sbin/wmon
	gzip -c DEBFILES/wmon.1 > DEB/usr/share/man/man1/wmon.1.gz
	
	echo "Package: wmon\nVersion: $(VERSION)-GUI\nSection: net\nPriority: optional\nArchitecture: $(ARCH)\nDepends: libqtgui4 (>= 4.3), libpthread-stubs0, libtrace3 (>= 3), libiw30, libpcap0.8 (>= 1), iw\nInstalled-Size: 100\nMaintainer: $(MAINTAINER)\nHomepage: $(HOMEPAGE)\nDescription: Wireless Network Monitor\n A Wireless Network Monitor." > DEB/DEBIAN/control
	
	echo "[Desktop Entry]\nType=Application\nVersion=$(VERSION)-GUI\nName=wmon\nGenericName=Wireless Network Monitor\nComment=Wireless Network Monitor\nIcon=gnome-nettool\nExec=gksudo wmon\nTerminal=false\nCategories=GNOME;Network;\nEncoding=UTF-8" > DEB/usr/share/applications/wmon.desktop
	
	cd DEB; rm -f DEBIAN/md5sums; md5sum `find . -type f | awk '/.\// { print substr($$0, 3) }'` > DEBIAN/md5sums
	fakeroot dpkg-deb --build DEB
	mv DEB.deb wmonGUI.deb
	rm -rf DEB

clean:
	rm -f $(PROGS) $(OBJECTS)

cleanGUI:
	make -f Makefile clean
	rm wmonGUI

## Dependencies
main.o: include/NetManager.h include/FileGUI.h include/ConsoleGUI.h include/GUIEventDispatcher.h
NetManager.o: include/NetManager.h include/CaptureStorage.h include/AirmonNG.h include/GUIEventDispatcher.h include/ChangeChannelEvent.h
CaptureStorage.o: include/CaptureStorage.h include/NetStructures.h include/NetID.h include/BeaconInfo.h include/NetInfo.h include/NetStats.h include/GUIEventDispatcher.h include/UpdateChannelEvent.h
NetID.o: include/NetID.h include/Utils.h
NetInfo.o: include/NetInfo.h include/NetStats.h
Utils.o: include/Utils.h
AirmonNG.o: include/AirmonNG.h
GUI.o: include/GUI.h
FileGUI.o: include/FileGUI.h include/GUI.h include/NetStats.h
ConsoleGUI.o: include/ConsoleGUI.h include/GUI.h include/NetStats.h
GUIEvent.o: include/GUIEvent.h include/GUI.h
GUIEventDispatcher.o: include/GUIEventDispatcher.h include/GUIEvent.h include/GUI.h
UpdateChannelEvent.o: include/UpdateChannelEvent.h include/GUIEvent.h include/GUI.h include/NetStats.h
ChangeChannelEvent.o: include/ChangeChannelEvent.h include/GUIEvent.h include/GUI.h
RemainingChannelTimeEvent.o: include/RemainingChannelTimeEvent.h include/GUIEvent.h include/GUI.h
