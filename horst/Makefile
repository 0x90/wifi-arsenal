# horst - Highly Optimized Radio Scanning Tool
#
# Copyright (C) 2005-2014 Bruno Randolf (br1@einfach.org)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

# build options
DEBUG=1
PCAP=0

NAME=horst
OBJS=main.o capture$(if $(filter 1,$(PCAP)),-pcap).o protocol_parser.o \
	protocol_parser_wlan.o network.o wext.o node.o essid.o channel.o \
	util.o wlan_util.o ieee80211_util.o listsort.o average.o \
	display.o display-main.o display-filter.o display-help.o \
	display-statistics.o display-essid.o display-history.o \
	display-spectrum.o display-channel.o control.o \
	radiotap/radiotap.o conf_options.o
LIBS=-lncurses -lm
CFLAGS+=-Wall -Wextra -g -I.

ifeq ($(DEBUG),1)
CFLAGS+=-DDO_DEBUG
endif

ifeq ($(PCAP),1)
CFLAGS+=-DPCAP
LIBS+=-lpcap
endif

.PHONY: force

all: $(NAME)

# dependencies, generated with 'gcc -MM *.c' and pasted here
average.o: average.c average.h util.h
capture.o: capture.c capture.h util.h
capture-pcap.o: capture-pcap.c capture.h util.h
channel.o: channel.c main.h ccan/list/list.h average.h channel.h \
 wlan80211.h util.h wext.h
control.o: control.c main.h ccan/list/list.h average.h channel.h \
 wlan80211.h control.h
display.o: display.c display.h main.h ccan/list/list.h average.h \
 channel.h wlan80211.h
display-channel.o: display-channel.c display.h main.h ccan/list/list.h \
 average.h channel.h wlan80211.h network.h
display-essid.o: display-essid.c display.h main.h ccan/list/list.h \
 average.h channel.h wlan80211.h util.h
display-filter.o: display-filter.c display.h main.h ccan/list/list.h \
 average.h channel.h wlan80211.h util.h network.h
display-help.o: display-help.c display.h main.h ccan/list/list.h \
 average.h channel.h wlan80211.h wlan_util.h
display-history.o: display-history.c display.h main.h ccan/list/list.h \
 average.h channel.h wlan80211.h util.h wlan_util.h
display-main.o: display-main.c display.h main.h ccan/list/list.h \
 average.h channel.h wlan80211.h util.h wlan_util.h olsr_header.h \
 batman_adv_header-14.h listsort.h
display-spectrum.o: display-spectrum.c display.h main.h ccan/list/list.h \
 average.h channel.h wlan80211.h util.h
display-statistics.o: display-statistics.c display.h main.h \
 ccan/list/list.h average.h channel.h wlan80211.h util.h wlan_util.h
essid.o: essid.c main.h ccan/list/list.h average.h channel.h wlan80211.h \
 util.h essid.h
ieee80211_util.o: ieee80211_util.c ieee80211_util.h wlan80211.h main.h \
 ccan/list/list.h average.h channel.h util.h
listsort.o: listsort.c ccan/list/list.h listsort.h
main.o: main.c main.h ccan/list/list.h average.h channel.h wlan80211.h \
 util.h capture.h protocol_parser.h network.h display.h wlan_util.h \
 ieee80211_util.h control.h node.h essid.h
network.o: network.c main.h ccan/list/list.h average.h channel.h \
 wlan80211.h util.h network.h
node.o: node.c main.h ccan/list/list.h average.h channel.h wlan80211.h \
 util.h essid.h
protocol_parser.o: protocol_parser.c olsr_header.h batman_header.h \
 batman_adv_header-14.h main.h ccan/list/list.h average.h channel.h \
 wlan80211.h util.h
protocol_parser_wlan.o: protocol_parser_wlan.c prism_header.h \
 radiotap/radiotap.h radiotap/radiotap_iter.h radiotap/radiotap.h \
 wlan80211.h wlan_util.h main.h ccan/list/list.h average.h channel.h \
 util.h
util.o: util.c util.h
wext.o: wext.c wext.h channel.h main.h ccan/list/list.h average.h \
 wlan80211.h util.h
wlan_util.o: wlan_util.c main.h ccan/list/list.h average.h channel.h \
 wlan80211.h util.h wlan_util.h

$(NAME): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

$(OBJS): .buildflags

check:
	sparse *.[ch]

clean:
	-rm -f *.o radiotap/*.o *~
	-rm -f $(NAME)
	-rm -f .buildflags

.buildflags: force
	echo '$(CFLAGS)' | cmp -s - $@ || echo '$(CFLAGS)' > $@
