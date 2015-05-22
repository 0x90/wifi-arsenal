CC = gcc
CFLAGS = -Wall -Werror
DEPS = pcap.h, stdio.h

sniffer: sniffer.c
	$(CC) $(CFLAGS) sniffer.c -o sniffer -lpcap

clean:
	rm -rf *.o
	rm -rf sniffer
