packetspammer: packetspammer.c
	gcc  -Wall -Werror radiotap.c packetspammer.c -o packetspammer -lpcap

clean:
	rm -f packetspammer *~

send:	packetspammer
	scp packetspammer root@192.168.0.60:/usr/local/bin
#	scp packetspammer root@192.168.0.99:/usr/local/bin

install:
	mkdir -p $(DESTDIR)/usr/bin
	cp packetspammer $(DESTDIR)/usr/bin

style:
	cstyle packetspammer.c radiotap.c
