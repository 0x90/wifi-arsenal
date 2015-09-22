SBINDIR=/usr/local/sbin
MANDIR=/usr/share/man/man8
OBJDIR=obj

all: $(OBJDIR) iwleeprom iwleeprom.8.gz

debug:
		CFLAGS="-g $(CFLAGS)" make all

$(OBJDIR):
		mkdir $(OBJDIR)

iwleeprom: $(OBJDIR)/iwlio.o $(OBJDIR)/ath5kio.o $(OBJDIR)/ath9kio.o $(OBJDIR)/iwleeprom.o
		gcc -Wall $(CFLAGS) -o iwleeprom $(OBJDIR)/iwleeprom.o $(OBJDIR)/iwlio.o $(OBJDIR)/ath5kio.o $(OBJDIR)/ath9kio.o

$(OBJDIR)/iwleeprom.o: iwleeprom.h iwlio.h ath5kio.h ath9kio.h iwleeprom.c
		gcc -Wall $(CFLAGS) -c -o $(OBJDIR)/iwleeprom.o iwleeprom.c

$(OBJDIR)/iwlio.o: iwleeprom.h iwlio.h iwlio.c
		gcc -Wall $(CFLAGS) -c -o $(OBJDIR)/iwlio.o iwlio.c

$(OBJDIR)/ath5kio.o: iwleeprom.h ath5kio.h ath5kio.c
		gcc -Wall $(CFLAGS) -c -o $(OBJDIR)/ath5kio.o ath5kio.c

$(OBJDIR)/ath9kio.o: iwleeprom.h ath9kio.h ath9kio.c
		gcc -Wall $(CFLAGS) -c -o $(OBJDIR)/ath9kio.o ath9kio.c

iwleeprom.8.gz: iwleeprom.8
		gzip -c iwleeprom.8 > iwleeprom.8.gz

clean:
		rm -f iwleeprom iwleeprom.8.gz *~
		rm -rf $(OBJDIR)

install: all
		install -m 4755 iwleeprom $(SBINDIR)
		install -m 644 iwleeprom.8.gz $(MANDIR)

uninstall:
		rm -f $(SBINDIR)/iwleeprom
		rm -f $(MANDIR)/iwleeprom.8.gz

.PHONY: all debug clean install uninstall

