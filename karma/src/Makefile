LDLIBS=-lpcap -lncurses
CFLAGS=-g -Wall -pedantic

OBJS=airtap.o karma.o karma_ui.o

karma: airtap.h $(OBJS)
	$(CC) $(CFLAGS) -o karma  $(OBJS) $(LDFLAGS) $(LDLIBS)

clean:
	rm karma *.o *~ *.core core
