
CC=gcc

CFLAGS=-c -Wall -O3 -fno-strict-aliasing -DOSX
LDFLAGS=-lm

SOURCES=prober.c tcp_client.c tcpserver.c wrappers.c tbdetect.c measflow.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=prober

all: clean $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS) 
		$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.c.o:
		$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf *.o prober
