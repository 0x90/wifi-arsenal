INCLUDES    = -I../include
LDFLAGS     = -pthread -lpcap

OBJ         = iw.o packet.o wlan.o list.o rtap.o mgt.o llc.o field.o

all: $(OBJ)

%.o: %.c
	$(CC) $(CFLAGS) -O2 -std=gnu99 -Wall -Wextra -pedantic $(INCLUDES) -c $<

clean:
	rm -rf *.o

