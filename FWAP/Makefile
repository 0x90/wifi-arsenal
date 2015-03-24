
CC = gcc

CFLAGS ?= -O2 -g
CFLAGS += -Wall -Wundef -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -Werror-implicit-function-declaration

OBJS = fwap.o

LIBS += -lnl-genl-3
LIBS += -lnl-3 
CFLAGS += -I/usr/include/libnl3/

test:	$(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) $(LIBS) -o fwap 


