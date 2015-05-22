$(shell chmod 755 ../evalrev)
include		../common.mak

LIBS		+= -lm -lpthread

COMMON_C_FILES	= common/pcap.c common/client.c common/server-client.c common/sockets.c global_var.c common/rpcap.c common/utils.c common/version.c common/protocol.c common/interface_control.c
C_FILES			= main.c client.c structures.c packet_capture.c command_parse.c rpcap.c $(COMMON_C_FILES)

SBIN_FILE	= openwips-ng

ifeq ($(DEBUG), yes)
	CFLAGS	+= -DDEBUG 
endif

ifeq ($(DEBUG), normal)
	CFLAGS	+= -DDEBUG 
endif

ifeq ($(DEBUG), true)
	CFLAGS	+= -DDEBUG 
endif

ifeq ($(DEBUG), extra)
	CFLAGS	+= -DDEBUG -DEXTRA_DEBUG
endif

default: all

all: openwips-ng

openwips-ng:
	$(CC) $(CFLAGS) $(LDFLAGS) $(REV_DEFINE) -o $(SBIN_FILE)  $(C_FILES) $(LIBS)

strip:
	strip $(SBIN_FILE)

install: openwips-ng
	install -m 755 $(SBIN_FILE) $(sbindir)

uninstall:
	rm $(sbindir)/$(SBIN_FILE)

clean:
	-rm -f *.o common/*.o $(SBIN_FILE)
