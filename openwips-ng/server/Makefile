$(shell chmod 755 ../evalrev)
include			../common.mak

LIBS			+= -lssl -lz -L/usr/local/lib -L/usr/lib -lcrypto -ldl -lsqlite3

BIN_FILE		= openwips-ng-server
CONF_FILE		= openwips-ng-server.conf
COMMON_C_FILES	= common/server.c common/server-client.c common/sockets.c common/rpcap.c common/pcap.c common/utils.c common/deamonize.c common/config.c common/protocol.c common/version.c
SENSOR_C_FILES	= sensor/packet_assembly.c sensor/sensor.c sensor/command_parse.c sensor/rpcap_server.c
C_FILES			= main.c config.c users.c plugins.c packet_analysis.c messages.c database/init.c database/database.c $(COMMON_C_FILES) $(SENSOR_C_FILES)


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

all: openwips-ng-server plugins

plugins:
	make -C plugin

openwips-ng-server:
	$(CC) $(CFLAGS) $(LDFLAGS) $(REV_DEFINE) -o $(BIN_FILE) $(C_FILES) $(LIBS)

strip:
	strip $(BIN_FILE)

install: openwips-ng-server
	$(MAKE) -C plugin $(@)
	install -m 755 $(BIN_FILE) $(bindir)
	install -d $(confdir)
	install -m 755 $(CONF_FILE) $(confdir)

uninstall:
	$(MAKE) -C plugin $(@)
	rm $(bindir)/$(BIN_FILE)
	rm $(confdir)/$(CONF_FILE)
	rmdir $(confdir)

clean:
	$(MAKE) -C plugin $(@)
	-rm -f *.o common/*.o sensor/*.o database/*.o $(BIN_FILE)
