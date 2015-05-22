CC				?= gcc
CFLAGS			?= -Wall -O0 -g3 -fvisibility=hidden

ifneq ($(OSNAME), cygwin)
	CFLAGS		+= -fPIC
else
	CC		= gcc-4
	INCLUDES	= -I/usr/include/pcap
endif

PROTO_CHECK_C	= protocol_check.c ../common/pcap.c
PROTO_CHECK_O	= protocol_check.o pcap.o

DS_BITS_CHECK_C	= ds_bits_check.c ../common/pcap.c
DS_BITS_CHECK_O	= ds_bits_check.o pcap.o

DEAUTH_DETECT_C	= deauth_detect.c ../common/pcap.c ../common/utils.c
DEAUTH_DETECT_O	= deauth_detect.o pcap.o utils.o

REPLAY_DETECT_C = replay_detect.c ../common/pcap.c
REPLAY_DETECT_O = deauth_detect.o pcap.o 

IE_C			= IEs.c ../common/pcap.c
IE_O			= IEs.o pcap.o

FRAG_DETECT_C	= frag_detection.c ../common/pcap.c
FRAG_DETECT_O	= frag_detection.o pcap.o

SUBTYPE_CHECK_C	= frame_subtype_check.c ../common/pcap.c
SUBTYPE_CHECK_O	= frame_subtype_check.o pcap.o

prefix			= /usr/local
plugin_dir		= $(prefix)/sbin/openwips-ng-plugins

default: all

all: clean protocol_check ds_bits_check deauth_detect ie frame_subtype_check frag_detection

frame_subtype_check:
	$(CC) $(INCLUDES) $(CFLAGS) -c $(SUBTYPE_CHECK_C)
	$(CC) -shared -Wl,-soname,frame_subtype_check.so.1 -o frame_subtype_check.so.1.0   $(SUBTYPE_CHECK_O)

frag_detection:
	$(CC) $(INCLUDES) $(CFLAGS) -c $(FRAG_DETECT_C)
	$(CC) -shared -Wl,-soname,frag_detection.so.1 -o frag_detection.so.1.0   $(FRAG_DETECT_O)

ie:
	$(CC) $(INCLUDES) $(CFLAGS) -c $(IE_C)
	$(CC) -shared -Wl,-soname,ie.so.1 -o ie.so.1.0   $(IE_O)

replay_detect:
	$(CC) $(INCLUDES) $(CFLAGS) -c $(REPLAY_DETECT_C)
	$(CC) -shared -Wl,-soname,replay_detect.so.1 -o replay_detect.so.1.0   $(REPLAY_DETECT_O)

deauth_detect:
	$(CC) $(INCLUDES) $(CFLAGS) -c $(DEAUTH_DETECT_C)
	$(CC) -shared -Wl,-soname,deauth_detect.so.1 -o deauth_detect.so.1.0   $(DEAUTH_DETECT_O)

ds_bits_check:
	$(CC) $(INCLUDES) $(CFLAGS) -c $(DS_BITS_CHECK_C)
	$(CC) -shared -Wl,-soname,ds_bits_check.so.1 -o ds_bits_check.so.1.0   $(DS_BITS_CHECK_O)
	
protocol_check:
	$(CC) $(INCLUDES) $(CFLAGS) -c $(PROTO_CHECK_C)
	$(CC) -shared -Wl,-soname,protocol_check.so.1 -o protocol_check.so.1.0   $(PROTO_CHECK_O)

clean:
	rm -f *.o *.so.*
	
install:
	install -d $(plugin_dir)
	install -m 755 *.so* $(plugin_dir)

uninstall:
	rm $(plugin_dir)/*.so*
	rmdir $(plugin_dir)
