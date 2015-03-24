PKG_CONFIG ?= pkg-config
CC=gcc

CFLAGS+=-c -Wall -O3 -DOSX  -Wundef -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -Werror-implicit-function-declaration 
LDFLAGS+=  -lm -lz 
NL1FOUND="" 
NL2FOUND=Y
NLLIBNAME="libnl-tiny" 
#LIBS="-lnl-tiny" 

NL1FOUND := $(shell $(PKG_CONFIG) --atleast-version=1 libnl-1 && echo Y)
ifeq ($(NL1FOUND),Y)
NLLIBNAME = libnl-1
endif

ifeq ($(NLLIBNAME),)
$(error Cannot find development files for any supported version of libnl)
endif

LIBS += $(shell $(PKG_CONFIG) --libs $(NLLIBNAME))
CFLAGS += $(shell $(PKG_CONFIG) --cflags $(NLLIBNAME))


SOURCES= create-interface.c mgmt.c write.c  anonymization.c util.c sha1.c 
OBJECTS=  $(SOURCES:.c=.o)

OBJECTS_NL= mac-darktest.o 
OBJ_2=nl_funcs.o
EXECUTABLE=mac-analyzer

all:  $(EXECUTABLE)


$(EXECUTABLE): $(OBJECTS) $(OBJ_2) $(OBJECTS_NL) 
	$(CC) $(LDFLAGS)   $(OBJECTS_NL) $(OBJ_2) $(OBJECTS) $(LIBS) -o $@



$(OBJECTS_NL): mac-darktest.c
	$(CC)  -DCONFIG_LIBNL20  -D_GNU_SOURCE   -I$(STAGING_DIR)/usr/include/mac80211 -I$(STAGING_DIR)/usr/include/libnl-tiny $(CFLAGS) -o $@ $<

$(OBJ_2):  nl_funcs.c
	$(CC)  -DCONFIG_LIBNL20  -D_GNU_SOURCE   -I$(STAGING_DIR)/usr/include/mac80211 -I$(STAGING_DIR)/usr/include/libnl-tiny $(CFLAGS) -o $@ $<

.o:	%.c 
	$(CC) $(CFLAGS)  -o $@ $<








clean:
	rm -rf *.o mac-darktest
