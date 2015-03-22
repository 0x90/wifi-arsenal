# 
#	Makefile
HAVE_PYTHON=1
CFLAGS=-O3 -Wall -ggdb3 -I./lorcon_install/include -DHAVE_PYTHON
LDFLAGS=-L./lorcon_install/lib -Wl,-rpath=./lorcon_install/lib -lorcon2 -lpthread -lpcap -lpcre -lpython2.7 -lnet
CC=gcc
LD=ldd
OBJ = logger.o lrc.o matchers.o
TARGET = lrc
RM = rm -f

all: $(TARGET)
	@echo

$(TARGET): $(OBJ)
	$(CC) ${LDFLAGS} -o $@ $(OBJ)

clean:
	$(RM) $(OBJ) $(TARGET) *~
