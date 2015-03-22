BIN=fft_eval
OBJ=fft_eval.o
LIBS=-lSDL -lSDL_ttf -lm
CC=gcc -std=c99 -O2 -Wall
LD=gcc
.SUFFIXES: .o .c
.c.o:
	$(CC) -c -o $@ $<

default:	all
all:	$(BIN)

$(BIN): $(OBJ)
	$(LD) -o $@ $(OBJ) $(LIBS)

clean:
	rm -rf $(BIN) $(OBJ)

