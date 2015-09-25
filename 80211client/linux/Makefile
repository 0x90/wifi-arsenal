CC = gcc
CFLAGS = -g
OBJECTS = main.o watcher.o

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

all:main

main : $(OBJECTS)
	gcc -o $@ $^ -lpcap

main.o : main.c
watcher.o : watcher.c data.h	

clean:
	rm -f main $(OBJECTS)
	
.PHONY : clean all
