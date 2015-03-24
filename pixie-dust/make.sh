#!/bin/bash
# no time to makefile, get in the car
gcc -ggdb -Wall -pedantic -ansi -std=c99 main.c && valgrind --leak-check=full --show-leak-kinds=all ./a.out wpsdata.cap debug
