#!/bin/sh
sudo sync
sudo insmod hughnav.ko
dmesg | tail
