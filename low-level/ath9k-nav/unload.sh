#!/bin/sh
sudo sync
sudo rmmod hughnav.ko
dmesg | tail
