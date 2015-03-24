#!/bin/sh
dir="/home/hugh/src/archlinux/core/linux/src/linux-3.11/drivers/net/wireless/ath/"
rsync --archive --checksum --delete ../hughnav "$dir"

cd "$dir/hughnav"
make clean
make all
