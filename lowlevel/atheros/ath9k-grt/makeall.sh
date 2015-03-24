#!/usr/bin/zsh
make -C /usr/src/linux-headers-$(uname -r) M=$PWD modules all 
