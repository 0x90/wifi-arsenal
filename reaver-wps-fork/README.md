Reaver WPS
==========
My fork of Reaver (the Wireless Protected Setup bruteforce tool).

Original code tree (1.4, now abandoned): https://code.google.com/p/reaver-wps/

Community-supported fork (supposedly 1.5): https://code.google.com/p/reaver-wps-fork/

I picked up the latter to continue fixing and improving the tool.

The patches I applied will be stored in `./patches/`

The ones I do not apply will be stored in `./patches_misc/`

Install
-------

```
sudo apt-get install libpcap-dev libsqlite3-dev
cd src
./configure
make -j 3
sudo make install
```
