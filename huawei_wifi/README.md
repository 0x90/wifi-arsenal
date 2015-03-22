Wifi utilities for finding Huawei routers' default key
======================================================

Some Huawei routers use a default WEP key that is easy findable because
it can be calculated using the MAC address of the router.

Thanks and congrats to the clever people at Websec.mx for
[figuring out](http://websec.mx/blog/ver/mac2wepkey_huawei) the generation
algorithm after many hours of reverse-engineering.

This repository contains two programs that make use of the discovery.


mac2defaults.py
---------------

This is the original script, improved so that it looks more like Python and
less like C.
The output was also cleaned a bit, and the program can work either in
interactive or automated mode.

- Interactive mode means no command-line parameter was given. The program then
  asks for a MAC address and outputs the corresponding key and default ESSID.
  Then it starts over until an empty address is given.
- When one or several MAC addresses are given on the command line, the program
  outputs the corresponding default key and ESSID in a machine-parseable
  format.

The program works as a Python module as well, which means its functions can be
used by other programs internally.


scan_vulnerable_aps.py
----------------------

This program scans the available networks around and computes the default WEP
key assuming it's a Huawei modem. If the default ESSID derived from the MAC
matches the actual ESSID, it marks the line with a '*' so that you know the
key will probably work. Otherwise, the line is marked with a '-', which means
it probably won't work, but you can try it anyway, since the ESSID could have
been changed manually.
