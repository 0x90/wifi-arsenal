#########################################
#
# wifitap.py --- WiFi injection tool through tun/tap device
# Cedric Blancher <sid@rstack.org>
#
# http://sid.rstack.org/index.php/Wifitap (french)
# http://sid.rstack.org/index.php/Wifitap_EN (english)
#
#########################################

This program is a proof of concept tool allowing WiFi communications using
traffic injection.
You'll need:

	. Python >= 2.2
	. Psyco Python optimizer (optional)
	. Philippe Biondi's Scapy
	. Injection ready wireless adapter

It's been tested on GNU/Linux using Atheros chipset based adapter with patched
Madwifi driver and Intersil Prism GT Full MACchipset with Prism54 driver. It
should as well work with Prism2/2.5/3 chipset hostap driver or wlan-ng driver,
Ralink rt2500/2750 chipset using rt2500 driver and Realtek RTL8180 chipset
using rtl8180-sa2400 driver.

I didn't take time to test Prism2/2.5/3 support and don't have Ralink or Realtek
based hardware for testing. By the way, I would be glad to have feedback for
Wifitap attempts with thoses chipsets.

Drivers patches are written by Christophe Devine and updated by Aircrack-ng
people. For details about drivers patch and installation, see PATCHING file.


To get wifitap work on other Unix operating systems than GNU/Linux, you have to
install pcap or dnet wrappers for Python so Scapy can work (see
http://www.secdev.org/projects/scapy/portability.html). Then, and it's the most
important part, you have to find a wireless adapter driver that supports raw
wireless traffic injection if any.


NB : Python is so slow...


o Getting Wifitap ;)

	Wifitap is available at:

		http://sid.rstack.org/index.php/Wifitap (french)
		http://sid.rstack.org/index.php/Wifitap_EN (english)

	Lastest version is downloadable at:

		http://sid.rstack.org/code/wifitap.tgz

	Repository available at:

		http://sid.rstack.org/code/wifitap/


o Getting Scapy

	A working Scapy version is attached, so Wifitap is ready to work.
	However, you can get a more featured version of the tool at:

		http://www.secdev.org/projects/scapy/
	
	Download "work-in-progress" version or (better) use provided version...


o Preparing WiFi adapter

	Download, patch and install driver (see PATCHING).
	
	Supposing channel is 11:

		~# iwconfig $IFACE mode monitor channel 11
		~# ifconfig $IFACE up promisc

	NB: Atheros driver Madwifi requires specific configuration to get driver
	    in promisc mode and/or activate traffic injection. See website
	    (http://www.madwifi.org/) for details if you use madwifi-ng or
	    madwifi-old.

o Launching Wifitap

		~# ./wifitap.py -b <bssid>

	A wj0 interface will be created that needs to be configured as a
	regular interface, with optional MAC address specification:

		~# ifconfig wj0 [hw ether <MAC>] 192.168.1.1 [mtu <MTU>]


o Using Wifitap

	Now, you can us wj0 interface just as a usual interface to communicate
	with your prefered applications and tools, according to system routing
	table :)


o Wifitap command line arguments

	Usage : wifitap -b <BSSID> [-o <iface>] [-i <iface> [-s <SMAC>]
			[-w <WEP key> [-k <key id>]] [-d [-v]] [-h]

	-b	Specifies BSSID in ususal 6 hex digits MAC address format:
			. 00:01:02:03:04:05

	-o	Specifies output WiFi interface for frames injection

	-i	Specifies input WiFi interface for frames sniffing

	-s	Specifies source MAC address
			. 00:01:02:03:04:05

	-w	Activates WEP encryption/decryption with specified WEP key
		Key can be given using following formats:
			. 0102030405 or 0102030405060708090a0b0c0d
			. 01:02:03:04:05 or
			  01:02:03:04:05:06:07:08:09:0a:0b:0c:0d
			. 0102-0304-05 or 0102-0304-0506-0708-090a-0b0c-0d

	-k	Specifies WEP key id, from 0 to 3

	-d	Activates debugging

	-v	Increases debugging verbosity

	-h	Help screen

o Latest libpcap fully supports Wi-Fi specific headers, typically Prism Headers.
  However, if your system uses old libpcap, you will need to apply provided
  patch:

	patch -p0 < prismheaders.patch

  It will add a flag (-p) to tell Wifitap to shift 144 bits of Prism Headers to
  access 802.11 frame.


#########################################
#
# Copyright (C) 2005 Cedric Blancher <sid@rstack.org>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation; version 2.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
#########################################
