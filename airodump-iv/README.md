airodump-iv
===========

A python implementation of airodump-ng - the classic wifi sniffing tool.

airodump-iv is probably inferior in a lot of ways to airodump-ng but is being written as a learning tool.  It might also be useful to python developers interested in wifi sniffing.

Currently the only feature in airodump-iv not in airodump-ng is clearly identifying the SSIDs for hidden networks (when possible).

airodump.py is being developed in ubuntu precise with an Alpha AWUS036H or D-Link DWA-123 wireless card.
* For more BackTrack: http://www.backtrack-linux.org/
* For more Alpha AWUS036H: https://www.google.com/search?q=Alpha+AWUS036H
* For more D-Link DWA-123: http://www.dlink.co.in/products/?pid=528
``TODO``

airodump.py makes uses of scapy	for sniffing and protocol/structure parsing
* For more scapy: http://www.secdev.org/projects/scapy/
* For better scapy docs: http://fossies.org/dox/scapy-2.2.0/index.html

My interest in this project was kicked off by a wifi penetration class @ Blackhat EU.  Since then I've read quite a few protocol documents.
* For more on the class: http://www.blackhat.com/eu-13/training/advanced-wifi-penetration-testing.html
* The class basically followed this book: http://www.amazon.com/BackTrack-Wireless-Penetration-Testing-Beginners/dp/1849515581
* 802.11 base spec - http://standards.ieee.org/getieee802/download/802.11-2012.pdf
* 802.11i security spec - http://standards.ieee.org/getieee802/download/802.11i-2004.pdf
* Radiotap Headers - http://www.radiotap.org/
* Wireless Extensions IOCTL - ``less /usr/include/linux/wireless.h``

Installation & Running
======================

Steps to run include:
* Grab the code:
  * ``git clone git://github.com/ivanlei/airodump-iv.git``
  * ``git submodule init``
  * ``git submodule update``
  * ``cd airodump-iv/airoiv``
* Set wireless card into monitor mode:
  * ``sudo airmon-ng check kill``
  * ``sudo airmon-ng start wlan0``
* Once the card	is in monitor mode:
  * ``sudo python airodump-iv.py``
* To exit
  * ``CTRL-C`` (... repeatedly sometimes)

Useful options include:
* ``--iface=IFACE`` - Set the interface	to sniff on.  By default ``mon0``.
* ``--channel=CHANNEL`` - Monitor a single channel.  By default it will channel-hop.
* ``--max-channel=MAX_CHANNEL``	- Set maximum channel during hopping.  By default queries Wireless Extensions.
* ``--packet_count=PACKET_COUNT`` - Number of packets to capture.  By default unlimited.
* ``--input-file=INPUT_FILE`` -	Read from PCAP file.
* ``-v`` - Verbose mode.  Does not play	well with curses mode.
* ``--no-curses`` - Disable the curses interface.

VirtualBox VM
=============
A Ubuntu precise Vagrantfile is included in the project.  It will use puppet standalone to configure a clean wifi test environment in VirtualBox that includes airocrack-ng (from unofficial apt repo), iw tools, wireless-tools, and the contents of this repo.

After installing Vagrant and Virtualbox:
* Boot the box:
  * ``cd airodump-iv/Vagrant``
  * ``vagrant up airoiv01``
  * ``vagrant ssh airoiv01``
* Let the box see a usb wifi adapter.  From the host:
  * ``vboxmanage list usbhost``  and find the UUID of the USB device
  * ``vboxmanage list vms`` and find the UUID of the vm
  * ``vboxmanager controlvm <UUID-of-vm> usbattach <UUID-of-usb-device>``

Interesting TODOs
=================
* Implement channel hopping in a standards compliant manner
* Fix curses mode display to not have quite so many bugs
* Improve station display
* Test with other wifi cards
* Write unit tests
* Cleanup code
* World peace
