KARMA
=====
KARMA Attacks Radioed Machines Automatically (KARMA) is a set of tools for assessing the security of wireless clients at multiple layers. Wireless sniffing tools discover clients and their preferred/trusted networks by passively listening for 802.11 Probe Request frames. From there, individual clients can be targeted by creating a Rogue AP for one of their probed networks (which they may join automatically) or using a custom driver that responds to probes and association requests for any SSID. Higher-level fake services can then capture credentials or exploit client-side vulnerabilities on the host.

KARMA includes patches for the Linux MADWifi driver to allow the creation of an 802.11 Access Point that responds to any probed SSID. So if a client looks for `linksys`, it is `linksys` to them (even while it may be `tmobile` to someone else). Operating in this fashion has revealed vulnerabilities in how Windows XP and MacOS X look for networks, so clients may join even if their preferred networks list is empty.

Thanks to some great work by HD Moore, KARMA now lives on in the modern era as [Karmetasploit](http://dev.metasploit.com/redmine/projects/framework/wiki/Karmetasploit). Karmetasploit is an integration of parts of KARMA and its ideas into the Metasploit framework. Karmetasploit is your best option for running KARMA these days, even though the original version by Dino and Shane is available here. For an in-depth description of the KARMA attacks against wireless clients, see the whitepaper and presentation.

### Docs

* Attacking Automatic Wireless Network Selection [[slides]](http://www.trailofbits.com/resources/attacking_automatic_network_selection_slides.pdf) [[paper]](http://www.trailofbits.com/resources/attacking_automatic_network_selection_paper.pdf)
* [Karmetasploit](http://dev.metasploit.com/redmine/projects/framework/wiki/Karmetasploit) documentation
* [CNET News.com](http://news.cnet.com/Microsoft-meets-the-hackers/2009-1002_3-5747813.html) story mentioning our KARMA demo at Microsoft’s Blue Hat summit
* [Legacy KARMA README](karma.README.txt)
* [KARMA HOWTO](http://www.wirelessdefence.org/Contents/KARMAMain.htm) at WirelessDefence.org

### Software

* Legacy KARMA Snapshot (20060124) - this repository
* [Karma 0.4 CanSecWest/core05 Alpha Release](/archive/karma-0.4.tar.gz)
* [Karma 0.3 Microsoft BlueHat Alpha Release](/archive/karma-0.3.tar.gz)
* [Karma 0.2 Immunity NYC Security Shindig Alpha Release](/archive/karma-0.2.tar.gz)
* [Karma 0.1 PACSEC Alpha Release](/archive/karma-0.1.tar.gz)

### Related Projects

* [KARMetasploit](http://dev.metasploit.com/redmine/projects/framework/wiki/Karmetasploit) - KARMA functionality in Metasploit
* [Jaseger](http://www.digininja.org/jasager/) - Portable KARMA on the FON La Fonera router
* [WiFi Pineapple](https://hakshop.myshopify.com/products/wifi-pineapple) - Integrated device with Jaseger pre-installed

### Authors

* Dino A. Dai Zovi <ddz@theta44.org> (All Things Ruby)
* Shane "K2" Macaulay <ktwo@ktwo.ca> (MADWifi and Samba patches)
