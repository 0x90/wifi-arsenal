# wifuzzit
## (a 802.11 wireless fuzzer)

* Written and maintained by Laurent Butti
* Released under terms and conditions of the GNU GPLv3 license

# What is wifuzzit?

Wifuzzit is a wireless fuzzer focused on 802.11 technology. It aims at discovering 802.11 implementation bugs both on access points and stations. It relies on the infamous Sulley Fuzzing Framework and thus is a model-based fuzzer.

Basically, it supports stateful fuzzing which is a strong requirement especially when fuzzing access point implementations.

Wifuzzit is able to operate autonomously and only requires some configuration tuning and minor manual operations to run.

Wifuzzit is the fruit of several generations of wireless fuzzers previously developped that found loads of 802.11 implementation bugs (mainly during 2006-2009). Nowadays, any (r|d)ecent 802.11 implementation should be robust against this fuzzer. Anyway, if you find a vulnerability thanks to this fuzzer, please credit it. 

As far as I know, it is the only Open Source 802.11 wireless fuzzer that supports both AP and STA stateful fuzzing with a model-based approach and which was proven to be successfull.

This fuzzer and its previous generations were able to discover loads of vulnerabilities, some of them were ethically disclosed and thus have a CVE number (see _Discovered Vulnerabilities_ section).

# Requirements and configuration

As wifuzzit relies on [Sulley](https://github.com/OpenRCE/sulley), you have to set up `PYTHONPATH` appropriately to include [Sulley].

You also have to patch Sulley with provided patches.

Two options to operate fuzzing:
* use `fuzz_ap.py` or `fuzz_sta.py` respectively with `ap_settings.py` and `sta_settings.py` configuration files ;
* use `wifuzzit_ap.py` or `wifuzzit_sta.py` (currently not implemented) command-line tools.

Settings and command-line options are quite straightforward.

# Monitor mode

Setting the monitor mode and appropriate channel is left to wifuzzit's user. Wifuzzit should be fully functional on any wireless card with injection capabilities but wifuzzit was only tested with Atheros chipsets (such as the AR5212) and madwifi drivers. You have to set up wireless monitor mode without any preamble headers (radiotap, prism or any other).

For madwifi drivers, this could be set thanks to:

`sysctl -w net.ath0.dev_type=801`

# STA fuzzing: instrumentation

The obvious requirement is that the station must not be associated to any access point. This may be sometimes a tricky part as you must instrument the target (station wireless driver) to initiate active scanning without any association to an Open access point. This could be done thanks to `iwlist iface scan` as a privilieged user. On Windows, using Netstumbler is usually good for that task. On other devices, you could observe the scanning process and tweak the fuzzer configuration to send the fuzzed testcases during a certain timeslot.

As the fuzzer has to be sure that fuzzed packets will be parsed by the wireless driver, the whole fuzzing process may take a lof of time.

# AP fuzzing: instrumentation

No instrumentation is needed here, but as some access points tend to become unstable, they may need a manual reboot. One opportunity is to instrument the access point thanks to an IP power device to be driven by this fuzzer. Remember, a fuzzing campaign must be autonomous!

Comparing to STA fuzzing, time required for a full fuzz testing campaign is quite short (usually several hours), but of course, you have to test several configurations of your access point (open, WPA-PSK, WPA-EAP, RSN-PSK, RSN-EAP) to ensure enough testing coverage.

# Discovered vulnerabilities

Here is a list of wireless implementation bugs discovered by our preliminary versions of wireless fuzzers including wifuzzit. Notably, it found CVE-2006-6059, probably the first (public) remotely exploitable 802.11 wireless driver for Linux (madwifi); and CVE-2007-5651, one of the first (public) EAP-based implementation bug that affected both 802.1X wired and wireless devices. It also discovered a set of wireless driver access point implementation bugs which was quite new in 2007.

* [CVE-2009-0052](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0052): Atheros Driver Reserved Frame Vulnerability (Wireless AP)
* [CVE-2008-4441](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4441): Marvell Driver Malformed Association Request Vulnerability (Wireless AP)
* [CVE-2008-1197](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1197): Marvell Driver Null SSID Association Request Vulnerability (Wireless AP)
* [CVE-2008-1144](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1144): Marvell Driver EAPoL-Key Length Overflow (Wireless AP)
* [CVE-2007-5651](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5651): Extensible Authentication Protocol Vulnerability (Cisco's Wireless AP and Wired Switches)
* [CVE-2007-5475](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5475): Marvell Driver Multiple Information Element Overflows (Wireless AP)
* [CVE-2007-5474](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5474): Atheros Vendor Specific Information Element Overflow (Wireless AP)
* [CVE-2007-0933](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0933): Buffer overflow in the wireless driver 6.0.0.18 for D-Link DWL-G650+ (Wireless STA)
* [CVE-2006-6332](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-6332): Stack-based buffer overflow in net80211/ieee80211_wireless.c in MadWifi before 0.9.2.1 (Wireless STA) - [This bug was proven to be remotely exploitable](http://www.metasploit.com/modules/exploit/linux/madwifi/madwifi_giwscan_cb).
* [CVE-2006-6125](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-6125): Heap-based buffer overflow in the wireless driver (WG311ND5.SYS) 2.3.1.10 for NetGear WG311v1 (Wireless STA)
* [CVE-2006-6059](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-6059): Buffer overflow in MA521nd5.SYS driver 5.148.724.2003 for NetGear MA521 (Wireless STA) 

# Current limitations

This fuzzer does not automagically generate PoC for discovered bugs. You have to instrument Sulley to replay appropriate test case that crashed the wireless driver (AP or STA). In the case of "stateful vulnerabilities", you have to manually pass 802.11 states thanks to a dedicated script that would be re-used for every discovered vulnerability.

Other vulnerabilities are much more tricky to replay, e.g. when a wireless driver becomes unstable after a (particular) ordered set of packets, you then have to manually identify offending packets thanks to a network capture.

# Future improvements

This software is provided as-is and improvements may occur depending on my motivation and spare time. Of course, feedbacks and contributions are welcome.

# References

* Laurent Butti - [Wi-Fi Advanced Fuzzing (Black Hat Europe 2007)](https://www.blackhat.com/presentations/bh-europe-07/Butti/Presentation/bh-eu-07-Butti.pdf)
* Laurent Butti and Julien Tinnès - [Recherche de vulnérabilités dans les drivers 802.11 par techniques de fuzzing (SSTIC 2007)](http://actes.sstic.org/SSTIC07/WiFi_Fuzzing/)
* Laurent Butti and Julien Tinnès - [Discovering and Exploiting Wireless Driver Vulnerabilities](http://www.springerlink.com/content/w423l0q5m04j5225/?MUD=MP)
* Laurent Butti, Julien Tinnès and Franck Veysset - [Wi-Fi Implementation Bugs: an Era of New Vulnerabilities (Hack.LU 2007)](https://www.cr0.org/paper/hacklu2007-final.pdf)
