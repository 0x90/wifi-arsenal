Offline bruteforce attack on WiFi Protected Setup 
===========

+ PoC for routers vulnerable with WPS and deficiencies in their PRNG state.
+ This code HAS NOT BEEN TESTED!! 

References
----

* [0] http://archive.hack.lu/2014/Hacklu2014_offline_bruteforce_attack_on_wps.pdf
* [1] https://forums.kali.org/showthread.php?24286-WPS-Pixie-Dust-Attack-%28Offline-WPS-Attack%29/page5
* [2] https://github.com/ml31415/wpscrack

* Bully, Reaver and Stefan Viehböck


Contact
----

Coder  : Eduardo Novella    Twitter : [@enovella_](https://twitter.com/enovella_)    
Website: (http://ednolo.alumnos.upv.es/)


Changelog
---------
- 1.0   [2015-3-22] First version just for Ralink routers with ES1=ES2=0


Licence
----
GPLv3
http://gplv3.fsf.org/

More info
----

+ http://ednolo.alumnos.upv.es

Usage
----
Help:
	wpscrack_mod:$ python wpscrack.py -h
	WARNING: No route found for IPv6 destination :: (no default route?)
	Usage: wpscrack.py --iface=IFACE --client=CLIENT_MAC --bssid=BSSID --ssid=SSID [optional arguments]

	Options:
	  -h, --help            show this help message and exit
	  -i IFACE, --iface=IFACE
	                        network interface (monitor mode)
	  -c CLIENT_MAC, --client=CLIENT_MAC
	                        MAC of client interface
	  -b BSSID, --bssid=BSSID
	                        MAC of AP (BSSID)
	  -s SSID, --ssid=SSID  SSID of AP (ESSID)
	  --dh=DH_SECRET        diffie-hellman secret number
	  -t TIMEOUT, --timeout=TIMEOUT
	                        timemout in seconds
	  -p START_PIN, --pin=START_PIN
	                        start pin for brute force
	  -v, --verbose         verbose
	  -o, --offline         Offline bruteforce. Pixie Dust Attack


Running:

	wpscrack_mod:$ sudo python wpscrack.py -i mon0 -b [BSSID] -s [ESSID] --offline -vv


