--author Roman Joost 
--title PyWifi -- a pythonic WIFI library 
--date 23.09.2005
--newpage
--boldon
--center PyWifi? Was das?
--boldoff
Python Bibliothek um Hardwaredaten des Wireless Treibers auszulesen.

--newpage
--boldon
--center Motivation
externe Programme zu benutzen ist:
---
* fehleranfällig
---
* umständlich
---
* nicht wirklich einfach

--newpage
--boldon
--center PyWifi ist ...
--boldoff
* suuuuper schnell ;)
---
* einfach für den Entwickler zu benutzen
---
* nur unter Linux benutzbar?

--newpage
--boldon
--center Derzeitige Problemchen
--boldoff
* schwierig Treiberwerte zu schreiben
---
* Testen des Programmcodes ist schwierig

--newpage
--center Some "funny" shell tricks
Beispiel um die ESSID auszulesen:
--beginshelloutput
$ python
Python 2.3.5 (#2, Aug 30 2005, 15:50:26)
[GCC 4.0.2 20050821 (prerelease) (Debian 4.0.1-6)] on linux2
Type "help", "copyright", "credits" or "license" for more information.
---
$>>> from pythonwifi.iwlibs import Wireless, getNICnames
---
$>>> getNICnames()
---
['eth1', 'wifi0']
---
$>>> wifi = Wireless('eth1')
---
$>>> wifi.getEssid()
---
'zope'
---
$>>> wifi.getAPaddr()
---
'00:80:C8:15:0C:65'
$>>> wifi.getRTS()
---
'off'
--endshelloutput
