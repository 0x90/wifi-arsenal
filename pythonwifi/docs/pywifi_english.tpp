--author Róman Joost 
--title PyWifi -- a Pythonic WIFI Library 
--date 27.12.2005
--newpage
--boldon
--center PyWifi? Whats that?
--boldoff
A python library to access wireless data directly by using the driver.

--newpage
--boldon
--center Motivation
calling external programs is:
---
* errorprone
---
* cumbersome
---
* not really easy 

--newpage
--boldon
--center PyWifi is...
--boldoff
* blazingly fast ;)
---
* easy to use for developers
---
* currently only usable under GNU/Linux

--newpage
--boldon
--center Problems
--boldoff
* not easy to figure how to set driver data
---
* writing tests 

--newpage
--center Example to get information about the current set ESSID
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
'22C3_DHCP'
---
$>>> wifi.getAPaddr()
---
'00:0B:86:A9:F4:21'
$>>> wifi.getRTS()
---
'off'
--endshelloutput
