 This scripts is edited under the General Public License as defined by the Free software foundation. 
 This package is distributed in the hope that it will be useful, but without any warranty; It can be used and modified and shared but should be referenced to, it CANNOT be 
 sold or be used for a commercial-economical purpose.
 See the details in the file LICENCE.txt that is situated in the folder of the script or visit http://gplv3.fsf.org/ ) 
 The discovery of One algorithm used in WPSPIN have been made parallely and previously by zhaochunsheng in a C. script named computepinC83A35. as i don't known C or
 programming and found this out after coding the first version of WPS, this bash script doesn't use a dingle line of computepinC83A35.
 But it had to be saved that zhaochunsheng found the main algorithm on Chinese access points months before I found it on a new Belkin N router, without knowing it works.
 The page of the author is sadly down and i cannot link you to a straight source
 This code wouldn't have been possible with the help and advices of antares_145, r00tnuLL and 1camaron1, thanks to them billion a billion time :)  
 It wouldn't have been possible neither without my beloved lampiweb.com work crew, maripuri, bentosouto, dirneet, betis-jesus, compota, errboricobueno, pinty_102 nad all users 
 greetings to crack-wifi.com familly, yasmine, M1ck3y, spawn, goliate, fuji, antares has been already credited, koala, noireaude, vances1, konik etc... and all users
 greetings to auditoriaswireless.net and thanks to the big chief papones for the hosting and greetings to everybody
 This code uses wps reaver that has to be installed on it own, reaver is a free software  "reaver" (GPL2) by Tactical Network Solutions. Thanks to 
 them for this amazing work
 You also need aircrack-ng, thanks to Mister X and kevin devine for providing the best suite ever (http://www.aircrack-ng.org/)
 I would like also to thanks Stefan Viehbock for all is amazing work on wps (http://sviehb.wordpress.com/2011/12/27/wi-fi-protected-setup-pin-brute-force-vulnerability/)  


<h1>HOW TO USE WPSPIN?</h1>

- Unzip the package that you download
   < unzip WPSPIN >



- once situated in the created folder (cd WPSPIN) launch the script with
  < bash WPSPIN.sh >


<h1>REQUIREMENTS</h1>

If you use WPSPIN as a simple generator no requierement. 
If you want to enjoy the scan and attack feature you need:
  - a wireless interface with a chipset compatible with mode monitor
  - aircrack-ng installed in yout system
  - WPS reaver installed

you can visit crack-wifi.com, lampiweb.com and auditroias-wireless.net to get indormattion and help about WPSPIN and others issues like thiese ones 


Just follow the script, it is very simple

<h1>CHANGELOG</h1>

 1.1 (10-12-2012)
	- Support for PIN beginning with one or several 0 thanks to the data of atim and tresal. 
	- New MAC supported : 6A:C0:6F (HG566 default ESSID vodafoneXXXX )
 1.2 (12/12/2012)
	- Fixed output bugs in backtrack and other distributions
	- Added support to the generic default PIN known
 1.3 (23/01/2013)
	- New supported devices:
		- 7 bSSID vodafoneXXXX (HG566a) > 6A:3D:FF / 6A:A8:E4 / 6A:C0:6F / 6A:D1:67 / 72:A8:E4 / 72:3D:FF / 72:53:D4
		- 2 bSSID WLAN_XXXX (PDG-A4001N de adbroadband) > 74:88:8B / A4:52:6F
		- 2 new models affected:
			1) SWL (Samsung Wireless Link), default ESSID SEC_ LinkShare_XXXXXX.  2 known affected BSSID > 80:1F:02 / E4:7C:F9
			2) Conceptronic  c300brs4a  (default ESSID C300BRS4A ) 1 BSSID known  > 00:22:F7   
	- Rules to check the validity of the mac address (thanks r00tnuLL and anteres_145 for your codes) 
	- More filter for some case where several default ssid are possible,check the difference between ssid and bssid for FTE for possibles mismatch...
       - More information displayed when a target is selected
	- Display and colours problems are definitively solved for all distributions, one version
	- Rewriting of code (tanks to r00tnuLL, antares_145, goyfilms and 1camron1 for their advices and feed back)
 1.4 ( 22/05/2013)
      - Complete Rewriting of code to provide new functions:
          - Multi language         
          - A automated mode using wash and reaver 
          - Interfaces management (automatic if only one interface is present, acting as filter if no mode monitor is possible to reduce options) 
          - New supported bssid
              -  2 news bssid for FTE-XXXX (HG532c)   34:6B:D3 and F8:3D:FF 
              -  17 new bssid for vodafone HG566a
               62:23:3D 62:3C:E4 62:3D:FF 62:55:9C 62:7D:5E 62:B6:86 62:C7:14 6A:23:3D 6A:3D:FF 6A:7D:5E 6A:C6:1F 6A:D1:5E 72:3D:FF 72:53:D4 72:55:9C 72:6B:D3  72:A8:E4  
          - New supported devices ( 9 models )    
              -  TP-LINK  >  TD-W8961ND v2.1 default SSID TP-LINK_XXXXXX  3 known bssids ; F8:D1:11 B0:48:7A 64:70:02
              -  EDIMAX  >  3G-6200n and EDIMAX  >  3G-6210n    bssid ; 00:1F:1F defaukt SSID : default
              -  KOZUMI >  K1500 and   K1550  bssid : 00:26:CE 
              -  Zyxel  >  P-870HNU-51B      bssid : FC:F5:28
              -  TP-LINK  TP-LINK_XXXXXX  TL-WA7510N    bssid : 90:F6:52:
              -  SAGEM FAST 1704 > SAGEM_XXXX    bssid :  7C:D3:4C:
              -  Bewan iBox V1.0 > one bssid   00:0C:C3  for two ssids with different defaukt PIN   >   DartyBox_XXX_X and TELE2BOX_XXXX
