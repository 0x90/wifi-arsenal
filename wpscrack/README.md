wpscrack
========
PoC implementation of a brute force attack against WPS - PIN External Registrar

My test environment was Backtrack 5R1 + an Atheros USB adapter.
I used a mac80211/carl9170 driver but any mac80211-based driver should be ok.

Original version: Stefan Viehböck  
Minor improvements: Michael Löffler

Dependencies
------------
* PyCrypto
* Scapy (2.2.0) (does not come with Backtrack)

Usage
-----
    iwconfig mon0 channel X
    ./wpscrack.py --iface mon0 --client 94:0c:6d:88:00:00 --bssid f4:ec:38:cf:00:00 --ssid testap -v

Show further usage parameters:

    ./wpscrack.py --help

References
----------
http://sviehb.wordpress.com/2011/12/27/wi-fi-protected-setup-pin-brute-force-vulnerability/
http://download.microsoft.com/download/a/f/7/af7777e5-7dcd-4800-8a0a-b18336565f5b/WCN-Netspec.doc
http://hostap.epitest.fi/wpa_supplicant/
