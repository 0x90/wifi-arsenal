Wireless IDS [Intrusion Detection System] 
=========================================

Wireless IDS is an open source tool written in Python and work on Linux environment. This tool will sniff your surrounding air traffic for suspicious activities such as WEP/WPA/WPS attacking packets. It do the following
* Detect mass deauthentication sent to client / access point which unreasonable amount indicate possible WPA attack for handshakes.
* Continual sending data to access point using broadcast MAC address which indicate a possibility of WEP attacks
* Unreasonable amount of communication between wireless client and access point using EAP authentication which indicate the possibility of WPS bruteforce attack by Reaver / WPSCrack
* Detection of changes in connection to anther access point which may have the possibility of connection to Rogue AP (User needs to assess the situation whether similar AP name)
* Detects possible Rogue Access Point responding to probe by wireless devices in the surrounding.

Newly Added !!!!
======================
* Display similar Access Point's name (SSID) which could have the possibility of WiFi 'Evil Twins'.
* Display of probing SSID by wireless devices
* Detection of Korek Chopchop packets sent by Aircrack-NG (WEP attacks)
* Detection of Fragmentation PRGA packets sent by Aircrack-NG (WEP attacks)
* Detection of possible WPA Downgrade attack by MDK3
* Detection of possible Michael Shutdown exploitation (TKIP) by MDK3
* Detection of Beacon flooding by MDK3
* Detection of possible Authentication DoS by MDK3
* Detection of possible association flooding
* Detection of WPA Migration Attack by Aircrack-NG (WPA Attack)
* Allow logging of events to file.
* Allow disabling of displaying of probing devices
* Setting of scanning count..


Visit and Like [my Facebook Page](https://www.facebook.com/syworks) for other updated information and tools.

Read Wiki for installation and other details (https://github.com/SYWorks/wireless-ids/wiki)

Submit issue [here](https://github.com/SYWorks/wireless-ids/issues)
