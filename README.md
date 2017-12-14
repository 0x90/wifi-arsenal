# WiFi Arsenal

Repo fully maintained by [0x90/wifi-arsenal](https://github.com/0x90/wifi-arsenal)

README.md created by [techge/wifi-arsenal](https://github.com/techge/wifi-arsenal)

## Table of Contents

* [General WiFi Information](#general-wifi-information)
* [Noteworthy Tools of Different Categories](#noteworthy-tools-of-different-categories)
* [Attack/PenTesting](#attackpentesting)
  * [Denial of Service](#denial-of-service)
  * [Encryption Attack](#encryption-attack)
    * [WEP/WPA/WPA2](#wepwpawpa2)
    * [WPS](#wps)
    * [Others](#others)
  * [Injection](#injection)
  * [Rogue AP/Fake AP/ MITM](#rogue-apfake-ap-mitm)
  * [Sniffing](#sniffing)
  * [Wardriving](#wardriving)
  * [Miscellaneous Attacking Tools](#miscellaneous-attacking-tools)
* [Information Gathering](#information-gathering)
* [Defence/Detection](#defencedetection)
* [Libraries/General Purpose Tools](#librariesgeneral-purpose-tools)
* [Visualization](#visualization)
* [Localisation](#localisation)
* [Configuration/setup](#configurationsetup)
* [Monitoring](#monitoring)
* [Miscellaneous/not sorted :)](#miscellaneousnot-sorted-)

TOC created by [gh-md-toc](https://github.com/ekalinin/github-markdown-toc)
## General WiFi Information
* [802.11 frames](https://supportforums.cisco.com/t5/wireless-mobility-documents/802-11-frames-a-starter-guide-to-learn-wireless-sniffer-traces/ta-p/3110019/) - A starter guide to learn wireless sniffer traces
* [80211 Pocket Reference Guide](http://www.willhackforsushi.com/papers/80211_Pocket_Reference_Guide.pdf) - Cheat Sheet for 802.11
* [802.11p-wireless-regdb ](https://github.com/CTU-IIG/802.11p-wireless-regdb/) - Wireless regulatory database for CRDA 
* [802.11 Wireless Networks: The Definitive Guide](http://my.safaribooksonline.com/book/networking/wireless/0596001835/802dot11-framing-in-detail/wireless802dot11-chp-4-sect-3/) - Partly open chapters of O‘Reilly 802.11 book
* [Armory](https://github.com/justinbeatz/Armory/) - The 802.11 Hacking Repo (Meta Information, Link collection)
* [Awesome-wifi-security](https://github.com/edelahozuah/awesome-wifi-security/) - A collection of awesome resources related to 802.11 security, tools and other things
* [Call-for-wpa3](https://github.com/d33tah/call-for-wpa3/) - Call for WPA3 - what's wrong with WPA2 security and how to fix it
* [Known manufacturer MAC list](https://code.wireshark.org/review/gitweb?p=wireshark.git&a=blob_plain&f=manuf) - 
* [Wikipedia](https://en.wikipedia.org/wiki/IEEE_802.11) - IEEE802.11 site of Wikipedia
## Noteworthy Tools of Different Categories
* [Aircrack-ng](https://github.com/aircrack-ng/aircrack-ng/) - WiFi security auditing tools suite
* [airgeddon](https://github.com/v1s1t0r1sh3r3/airgeddon/) - This is a multi-use bash script for Linux systems to audit wireless networks
* [karma](https://github.com/atimorin/karma/) - KARMA Attacks Radioed Machines Automatically (KARMA)
* [kismet](https://github.com/kismetwireless/kismet/) - Wireless network detector, sniffer, and intrusion detection system
* [mdk3_6.1](https://github.com/ytisf/mdk3_6.1/) - A fork and modification of the original MDK3 
* [pyrit](https://github.com/JPaulMora/Pyrit/) - The famous WPA precomputed cracker, Migrated from Google
* [Scapy](https://github.com/secdev/scapy) - Python-based interactive packet manipulation program & library
* [waidps](https://github.com/SYWorks/waidps/) - Wireless Auditing, Intrusion Detection & Prevention System
* [WiFi-Pumpkin](https://github.com/P0cL4bs/WiFi-Pumpkin/) - Framework for Rogue Wi-Fi Access Point Attack
* [Wireless-ids](https://github.com/SYWorks/wireless-ids/) - Ability to detect suspicious activity such as (WEP/WPA/WPS) attack by sniffing the air for wireless packets
* [zarp](https://github.com/hatRiot/zarp/) - Network attack tool centered around the exploitation of local networks
## Attack/PenTesting
### Denial of Service
* [80211mgmtDoS](https://github.com/phildom/80211mgmtDoS/) - 802.11 DoS Attacks based on unprotected Management frames
* [airodump_mod](https://github.com/maroviher/airodump_mod/) - Improved version of airodump-ng with ability to kick-off a stations from AP
* [android_packetspammer](https://github.com/bcopeland/android_packetspammer/) - Packetspammer sends unencrypted broadcast packets down a mac80211 wireless interface that should be set for Monitor mode
* [apflood](https://github.com/d4rkcat/apflood/) - Flood area with fake essids
* [dw](https://github.com/ndyakov/dw/) - Small tool for sending 802.11 disassociation and deauthentication packets to specific clients. 
* [hwk](https://github.com/0x90/wifi-arsenal/tree/master/hwk/) - Hwk is a collection of packet crafting/network flooding tools
* [JamWiFi](https://github.com/unixpickle/JamWiFi/) - A GUI, easy to use WiFi network jammer for Mac OS X
* [Mass-deauth-attack](https://github.com/shunghsiyu/mass-deauth-attack/) - A program that does Deauthentication Attack on every nearby wireless device
* [Mass-deauth](https://github.com/Andy-Maclachlan/mass-deauth/) - A script for 802.11 mass-deauthentication
* [mdk3_6.1](https://github.com/ytisf/mdk3_6.1/) - A fork and modification of the original MDK3 
* [modwifi](https://github.com/vanhoefm/modwifi/) - Advanced Wi-Fi Attacks Using Commodity Hardware
* [netattack](https://github.com/chrizator/netattack/) - Python script that allows you to scan your local area for WiFi Networks and perform deauthentification attacks
* [Scapy-deauth](https://github.com/catalyst256/MyJunk/blob/master/scapy-deauth.py/) - Scapy based wifi Deauth
* [ska](https://github.com/0x90/wifi-arsenal/tree/master/ska/) - Framework for sniffing ieee80211 packets and generating deauth packets and sending raw packets.
* [wificurse](https://github.com/0x90/wifi-arsenal/tree/master/wificurse/) - WiFi DoS attack tool created for educational purposes only. It works only in Linux and requires wireless card drivers capable of injecting packets in wireless networks
* [WifiDeauth](https://github.com/Revimal/WifiDeauth/) - A lightweight Wi-Fi auto deauthentication attack tool (libtins/C++)
* [wifijammer](https://github.com/DanMcInerney/wifijammer/) - Continuously jam all wifi clients/routers
* [WiFi-Rifle](https://github.com/sensepost/WiFi-Rifle/) - Creating a wireless rifle de-authentication gun, which utilized a yagi antenna and a Raspberry Pi
* [wirelessjammer](https://github.com/phr34k0/wirelessjammer/) - Continuously jam all wifi clients and access points within range
* [zizzania](https://github.com/cyrus-and/zizzania/) - Automated DeAuth attack
### Encryption Attack
#### WEP/WPA/WPA2
* [Eicrog](https://github.com/nosmo/Eircog/) - WEP key generator for predictable key weaknesses
* [huawei_wifi](https://github.com/davux/huawei_wifi/) - Wifi utilities for finding Huawei routers' default key
* [Aircrack-ng](https://github.com/aircrack-ng/aircrack-ng/) - WiFi security auditing tools suite
* [airmode](https://github.com/parrotsec/airmode/) - AirMode is a GUI that can help you to use the Aircrack framework
* [airoscriptng](https://github.com/wi-fi-analyzer/airoscriptng/) - Airoscript-ng python complete implementation
* [Airvengers](https://github.com/hiteshchoudhary/Airvengers/) - A GUI to pentest wifi Network, based on Aircrack-ng tools
* [asleap](https://github.com/0x90/wifi-arsenal/tree/master/asleap/) - Recovers weak LEAP password.  Pronounced asleep.
* [autokwaker](https://github.com/pasdesignal/autokwaker/) - Creating an auto cracker for 802.11 networks
* [cenarius](https://github.com/adelashraf/cenarius/) - Cenarius tool for crack Wi-Fi , crack wpa-psk , crack wpa2-psk , crack wep , crack wps pin and crack hidden AP . cenarius psk crack
* [cherry](https://github.com/axilirator/cherry/) - Distributed WPA/WPA2 cracker
* [Cowpatty](http://www.willhackforsushi.com/?page_id=50/) - Offline dictionary attack against WPA/WPA2 networks using PSK-based authentication (e.g. WPA-Personal)
* [dot11decrypt](https://github.com/mfontanini/dot11decrypt/) - An 802.11 WEP/WPA2 on-the-fly decrypter. 
* [Fern-wifi-cracker](https://github.com/savio-code/fern-wifi-cracker/) - Crack and recover WEP/WPA/WPS keys and also run other network based attacks on wireless or ethernet based networks
* [HandShaker](https://github.com/d4rkcat/HandShaker/) - Detect, capture, crack WPA/2 handshakes, WEP Keys and geotag with Android GPS
* [hcxtools](https://github.com/ZerBea/hcxtools/) - Solution for capturing wlan traffic and conversion to hashcat formats (recommended by hashcat) and to John the Ripper
* [kismet-deauth-wpa2-handshake-plugin](https://github.com/ph4r05/kismet-deauth-wpa2-handshake-plugin/) - Python plugin for Kismet to perform deauthentication to collect WPA2 handshakes
* [marfil](https://github.com/pupi1985/marfil/) - Assess WiFi network security. It allows to split the work of performing long running dictionary attacks among many computers
* [peapwn](https://github.com/rpp0/peapwn/) - Proof-of-concept implementation of the Apple relay attack in Python 
* [pyrcrack](https://github.com/XayOn/pyrcrack/) - Python Aircrack-ng
* [pyrit](https://github.com/JPaulMora/Pyrit/) - The famous WPA precomputed cracker, Migrated from Google
* [pythonAir](https://github.com/Slickness/pythonAir/) - Flask/aircrack
* [uploadwpa](https://github.com/Alf-Alfa/uploadwpa/) - This module will upload a wpa handshake from a single capture file to an online hash cracker site
* [WiFi-autopwner](https://github.com/Mi-Al/WiFi-autopwner/) - Script to automate searching and auditing Wi-Fi networks with weak security
* [Wifi-bruteforcer-fsecurify](https://github.com/faizann24/wifi-bruteforcer-fsecurify/) - Android application to brute force WiFi passwords without requiring a rooted device
* [wificracking](https://github.com/brannondorsey/wifi-cracking/) - Crack WPA/WPA2 Wi-Fi Routers with Airodump-ng and Aircrack-ng/Hashcat
* [Wifi-hacker](https://github.com/esc0rtd3w/wifi-hacker/) - Shell Script For Attacking Wireless Connections Using Built-In Kali Tools. Supports All Securities (WEP, WPS, WPA, WPA2) 
* [wifite2](https://github.com/derv82/wifite2/) - Python script for auditing wireless networks
* [wifite](https://github.com/derv82/wifite/) - An automated wireless attack tool
* [Wifite-mod-pixiewps](https://github.com/aanarchyy/wifite-mod-pixiewps/) - Wifite with PixieWPS support
* [Wifite-openwrt](https://github.com/kbeflo/wifite-openwrt/) - Wifite for the WiFi Pineapple NANO + TETRA (Chaos Calmer - openWrt) 
* [wlandecrypter](https://github.com/wi-fi-analyzer/wlandecrypter/) - Dictionary attack (spanish)
* [WPA2-HalfHandshake-Crack](https://github.com/dxa4481/WPA2-HalfHandshake-Crack/) - Capture enough of a handshake with a user from a fake AP to crack a WPA2 network without knowing the passphrase of the actual AP
* [wpa2hc](https://github.com/historypeats/wpa2hc/) - Quick script to automate converting WPA .cap files for Hashcat .hccap files. 
* [Wpa-autopwn](https://github.com/vnik5287/wpa-autopwn/) - WPA/WPA2 autopwn script that parses captured handshakes and sends them to the Crackq
* [Wpa-bruteforcer](https://github.com/SYWorks/wpa-bruteforcer/) - Attacking WPA/WPA encrypted access point without client. 
* [wpacrack](https://github.com/derv82/wpacrack/) - Open-source distributed Wifi-Protected Access (WPA) cracker
* [WPA_DECRYPTION_MPI](https://github.com/shagrath89m/WPA_DECRYPTION_MPI/) - WPA/WPA2 for cluster processing
* [WPAdiz](https://github.com/leminski/WPAdiz/) - Bruteforce - New method for generate dictionaries (Wireless)
#### WPS
* [autoreaver](https://github.com/0x90/auto-reaver/) - Automatically exported from code.google.com/p/auto-reaver
* [bully](https://github.com/aanarchyy/bully/) - New implementation of the WPS brute force attack, written in C
* [greaver](https://github.com/sigginet/greaver/) - GUI for Reaver, WPS brute force tool
* [HT-WPS-Breaker](https://github.com/SilentGhostX/HT-WPS-Breaker/) - HT-WPS Breaker (High Touch WPS Breaker)
* [Penetrators-wps](https://github.com/dadas190/penetrator-wps/) - Experimental tool that is capable of attacking multiple WPS-enabled wireless access points in real time.
* [phpreaver](https://github.com/phpreaver/phpreaver/) - A command line PHP script which uses the reaver WPS pin cracker to test multiple AP's with multiple WiFi adapters.
* [Pixiewps-android](https://github.com/ru-faraon/pixiewps-android/) - Pixiewps is a tool written in C used to bruteforce offline the WPS pin exploiting the low or non-existing entropy of some APs (pixie dust attack).
* [pixiewps](https://github.com/wiire-a/pixiewps/) - An offline WPS brute-force utility 
* [pyReaver](https://github.com/byt3bl33d3r/pyReaver/) - WPS attack tool written in Python
* [pyxiewps_WPShack-Python](https://github.com/jgilhutton/pyxiewps_WPShack-Python/) - Wireless attack tool written in python that uses reaver, pixiewps and aircrack to retrieve the WPS pin of any vulnerable AP in seconds
* [reaver_reattempt](https://github.com/kurobeats/reaver_reattempt/) - Change the Mac address of the wifi connection as well as the emulated one created by airmon-ng in an attempt to avoid being locked out of routers for repeated WPS attack attempts
* [Reaver-ui](https://github.com/deoxxa/reaver-ui/) - Hacky UI to wrap around reaver-wps 
* [Reaver-webui](https://github.com/fopina/reaver-webui/) - Simple WebUI to crack wireless networks using reaver
* [Reaver-wps-fork-t6x](https://github.com/t6x/reaver-wps-fork-t6x/) - Community forked version which includes various bug fixes, new features and additional attack method (such as the offline Pixie Dust attack)
* [Reaver-wps](https://github.com/gabrielrcouto/reaver-wps/) - Brute force attack against Wifi Protected Setup 
* [wpscrack](https://github.com/ml31415/wpscrack/) - Continuation of wpscrack originally written by Stefan Viehböck
* [wps](https://github.com/devttys0/wps/) - WPS related utilities 
* [WPSIG](https://www.coresecurity.com/corelabs-research/open-source-tools/wpsig) - Simple tool (written in Python) that does information gathering using WPS information elements.
* [wpsoffline](https://bitbucket.org/dudux/wpsoffline/) - PoC for routers vulnerable with WPS and deficiencies in their PRNG state
* [Wps-scripts](https://github.com/0x90/wps-scripts/) - WPS hacking scripts
* [Wps-Ultimate-Cracker](https://github.com/younextvictim/Wps-Ultimate-Cracker/) - This script will help help you to get the most of router in morocco by using pixiewps , reaver , aircrack-ng ,wifite 
#### Others
* [apbleed](https://github.com/vanhoefm/apbleed/) - Allows you to use existing heartbleed tools to test the RADIUS server
* [eapmd5pass](http://www.willhackforsushi.com/?page_id=67) - An implementation of an offline dictionary attack against the EAP-MD5 protocol. This utility can be used to audit passwords used for EAP-MD5 networks from wireless packet captures, or by manually specifying the challenge, response and associated authentication information.
* [haircrack](https://github.com/AdamKnube/haircrack/) - Automated aircrack/reaver/pyrit (An interface for aircrack/reaver/pyrit written in python. The interface itself may never get finished.)
* [IKECrack](http://ikecrack.sourceforge.net/) - IKE/IPSec authentication crack tool. This tool is designed to bruteforce or dictionary attack the key/password used with Pre-Shared-Key [PSK] IKE authentication.
* [Wpe-parse](https://github.com/sa7mon/wpe-parse/) - This is a simple parsing script to convert output from hostapd-wpe (which makes John the Ripper-formatted logs) to Hashcat format. 
### Injection
* [Aggr-inject](https://github.com/rpp0/aggr-inject/) - Remote frame injection PoC by exploiting a standard compliant A-MPDU aggregation vulnerability in 802.11n networks. 
* [Aircrack-db](https://github.com/SaltwaterC/aircrack-db/) - A list of wireless cards tested with the dual-card injection test and in the field
* [airown](https://github.com/sh0/airown/) - Packet injection tool
* [airpwn](https://github.com/M0Rf30/airpwn/) - A generic packet injection tool for 802.11 networks.
* [Airpwn-ng](https://github.com/ICSec/airpwn-ng/) - New and improved version of airpwn
* [Iitis-generator](https://github.com/iitis/iitis-generator/) - Software for distributed statistical evaluation of IEEE 802.11 wireless networks using Linux mac80211 packet injection facility
* [libfcap](https://github.com/teddyyy/libfcap/) - Library for manipulate 802.11 frame in monitor mode
* [libmoep](https://github.com/0x90/wifi-arsenal/tree/master/libmoep-1.1/) - Allows for frame injection on monitor mode devices with per-frame radiotap options such as TX rate / MCS index and RTS/CTS protection
* [Lorcon-examples](https://github.com/OpenSecurityResearch/lorcon_examples/) - Various examples and patches for LORCON
* [lorcon](https://code.google.com/archive/p/lorcon/) - A common injection and control library for wireless packet crafting
* [lrc](https://github.com/0x0d/lrc/) - Fast Wi-Fi hijacker in C, based on AirPwn ideas and LORCON
* [moepdefend](https://github.com/moepinet/moepdefend/) - Example monitoring/injection tool based on libmoep
* [packetinjector](https://github.com/juzna/packet-injector/) - Packet analyzer and injector, written in JavaScript
* [packetvector](https://github.com/derosier/packetvector/) - 802.11 management packet injection tool based on packetspammer
* [pylorcon2](https://github.com/tom5760/pylorcon2/) - Pure Python wrapper for the LORCON library. 
* [wifitap](https://github.com/viscousliquid/wifitap/) - WiFi injection tool through tun/tap device
* [wiwo](https://github.com/CoreSecurity/wiwo/) - Wiwo is a distributed 802.11 monitoring and injecting system that was designed to be simple and scalable
* [wperf](https://github.com/anyfi/wperf/) - 802.11 frame injection/reception tool for Linux mac80211 stack
### Rogue AP/Fake AP/ MITM
* [Aerial](https://github.com/Nick-the-Greek/Aerial/) - Multi-mode wireless LAN Based on a Software Access point for Kali Linux.
* [AIRBASE-NG-SSLSTRIP-AIRSTRIP- ](https://github.com/MrMugiwara/AIRBASE-NG-SSLSTRIP-AIRSTRIP-/) - AIRBASE-NG + SSLSTRIP = AIRSTRIP
* [cupid](https://github.com/lgrangeia/cupid/) - Patch for hostapd and wpa_supplicant to attempt to exploit heartbleed on EAP-PEAP/TLS/TTLS connections
* [FakeAP](https://github.com/DanMcInerney/fakeAP/) - Create fake AP in Kali with 1 command 
* [fakeaps](https://github.com/0x90/wifi-arsenal/blob/master/fakeaps.c/) - Fake Access Points using Atheros wireless cards in Linux
* [fluxion](https://github.com/FluxionNetwork/fluxion/) - Fluxion is the future of MITM WPA attacks
* [FuzzAP](https://github.com/lostincynicism/FuzzAP/) - A python script for obfuscating wireless networks
* [Hostapd-karma](https://github.com/xtr4nge/hostapd-karma/) - DigiNinja patches to hostapd for rogue access points. 
* [Hostapd-wpe-extended](https://github.com/NerdyProjects/hostapd-wpe-extended/) - Modification and tools for using hostapd for rogue AP attacks impersonating WPA-Enterprise networks to steal user credentials
* [Hostapd-wpe](https://github.com/OpenSecurityResearch/hostapd-wpe/) - Modified hostapd to facilitate AP impersonation attacks 
* [karma](https://github.com/atimorin/karma/) - KARMA Attacks Radioed Machines Automatically (KARMA)
* [mana](https://github.com/sensepost/mana/) - Our mana toolkit for wifi rogue AP attacks and MitM 
* [mitmAP](https://github.com/xdavidhu/mitmAP/) - A python program to create a fake AP and sniff data
* [Mitm-helper-wifi](https://github.com/jakev/mitm-helper-wifi/) - Make it easy and straight-forward to configure a Ubuntu virtual machine to act as a WiFi access point (AP)
* [Mitm-rogue-WiFi-AP](https://github.com/wshen0123/mitm-rogue-WiFi-AP/) - MITM Attack Example Code with Rogue Wi-Fi AP
* [openrtls](https://github.com/konker/openrtls/) - 
* [Platform-hostapd](https://github.com/experimental-platform/platform-hostapd/) - Wireless access point for experimental-platform. 
* [PwnSTAR](https://github.com/SilverFoxx/PwnSTAR/) - PwnSTAR (Pwn SofT-Ap scRipt) - for all your fake-AP needs
* [rogue_ap](https://github.com/andrew14824/rogue_ap/) - RogueAP_hostapd.py is a script designed to create a Rogue Access Point
* [rogueap](https://github.com/wouter-glasswall/rogueap/) - Start a rogue access point with no effort, with support for hostapd, airbase, sslstrip, sslsplit, tcpdump builtin
* [rogueDetect](https://github.com/olanb7/rogueDetect/) - 
* [RogueSploit](https://github.com/H0nus/RogueSploit/) - Powerfull Wi-Fi trap
* [Rspoof](https://github.com/zackiles/Rspoof/) - Wifi Automated Fake HotSpot Hijacking with aicrack-ng, airbase, ssl-strip, and dns spoof in Python
* [Scapy-fakeap](https://github.com/rpp0/scapy-fakeap/) - Fake wireless Access Point (AP) implementation using Python and Scapy
* [snifflab](https://github.com/andrewhilts/snifflab/) - Scripts to create your own MITM'ing, packet sniffing WiFi access point 
* [startools](https://github.com/sa7mon/startools/) - To use a RasPi to do an Evil Twin attack and capture 802.1x RADIUS creds
* [wifi_honey](https://github.com/0x90/wifi-arsenal/tree/master/wifi_honey/) - Setting up four fake access points, each with a different type of encryption, None, WEP, WPA and WPA2 and the seeing which of the four the client connects to
* [wifiphisher](https://github.com/wifiphisher/wifiphisher/) - Automated victim-customized phishing attacks against Wi-Fi clients
* [WiFi-Pumpkin](https://github.com/P0cL4bs/WiFi-Pumpkin/) - Framework for Rogue Wi-Fi Access Point Attack
* [wifisoftap](https://github.com/coolshou/wifisoftap/) - 
* [Wifi_Trojans](https://github.com/ahhh/Wifi_Trojans/) - Collection of wireless based bind and reverse connect shells for penetration testers
### Sniffing
* [Airodump-iv](https://github.com/ivanlei/airodump-iv/) - A python implementation of airodump-ng
* [Airodump-logger](https://github.com/atiti/airodump-logger/) - Logging clients with airodump-ng
* [Airport-sniffer](https://github.com/zhovner/airport-sniffer/) - Very simple Wi-Fi sniffer and dump parser for built-in macbook AirPort Extreme card. Only native MacOS tools used. 
* [airtraf](https://github.com/saintkepha/airtraf/) - Wireless 802.11 network sniffer and analyzer
* [darm](https://github.com/eldraco/darm/) - Intelligent network sniffer for the masses
* [datasamalen](https://github.com/4ZM/datasamalen/) - Pick up wifi-probe requests
* [DeSniffer](https://github.com/wirelesshack/DeSniffer/) - 802.11 wireless sniffer
* [dot11sniffer](https://github.com/DepthDeluxe/dot11sniffer/) - Sniffs 802.11 traffic and counts the number of active wireless devices in an area
* [eap_detect](https://github.com/rafikMeg/eap_detect/) - A simple script using the python library Scapy to detect the 802.1X authentication mechanism
* [handshakeharvest](https://github.com/0x90/wifi-arsenal/blob/master/handshakeharvest-K1-K2-K2016-4-0.sh/) - 
* [liber80211](https://github.com/brycethomas/liber80211/) - 802.11 monitor mode for Android without root
* [libpcap-80211-c](https://github.com/weaknetlabs/libpcap-80211-c/) - Sniffs on a RFMON-enabled device for a beacon when compiled, linked and loaded
* [mac80211-user](https://github.com/chillancezen/mac80211-user/) - Intercept 80211 data frame and put it into userspace
* [milicone](https://github.com/jazoza/milicone/) - Investigating interaction with wireless communication traffic
* [Mr-nosy](https://github.com/jgumbley/mr-nosy/) - Liked to know about everything that was going on
* [mupe](https://github.com/DE-IBH/mupe/) - MUltiPath Estimator - Create statistical analysis of 802.11 Radiotap sniffs
* [Naive-project](https://github.com/veenfang/naive_project/) - 
* [Native-WiFi-API-Beacon-Sniffer ](https://github.com/6e726d/Native-WiFi-API-Beacon-Sniffer/) - Tool that dumps beacon frames to a pcap file. Works on Windows Vista or Later with any Wireless Card
* [oculus](https://github.com/abnarain/oculus/) - Lightweight tool to collect traces from wifi
* [ofxSniffer](https://github.com/HalfdanJ/ofxSniffer/) - Wrapper for the libtins library. Libtins can be used to sniff network packages, or to generate network pacakages yourself.
* [phystats](https://github.com/ransford/phystats/) - Gather & plot ieee80211 counters from Linux debugfs
* [probecap](https://github.com/hydrogen18/probecap/) - A quick and dirty utility to capture and store WiFi probes.
* [probemon](https://github.com/jjb3tee3/probemon/) - Monitors 802.11 probe packets sent from roaming mobile devices. Developed using PyLorcon2. 
* [probesniffer](https://github.com/xdavidhu/probeSniffer/) - A tool for sniffing unencrypted wireless probe requests from devices
* [rifsniff](https://github.com/dappiu/rifsniff/) - Remote Interface Sniffer
* [ScapyGELFtoGraylog2](https://github.com/wouterbudding/ScapyGELFtoGraylog2/) - Sniff some 802.11 packages and send the date and MAC with GELF UDP to Graylog2
* [Scapy-wireless-scanner](https://github.com/rahilsharma/Scapy-wireless-scanner/) - Simple wireless scanner built using Scapy Library
* [SSIDentity](https://github.com/SamClarke2012/SSIDentity/) - Passive sniffing of 802.11 probe requests, stored in a central database.
* [TCP-SeqNum](https://github.com/bwoolf1122/TCP-SeqNum/) - Means to sniff 802.11 traffic and obtain TCP session info using netfiter_queue. Use that data to construct a packet in scappy. 
* [wallofshame](https://github.com/0x0d/wallofshame/) - Multi protocol sniffer, created for ChaosConstruction conference HackSpace
* [Watcher](https://github.com/catalyst256/Watcher/) - Canari framework based Maltego transform pack that allows you to perform wireless sniffing within Maltego
* [WiFi-802.11-Demo-Sniffer](https://github.com/dcrisan/WiFi-802.11-Demo-Sniffer/) - This 802.11 sniffer written in Python provides a useful tool to raise awareness at the amount of data phones release for anyone to read. 
* [Wifi-harvester](https://github.com/SYWorks/wifi-harvester/) - For collecting probed SSID name by wireless devices, Access point detail and connected clients.
* [wifijamMac](https://github.com/rajkotraja/wifiJamMac/) - Allows you to select one or more nearby wireless networks, thereupon presenting a list of clients which are currently active on the network(s)
* [Wifimon](https://github.com/Wifimon/Wifimon/) - Wi-fi 802.11 Beacon Frame sniffer
* [Wifi-scan](https://bitbucket.org/edkeeble/wifi-scan/) - Short python script scans for probe requests from whitelisted WiFi clients
* [wifispy](https://github.com/Geovation/wifispy/) - Sniff Wifi traffic, log device addresses
* [Wireless-info](https://github.com/wlanslovenija/wireless-info/) - Obtain information about wireless interfaces from MAC80211 stack
* [Wireless-radar](https://github.com/stef/wireless-radar/) - DF and other tools to explore a 2.4GHz environment
* [Wireless-Sniffer](https://github.com/gauravpatwardhan/Wireless-Sniffer/) - A 802.11 wireless sniffer tool (c-based)
### Wardriving
* [MappingWirelessNetworks](https://github.com/jeffThompson/MappingWirelessNetworks/) - Code, data, and (possibly) schematics for recording wireless network data around a city
* [WAPMap](https://github.com/pan0pt1c0n/WAPMap/) - Parse Kismet .netxml output and then return a CSV file that can be uploaded to Google Maps Engine to map WEP or OPEN networks
* [warcarrier](https://github.com/0x90/warcarrier/) - An NCURSES-based, all-in-one instrument panel for professional Wardriving
* [WifiScanAndMap](https://github.com/cyberpython/WifiScanAndMap/) - A Linux Python application to create maps of 802.11 networks
### Miscellaneous Attacking Tools
* [80211scrambler](https://github.com/travisgoodspeed/80211scrambler/) - Small collection of tools in Verilog for working
* [airgeddon](https://github.com/v1s1t0r1sh3r3/airgeddon/) - This is a multi-use bash script for Linux systems to audit wireless networks
* [airodump_mar_attack](https://github.com/maroviher/airodump_mar_attack/) - Maroviher attack
* [AirPirate](https://github.com/gat3way/AirPirate/) - Android 802.11 pentesting tool 
* [airspf](https://github.com/davll/airspf/) - AirSpoof/Airpwn ??
* [airxploit](https://github.com/balle/airxploit/) - Wireless discovery and exploitation framework written in Python
* [AtEar](https://github.com/NORMA-Inc/AtEar/) - Wireless Hacking, WiFi Security, Vulnerability Analyzer, Pentestration
* [BoopSuite](https://github.com/MisterBianco/BoopSuite/) - A Suite of Tools written in Python for wireless auditing and security testing.
* [chap2aleap](https://github.com/xiao106347/chap2asleap/) - Work with asleap+genk
* [CloudCrackInstaller](https://github.com/tjetzinger/CloudCrackInstaller/) - Script which installs Crunch, Pyrit and Cowpatty on a running Amazon EC2 Cluster GPU Instance to crack WPA and WPA2 keys.
* [Crippled](https://github.com/Konsole512/Crippled/) - WPA/WPA2 Belkin.XXXX, Belkin_XXXXXX, belkin.xxx and belkin.xxxx router default key generator.
* [eapeak](https://github.com/securestate/eapeak/) - Analysis Suite For EAP Enabled Wireless Networks
* [Easy-creds](https://github.com/brav0hax/easy-creds/) - Leverages tools for stealing credentials during a pen test
* [FruityWiFi](https://github.com/xtr4nge/FruityWifi/) - Wireless network auditing tool
* [Hijacker](https://github.com/chrisk44/Hijacker/) - Aircrack, Airodump, Aireplay, MDK3 and Reaver GUI Application for Android
* [killosx](https://github.com/d4rkcat/killosx/) - Use the Apple CoreText exploit (CVE-2012-3716) and launch an AP to affect all devices within wifi range 
* [LANs.py](https://github.com/DanMcInerney/LANs.py/) - Inject code, jam wifi, and spy on wifi users
* [Null-packet-wifi-promt](https://bitbucket.org/edkeeble/null-packet-wifi-prompt/) - Simple script to prompt responses from wireless devices with a known MAC address
* [PiWAT](https://github.com/Crypt0s/PiWAT/) - Wireless Attack Toolkit
* [Python-wireless-attacks](https://github.com/jordan-wright/python-wireless-attacks/) - Wireless Attacks in Python (Based on blog series)
* [Secpi](https://github.com/nrohsak/Secpi/) - Python based script for wifi pentesting on the RasPi
* [Sly-fi](https://github.com/sinistermachine/sly-fi/) - Wifi pwnage automation
* [smoothie](https://github.com/XayOn/smoothie/) - Web based wireless auditory tools
* [WHAT-PRO](https://github.com/smoz1986/WHAT-PRO/) - 802.11 Exploitation Tool for use with Kali 2. More tools available than WHAT or WHAT Pi 
* [Wi-door](https://github.com/Vivek-Ramachandran/wi-door/) - Wi-Fi Backdoors
* [WIDSTT](https://github.com/0x90/wifi-arsenal/blob/master/Wireless%20IDS%20Tool.py/) - Wireless Intrusion Detection Systems Testing Tool – test your WIDS by performing attacks
* [WifiAttack](https://github.com/AbbySec/WifiAttack/) - 
* [wifi-default-password](https://bitbucket.org/jpgerek/wifi-default-password/) - Bash script that tries all the default passwords for a particular wifi access point
* [wifimonster](https://github.com/flankerhqd/wifimonster/) - Wifi sniffing and hijacking tool
* [wifuzz](https://github.com/0x90/wifuzz/) - Access Point 802.11 stack fuzzer
* [wifuzzit](https://github.com/0xd012/wifuzzit/) - A 802.11 wireless fuzzer
* [wtf](https://github.com/cozybit/wtf/) - Wireless Test Framework. Collection of test suites for validating various wifi functionality on various wifi devices.
* [zarp](https://github.com/hatRiot/zarp/) - Network attack tool centered around the exploitation of local networks
## Information Gathering
* [3WiFi Database](https://github.com/binarymaster/3WiFi/) - Collect data from Router Scan log reports, search for access points, obtain its geolocation coordinates, and display it on world map
* [access_points](https://github.com/kootenpv/access_points/) - Scan your WiFi and get access point information and signal quality
* [Accumulation-rssi](https://github.com/h3pr5tq/accumulation-rssi/) - Linux utility for accumulation of WiFi RSSI to text file. Using nl80211, Managed mode. Useful for experiments with WiFi (example, localization)
* [airscan](https://github.com/trou/airscan/) - Wi-Fi scanning utility for the Nintendo DS
* [basiciw](https://github.com/enkore/basiciw/) - Retrieve information such as ESSID or signal quality from wireless cards (Python module)
* [Get-rssi](https://github.com/h3pr5tq/get-rssi/) - Linux utility for getting RSSI WiFi of APs to text file. Using Monitor mode, libpcap.
* [IndoorPositionr](https://github.com/otherview/IndoorPositionr/) - Indoor positioning using Android to provide the surrounding Access Points signals and guess the position
* [Isniff-GPS](https://github.com/hubert3/iSniff-GPS/) - Passive sniffing tool for capturing and visualising WiFi location data disclosed by iOS devices
* [rssi](https://github.com/AravinthPanch/rssi/) - Indoor localisation using RSSI. RSSI is received signal strength indicator in IEEE 802.11 beacon packet to announce the presence of WiFi
* [whoishere](https://github.com/hkm/whoishere.py/) - WIFI Client Detection - Identify people by assigning a name to a device performing a wireless probe request.
* [Wifi-Dumper](https://github.com/Viralmaniar/Wifi-Dumper/) - Dump the wifi profiles and cleartext passwords of the connected access points on the Windows machine
* [Wifi-monitor](https://github.com/eye9poob/Wifi-monitor/) - Prints the IPs on your local network that're sending the most packets ack = 802.11 control frame acknowledgement or …
* [WIG](https://github.com/6e726d/WIG/) - Tools for 802.11 information gathering. 
## Defence/Detection
* [badkarma](https://github.com/atechdad/badkarma/) - BadKarma is a simple python script used to detect and disrupt rouge access points/honeypots using the karma attack such as the wifi pineapple
* [EvilAP_Defender](https://github.com/moha99sa/EvilAP_Defender/) - Protect your Wireless Network from Evil Access Points
* [huntpineapples](https://github.com/0x90/wifi-arsenal/tree/master/huntpineapples/) - WiFi Pineapple hunter from DC23
* [KisMac2](https://github.com/IGRSoft/KisMac2/) - Free, open source wireless stumbling and security tool for Mac OS X
* [kismetclient](https://github.com/PaulMcMillan/kismetclient/) - A Python client for the Kismet server protocol
* [kismet](https://github.com/kismetwireless/kismet/) - Wireless network detector, sniffer, and intrusion detection system
* [kismon](https://github.com/Kismon/kismon/) - A GUI client for kismet
* [Openwips-ng](https://github.com/aircrack-ng/OpenWIPS-ng) - Open source and modular Wireless IPS (Intrusion Prevention System)
* [Python-kismet](https://code.google.com/archive/p/python-kismet/) - Python threaded listener to Kismet broadcasts
* [RogueDetection](https://github.com/baggybin/RogueDetection/) - Rogue Access Point Detection and WIDS
* [waidps](https://github.com/SYWorks/waidps/) - Wireless Auditing, Intrusion Detection & Prevention System
* [Wave](https://github.com/hkparker/Wave/) - 802.11 IDS, visualizer, and analytics platform for the web
* [Wireless-forensics-framework](https://github.com/nipunjaswal/Wireless-forensics-framework/) - Automated Wireless Penetration Testing and Carrying out Wireless Forensics in Python
* [Wireless-ids](https://github.com/SYWorks/wireless-ids/) - Ability to detect suspicious activity such as (WEP/WPA/WPS) attack by sniffing the air for wireless packets
* [wmd](https://github.com/securestate/wmd/) - Simple solution for the detection and location of Rogue Access Points.
* [wraith](https://github.com/wraith-wireless/wraith/) - Wireless Reconnaissance And Intelligent Target Harvesting
* [wspy](https://github.com/Nan-Do/wspy/) - Python tool to create a wireless ids it detects which clients are connected to a network to allow the creation of usage patterns of a netowrk by the clients
## Libraries/General Purpose Tools
* [80211p_raw](https://github.com/allanmatthew/80211p_raw/) - Raw socket utilities for 802.11p transmission
* [80211_raw](https://github.com/MinimumLaw/80211_raw/) - Sender and receiver for WiFi (IEEE802.11) network with raw sockets 
* [banjax](https://github.com/0x90/banjax/) - Library for low-level programming of IEEE 802.11 wireless network interfaces on the GNU/Linux operating system
* [dot11er](https://github.com/timow/dot11er/) - Some tools for playing with IEEE802.11
* [Frame-utils.js](https://github.com/rhodey/frame-utils.js/) - A collection of utilities for processing streams of 80211 frames and radiotap headers.
* [Gopacket-80211](https://github.com/dutchcoders/gopacket-80211/) - Extra gopacket layers for Radiotap and 802.11 (has been integrated in Gopacket) 
* [itamae](https://github.com/wraith-wireless/itamae/) - 802.11 radiotap and MPDU parser 
* [Libairpcap-nl](https://github.com/hbock/libairpcap-nl/) - Implementation of AirPcap library, targetting the NL80211 protocol. 
* [libuwifi](https://github.com/br101/libuwifi/) - C library for parsing, generating and analyzing Wifi (WLAN 802.11) frames in userspace and related functions
* [packetparser](https://github.com/flupzor/packetparser/) - IEEE 802.11 packetparser
* [pcap2xml](https://github.com/securitytube/pcap2xml/) - Convert 802.11 Packet Traces to XML and SQLITE Format 
* [PCS](https://github.com/gvnn3/PCS/) - Set of Python modules and objects that make building network protocol code easier for the protocol developer
* [Probr-core](https://github.com/probr/probr-core/) - The core-component for generic WiFi tracking: remote device management, packet capturing, packet storage
* [py80211](https://github.com/0x90/py80211/) - Suite of libraries for parsing 802.11 packets as well as managing wireless cards and working with 802.11 information
* [PyRIC](https://github.com/wraith-wireless/PyRIC/) - PyRIC (is a Linux only) library providing wireless developers and pentesters the ability to identify, enumerate and manipulate their system's wireless cards programmatically in Python.
* [python3-wifi](https://github.com/llazzaro/python3-wifi/) - Python WiFi is a Python module that provides read and write access to a wireless network card's capabilities using the Linux Wireless Extensions.
* [Python-radiotap](https://github.com/bcopeland/python-radiotap/) - Tiny lib for parsing radiotap/802.11 headers in python 
* [python-wifi](https://pypi.python.org/pypi/python-wifi/) - Python WiFi is a Python module that provides read and write access to a wireless network card's capabilities using the Linux Wireless Extensions.
* [Qca-swiss-army-knife](https://github.com/mcgrof/qca-swiss-army-knife/) - Hosts a set of utilities that we use to debug / help with our driver development
* [Radioparse](https://github.com/AlexanderSelzer/Radioparse/) - A WiFi protocol parser that can be used with radiotap packets and node-pcap
* [Scapy](https://github.com/secdev/scapy) - Python-based interactive packet manipulation program & library
* [Wifi-scan](https://github.com/bmegli/wifi-scan/) - A nl80211 C/C++ library for monitoring signal strength of WiFi networks
* [wifi-scripts](https://github.com/0x90/wifi-scripts) - Misc scripts and tools for WiFi
* [wireless](https://github.com/joshvillbrandt/wireless/) - Dead simple, cross-platform Python library to connect to wireless networks
## Visualization
* [airview](https://github.com/Crypt0s/airview/) - A python web application compliment to py80211 which allows you to visualize the airwaves around you with your web browser. 
* [speccy](https://github.com/bcopeland/speccy/) - Visualization tool for ath spectral scan
* [Wifi-contour](https://github.com/bertabus/wifi-contour/) - A contour mapping program of wireless 802.11 signal strength
* [Wifi-heatmap](https://github.com/beaugunderson/wifi-heatmap/) - Generate heatmaps of wifi coverage with Python
* [wifiscanvisualizer](https://github.com/securitytube/wifiscanvisualizer/) - Wi-Fi Scan Visualizer by Pentester Academy 
* [Wifi-Signal-Plotter](https://github.com/s7jones/Wifi-Signal-Plotter/) - A Python script for graphing and comparing the WiFi signal strengths between WiFi adaptors in Windows or Linux.
* [wifivis](https://github.com/mitdbg/wifivis/) - Visualize some mit wifi access point data
* [wipi](https://github.com/dioh/wipi/) - Visualize the WiFi packages that are floating around us all the time.
* [Wlan-stats](https://github.com/hughobrien/wlan-stats/) - Tool chain using tshark to pull data from pcaps, further process them in python, and graph the output in R. 
## Localisation
* [Find-lf](https://github.com/schollz/find-lf/) - Track the location of every Wi-Fi device (📱) in your house using Raspberry Pis and FIND
* [geowifi](https://github.com/yzfedora/geowifi/) - This is a Geographic WiFi Positioning program written under the Linux.(it is also a WiFi Positioning API written for C language
* [GrapplingHook](https://github.com/nikseetharaman/GrapplingHook/) - Open Source 802.11 Direction Finder
* [gtaiad](https://github.com/jedivind/gtaiad/) - Indoor Wi-Fi navigation prototype using triangulation
* [Openwifimap-api](https://github.com/freifunk/openwifimap-api/) - OpenWiFiMap database and its api 
* [Python Wi-Fi Positioning System](https://github.com/initbrain/Python-Wi-Fi-Positioning-System/) - Python Wi-Fi Positioning System - Wi-Fi geolocation script using the Google Geolocation API 
* [pyWPSLocation](https://github.com/akrv/pyWPSLocalisation/) - Using Python for localisation using Google Geolocation API (GGAPI) and WiFi Positioning System (WPS)
* [whereami](https://github.com/kootenpv/whereami/) - Uses WiFi signals 📶 and machine learning to predict where you are 
* [Wifi-geolocation](https://github.com/genekogan/wifi_geolocation/) - Get your latitude/longitude via wifi access points
* [Wifi-localization](https://github.com/utexas-air-fri/wifi_localization/) - Wifi Localization using a map and reference
* [Wifi-locator](https://github.com/clockfort/wifi-locator/) - Determines physical location of station judging from 802.11 beacons' BSSID/Signal/Noise/Quality information.
* [Wi-finder](https://github.com/romebop/wi-finder/) - Wi-Fi hotspot finder
* [Wlan-pos](https://github.com/0x90/wlan-pos/) - Location fingerprinting and triangulation engine for WLAN (IEEE802.11,aka WiFi) environment.
## Configuration/setup
* [802.11p-iw ](https://github.com/CTU-IIG/802.11p-iw/) - Wireless configuration tool (UNIX)
* [agentapd](https://github.com/mengning/agentapd/) - Agent of WiFi hardware
* [AirLibre](https://github.com/nathanshimp/AirLibre/) - Python API For UBNT AirOS Devices 
* [Atheros-AR9271 ](https://github.com/aaronkish/Atheros-AR9271/) - Kernel Extension for AR9271 chipset (Wireless USB Card)
* [AtherosROMKit ](https://github.com/andyvand/AtherosROMKit/) - Atheros ROM modding and recovery kit 
* [cac](https://github.com/paulpatras/cac/) - A Centralized Adaptive Control algorithm that optimises the performance of IEEE 802.11 WLANs 
* [captiveportal](https://github.com/bendemott/captiveportal/) - A captive portal that can be used on most linux distributions. 
* [cloudap](https://github.com/mengning/cloudap/) - AP Manager in Cloud,AP Hardware on your side
* [connme](https://github.com/kurokid/connme/) - Client for Hostapd 
* [crda](https://github.com/mcgrof/crda/) - Central Regulatory Domain Agent
* [create_ap](https://github.com/oblique/create_ap/) - This script creates a NATed or Bridged WiFi Access Point. 
* [disable-802.11b-snmp](https://github.com/claymichaels/disable-802.11b-snmp/) - A tool to set 802.11 protocols on thousands of Access Points with SNMP.
* [Do-wifi](https://github.com/ealexeev/do-wifi/) - Command line tool for scanning and connecting to wifi networks in Linux. 
* [full_permissive_unlock_ath](https://github.com/doom5/ath9k_ath5k_full_permissive_unlock_all_channels.patch/) - This kernel patch enable all 2GHZ & 5GHZ channels (without restriction) for ath9k & ath5k forced to use buildin world regulatory
* [FWAP](https://github.com/szehl/FWAP/) - Minimal, very lightweight access point implementation
* [hostapd](https://github.com/nims11/hostapd.py/) - Python script to make using and configuring hostapd easier 
* [hostapd](https://w1.fi/hostapd/) - User space daemon for access point and authentication servers
* [Hostapd-mana](https://github.com/adde88/hostapd-mana/) - Hostapd-mana for the 6.th gen. Wifi Pineapple, and OpenWRT
* [hostapd-mana-openwrt](https://github.com/adde88/hostapd-mana-openwrt/) - Hostapd-mana - build-files, and installation-files for OpenWRT
* [Hostapd-with-WebID](https://github.com/yunus/Hostapd-with-WebID/) - WebID integrated hostapd
* [Hostapd-wpe-openwrt](https://github.com/TarlogicSecurity/hostapd-wpe-openwrt/) - Hostapd-wpe (Wireless Pwnage Edition) packages for OpenWRT Barrier Breaker 14.07 
* [hotspotd](https://github.com/prahladyeri/hotspotd/) - Simple daemon to create a wifi hotspot on Linux
* [IEEE802.11-complete](https://github.com/UtkMSNL/IEEE802.11-complete/) - IEEE802.11 protocol, including PHY, MAC, and rate adaptation approaches upon GNURadio/USRP software-defined radio platform
* [Linux-wifi-tools](https://github.com/R2dR/linux-wifi-tools/) - A set of Linux command line tools for managing and troubleshooting wifi
* [monmob](https://github.com/tuter/monmob/) - Set of tools to provide monitor mode and raw frame injection for devices using broadcom chipsets bcm4325, bcm4329 and bcm4330
* [nexmon](https://github.com/seemoo-lab/nexmon/) - The C-based Firmware Patching Framework for Broadcom/Cypress WiFi Chips that enables Monitor Mode, Frame Injection and much more
* [PyWiWi](https://github.com/6e726d/PyWiWi/) - Python Windows Wifi
* [reghack](https://github.com/0x90/wifi-arsenal/tree/master/lowlevel/reghack/) - Replaces the regulatory domain rules in the driver binaries with less restrictive ones
* [RegMon](https://github.com/thuehn/RegMon/) - RegMon is a Atheros WiFi card register monitoring tool for Linux OpenWrt
* [remoteapd](https://github.com/mengning/remoteapd/) - Remote NL80211-Extent driver for Hostapd 2.0
* [resfi](https://github.com/resfi/resfi/) - Framework supporting creation of RRM functionality in residential WiFi deployments
* [rollmac](https://github.com/violentshell/rollmac/) - Automated WiFi limit evasion
* [RT73-USB-Wireless-](https://github.com/Marchrius/RT73-USB-Wireless-/) - Patched version of RT73USBWireless for Yosemite
* [RTL8188-hostapd](https://github.com/jenssegers/RTL8188-hostapd/) - Hostapd for Realtek RTL8188
* [Wifi-ap](https://github.com/foosel/wifi-ap/) - Library wrapper around hostapd and dnsmasq and their respective configuration files that allows for programmatically creating access points in Debian-based Linux environments
* [Wifi-frequency-hacker](https://github.com/singe/wifi-frequency-hacker/) - A modified frequency regulatory domain configuration that doesn't limit you. 
* [Wifi-pentesting](https://github.com/baldwmic/wifi-pentesting/) - Wifi Penetration Testing of Home Network
* [WirelessConfig](https://github.com/acidprime/WirelessConfig/) - A 802.1x Python wireless configuration tool with Cocoa wrappers
## Monitoring
* [como](https://github.com/JackieXie168/como/) - CoMo is a passive monitoring system that supports arbitrary real time traffic queries
* [horst](https://github.com/br101/horst/) - Lightweight IEEE802.11 wireless LAN analyzer with a text interface. Its basic function is similar to tcpdump, Wireshark or Kismet, but it's much smaller and shows different, aggregated information which is not easily available from other tools.
* [scapybase](https://github.com/jahrome/scapybase/) - 802.11 monitor AP based on scapy
* [Scapy-survey](https://github.com/tuomasb/scapy-survey/) - 802.11 signal strength logger using Scapy
* [sigmon](https://github.com/tecknowledge/sigmon/) - Modular WiFi/RF Monitoring and Analysis Implementation
* [Uniband-installer](https://github.com/wi-fi-analyzer/uniband-installer/) - Wireless monitoring framework to help using kismet dumpcap and horst (installation files)
* [Wifi-linux](https://github.com/dixel/wifi-linux/) - Simple python script to monitor access point signal strength.
* [Wifi-monitor](https://github.com/dave5623/wifi_monitor/) - 
* [Wifi-monitor](https://github.com/tadashi/wifi-monitor/) - Python, py_libpcap, handover 
* [WiPy](https://github.com/bliz937/WiPy/) - Sends the WiFi signal strength from multiple clients to a central server. Built for Arch Linux ARM running on Raspberry pi 2
* [WLAN-Monitoring](https://github.com/sajjanbh/WLAN-Monitoring/) - Monitor our vicinity to monitor wireless devices and traffic
* [wmon](https://github.com/wmon/wmon/) - A Wireless Network Monitor with advanced measurement capabilities. 
## Miscellaneous/not sorted :)
* [80211ping](https://github.com/tillwo/80211ping/) - Linux command-line tool to ping 802.11 stations (e.g. any WiFi device)
* [acs](https://github.com/mcgrof/acs/) - Automatic Channel Selection utility
* [Airfree-wt](https://github.com/rednaks/airfree-wt/) - Wireless Security Toolkit
* [Ap-notify](https://github.com/doctaweeks/ap-notify/) - An example of using the Linux kernel netlink protocol, specifically nl80211 via libnl/libnl-genl, to catch stations associating/disassociating with an 802.11 AP
* [ath9k-4w-patch](https://github.com/rboninsegna/ath9k-4W-patch/) - Resources for increasing power of ath9k devices, such as TP-link WN722N
* [Ath9k-nav](https://github.com/hughobrien/ath9k-nav/) - Linux kernel module to poll the NAV register on Atheros 9k series WLAN cards. 
* [bunny](https://github.com/mothran/bunny/) - Bunny is a wireless. meshing, darknet that uses 802.11 to hide its communications 
* [captiv8](https://github.com/wraith-wireless/captiv8/) - Captive Portal Evasion Tool
* [Connect-wifi](https://github.com/mousam05/connect-wifi/) - Dmenu based application for Linux that connects to the strongest open wireless network
* [Cover-channel](https://github.com/abnarain/covert_channel/) - Userland code for creating a covert channel in wireless broadcast medium
* [disassociatedWiFi](https://github.com/bradleykirwan/disassociatedWiFi/) - DisassociatedWiFi creates a virtual network interface (using the Linux TUN/TAP device driver) which sends and receives ethernet frames over an 802.11 (WiFi) interface, that has been placed in monitor mode, and supports packet injection.
* [FFT_eval](https://github.com/simonwunderlich/FFT_eval/) - Aid open source spectrum analyzer development for Qualcomm/Atheros AR92xx and AR93xx based chipsets
* [Frame-randomizer](https://github.com/mike-albano/frame-randomizer/) - Capture and randomize 802.11 Association Request frames
* [FreeWifi](https://github.com/kylemcdonald/FreeWifi/) - How to get free wifi
* [Haiku-wifi](https://github.com/jedahan/haiku-wifi/) - Turn your wireless router's extra radios into a public billboard!
* [kismet2earth](https://code.google.com/archive/p/kismet2earth/) - Set of utilities that convert from Kismet logs to Google Earth .kml format
* [kismeth2earth](https://github.com/andreagrandi/kismeth2earth/) - Parsing Kismet logs to get collected data from wireless networks and generate a Google Earth map
* [Kismet-to-KML](https://github.com/exp/Kismet-to-KML/) - Converts kismet gps log files into kml files
* [Mac-analyzer](https://github.com/abnarain/mac-analyzer/) - Collects cross layer stats from ath9k 
* [Madwifi-be](https://github.com/paulpatras/madwifi-be/) - Modified version of the madwifi driver allowing update of WME parameters for the BE access category
* [Madwifi-hopping](https://github.com/paulpatras/madwifi-hopping/) - Modified version of the Madwifi WLAN driver, that employs power-hopping for packet transmission
* [make-a-new-mac80211-to-wirelessAP](https://github.com/fhector/make-a-new-mac80211-to-wirelessAP/) - 
* [netxml2kml](http://www.salecker.org/software/netxml2kml.html/) - Converts netxml files from Kismet Newcore into KML or KMZ files for Google Earth
* [Osx-wificleaner](https://github.com/mubix/osx-wificleaner/) - Cleans out open wireless connections from OSX machine 
* [Osx-wifi-scan](https://github.com/kornysietsma/osx-wifi-scan/) - Hacky wifi signal scanner for osx 
* [parsecaps](https://github.com/sa7mon/parsecaps/) - Parse wpa.cap generated from besside-ng and create individual .caps for each network with a captured handshake. 
* [pcap80211analyzer](https://github.com/enukane/pcap80211analyzer/) - Not-so-smart 802.11 frame pcapng analyzer 
* [Probr-analysis](https://github.com/probr/probr-analysis/) - Analysis components for the probr WiFi tracking system
* [py_DD_WRT_Remote_Mac_Adder](https://github.com/mzhaase/py_DD_WRT_Remote_Mac_Adder/) - Python Script to remotely update mac filterlists of DD-WRT routers with wl or atheros wifi drivers
* [pykismetkml](https://code.google.com/archive/p/pykismetkml/wikis/pykismetkml.wiki/) - Python script designed to export .gps and .xml files (in < Kismet RC1) to .kml files and .netxml files to .kml files in => Kismet RC2
* [pykismetstats](https://github.com/0x90/pykismetstats/) - Pykismetstats parses NetXML file generated by kismet and write statistics to CSV file.
* [PyScapy](https://github.com/ogreworld/PyScapy/) - This is a package of using scapy.
* [react80211](https://github.com/fabriziogiuliano/react80211/) - Solution for mitigating the performance impairments of CSMA/CA protocols in multi-hop topologies based on the dynamic adaptation of the contention process experienced by nodes in a wireless network
* [Rollmac](https://github.com/violentshell/Rollmac/) - Automated WiFi limit evasion
* [Scapy-rssi](https://github.com/azz2k/scapy-rssi/) - Example of how to read RSSI values from wifi packaged using Scapy
* [setbssid](https://github.com/sheenhx/setbssid/) - Modify the MAC80211 layer in Linux Kernel
* [skybluetero](https://code.google.com/archive/p/skybluetero/) - 802.11b/g packet airtime consumption analyzer GUI for Linux
* [sniffmypackets](https://github.com/catalyst256/sniffMyPackets/) - Canari package for pcap file analysis within Maltego
* [Snoopy-ng](https://github.com/sensepost/snoopy-ng/) - Snoopy v2.0 - modular digital terrestrial tracking framework
* [spectrum.py](https://github.com/0x90/wifi-arsenal/blob/master/spectrum.py/) - 
* [VX](https://github.com/hellais/VX/) - It might be fun to play tricks on somebody trying to crack your WEP protected router
* [Wbc-utils](https://github.com/skullkey/wbc-utils/) - Couple of hacked together utils for use with the wifibroadcast system by befinitiv
* [wi5-aggregation](https://github.com/Wi5/wi5-aggregation/) - Implementing and testing 802.11 frame aggregation (A-MPDU) 
* [WiFi-Analyzer](https://github.com/b00sti/WiFi-Analyzer/) - Analyzer 802.11 networks - android app [to refactor] 
* [wifi_based_population_estimator](https://github.com/siriuxy/wifi_based_population_estimator/) - This is a piece of glueware that sticks up different components from hardware detection to real-time web display.
* [Wifi-beeper](https://github.com/tillwo/wifi-beeper/) - Linux command-line tool to make WLAN frames audible
* [wifidec](https://github.com/twitchyliquid64/wifidec/) - Repository for scriptz playing around with decoding elements of the Wifi stack (mainly Radiotap and 802.11 frames)
* [wifi_decode](https://github.com/cmpxchg8/wifi_decode/) - Wireless Key Dumper for Windows
* [WifiDirectLinux](https://github.com/arplote/WifiDirectLinux/) - Use p2p with Wifi Direct on Linux
* [Wifidog-gateway](https://github.com/wifidog/wifidog-gateway/) - Repository for the wifidog-gateway captive portal designed for embedded systems
* [Wifi-dump-analysis](https://github.com/abnarain/wifi-dump-analysis/) - Processing wireless traces from binary files written and read in custom format.
* [wifi_dump_parser-v3](https://github.com/abnarain/wifi_dump_parser-v3/) - Is the modified parser for the new data set collected using Wifi-dump
* [wifi_dump-tmpfs](https://github.com/abnarain/wifi_dump-tmpfs/) - Dumps wifi data 
* [wifihisicipy](https://github.com/saljam/wifihisicipy/) -  Temporarily runs a wifi hotspot and a 'captive portal' to let you choose a permanent wireless network to connect to.
* [wifi](https://github.com/rockymeza/wifi/) - [unmaintained] WiFi tools for linux http://pypi.python.org/pypi/wifi
* [wifirxpower](https://github.com/cnlohr/wifirxpower/) - Linux-based WiFi RX Power Grapher
* [wifiScanMap](https://github.com/mehdilauters/wifiScanMap/) - An other wifi mapping tool
* [WiFi-scheduling](https://github.com/UtkMSNL/WiFi-scheduling/) - This project evaluates the efficiency and overhead of wireless network scheduling
* [wifi_statistics](https://github.com/simonwunderlich/wifi_statistics/) - Linux kernel module to gather wifi statistics from peer and non-peer STAs 
* [wifitracker](https://github.com/DHNishi/wifitracker/) - Raspberry Pi Wifi Tracking API
* [WifiTrafficAnalyzer](https://github.com/Bob-King/WifiTrafficAnalyzer/) - 
* [wifresti](https://github.com/LionSec/wifresti/) - Find your wireless network password in Windows , Linux and Mac OS
* [wime](https://github.com/anburocky3/wime/) - Wifi password recover tool for Windows, Linux, Mac.
* [win32wifi](https://github.com/kedos/win32wifi/) - Python Windows Wifi
* [wireless_half-mini](https://github.com/toleda/wireless_half-mini/) - MacOS Airport Half Mini (WiFi and Bluetooth)
* [WIRELESSINFO](https://github.com/rgupta9/WIRELESSINFO/) - Extract Important Data From Cisco Wireless Controllers
* [wireless_RSSI](https://github.com/agnostino/wireless_RSSI/) - 
* [Wireless-tools](https://github.com/bakerface/wireless-tools/) - Wireless tools for Node.js 
* [wit](https://github.com/substack/wit/) - Command-line wifi manager for linux
* [wobs](https://github.com/observ3r/wobs/) - Detects near-by devices such as cell phones, tablets, and laptops. Does this through 802.11, Bluetooth, cell phone protocols, etc.. 
