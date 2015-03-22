# WPA2-HalfHandshake-Crack
Conventional WPA2 attacks work by listening for a handshake between client and Access Point. This full fourway handshake is then used in a dictonary attack. This tool is a Proof of Concept to show it is not necessary to have the Access Point present. A person can simply listen for WPA2 probes from any client withen range, and then throw up an Access Point with that SSID. Though the authentication will fail, there is enough information in the failed handshake to run a dictionary attack against the failed handshake. 

## Install

```
  $ sudo python setup.py install
```

## Sample use

```
  $ python halfHandshake.py -r sampleHalfHandshake.cap -m 48d224f0d128 -s "no place like 127.0.0.1"
```

* **-r** Where to read input pcap file with half handshake (works with full handshakes too)
* **-m** AP mac address (From the 'fake' access point that was used during the capture)
* **-s** AP SSID
* **-d** (optional) Where to read dictionary from

## Capturing half handshakes

#### To listen for device probes the aircrack suite can be used as follows

```
sudo airmon-ng start wlan0
sudo airodump-ng mon0
```

  You should begin to see device probes with BSSID set as (not associated) appearing at the bottom. If WPA2 SSIDs pop up for these probes, these devices can be targeted

#### Setup a WPA2 wifi network with an SSID the same as the desired device probe. The passphrase can be anything

  In ubuntu this can be done here

http://ubuntuhandbook.org/index.php/2014/09/3-ways-create-wifi-hotspot-ubuntu/

#### Capture traffic on this interface.

  In linux this can be achived with TCPdump
```
sudo tcpdump -i wlan0 -s 65535 -w file.cap
```

#### (optional) Deauthenticate clients from nearby WiFi networks to increase probes

If there are not enough unassociated clients, the aircrack suite can be used to deauthenticate clients off nearby networks http://www.aircrack-ng.org/doku.php?id=deauthentication
