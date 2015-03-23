dot11decrypt
============

dot11decrypt is a WEP/WPA2(AES and TKIP) on-the-fly decrypter. 

## Description ##
-----

dot11decrypt requires a wireless interface in monitor mode and the 
appropriate information required to decrypt the encrypted traffic. The 
decrypted traffic is encapsulated using Ethernet frames and written to a 
tap device. 

After that, you can use any application(such as tcpdump, wireshark, 
ngrep, etc) that interprets network traffic to analyze the decrypted 
traffic.

This is **not** a WEP/WPA2 cracker, it is just a tool that allows you to
use other tools that don't support the decryption of encrypted traffic.

There's a more detailed explanation of this application in 
[my blog](http://average-coder.blogspot.com/2013/06/decrypting-wepwpa2-traffic-on-fly.html).

## Requirements ##
-----

The only requirement is [libtins >= v1.1](http://libtins.github.io), 
compiled using support for WPA2 decryption(this is enabled by default),
and a fairly recent C++ compiler. g++ 4.6 is enough, probably 4.5 works
as well, but I haven't had the chance to try it.

## Compilation ##
-----

In order to compile, just do  the usual:


```Shell
./configure
make
```

## Decryption data ##
-----

In order to decrypt WEP/WPA2 encrypted frames, the following data is
required:

* WEP: The access point's BSSID(aka MAC address) and the WEP key.
* WPA2: The access point's SSID(aka "name") and the PSK(aka "password").

dot11decrypt supports the decryption of both WPA2 AES(CCMP) and TKIP.
If there are more than one access points that broadcast the same SSID,
then all of them will be decrypted. 

In order to decrypt WPA2, the application waits for Beacon frames, so 
as to identify the BSSIDs associated with each SSID. Afterwards, 
it waits for EAPOL handshakes, which are required for decryption. Note
that if the 4-way handshake is not processed, then decryption will not
be successfull. After that, the traffic sent by clients for which the
handshake was captured will be decrypted.


## Decrypted packets ##
-----

When the application is launched, a tap network interface will be 
created. Every decrypted packet will be encapsulated using Ethernet 
frames and written to that interface. 

## Usage ##
-----

In order to use dot11decrypt, you need to specify the interface in which
to listen and the decryption options:

```Shell
./dot11decrypt wlan0 wpa:MyAccessPoint:some_password
./dot11decrypt mon0 wep:00:01:02:03:04:05:blahbleehh
```

The *wpa:* option allows you to decrypt

You can provide as many decryption data tuples as you want.
