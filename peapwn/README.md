PEAPwn
======

PEAPwn is a proof-of-concept implementation of the Apple relay attack introduced at WiSec 2014. It uses a modified version of the ```wpa_supplicant``` tool by Jouni Malinen to establish a PEAP or EAP-TTLS session with the target Authentication Server, and a Python script to exploit several vulnerabilities in iOS < 8 and the MSCHAPv2 protocol. This allows an attacker to gain unauthorized access to any WPA2-Enterprise network that uses a tunneled authentication protocol such as PEAP or EAP-TTLS.

Link to the paper: http://research.edm.uhasselt.be/~bbonne/docs/robyns14wpa2enterprise.pdf


Building the PoC
----------------

Currently, only Linux based operating systems are supported. To build the PoC, perform the following steps:

1. Install the Scapy library for Python 2.
2. Install libnl1
3. Navigate to mods/hostap/wpa_supplicant.
4. cp defconfig .config
5. Run ```make```. 


Running the PoC
---------------

To run the PoC, one is required to have two NICs. At least one of these devices is required to support Monitor mode. The PoC can then be run as follows:

```# python2 peapwn.py <infra_nic> <mon_nic> <essid>```

For example, to attack a network with SSID ```testnet```:

```# python2 peapwn.py wlan0 wlan1 testnet```


Legal notice
------------

This PoC is intended for research purposes only, and should only be used in a legal context. For example, to verify the security of your own networks.


TODO list
---------

- [ ] More robust error handling.
