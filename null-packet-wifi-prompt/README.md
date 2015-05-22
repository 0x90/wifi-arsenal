This is a simple script to prompt responses from wireless devices with a known MAC address. It repeatedly sends null packets to the target address. The device *should* respond with an ack packet. It still requires testing on a variety of devices. I will update the results of my completely anecdotal and not-at-all rigorous testing on different devices at the bottom of this readme.

Interestingly, it seems to work most consistently when devices are connected to a wireless network (although the scanner does not need to be connected to that network).

The script can be used from the command line like so:

`python null.py [iface] [target_mac] [src_mac]`

e.g.

`python null.py wlan0 ab:cd:ef:01:23:45 ab:cd:ef:01:23:47`

src_mac should be a unique address, specific to your target, so that you can scan for responses without accidentally picking up legit wireless traffic.

It requires scapy to be installed and a wireless interface in monitor mode.

You can scan for responses with the following command:

`tcpdump -i wlan0 'wlan addr1 ff:ff:ff:ff:ff:ff && type ctl subtype ack' -vv -s0`

Just replace wlan0 with your wireless interface and 'ff:ff:ff:ff:ff:ff' with src_mac.

Testing Results:

**iOS**

iPhone 4S

Generates responses consistently, as long as the device is awake. If the device is asleep, it seems to generate no response, but once it's woken up, it can be put back to sleep and it will continue to respond for a brief period. Responds more frequently when connected to a network, but it doesn't seem to be a requirement.

**Windows Phone**

Nokia Lumia 920

Responds very rarely. Seems to respond once when you wake it up, but not before or after.

**Android**

Samsung Galaxy S4

Responds reasonably consistently while the device is awake and connected to a wifi network. Continues responding briefly after the device is put to sleep.

Samsung Galaxy Note 3

Responds occasionally while the device is awake and connected to a network. Seems to respond when not connected, as well.

LG G2

Responds reasonably consistently while the device is awake and connected to a wifi network. Does not respond at all when not connected to a network.