Cornuprobia
===========

Cornuprobia - Fountain of 802.11 Probe Requests

This small program will generate a large amount of dummy probe requests to thwart mobile phone tracking systems.

Sample output:
```
$ python cornuprobia.py -w 1984.wl mon1
[*] Cornuprobia - Fountain of 802.11 Probe Requests (mon1)
[*] Loading SSID wordlist: 1984.wl
[*] Sending 6 probe(s): 4f:3a:f8:1a:aa:2e 'vomited'
[*] Sending 7 probe(s): cd:55:e7:80:82:ad 'inefficiently'
[*] Sending 7 probe(s): 54:27:53:dc:ea:d3 'hot'
[*] Sending 3 probe(s): 5f:c6:1c:71:fe:9e 'dishes'
[*] Sending 9 probe(s): 4e:91:4f:54:53:20 'roughed'
[*] Sending 1 probe(s): 21:e9:fd:b9:14:12 'secretary'
[*] Sending 8 probe(s): 1a:92:6f:10:30:ba 'United'
[*] Sending 2 probe(s): 81:9d:cb:7d:27:73 'slipped'
[*] Sending 1 probe(s): 9b:36:35:54:33:7a 'drug'
[*] Sending 4 probe(s): 74:8c:3f:47:93:ec 'motioned'
[*] Sending 5 probe(s): aa:bb:42:18:a6:ac 'meat'
[*] Sending 3 probe(s): 4c:79:20:93:df:58 'ghastly'
[*] Sending 7 probe(s): 03:ab:30:d6:f9:05 'shallower'
[*] Sending 1 probe(s): e2:68:f1:7c:70:22 'held'
[*] Sending 6 probe(s): d5:ca:71:24:2e:fe 'furnaces'
[*] Sending 6 probe(s): 48:b4:71:47:4c:60 'tribute'
^C[*] Turning off goodness
```


Installing on a Raspberry Pi
============================

* Install Raspian (http://raspbian.org) - Confirmed with: 2014-09-09
  - update and configure the base system.
  - Install drivers for your wifi-chard if it doesn't work out of the box.

* Install packages: python-scapy, python-daemon

* Download Cornuprobia
  $ git clone https://github.com/4ZM/cornuprobia.git

* Test Cornuprobia:
  $ cd cornuprobia
  $ sudo ./scripts/mkif.sh
  $ sudo python cornuprobia.py -w 1984.wl mon0

  -- Watch it run.
  -- You can see the probe requests using airodump-ng on another computer.

  $ sudo ./scripts/rmif.sh

* Install the script to start Cornuprobia at boot
  $ sudo cp cornuprobia/scripts/cornuprobia-service.sh /etc/init.d/
  $ sudo chmod +x /etc/init.d/cornuprobia-service.sh
  $ sudo update-rc.d cornuprobia-service.sh defaults

* Test the service
  $ sudo /etc/init.d/cornuprobia-service.sh start

  -- Make sure it runs

  $ sudo /etc/init.d/cornuprobia-service.sh stop

  -- Make sure it stopped

* Reboot and verify that the script starts automatically
