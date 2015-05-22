fakeAP
======

Create a fake access point in Kali. Determines the correct DHCP settings and creates the dhcpd.conf file for you. Includes the option to sniff all APs in the area and copy one of their settings.


Usage
-----


``` shell
python fakeAP.py
```
Create a fake access point with the ESSID of 'Free Wifi' on channel 6 without encryption that responds to all broadcast probes


``` shell
python fakeAP.py -t
```
-t, Sniff the air for all access points in range, Ctrl-C to select one and use its ESSID and channel in the creation of your fake AP


``` shell
python fakeAP.py -c 1 -e 'New SSID' -w
```

-c, Start the access point on channel 1

-e, Set the broadcast ESSID as 'New SSID'

-w, Set the fake access point to use WPA2 flagged beacon frames and save handshakes to fakeAPlog.cap


License
-------
Copyright (c) 2013, Dan McInerney
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
* Neither the name of Dan McInerney nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


***
* [danmcinerney.org](http://danmcinerney.org)
* [![Flattr this](http://api.flattr.com/button/flattr-badge-large.png)](https://flattr.com/submit/auto?user_id=DanMcInerney&url=https://github.com/DanMcInerney/fakeAP&title=fakeAP&language=&tags=github&category=software) 
* [![Analytics](https://ga-beacon.appspot.com/UA-46613304-4/fakeAP/README.md)](https://github.com/igrigorik/ga-beacon)
