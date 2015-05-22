# frame-randomizer
Capture and randomize 802.11 Association Request frames.

USAGE

On Linux:
Run the script, passing it a pcap file as an argument (ie assoc-randomizer.py foo.pcap), and it will go through looking for 802.11 Association Request frames. Each time it finds a frame it will display the client MAC, BSSID and ESSID; prompting user for 'Randomization'. If you'd like to randomize that Assocation Frame, type 'y' and the client MAC, BSSID and ESSID will be replaced by meanengless data (1's, 2's and random numbers).
The frame will be saved in the current directory as it's own pcap file. Upon completion you can merge all the individual pcaps into a single pcap (useful, if multiple Association Frames contained in the original pcap).

On OSX:
Same as above, except you can run script without passing any arguments, and capture frames real-time. Follow the prompts for channel settings, starting/stopping capture (Ctrl-c) etc.

NOTE: If doing Live captures from script, it must be run as root. For example:
```
sudo /opt/local/bin/python2.7 association-randomizer.py
```
note: I specified full path to python2.7. Alternatively, you could modify appropriate paths to include /opt/local/bin

Example of using this on OSX to determine & verify supported channels of a client:

```
1. sudo /opt/local/bin/python2.7 association-randomizer.py

2. what 20MHz channel would you like to capture on? (1, 36, 40, 44, etc.) > 36
        Set AP to channel 36, and associate with client. Once connected: Ctrl-c to stop capture (after associating)
	Capturing on 'Wi-Fi'

	^CYou pressed Ctrl+c to stop capturing...
	Saved pcap as /tmp/capture_chan36.pcap
	Would you like to capture on another channel? (y/n)> y
	what 20MHz channel would you like to capture on? (1, 36, 40, 44, etc.) > 40
        Set AP to channel 40, and associate with client. Once connected: Ctrl-c to stop capture (after associating)
        Capturing on 'Wi-Fi'

	^CYou pressed Ctrl+c to stop capturing...

4. Start capturing on channel 40, then set AP to channel 40...Client should associate automatically. Once connected: 
	Ctrl-c to stop capture.
        ^CYou pressed Ctrl+c to stop capturing...
        Saved pcap as /tmp/capture_chan40.pcap
        Would you like to capture on another channel? (y/n)> n
	Association Request found...
	Original info:
 	Client: 14:1a:c3:d2:a1:c5
 	AP: e5:fd:a6:15:9b:d2
 	BSSID: e2:24:d6:32:7a:c1
 	SSID: Free Public WiFi
	Randomize this Association Request? (y/n) > y
	New info:
 	Client: 22:22:22:22:22:22
 	AP: 11:11:11:11:11:11
 	BSSID: 11:11:11:11:11:11
 	SSID: 8118114112883
	Wrote new pcap file to ./assoc_randomized_0.pcap
	Hit enter to continue...
 
	Would you like to merge all individual randomized pcaps into one? (y/n)> y
	Saved combined randomized pcap as ./allpcaps.pcap
```

The file "allpcaps.pcap" will contain all of the associations, with randomized data.

DEPENDENCIES

Dependencies on Linux include:
scapy, tshark (usually installed with Wireshark)

Dependencies on OSX include the following:
xCode, macports, scapy (macports used to install scapy) & tshark (usually installed with Wireshark)

OSX Dependency instructions:
First install Xcode: http://guide.macports.org/#installing.xcode (app store or dev website)

Then install macports: https://www.macports.org/install.php

Then install scapy (taken from recipe 3: http://www.secdev.org/projects/scapy/portability.html):
```
  sudo /opt/local/bin/port -d selfupdate
  sudo port install scapy
```
You must use the version of python installed by macports in order to use the other libraries installed by macports (including scapy). 
For example: python2.7 (full path is on my OSX install is: /opt/local/bin/python2.7)
Perform a quick test of scapy install by running: 
```
/opt/local/bin/python2.7
```
You should then be able to "import scapy" from IDLE; or simply run "scapy" from command line.

