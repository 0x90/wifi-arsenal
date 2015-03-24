# badKarma
badKarma is a simple python script used to detect and disrupt rouge access points/honeypots using the karma attack such as the wifi pineapple.

# System Requirements
This script was built to run on kali linux. Packages that must be installed are:
mdk3
aircrack-ng 
wireless-tools

# Features
Auto detection of karma honeypot and automated deauth of all connected clients.

# Options
<code>
-h, --help    show this help message and exit
-i interface  wireless interface
</code>

# Usage
<code>
$ ./badkarma.py -i wlan0
</code>
To exit, press ctrl-c

# More Info
http://atechdad.com/karma-rouge-accesspoint-offense-with-badkarma-py

