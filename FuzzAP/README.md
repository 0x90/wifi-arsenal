FuzzAP
======

A python script for obfuscating wireless networks

'''
Warning: I am not a programmer by trade, nor would I consider myself one

The common SSID list was pulled from https://wigle.net/gps/gps/Stat
The OUI vendor list was parsed from http://standards.ieee.org/develop/regauth/oui/oui.txt 
for well known vendors (netgear, cisco, linksys, d-link, atheros, ralink, apple)

This idea was created based off of Black Alchemy's FakeAP 
http://www.blackalchemy.to/project/fakeap/ and Pettinger's airraid 
http://www.pettingers.org/code/airraid.html
Some logic for parsing required info from packets was taken from Leandro Meiners 
(lea@coresecurity.com) at Core Security Technology's Power-Saving DoS script

The main differences between these implementations is hardware requirements and how the 
fake access point is generated.

FakeAP generates fake access points by creating an access point using iw and ifconfig 
with a PRISM-based wireless card. The problem is PRISM drivers are mostly deprecated in
most modern distros. Even with a working driver and a PRISM card, I was unable to get
FakeAP to work out of the box.

AirRaid is almost identical to how FakeAP works. However, it is tailored towards Atheros-
based cards and utilizes the madwifi drivers and utilities to create fake access points.
The Madwifi projects seems to be mostly dying down in favor of ath5/9k drivers.
Out-of-the-box, AirRaid no longer worked with my atheros card.

Another problem with these implementations, was speed. As each fake access point was
created, the wireless deviced had to be up-downed and reconfigured.

This implementation differs in a number of ways. It is not totally hardware specific like
FakeAP or AirRaid. Instead of creating a fake access point by changing the settings for 
the wireless adapter and having to reset and reconfigure the device, it takes advantage of
 wireless cards that support packet-injection.

This helps in a number of ways. It supports far more adapters as well as a lot
of modern drivers that support packet-injection and monitor-mode (rtl8187, ath5k, ath9k,
most ralink, etc...). In short, any device that has drivers that can allow an adapter to 
run in monitor-mode via airmon-ng, can use this. Because this utilizes packet-injection 
instead of actually creating an access-point, it injects packets that look like they are
from actual access points. 

This is my first project in python, so there are likely going to be flaws, inefficiencies, 
possible ways to detect which APs are the fake ones. I plan on improving this over time as
 problems are discovered and enhancements requested.

One may need less than these requirements to make this work, but I know they work with
the following:

Atheros-based cards using ath5k and ath9k
Realtek 8187 chipsets(ie Alfa AWUS 036H)
Most Ralink chipsets

This was coded in python 2.7 with Scapy 2.2.0. I really don't have a firm grasp on Scapy
as their documentation is kind of thin, so anything done incorrectly, please let me know.
airmon-ng was used to create the monitor interfaces which allows packet injection.

I also realize this writeup is longer than the actual code.

------------------------------------------------------------------------------------------

To run:

Requires python 2.7, Scapy 2.2.0, wireless card with drivers that support packet injection

#####EARLY VERSION WARNING#####

There is virtually no logging for this as I don't know scapy very well at this point, and
when it sends beacon frames and probe responses, it sends "Sent 1 packets" to the terminal.
When we are sending multiple packets a second, this spams your screen with "Sent 1 packets"
I am currently working on finding a way around this and provide more useful logging.

Make sure you have a wireless NIC in monitor mode with packet injection capabilities. I use 
the aircrack-ng suite's airmon-ng to do this:

airmon-ng start \<interface\>

Which should tell you the new virtual monitoring interface that has been created (something like
mon 0)

FuzzAP.py takes two required arguments. First argument is the interface to use, the second
is the number of fake access points to generate.

python fuzzap.py \<interface \> \<number of APs\>

What it looks like from a client perspective: http://imgur.com/QsoFP1a

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
'''

TODO:

Bogus traffic between 'APs' and 'clients'
Channel hopping
