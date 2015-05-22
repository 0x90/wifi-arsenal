#Bunny
Bunny is intended to act as a layer 1/2 technology that attempts to hide its wireless mesh communication traffic.
Bunny wraps all data in and out in a layer of obfuscation. It does this by passively listening to 
the local wireless and building a model of 'average' traffic. Then using this model, it hides small 
snippets of data within various fields of the 802.11 protocol that are either poorly defined or 
prone to contain data that mutates a lot.  These fields will include but are not limited to, vendor 
data, data packets of encrypted networks, duration fields.


For full whitepaper like decription of Bunny, check proposal.txt.


You need a monitor/injection capable wireless chipset.  Please check the aircrack website for 
compatible cards.


##Tested chipsets / cards:
	rtl8187		-	Alfa AWUS036NH
					Note: These are by far the WORST chipsets on the market, the RX sensitivity makes them almost worless for any kind of application besides cracking WEP passwords.
	ath9k_htc	-	TP-LINK tl-wn722n
	rt2800usb	-	5370 Chipset (sold with raspberry pi's)
					Note: Bunny works well on raspberry pi's

##Configuration
Configuring bunny is as simple as editing the "libbunny/config.py" file

The most important item to modify is the IFACE varible, this sets which wireless interface you will use for Bunny. 
 
Also if you wish to run a non-testing network, delete the 'keys.kz' file and bunny will make a new one with random values.  
Distribute this file to the peers on your network.  Also Modulus and Remainder values should be changed as well, 
for help generating mod/remain vaules check testScripts/mod.py

##Usage (bunnyChat.py example code)

	sudo python bunnyChat.py
	
	-l              --   Listen mode, gets packets and prints data
	-s [data]       --   Send mode, sends packets over and over
	-m              --   Passive profiling of all the channels (1-11)
	-c [UserName]   --   Chat client mode
	-r              --   Reloop shows the mod/remainder of the specified channel
	-p              --   Ping/Pong testing, Run this on one machine and it will
						 respond with a pong.
	-k              --   Ping server mode, will repsond to pings with pong and current time

##Usage of the module
	import libbunny
	
	bunny = libbunny.Bunny()
	bunny.sendBunny(DATA)

	while True:
		print bunny.recvBunny()
	bunny.killBunny()

The modules aspect of Bunny is under-developed currently, the key file needs to be more controlable through the API 
and BunnyExceptions need to be built out and used

##Dependencies

	pycrypto
	keyczar
		pyasn1
	lorcon2 (current)
	pylorcon2 (https://code.google.com/p/pylorcon2/)
	pcapy

##Installation
Check INSTALL file

##TODO

Routing layers and support for projects to be built ontop of what I have done
like cjdns and others

Attempt to make a bunny tun device so testing with the batman-adv kernal module.

Create a packaged version with dependencies to reduce the install time. 

##Bugs
Due to this (https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=500041) bug in pcapy, at least on Arch linux I had to NOT use the offical upstream but the packaged AUR here: https://aur.archlinux.org/packages/python2-pcapy/

Sometimes on ubuntu there is a rfkill block when trying to bring up an interface and you might see:
    SIOCSIFFLAGS: Operation not possible due to RF-kill
    
you can solve this temporarly by:
    sudo rfkill unblock wifi