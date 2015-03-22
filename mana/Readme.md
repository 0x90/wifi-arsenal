The MANA Toolkit
================
by Dominic White (singe) & Ian de Villiers @ sensepost (research@sensepost.com)

Overview
--------
A toolkit for rogue access point (evilAP) attacks first presented at Defcon 22.

More specifically, it contains the improvements to KARMA attacks we implemented into hostapd, as well as some useful configs for conducting MitM once you've managed to get a victim to connect.

Contents
--------

It contains:
* kali/ubuntu-install.sh - simple installers for Kali 1.0.9 and Ubuntu 14.04 (trusty)
* slides - an explanation of what we're doing here
* run-mana - the controller scripts
* hostapd-manna - modified hostapd that implements our new karma attacks
* crackapd - a tool for offloading the cracking of EAP creds to an external tool and re-adding them to the hostapd EAP config (auto crack 'n add)
* sslstrip-hsts - our modifications to LeonardoNVE's & moxie's cool tools
* apache - the apache vhosts for the noupstream hacks; deploy to /etc/apache2/ and /var/www/ respectivley

Installation
------------

The simplest way to get up and running is it "apt-get install mana-toolkit" on Kali. If you want to go manual, check below. Make sure to edit the start script to point to the right wifi device.

To get up and running setup a Kali 1.0.9 box (VM or otherwise), update it, then run kali-install.sh

To get up and running setup a Ubuntu 14.04 box (VM or otherwise), update it, then run ubuntu-install.sh

The ubuntu installer has much more dependency info than the kali one if you're looking for a template.

Pre-Requisites
--------------

_Software_

Check the ubuntu installer for more details on software pre-requisites.

_Hardware_

You'll need a wifi card that supports master mode. You can check whether it does by running:
    iw list
You want to see "AP" in the output. Something like:
```
Supported interface modes:
         * IBSS
         * managed
         * AP
         * AP/VLAN
         * monitor
         * mesh point
```
More information at https://help.ubuntu.com/community/WifiDocs/MasterMode#Test_an_adapter_for_.22master_mode.22

Three cards that have been confirmed to work well, in order of preference are:
* Ubiquiti SR-71 (not made anymore :(, chipset AR9170, driver carl9170 http://wireless.kernel.org/en/users/Drivers/carl9170 ) 
* Alfa Black AWUS036NHA (chipset Atheros AR9271, buy at http://store.rokland.com/products/alfa-awus036nha-802-11n-wireless-n-usb-wi-fi-adapter-2-watt ) 
* TP-Link TL-WN722N (chipset Atheros AR9271 )

Note, the silver Alfa does not support master mode and will not work.

Running
-------

Mana has several components, these can be started using the example start scripts, or you can use these as templates to mix your own.

Mana will be installed to several directories:
* The mana tools are installed to /usr/share/mana-toolkit
* The start scripts are in /usr/share/mana-toolkit/run-mana
* The captured traffic will be in /var/lib/mana-toolkit

The different start scripts are listed below and must be edited to point to the right wifi device (default is wlan0, this may not be right for your installation):

* start-nat-full.sh - Will fire up MANA in NAT mode (you'll need an upstream link) with all the MitM bells and whistles.
* start-nat-simple.sh - Will fire up MANA in NAT mode, but without any of the firelamb, sslstrip, sslsplit etc.
* start-noupstream.sh - Will start MANA in a "fake Internet" mode. Useful for places where people leave their wifi on, but there is no upstream Internet. Also contains the captive portal.
* start-noupstream-eap.sh - Will start MANA with the EAP attack and noupstream mode.

While these should all work, it's advisable that you craft your own based on your specific needs.
