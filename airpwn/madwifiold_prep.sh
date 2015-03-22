#!/bin/sh
#
# Script to setup atheros chipsets for packet injection using the (old) 
# madwifi driver.  This creates an "ath0raw" device that should be used 
# instead of ath0.  You may get a warning about not being able to put 
# the card into "monitor mode." This is OK and can be ignored.
#
# After running this script, run airpwn with the following arguments:
#
# -i ath0 -I ath0raw
#

sysctl -w dev.ath0.rawdev=1
#sysctl -w dev.ath0.acktimeout=1
ifconfig ath0raw up
