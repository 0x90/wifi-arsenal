ath9k_ath5k_full_permissive_unlock_all_channels.patch
=====================================================

This kernel patch enable all 2GHZ &amp; 5GHZ channels (without restriction) for ath9k &amp; ath5k forced to use buildin world regulatory. Work with: 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6c, 0x8***

ATTENTION: THIS PATCH ENABLE CHANNELS THAT ARE NOT FREELY USABLE IN MANY COUNTRIES. USE THE PATCH WITH CARE AND YOUR TOTAL RISK. I AM NOT RESPONSIBLE FOR ANYTHING!

Tested with kernel 3.9.4

Apply the patch:

patch -d /usr/src/linux/drivers/net/wireless/ath/ < ath9k_ath5k_full_permissive_unlock_all_channels.patch 

and then recompile.

I hope it will be useful...

Doom5 <doom5@inbox.com> 
