The reghack utility replaces the regulatory domain rules in the driver binaries
with less restrictive ones. The current version also lifts the 5GHz radar
channel restrictions in ath9k.

This version is made for current OpenWrt trunk. To patch older releases like 12.09,
use http://luci.subsignal.org/~jow/reghack/old/ .

How to use:

ssh root@openwrt

On ar71xx:

cd /tmp/
wget http://luci.subsignal.org/~jow/reghack/reghack.mips.elf
chmod +x reghack.mips.elf
./reghack.mips.elf /lib/modules/*/ath.ko
./reghack.mips.elf /lib/modules/*/cfg80211.ko
reboot

On mpc85xx:

cd /tmp/
wget http://luci.subsignal.org/~jow/reghack/reghack.ppc.elf
chmod +x reghack.ppc.elf
./reghack.ppc.elf /lib/modules/*/ath.ko
./reghack.ppc.elf /lib/modules/*/cfg80211.ko
reboot

On x86:

cd /tmp/
wget http://luci.subsignal.org/~jow/reghack/reghack.x86.elf
chmod +x reghack.x86.elf
./reghack.x86.elf /lib/modules/*/ath.ko
./reghack.x86.elf /lib/modules/*/cfg80211.ko

On amd64:

cd /tmp/
wget http://luci.subsignal.org/~jow/reghack/reghack.x86_64.elf
chmod +x reghack.x86_64.elf
./reghack.x86_64.elf /lib/modules/*/ath.ko
./reghack.x86_64.elf /lib/modules/*/cfg80211.ko
