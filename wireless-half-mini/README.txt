wireless_half-mini
============
OS X Airport Half Mini (WiFi and Bluetooth)

Updates
2/12/2015 10.10.2 Update; added 1. BCM94360HMB, 2. wireless_bcm94352-100-v2.0.command and 3. config-bcm94352-102.plist. wireless_bcm94352-100_patch.command deprecated
12/9/2014 New Broadcomm Bluetooth 4.0 solution, see BCM94352 BT4
11/19/2014 GYMLE BT4LE/Handoff
11/16/2014 BCM94352/US-FCC patch, Credit: webcivilian
11/12/2014 Yosemite Release/BCM94352 5GHz/Handoff

Airport working OOB on Mavericks with Broadcom BCM94360/BCM94331/BCM943224 and Atheros AR9280   OS X reports as Airport Extreme; Wake on Wireless and AirDrop supported.  Newer Broadcom WiFi cards no longer require rebranding to work in OS X.

BCM943224 HMS, BCM943225 HMB and BCM94352 HMB  PCIe Half Mini versions tested.  AR9280, AR9285 and AR9287 PCIe Half Mini versions tested.   Mini PCIe versions and Mini PCIe to PCIe versions work; BT 4.0 requires USB motherboard connector. 

Requirements
1. 10.10 and newer
2. 10.9 and newer
3. 10.8.5 or newer (Solution does not work in 10.8.4 or earlier) 

Airport Half Mini Guides:
1. [Guide]_airport_half-mini_details.pdf.zip
2. [Guide]_airport_half-mini_dsdt_edits.pdf.zip
3. [Guide]_airport_half-mini_plist_edits.pdf.zip

Native Airport Half Mini cards.
1. BCM94360HMB - 2.4/5 GHz, ac+abgn, 3 Stream, 1300 Mbs
2. BCM94360CD - 2.4/5 GHz, ac+abgn, 3 Stream, 1300 Mbs  (PCIe x1, not HM)
3. BCM94331CD - 2.4/5 GHz, abgn, 3 stream, 450 Mbs + BT (4.0) 10.10+/Whitelist
4. BCM943224 HMS/HMB - 2.4/5, GHz abgn, 2 stream, 150/300 Mbs 10.10+/Whitelist
5. AR9280 - 2.4/5 GHz, abgn, 2 Stream, 300 Mbs
6. AR9380 - 2.4/5 GHz, abgn, 3 Stream, 450 Mbs

Non-Native Airport Half Mini cards, see [Guide] airport_half_mini_details.pdf
1. BCM94352 HMB - 2.4/5 GHz, ac+abgn, 2 stream, 867 Mbs + BT (4.0)
2. BCM943225 HMS - 2.4 GHz, bgn, 2 stream, 108/150 Mbs
3. BCM943225 HMB - 2.4 GHz, bgn, 2 stream, 108/150 Mbs + BT (3.0)
4. AR9285 - 2.4 GHz, abgn, 1 stream, 54/75 Mbs
5. AR9287 - 2.4 GHz, abgn, 2 stream, 108/150 Mbs

WiFi + BT
1. BCM943352 HMB/AzureWave AW-CE123H supports both Airport and Bluetooth 4.0
2. BCM943225 HMB supports both Airport and Bluetooth 3.0
3. For any working WiFi without BT; 4.0, wake, low energy, native - suggest:
http://www.gmyle.com/products/micro-usb-bluetooth-4-0-dongle-dual-mode-w-low-energy-technology-wireless-adapter-broadcom-bcm20702-chipset-x10

BCM94352 5 GHz/Handoff Patch (10.10 and newer) Credit: Skvo, Dokterdok, webcivilian
1. Kext/binary patch
   1. Download (View Raw)  wireless_bcm94352-100-v2.0.command.zip
   2. Double click Downloads/ wireless_bcm94352-100-v2.0.command
2. Clover patch
   1. Download (View Raw)
	1. 10.10.2 and newer, config-bcm94352-102.plist.zip
	2. 10.10 and 10,10.1. config-bcm94352-100.plist.zip
   2. Paste 3 Patches to config.plist/KernelAndKextPatches/KextsToPatch

BCM94352 5 GHz Patch (10.9 and newer) - Credit: Skvo
1. Kext/binary patch
   1. Download (View Raw) wireless_bcm94352-90_patch.command.zip
   2. Double click Downloads/wireless_bcm94352-90_patch.command
2. Clover patch
   1. Download (View Raw) config-bcm94352-90.plist.zip
   2. Add 3 Patches to config.plist/KernelAndKextPatches/KextsToPatch
3. wireless_half-mini-brcm4360-90_patch.command deprecated

BCM94352 BT4 (10.10 and newer, 10.9 and newer), either choice, not both
1. https://github.com/robvanoostenrijk/BrcmPatchRAM/releases

Airport Injection Methods
1. kext enabler, see airport_kext_enabler/README.txt
2. kext edit/Info.plist, see [Guide] airport_half_mini_plist_edits.pdf
3. dsdt edits, [Guide] airport_half_mini_dsdt_edits.pdf
4. ssdt enabler, see airport_ssdt_enabler/README.txt

Installation/Configuration/Troubleshooting
[Guide] airport_half-mini_details.pdf.zip

Problem Reporting (include the following information)
1. Description of wireless problem
2. OS X version/motherboard model/BIOS version/processor/graphics
3. Copy of IOReg - IOReg_v2.1/File/Save a Copy As…, verify file (not
   ioreg.txt)
4. Extra/org.chameleon.Boot.plist or EFI/Clover/config.plist
5. Extra/dsdt.aml or EFI/Clover/ACPI/Patched/dsdt.aml (if installed)
6. Extra/dsdt.aml or EFI/Clover/ACPI/Patched/ssdt.aml (if installed)
7. Console/All Messages/kernel bcn/ath messages selected/Save
   Selection As…..
8. WiFi: Screenshot of System Information/Hardware/Network and WiFi
9. Bluetooth: Screenshot of System Information/Hardware/Bluetooth and 
   USB/Bluetooth USB Host Controller
Post to:
1. http://www.tonymacx86.com/network/104850-guide-airport-pcie-half-mini-v2.html
2. http://www.insanelymac.com/forum/topic/292542-airport-pcie-half-mini/

Credit
THe KiNG 
Andy Vandijck
PikeRAlpha
Skvo
Dokterdok
webcivilian
AREOS
the-darkvoid
Machanical
sefki21

toleda
https://github.com/toleda/airport_half_mini
