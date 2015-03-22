airport_kext_enabler
============
OS X Airport PCIe Half Mini

An airport_kext_enabler enables native Airport with non- native WiFi PCIe Half Mini cards on OS X/Mountain Lion/10.8.5 and newer. This method avoids dsdt and kext edits and is immune to Software Updates and BIOS revisions. 

Requirements
1. !0.9 or newer
2. 10.8.5 or newer (This solution does not work in 10.8.4 or earlier)

Airport Kext Enablers
1. bcm4352.kext - enables Airport WiFi and BT on installed BCM94352/AE-CE123H WiFi Card
1a. Airport 802.11 ac/a/b/g/n dual band WiFi
1b. BT 4.0 dual mode with Low Energy Technology

2. bcm4352bt.kext - enables BT on installed BCM94352 WiFi Card
2a. Use dsdt/ssdt to enable WiFi
2b. BT 4.0 dual mode with Low Energy Technology

3. toledaARPT.kext - enables Airport WiFi with the specified Non-Native Airport PCIe Half Mini cards, see [Guide] airport_pcie-hm_details.pdf
2a. BCM943224 HMS - 2.4/5 GHz, bgn, 2 stream, 300 Mbs
2b. BCM943225 HMB - 2.4 GHz, bgn, 2 stream, 108 Mbs + BT (3.0)
2c. AR9285 - 2.4 GHz, abgn, 1 stream, 150 Mbs
2d. AR9287 - 2.4 GHz, abgn, 2 stream, 300 Mbs
2e. BT - Broadcom default

Downloads (select one)
1. Select bcm4352.kext.zip/View Raw
2. Select bcm4352t.kext.zip/View Raw
3. Select toledaARPT.kext.zip/View Raw
=======
2. bcm4352bt.kext - enables BT on installed BCM94352/AE-CE123H WiFi Card
2a. BT 4.0 dual mode with Low Energy Technology
3. toledaARPT.kext - enables Airport WiFi with the specified Non-Native Airport PCIe Half Mini cards, see [Guide] airport_pcie-hm_details.pdf.zip
3a. BCM943224 HMS - 2.4/5 GHz, bgn, 2 stream, 300 Mbs
3b. BCM943225 HMB - 2.4 GHz, bgn, 2 stream, 108 Mbs + BT (3.0)
3c. BCM94352 HMB - 2.4/5 GHz, ac+abgn, 2 stream, 867 Mbs + BT (4.0)
3d. AR9285 - 2.4 GHz, abgn, 1 stream, 150 Mbs
3e. AR9287 - 2.4 GHz, abgn, 2 stream, 300 Mbs
3f. BT - Broadcom default

Downloads (select one)
1a. bcm4352.kext.zip - bcm4352/aw-ce123h WiFi + BT
1b. bcm4352bt.kext.zip - bcm4352/aw-ce123h BT only
1c. toledaARPT.kext.zip - see [Guide] airport_pcie-hm_details.pdf.zip
>>>>>>> e6a72efbae6cf519ccc16f7f7e8cd4178ba6f067

Tools
1. Kext installers - KextBeast, Kext Utility, DPCIManager

Installation
1. Copy Downloads/
1a. bcm4352.kext to Desktop or
<<<<<<< HEAD
1b. bcm4352t.kext to Desktop or
=======
1b. bcm4352bt.kext to Desktop or
>>>>>>> e6a72efbae6cf519ccc16f7f7e8cd4178ba6f067
1c. toledaARPT.kext to Desktop
2. Run kext installer
3. Restart
4. Configure System Preferences/Network/Airport
5. Verify Airport

Configuration/Troubleshooting
1.[Guide] airport_pcie-hm_details.pdf

Credit
MasterChef
EMlyDinEsH

toleda
https://github.com/toleda/airport_ARPTinjection
Files:
toledaARPT.kext