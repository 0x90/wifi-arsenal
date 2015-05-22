airport_ssdt_enabler
============
OS X Airport Half Mini

An airport_ssdt_enabler enables native Airport with non-native WiFi PCIe Half Mini cards on OS X/Mountain Lion/10.8.5 and newer. This method avoids dsdt and kext edits and is immune to Software Updates and BIOS revisions. 

Requirements
<<<<<<< HEAD
1. 10.8.5 or newer (This solution does not work in 10.8.4 or earlier)
2. AMI 6/7/8 Series UEFI
=======
1. OS X versions supported
1a.10.9 or newer
1b.10.8.5 or newer (This solution does not work in 10.8.4 or earlier)
2. AMI 7/8 Series UEFI
>>>>>>> e6a72efbae6cf519ccc16f7f7e8cd4178ba6f067
3. Airport Wifi card at: IOReg/RP0x/PSXS@0/vendor-id 
3a. <e4 14 00 00> (BCM) or 
3b. <8c 16 00 00> (AR)

Airport ssdt Enablers
1. airport_ssdt-ami..-bcm43xx_v1, supports
1a. BCM943224 HMS - 2.4/5 GHz, bgn, 2 stream, 300 Mbs
1b. BCM943225 HMB - 2.4 GHz, bgn, 2 stream, 108 Mbs + BT (3.0)
1c. BCM94352 HMB - 2.4/5 GHz, ac+abgn, 2 stream, 867 Mbs + BT (4.0)
2. airport_ssdt-ami.._ar928x_v1, supports
2a. AR9285 - 2.4 GHz, abgn, 1 stream, 150 Mbs
2b. AR9287 - 2.4 GHz, abgn, 2 stream, 300 Mbs

Downloads (select one*)
1. airport_ssdt-ami6-ar928x_v1.zip/View Raw/Save as .zip
2. airport_ssdt-ami7&8-ar928x_v1.zip/View Raw/Save as .zip
3. airport_ssdt-ami6-bcm43xx_v1.zip/View Raw/Save as .zip
4. airport_ssdt-ami7&8-bcm43xx_v1.zip/View Raw/Save as .zip
* ami6 - 6 Series motherboard, ami7&8 - 7 and 8 Series motherboards 

Tools
1. IORegistryExplorer https://github.com/toleda/audio_ALCInjection/blob/master/IORegistryExplorer_v2.1.zip
2. MaciASL http://sourceforge.net/projects/maciasl/?source=directory
3. DPCIManager http://sourceforge.net/projects/dpcimanager/

Edit airport PCIe Device Name (IOReg/RP0x)
1. MaciASL/File/Open/Downloads/airport_ssdt-…
2. Find: Method (_SB.PCI0.RP04.PXSX._DSM, 4, NotSerialized)
3. Edit: RP04 to RP0x (Use value x from IOReg/RP0x)
4. Save

Installation
1. Copy Downloads/airport_ssdt-.. . ./SSDT-2.aml to Extra
1a. If Extra/SSDT.aml is present and no SSDT-1.aml, install SSDT-2.aml as is: Extra/SSDT-1.aml
1b. If no Extra/SSDT.aml, rename SSDT-2.aml to SSDT.aml and install as: Extra/SSDT.aml
1c. The 1st SSDT is SSDT, 2nd is SSDT-1, 3rd is SSDT-2, etc.; no gaps
2. Enable SSDT (Chameleon/Chimera - DropSSDT, Clover - DropOem)
3. DPCIManager/Rebuild cache
4. Restart

Configuration/Troubleshooting
1.[Guide] [Guide]_airport_half-mini_details.pdf

Credit
MasterChef
bcc9 http://www.insanelymac.com/forum/topic/290783-intel-hd-graphics-4600-haswell-working-displayport/?p=1934889
PikeRAlpha https://pikeralpha.wordpress.com/2013/06/16/intel-hd4600-with-full-resolution/

toleda
https://github.com/toleda/airport_ARPTinjection
Files:
README.txt
ssdts:
1. airport_ssdt-ami6-ar928x_v1.zip
2. airport_ssdt-ami7&8-ar928x_v1.zip
3. airport_ssdt-ami6-bcm43xx_v1.zip
4. airport_ssdt-ami7&8-bcm43xx_v1.zip
