Firmware Files
==============

All the firmware files on this repository are licensed and copyrighted by Broadcom Inc.
These are all publicly distributed as part of the Windows 7/8/8.1 Bluetooth driver package.

Compression
===========

The .hex files are compressed for optimal file size using zlib.pl and renamed to .zhx to indicate zlib compression.
zlib.pl is written by Revogirl.

Usage
=====

.zhx files can be inserted into the BrcmPatchRAM plist as base64 data.
To convert the .zhx file to a hex dump for insertion into the plist, you can use "xxd -ps file.zhx > plist_hex.txt".

The resulting data can be inserted using Plist Editor Pro, or any other plist editor.