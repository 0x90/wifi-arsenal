## Introduction

This is a simple spectrum visualizer based on the ath9k spectral scan feature.
If you have a Qualcomm/Atheros Wifi device on Linux, and have built the
driver with debugfs support, you can use this program to see the RF spectrum
in something resembling real-time.

![UI](http://bobcopeland.com/images/lj/speccy-anim.gif)

## Prerequisites

 * a device that supports the spectral scan feature (ath9k and ath9k\_htc
   drivers tested at this point)
 * above drivers compiled with debugfs enabled
 * the iw utility installed

## Usage

As root, run:
```
# ./speccy.py wlan0
```
where ```wlan0``` is the device you'd like to use.

## Key bindings

 * 'l' - Toggle line graph
 * 's' - Toggle scatter plot
 * 'q' - Quit the program

