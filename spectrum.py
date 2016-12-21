#!/usr/bin/env python
#
# Copyright 2015 Bastian Bloessl <bloessl@ccs-labs.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import array
import struct
import sys
import time

from subprocess import call

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt

phy = "phy0"

call("echo chanscan > /sys/kernel/debug/ieee80211/" + phy + "/ath9k_htc/spectral_scan_ctl", shell=True)

plt.ion()
fig = plt.figure()
ax = fig.add_subplot(111)

scatter, = ax.plot([2400, 2480], [-160, 50], 'r*')
scatter_min, = ax.plot([], [], 'bx')
scatter_max, = ax.plot([], [], 'go')
plt.show()


print "time,freq,signal"

while True:

    ### do measurement
    call("iw dev wlan0 scan &>/dev/null", shell=True)
    call("cat /sys/kernel/debug/ieee80211/" + phy + "/ath9k_htc/spectral_scan0 > data", shell=True)

    with open("data", "rb") as file:

        data = file.read(76)

        x = []
        y = []
        now = time.time()

        while data != "":
            t, length = struct.unpack(">BH", data[0:3])

            if t != 1 or length != 73:
                print "only 20MHz supported atm"
                sys.exit(1)

            ### metadata
            max_exp, freq, rssi, noise, max_magnitude, max_index, bitmap_weight, tsf = struct.unpack('>BHbbHBBQ', data[3:20])

            #print "max_exp: "       + str(max_exp)
            #print "freq: "          + str(freq)
            #print "rssi: "          + str(rssi)
            #print "noise: "         + str(noise)
            #print "max_magnitude: " + str(max_magnitude)
            #print "max_index: "     + str(max_index)
            #print "bitmap_weight: " + str(bitmap_weight)
            #print "tsf: "           + str(tsf)

            ### measurements
            measurements = array.array("B")
            measurements.fromstring(data[20:])

            squaresum = sum([(m << max_exp)**2 for m in measurements])
            if squaresum == 0:
                data = file.read(76)
                continue

            for i, m in enumerate(measurements):
                if m == 0 and max_exp == 0:
                    m = 1
                v = 10.0**((noise + rssi + 20.0 * np.log10(m << max_exp) - 10.0 * np.log10(squaresum))/10.0)

                if i < 28:
                    f = freq - (20.0 / 64) * (28 - i)
                else:
                    f = freq + (20.0 / 64) * (i - 27)

                x.append(f)
                y.append(v)
                print str(now) + "," + str(f) + "," + str(v)

            data = file.read(76)

        df = pd.DataFrame(np.matrix([x, y]).T, columns = ["freq", "rssi"])
        group = df.groupby('freq')
        spectrum = group.mean()
        spectrum_min = group.min()
        spectrum_max = group.max()

        ### print output
        #sys.stdout.write(str(time.time()))
        #for freq, row in spectrum.iterrows():
        #    sys.stdout.write("," + str(freq) + ":" + str(row['rssi']))
        #sys.stdout.write("\n")
        scatter.set_xdata(spectrum.index)
        scatter.set_ydata([10.0 * np.log10(val) for val in spectrum['rssi']])

        scatter_min.set_xdata(spectrum_min.index)
        scatter_min.set_ydata([10.0 * np.log10(val) for val in spectrum_min['rssi']])

        scatter_max.set_xdata(spectrum_max.index)
        scatter_max.set_ydata([10.0 * np.log10(val) for val in spectrum_max['rssi']])
        fig.canvas.draw()

