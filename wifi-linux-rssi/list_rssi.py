#!/usr/bin/env python
#-*- encoding: utf-8 -*-
import dbus
import gobject 
import os
import sys
import glib 
from dbus.mainloop.glib import DBusGMainLoop 
import Gnuplot 
class WiFiList(): 
    def __init__(self, timer, watched):
        self.bus = dbus.SystemBus()
        self.NM = 'org.freedesktop.NetworkManager'
        self.bus.add_signal_receiver(self.handle_change, None, self.NM + '.AccessPoint', None, None)
        nm = self.bus.get_object(self.NM, '/org/freedesktop/NetworkManager')
        self.devlist = nm.GetDevices(dbus_interface = self.NM) 
        self.rssid = {}
        self.gnpl = Gnuplot.Gnuplot()
        self.timing = 0
        self.data = {}
        self.watched = watched
        self.timer = timer
        self.plotchange = 0

    def __repr__(self):
        return "\n".join(["%20s: %5d" % (k, j) for k, j in self.rssid.items()])

    def dbus_get_property(self, prop, member, proxy):
        return proxy.Get(self.NM+'.' + member, prop, dbus_interface = 'org.freedesktop.DBus.Properties')

    def repopulate_ap_list(self):
        apl = []
        res = []
        for i in self.devlist:
            tmp = self.bus.get_object(self.NM, i)
            if self.dbus_get_property('DeviceType', 'Device', tmp) == 2:
                apl.append(self.bus.get_object(self.NM, i).GetAccessPoints(dbus_interface = self.NM+'.Device.Wireless'))
        for i in apl:
            for j in i:
                res.append(self.bus.get_object(self.NM, j))
        return res
    
    def form_rssi_dic(self):
        for i in self.repopulate_ap_list():
            ssid = self.dbus_get_property('Ssid', 'AccessPoint', i)
            strength = self.dbus_get_property('Strength', 'AccessPoint', i);
            self.rssid["".join(["%s" % k for k in ssid])] =  int(strength)

    def handle_change(self, kwargs = None):
        print "changed"
        self.form_rssi_dic()
        if self.plotchange == 1:
            self.timeout()

    def plotter(self, data):
        self.gnpl('set terminal x11 size 1024 3000')
        self.gnpl('set grid')
        self.gnpl('set multiplot')
        cnt = 0
        for i in data:
            cnt+=1
            self.gnpl('set origin 0, %f' % (1 - 0.33*cnt))
            self.gnpl('set size 1, %f' % (0.33))
            self.gnpl('set style data linespoints')
            self.gnpl.title(i)
            self.gnpl.plot(data[i])
        self.gnpl('unset multiplot')

    def timeout(self, breakpoint = False):
        self.timing+=1;
        for i in [x for x in self.watched if x in self.rssid]:
            if i in self.data.keys():
                self.data[i].append([self.timing, self.rssid[i]])
                if breakpoint:
                    self.data[i].append([self.timing, self.rssid[i]+4])
                    self.data[i].append([self.timing, self.rssid[i]-4])
                    self.data[i].append([self.timing, self.rssid[i]])
            else:
                self.data[i] = []
                self.data[i].append([self.timing, self.rssid[i]])
                if breakpoint:
                    self.data[i].append([self.timing, self.rssid[i]+4])
                    self.data[i].append([self.timing, self.rssid[i]-4])
                    self.data[i].append([self.timing, self.rssid[i]])
        return True

    def iowch(self, arg, key, loop):
        cmd = sys.stdin.readline()
        if "plot" in cmd: 
            print 'plotting your wifi data'
            self.plotter(self.data)
        if "bp" in cmd:
            print 'added a breakpoint'
            self.timeout(breakpoint = True)
        if "stop" in cmd:
            print 'stop program'
            loop.quit()
            return False
        if "print" in cmd:
            print self
        if "start" in cmd:
            gobject.timeout_add(self.timer,self.timeout)
        if "start changer" in cmd:
            print "started plotting as a function of changes"
            self.plotchange = 1
        return True

if __name__ == '__main__':
    loop = gobject.MainLoop()
    DBusGMainLoop(set_as_default=True)
    try:
        timeout = int(sys.argv[1]) * 1000
    except:
        timeout = 5000
    print timeout
    wfl = WiFiList(timeout, sys.argv[2:])
    wfl.form_rssi_dic()
    gobject.io_add_watch(sys.stdin, glib.IO_IN, wfl.iowch, loop)
    print wfl
    loop.run()
