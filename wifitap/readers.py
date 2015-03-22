########################################
#
# Copyright (C) 2011 Daniel Smith <viscous.liquid@gmail.com>
# Copyright (C) 2005 Cedric Blancher <sid@rstack.org>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation; version 2.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
#########################################

import os,sys,struct,re,string,asyncore

from scapy.all import Raw,Ether,RadioTap,Dot11,Dot11WEP,LLC,SNAP,sendp,conf

class WifiTapReader(asyncore.file_dispatcher):
    def __init__(self, wifitap, map=None):
        self._tap = wifitap

        if not wifitap.is_open():
            wifitap.open()

        self.fd = wifitap.fileno()
        asyncore.file_dispatcher.__init__(self, self.fd, map)

    def radiotap(self):
        present = ''
        data = ''

        if self._tap.rate is not None:
            if present == '':
                present = 'Rate'
            else:
                present += '+Rate'
            data += struct.pack('<B',((self._tap.rate)*10)/5)

        if self._tap.power is not None:
            if present == '':
                present = 'dBm_TX_Power'
            else:
                present += '+dBm_TX_Power'
            data += struct.pack('<b',self._tap.power)

        if self._tap.tx_flags is not None:
            pass

        if self._tap.retries is not None:
            if present == '':
                present = 'b17'
            else:
                present += '+b17'
            data += struct.pack('<B',self._tap.retries)

        if self._tap.mcs is not None:
            pass

        if present == '':
            rt = RadioTap()
        else:
            rt = RadioTap(present=present, notdecoded=data)

        return rt

    def writable(self):
        return False

    def handle_read(self):
        # | 4 bytes | 4 bytes |   18 bytes   |     1500 bytes    |
        #     Tap       VLAN    Ether Header          Frame
        buf = self.read(1526)
        eth_rcvd_frame = Ether(buf[4:])

        #if DEBUG:
        #    os.write(1,"Received from %s\n" % ifname)
        #    if VERB:
        #        os.write(1,"%s\n" % eth_rcvd_frame.summary())

        # Prepare Dot11 frame for injection
        dot11_sent_frame = self.radiotap()

        dot11_sent_frame /= Dot11(
            type = "Data",
            FCfield = "from-DS",
            addr1 = eth_rcvd_frame.getlayer(Ether).dst,
            addr2 = self._tap.bssid)

        # It doesn't seem possible to set tuntap interface MAC address
        # when we create it, so we set source MAC here
        if self._tap.smac == '':
            dot11_sent_frame.addr3 = eth_rcvd_frame.getlayer(Ether).src
        else:
            dot11_sent_frame.addr3 = self._tap.smac

        if self._tap.has_wep:
            dot11_sent_frame.FCfield |= 0x40
            dot11_sent_frame /= Dot11WEP(
                iv = "111",
                keyid = self._tap.key_id)

        dot11_sent_frame /= LLC(ctrl = 3)/SNAP(code=eth_rcvd_frame.getlayer(Ether).type)/eth_rcvd_frame.getlayer(Ether).payload

        #if DEBUG:
        #    os.write(1,"Sending from-DS to %s\n" % OUT_IFACE)
        #    if VERB:
        #        os.write(1,"%s\n" % dot11_sent_frame.summary())

        # Frame injection :
        sendp(dot11_sent_frame,verbose=0) # Send from-DS frame

    def handle_except(self):
        pass

    def handle_close(self):
        self.close

class InterfaceReader(asyncore.file_dispatcher):
    def __init__(self, wifitap, map=None):
        self._tap = wifitap

        # Here we put a BPF filter so only 802.11 Data/to-DS frames are captured
        self.fd = conf.L2listen(iface = wifitap.inface,
            filter = "link[0]&0xc == 8 and link[1]&0xf == 1")

        asyncore.file_dispatcher.__init__(self, self.fd, map)

    def writable(self):
        return False

    def handle_read(self):
        # 802.11 maximum frame size is 2346 bytes (cf. RFC3580)
        # However, WiFi interfaces are always MTUed to 1500
        dot11_rcvd_frame = self.fd.recv(2346)

        # WEP handling is automagicly done by Scapy if conf.wepkey is set
        # Nothing to do to decrypt (although not yet tested)
        # WEP frames have Dot11WEP layer, others don't

        #if DEBUG:
        #    if dot11_rcvd_frame.haslayer(Dot11WEP): # WEP frame
        #        os.write(1,"Received WEP from %s\n" % self._intf)
        #    else: # Cleartext frame
        #        os.write(1,"Received from %s\n" % self._intf)
        #    if VERB:
        #        os.write(1,"%s\n" % dot11_rcvd_frame.summary())

	#    if dot11_frame.getlayer(Dot11).FCfield & 1: # Frame is to-DS
	# For now, we only take care of to-DS frames...

        if dot11_rcvd_frame.getlayer(Dot11).addr1 != self._tap.bssid:
            return

	# One day, we'll try to take care of AP to DS trafic (cf. TODO)
	#    else: # Frame is from-DS
	#        if dot11_frame.getlayer(Dot11).addr2 != BSSID:
	#            continue
	#	eth_frame = Ether(dst=dot11_frame.getlayer(Dot11).addr1,
	#           src=dot11_frame.getlayer(Dot11).addr3)
	    
        if dot11_rcvd_frame.haslayer(SNAP):
            eth_sent_frame = Ether(
                dst=dot11_rcvd_frame.getlayer(Dot11).addr3,
                src=dot11_rcvd_frame.getlayer(Dot11).addr2,
                type=dot11_rcvd_frame.getlayer(SNAP).code)
            eth_sent_frame.payload = dot11_rcvd_frame.getlayer(SNAP).payload

            #if DEBUG:
            #    os.write(1, "Sending to %s\n" % ifname)
            #    if VERB:
            #        os.write(1, "%s\n" % eth_sent_frame.summary())

            # Add Tun/Tap header to frame, convert to string and send
            buf = "\x00\x00" + struct.pack("!H",eth_sent_frame.type) + str(eth_sent_frame)
            os.write(self.fd, buf)

    def handle_except(self):
        pass

    def handle_close(self):
        self.close

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4 autoindent
