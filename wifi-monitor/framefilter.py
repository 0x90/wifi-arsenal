#! /usr/bin/env python

import sys
import pcap
import string
import time
import socket
import struct
import getopt

from linkquality import LinkQuality

## Necesarry Filters
SNR = 0
SRC = 1
DST = 2

##
# RX frame                               TX frame                             
# <------- Radiotap -------->            <------- Radiotap -------->            
# |                         |            |                         |          
# +----+----+----+----------+---//---+   +----+----+----+----------+---//---+ 
# |    |    |    |          |        |   |    |    |    |          |        | 
# | 00 | 00 | 1a | ........ |   aa   |   | 00 | 00 | 17 | ........ |   bb   | 
# |    |    |    |          |        |   |    |    |    |          |        | 
# +----+----+----+----------+---//---+   +----+----+----+----------+---//---+ 
#             ^                                      ^                        
#             |                                      |                        
#             +--- length = 26                       +--- length = 23         
#
# bit 'aa' = bit 'bb' << 3
# then, OFFSET = 3
##

#### 802.11a bitrate/modulation
DATARATE_11a = [6.0, 9.0, 12.0, 18.0, 24.0, 36.0, 48.0, 54.0]
DATARATE_11g = [1.0, 2.0, 5.5, 11.0] + DATARATE_11a

#### Radiotap Header
LENGTH = 2
DATARATE = 17
CHANNEL_FREQ = 18 # 18, 19
RADIO_RETRY_FLAG = 22
SSISIGNAL = 25

RADIOTAP_RX = { 
   LENGTH:LENGTH, 
   DATARATE:DATARATE,
   CHANNEL_FREQ:CHANNEL_FREQ,
   SSISIGNAL:SSISIGNAL
   }

RADIOTAP_TX = { 
   LENGTH:LENGTH,     
   DATARATE:DATARATE,
   RADIO_RETRY_FLAG:RADIO_RETRY_FLAG
   }

#### IEEE 802.11 MAC Header
OFFSET = 3

## Bit number in RX frame
SUBTYPE = 26
RETRY_FLAG = 27
DST_ADDR = 30 # 30 - 35
SRC_ADDR = 36 # 36 - 41
BSSID = 42 # 42 - 47

IEEE_DATA_RX = { 
   SUBTYPE:SUBTYPE,
   RETRY_FLAG:RETRY_FLAG,
   DST_ADDR:DST_ADDR,
   SRC_ADDR:SRC_ADDR,
   BSSID:BSSID 
   }

IEEE_DATA_TX = { 
   SUBTYPE:SUBTYPE - OFFSET,
   RETRY_FLAG:RETRY_FLAG - OFFSET,
   DST_ADDR:DST_ADDR - OFFSET,
   SRC_ADDR:SRC_ADDR - OFFSET,
   BSSID:BSSID - OFFSET
   }

RX = { 
   LENGTH:RADIOTAP_RX[LENGTH], 
   SRC_ADDR:IEEE_DATA_RX[SRC_ADDR],
   DST_ADDR:IEEE_DATA_RX[DST_ADDR],
   SSISIGNAL:RADIOTAP_RX[SSISIGNAL],
   SUBTYPE:IEEE_DATA_RX[SUBTYPE],
   DATARATE:RADIOTAP_RX[DATARATE],
   RETRY_FLAG:IEEE_DATA_RX[RETRY_FLAG]
   }

TX = {
   LENGTH:RADIOTAP_TX[LENGTH],
   SRC_ADDR:IEEE_DATA_TX[SRC_ADDR],
   DST_ADDR:IEEE_DATA_TX[DST_ADDR],
   SUBTYPE:IEEE_DATA_TX[SUBTYPE],
   DATARATE:RADIOTAP_TX[DATARATE],
   RETRY_FLAG:RADIOTAP_TX[RADIO_RETRY_FLAG]
   }

### Class FrameFilter
##--------------------------------------------------------------------------
## FUNCTION  : 
## PURPOSE   : 
## ARGUMENTS : 
## RETURN    : 
## External Library : 
##--------------------------------------------------------------------------
class FrameFilter(object):
    def __init__(self, cf, th, ft):
        super(FrameFilter, self).__init__()

        # Static Global Values
        self.cf = cf
        self.fil = ft
        self.thr = th
        self.my_addr = [ cf.ether_aaddr, cf.ether_maddr ] # both ath0 and ath1
        #print "init................... [%s]" % self.my_addr
        self.channel = cf.channel
        #self.dst_addr = daddr

        # Variable Local Values
        self.timestamp = ''
        self.frame = 0
        self.rx_frame = 0
        self.tx_frame = 0
        #self.addr_snr = {}
        self.addr_lq = {}

        # Static Local Values per frame
        self.saddr = ''
        self.daddr = ''
        self.snr = 0
        self.rate = 0
        self.rt = 0

    def is_higher(self, addr):
        try:
            print "Current EMA SNR %.2f : Threshold SNR %i" % (self.addr_lq[addr].snr.emavalue(0.8), self.thr)
            if self.addr_lq[addr].snr.emavalue(0.8) > self.thr:
                return True

            else:
                return False
        
        except KeyError:
            pass
            #print "is_higher(): pass"
        
    def dump_hex(self, raw):
        return map(lambda x: '%.2x' % x, map(ord, raw))

    def filter_rt(self, bytes):
        if bytes[LENGTH] == '17':
            return TX
        
        elif bytes[LENGTH] == '1a':
            return RX

    def filter_beacon(self, bytes, key):
        #print "key[SUBTYPE]", key[SUBTYPE}
        #print "filter_beacon %s " % bytes[key[SUBTYPE]]
        if bytes[key[SUBTYPE]] == '80':
            return 1
        
        else:
            #print "FRAME is NOT BEACON"
            return 0

    def filter_data(self, bytes, key):
        if bytes[key[SUBTYPE]] == '08':
            return 1
        
        else:
            #print "FRAME is NOT DATA"
            return 0


    def filter_src_addr(self, bytes, addr, key):
        self.saddr = string.join(bytes[key[SRC_ADDR]:key[SRC_ADDR] + 6], ':')
        #print "self.saddr", self.saddr
        if self.saddr in addr:
            return 1

        else:
            return 0


    def filter_dst_addr(self, bytes, addr, key):
        self.daddr = string.join(bytes[key[DST_ADDR]:key[DST_ADDR] + 6], ':')
        #print "self.daddr", self.daddr
        if self.daddr in addr:
            return 1

        else:
            return 0


##
# RX functions
##
    def filter_snr(self, bytes, key):
        self.snr = int(string.atoi(bytes[key[SSISIGNAL]], 16))

        self.regist_addr_lq(self.saddr)
        self.push_snr(self.snr, self.saddr)

    def push_snr(self, snr, addr):
        try:
            self.addr_lq[addr].snr.push(snr)
            #print "DEBUG [%s]: SNR = %i" % (addr, snr)

        except KeyError:
            #print "[%s] is currently not registed yet." % addr
            pass

    def regist_addr_lq(self, addr):
        if not self.addr_lq.has_key(addr) and len(addr) == 17: # First time
            self.addr_lq[addr] = LinkQuality(addr, self.thr, self.channel)
            print "register receive address: ", self.addr_lq[addr]

##
# TX functions
##
    def filter_bitrate(self, bytes, key):
        self.rate = string.atoi(bytes[key[DATARATE]], 16) / 2.0
        self.regist_addr_lq(self.daddr)

        if self.rate not in DATARATE_11g:
            #print "DATARATE is UNKNOWN"
            return 0
        
        else:
            #self.addr_lq[self.daddr].rate.append(self.rate)
            try:
                self.addr_lq[self.daddr].rate[self.rate] += 1
            except KeyError:
                print "First time bitrate added."
                self.addr_lq[self.daddr].rate[self.rate] = 1

            return 1


    def filter_retry_count(self, bytes, key):
        self.addr_lq[self.daddr].all += 1
        #print "self.LQ.all", self.addr_lq[self.daddr].all

        tmp_flag = int(bytes[key[RETRY_FLAG]], 16)
        #print "tmp_flag", tmp_flag, bytes[key[RETRY_FLAG]]
        if tmp_flag & 0x08 == 8 or bytes[key[RETRY_FLAG]] == '01':
            self.addr_lq[self.daddr].retry += 1
            return 1

        else:
            #print "FRAME is not retransmitted"
            return 0

##
# Print Functions
##
    def print_rx_filter(self, int):
        #print self.rate
        #print self.rx_frame

        if not (self.frame % 300):
            print "%s: monitoring RX Beacon frame [%u]" % (int, self.rx_frame)
            for saddr in self.addr_lq:
                #print self.addr_lq[saddr].snr.emavalues
                #print self.addr_lq[saddr].snr.values
                print "      EMA SNR[%s]  : %f" % (saddr, self.addr_lq[saddr].snr.emavalue(0.8))

    def print_tx_filter(self, int):
        #print self.rate
        #print self.tx_frame

        if not (self.frame % 100):
            #print_stime = time.time()
            #print "print_tx_filter: loop starts %f" % print_stime
            #print "%s: monitoring Data frames [%u]" % (int, self.tx_frame)
            #print self.addr_lq

            for daddr in self.addr_lq:
                #print self.addr_lq[daddr].snr.emavalue(0.8)

                if self.is_higher(daddr): # Algorithm 1, but just for print purpose
                    try:
                        print "      EMA SNR[%s]  : %f" % (daddr, self.addr_lq[daddr].snr.emavalue(0.8))
                        print "      rt count[%s]  : %i" % (daddr, self.addr_lq[daddr].retry)

                    except KeyError:
                        print "[%s] is currently not registed yet." % daddr
                    
            
                    print "      8 available bit-rates[%s]:" % daddr
                    for rate in DATARATE_11a:
                        try:
                            print "            %.1f Mb/s  : %i" % (rate, self.addr_lq[daddr].rate[rate])
                        except KeyError:
                            print "            %.1f Mb/s  : 0" % rate
                            #print "[%s] is currently not registed yet." % daddr

            #print_etime = time.time()
            #print "print_tx_filter: loop ends %f in %f" % (print_stime, print_etime - print_stime)

        ## for experimentation 200812111900
        for daddr in self.addr_lq:
            self.addr_lq[daddr].refresh(self.addr_lq[daddr].snr.emavalue(0.8), self.timestamp) # print rtETX

##
# Main Functions: RX filter & TX filter
##
    def filter_rx(self, bytes, key):
        """docstring for filter_rx"""
        #bytes = self.dump_hex(raw)
        self.rx_frame += 1        

        if self.filter_beacon(bytes, key): # Measure SNR from beacon frames
        #if self.filter_data(bytes, key): # Measure SNR from data frames
        #if 1: # promiscous data type 
            #if self.fil[DST]:  # When packets are sent to this node
            self.filter_src_addr(bytes, [], key) # to get self.saddr
            self.filter_dst_addr(bytes, self.my_addr, key) # to get self.daddr

            #if self.fil[SNR]:
            self.filter_snr(bytes, key)


    def filter_tx(self, bytes, key):
        """docstring for filter_tx"""
        #bytes = self.dump_hex(raw)
        self.tx_frame += 1        

        if self.filter_data(bytes, key):
            if self.fil[SRC]: # When packets are sent by this node
                if not self.filter_src_addr(bytes, [], key):
                    return 0
                
            if self.fil[DST]:
                if not self.filter_dst_addr(bytes, self.daddr, key):
                    return 0

            if self.filter_bitrate(bytes, key):
                if self.filter_retry_count(bytes, key):
                    return 1



    def filter_rxtx(self, bytes, key):
        """docstring for filter_rt"""
        #print "\n"

        if self.filter_beacon(bytes, key): # Measure SNR from beacon frames
            #print "RRRRRRR"
            self.rx_frame += 1

            self.filter_src_addr(bytes, [], key) # to get self.saddr
            self.filter_dst_addr(bytes, [], key) # to get self.daddr

            self.filter_snr(bytes, key) # to get SNR and register hosts


        elif self.filter_data(bytes, key):
            self.tx_frame += 1        
            if self.fil[SRC]: # When packets are sent by this node (either adhoc int. or monitor int.)
                if not self.filter_src_addr(bytes, self.my_addr, key):
                    #print "XXXXXXX"
                    return 0
                
            self.filter_dst_addr(bytes, self.daddr, key) # to get self.daddr

            if self.filter_bitrate(bytes, key):
                #print "YYYYYYYY"
                self.filter_retry_count(bytes, key) # in retry_count add lq.all++ (and lq.retry++ in case)
                return 1


        else:
            #print "ZZZZZZZZ"
            return 0

##
# Callable Function
##
    def filter(self, pktlen, raw, timestamp):
        """docstring for filter"""
        self.timestamp = timestamp
        self.frame += 1

        bytes = self.dump_hex(raw)
        key = self.filter_rt(bytes)

        #self.filter_rx(bytes, key)
        #self.filter_tx(bytes, key)
        self.filter_rxtx(bytes, key)
