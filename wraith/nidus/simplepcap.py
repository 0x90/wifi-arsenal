#!/usr/bin/env python

""" simplepcap.py: pcap writer (802.11 packets)

provides a pythonic pcap writer for 802.11 frames w/o requiring additional libraries
see http://wiki.wireshark.org/Development/LibpcapFileFormat
"""
__name__ = 'simplepcap'
__license__ = 'GPL v3.0'
__version__ = '0.0.1'
__date__ = 'November 2014'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Development'

import struct
from wraith.utils.timestamps import iso2ts

class PCAPException(Exception): pass         # generic pcap exception
class PCAPIOException(PCAPException): pass   # pcap IO error
class PCAPPackException(PCAPException): pass # pcap struct errors

def pcapopen(fname):
    """ opens fname and writes pcap header, returning open file object """
    try:
        fout = open(fname,'wb')
        fout.write(pcaphdr())
    except IOError as e:
        raise PCAPIOException(e)
    except struct.error as e:
        raise PCAPPackException(e)
    else:
        return fout

    
def pktwrite(fout,ts,pkt):
    """ writes packet pkt with timestamp ts to pcap file object fout """
    try:
        pkt = pcappkt(ts,pkt)
        fout.write(pkt)
    except IOError as e:
        raise PCAPIOException(e)
    except struct.error as e:
        raise PCAPPackException(e)

# pcaps are constructed as PCAP HEADER|RECORD HEADER<1>|DATA<1>|...|RECORD HEADER<n>|DATA<n>
# where the PCAP HEADER as defined in pcap.h is:
#struct pcap_file_header {
#	bpf_u_int32 magic;
#	u_short version_major;
#	u_short version_minor;
#	bpf_int32 thiszone;	    /* gmt to local correction */
#	bpf_u_int32 sigfigs;	/* accuracy of timestamps */
#	bpf_u_int32 snaplen;	/* max length saved portion of each pkt */
#	bpf_u_int32 linktype;	/* data link type (LINKTYPE_*) */
#};
# compile header with link type = DLT_IEEE802_11_RADIO = 127
_MAGIC_NUM_ = 2712847316
_VERS_MAJ_ = 2
_VERS_MIN_ = 4
_ZONE_ = 0
_SIG_FIGS_ = 0
_SNAP_LEN_ = 65535
_LINK_TYPE_ = 127
_PCAP_HDR_FMT_ = "<IHHiIII"
def pcaphdr():
    return struct.pack(_PCAP_HDR_FMT_,*(_MAGIC_NUM_,_VERS_MAJ_,_VERS_MIN_,_ZONE_,
                                        _SIG_FIGS_,_SNAP_LEN_,_LINK_TYPE_))

# and the RECORD HEADER as defined in pcap.h is:
#struct pcap_pkthdr {
#	struct timeval ts;	/* time stamp */
#	bpf_u_int32 caplen;	/* length of portion present */
#	bpf_u_int32 len;	/* length this packet (off wire) */
#};
# where timeval is long tv_sec, long tv_usec
# for each record header we use struct to pack the values
# (sec,usec) = str(Decimal(ts)).split('.')
# sec and usec is "<I"
# \x36\x00\x00\x00 max length, max length
_PCAP_PKT_FMT_ = "<llII"
def pcappkt(ts,pkt):
    """
     returns a pcap packet (pkt_hdr+pkt) for writing
     ts must be an isoformat string, pkt is the hex packet for writing 
    """
    # is there an easier/better/more efficient way of extracting seconds and
    # microseconds from a timestamp
    (sec,usec) = ("{0:.6f}".format(iso2ts(ts))).split('.')
    sec = int(sec)
    usec = int(usec)
    olen = len(pkt)
    clen = olen if olen <= _SNAP_LEN_ else _SNAP_LEN_
    return struct.pack(_PCAP_PKT_FMT_,*(sec,usec,clen,olen)) + pkt[:_SNAP_LEN_]
