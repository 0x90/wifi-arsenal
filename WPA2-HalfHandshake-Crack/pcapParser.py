# pypcapfile.savefile.py
"""
Core functionality for reading and parsing libpcap savefiles. This contains
the core classes pcap_packet and pcap_savefile, as well as the core function
load_savefile.
"""

import binascii
import ctypes
import struct
import sys

import pcapfile.linklayer as linklayer

from pcapfile.structs import __pcap_header__, pcap_packet

VERBOSE = False


def __TRACE__(msg, args=None):
    if VERBOSE:
        if args:
            print msg % args
        else:
            print msg


class pcap_savefile(object):
    """
    Represents a libpcap savefile. The packets member is a list of pcap_packet
    instances. The 'valid' member will be None for an uninitialised instance,
    False if the initial validation fails, or True if the instance has been
    successfully set up and the file has been parsed.
    """
    def __init__(self, header, packets=None):
        if not packets:
            packets = []
        self.header = header
        self.packets = packets
        self.valid = None
        self.byteorder = sys.byteorder

        if not self.__validate__():
            self.valid = False
        else:
            self.valid = True

        assert self.valid, 'Invalid savefile.'

    def __validate__(self):
        assert __validate_header__(self.header), "Invalid header."
        if not __validate_header__(self.header):
            return False

        # TODO: extended validation
        valid_packet = lambda pkt: (pkt is not None or
                                    pkt.issubclass(ctypes.Structure))
        if not 0 == len(self.packets):
            valid_packet = [valid_packet(pkt) for pkt in self.packets]
            assert False not in valid_packet, 'Invalid packets in savefile.'
            if False in valid_packet:
                return False

        return True

    def __repr__(self):
        string = '%s-endian capture file version %d.%d\n'
        string += 'snapshot length: %d\n'
        string += 'linklayer type: %s\nnumber of packets: %d\n'
        string = string % (self.header.byteorder, self.header.major,
                           self.header.minor, self.header.snaplen,
                           linklayer.lookup(self.header.ll_type),
                           len(self.packets))
        return string


def _load_savefile_header(file_h):
    """
Load and validate the header of a pcap file.
    """
    raw_savefile_header = file_h.read(24)

    # in case the capture file is not the same endianness as ours, we have to
    # use the correct byte order for the file header
    if raw_savefile_header[:4] == '\xa1\xb2\xc3\xd4':
        byte_order = 'big'
        unpacked = struct.unpack('>IhhIIII', raw_savefile_header)
    elif raw_savefile_header[:4] == '\xd4\xc3\xb2\xa1':
        byte_order = 'little'
        unpacked = struct.unpack('<IhhIIII', raw_savefile_header)
    else:
        raise Exception('Invalid pcap file.')

    (magic, major, minor, tz_off, ts_acc, snaplen, ll_type) = unpacked
    header = __pcap_header__(magic, major, minor, tz_off, ts_acc, snaplen,
                             ll_type, ctypes.c_char_p(byte_order))
    if not __validate_header__(header):
        raise Exception('invalid savefile header!')
    else:
        return header


def load_savefile(input_file, layers=0, verbose=False):
    """
    Parse a savefile as a pcap_savefile instance. Returns the savefile
    on success and None on failure. Verbose mode prints additional information
    about the file's processing. layers defines how many layers to descend and
    decode the packet. input_file should be a Python file object.
    """
    global VERBOSE
    old_verbose = VERBOSE
    VERBOSE = verbose

    __TRACE__('[+] attempting to load %s', (input_file.name,))

    header = _load_savefile_header(input_file)
    if __validate_header__(header):
        __TRACE__('[+] found valid header')
        packets = _load_packets(input_file, header, layers)
        __TRACE__('[+] loaded %d packets', (len(packets),))
        sfile = pcap_savefile(header, packets)
        __TRACE__('[+] finished loading savefile.')
    else:
        __TRACE__('[!] invalid savefile')
        sfile = None

    VERBOSE = old_verbose
    return sfile, header


def __validate_header__(header):
    if not type(header) == __pcap_header__:
        return False

    if not header.magic == 0xa1b2c3d4:
        if not header.magic == 0xd4c3b2a1:
            return False

    assert header.byteorder in ['little', 'big'], 'Invalid byte order.'

    # as of savefile format 2.4, 'a 4-byte time zone offset; this
    # is always 0'; the same is true of the timestamp accuracy.
    if not header.tz_off == 0:
        return False

    if not header.ts_acc == 0:
        return False

    return True


def _load_packets(file_h, header, layers=0):
    """
    Read packets from the capture file. Expects the file handle to point to
    the location immediately after the header (24 bytes).
    """
    pkts = []

    hdrp = ctypes.pointer(header)
    while True:
        pkt = _read_a_packet(file_h, hdrp, layers)
        if pkt:
            pkts.append(pkt)
        else:
            break

    return pkts


def _read_a_packet(file_h, hdrp, layers=0):
    """
    Reads the next individual packet from the capture file. Expects
    the file handle to be somewhere after the header, on the next
    per-packet header.
    """
    raw_packet_header = file_h.read(16)
    if raw_packet_header == '':
        return None
    assert len(raw_packet_header) == 16, 'Unexpected end of per-packet header.'

    # in case the capture file is not the same endianness as ours, we have to
    # use the correct byte order for the packet header
    if hdrp[0].byteorder == 'big':
        packet_header = struct.unpack('>IIII', raw_packet_header)
    else:
        packet_header = struct.unpack('<IIII', raw_packet_header)
    (timestamp, timestamp_ms, capture_len, packet_len) = packet_header
    raw_packet_data = file_h.read(capture_len)

    assert len(raw_packet_data) == capture_len, 'Unexpected end of packet.'

    if layers > 0:
        layers -= 1
        raw_packet = linklayer.clookup(hdrp[0].ll_type)(raw_packet_data,
                                                        layers=layers)
    else:
        raw_packet = binascii.hexlify(raw_packet_data)

    packet = pcap_packet(hdrp, timestamp, timestamp_ms, capture_len,
                         packet_len, raw_packet)
    return (raw_packet_header, packet)
