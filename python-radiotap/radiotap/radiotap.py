#!/usr/bin/env python
# parse radiotap fields from pcap buffers into a dictionary
#
# example:
# >>> import radiotap as r, pcap
# >>> pc = pcap.pcap(name='foo.pcap')
# >>> tstamp, pkt = pc[0]
# >>> off, radiotap = r.radiotap_parse(pkt)
# >>> off, mac = r.ieee80211_parse(pkt, off)
import struct

mcs_rate_table = [
    (6.50, 7.20, 13.50, 15.00),
    (13.00, 14.40, 27.00, 30.00),
    (19.50, 21.70, 40.50, 45.00),
    (26.00, 28.90, 54.00, 60.00),
    (39.00, 43.30, 81.00, 90.00),
    (52.00, 57.80, 108.00, 120.00),
    (58.50, 65.00, 121.50, 135.00),
    (65.00, 72.20, 135.00, 150.00),
    (13.00, 14.40, 27.00, 30.00),
    (26.00, 28.90, 54.00, 60.00),
    (39.00, 43.30, 81.00, 90.00),
    (52.00, 57.80, 108.00, 120.00),
    (78.00, 86.70, 162.00, 180.00),
    (104.00, 115.60, 216.00, 240.00),
    (117.00, 130.00, 243.00, 270.00),
    (130.00, 144.40, 270.00, 300.00),
    (19.50, 21.70, 40.50, 45.00),
    (39.00, 43.30, 81.00, 90.00),
    (58.50, 65.00, 121.50, 135.00),
    (78.00, 86.70, 162.00, 180.00),
    (117.00, 130.00, 243.00, 270.00),
    (156.00, 173.30, 324.00, 360.00),
    (175.50, 195.00, 364.50, 405.00),
    (195.00, 216.70, 405.00, 450.00),
    (26.00, 28.80, 54.00, 60.00),
    (52.00, 57.60, 108.00, 120.00),
    (78.00, 86.80, 162.00, 180.00),
    (104.00, 115.60, 216.00, 240.00),
    (156.00, 173.20, 324.00, 360.00),
    (208.00, 231.20, 432.00, 480.00),
    (234.00, 260.00, 486.00, 540.00),
    (260.00, 288.80, 540.00, 600.00),
]

def align(val, align):
    return (val + align - 1) & ~(align-1)

def _parse_mactime(packet, offset):
    mactime, = struct.unpack_from('<Q', packet, offset)
    return offset + 8, {'TSFT' : mactime}

def _parse_flags(packet, offset):
    flags, = struct.unpack_from('<B', packet, offset)
    return offset + 1, {'flags' : flags}

def _parse_rate(packet, offset):
    rate, = struct.unpack_from('<B', packet, offset)
    return offset + 1, {'rate' : rate / 2.}

def _parse_channel(packet, offset):
    offset = align(offset, 2)

    chan_freq, chan_flags, = struct.unpack_from('<HH', packet, offset)
    return offset + 4, {'chan_freq' : chan_freq, 'chan_flags' : chan_flags}

def _parse_fhss(packet, offset):
    fhss, = struct.unpack_from('<H', packet, offset)
    return offset + 2, {'fhss' : fhss}

def _parse_dbm_antsignal(packet, offset):
    dbm_antsignal, = struct.unpack_from('<b', packet, offset)
    return offset + 1, {'dbm_antsignal' : dbm_antsignal}

def _parse_dbm_antnoise(packet, offset):
    dbm_antnoise, = struct.unpack_from('<b', packet, offset)
    return offset + 1, {'dbm_antnoise' : dbm_antnoise}

def _parse_lock_quality(packet, offset):
    offset = align(offset, 2)
    lock_quality, = struct.unpack_from('<H', packet, offset)
    return offset + 2, {'lock_quality' : lock_quality}

def _parse_tx_attenuation(packet, offset):
    offset = align(offset, 2)
    tx_attenuation, = struct.unpack_from('<H', packet, offset)
    return offset + 2, {'tx_attenuation' : tx_attenuation}

def _parse_db_tx_attenuation(packet, offset):
    offset = align(offset, 2)
    db_tx_attenuation, = struct.unpack_from('<H', packet, offset)
    return offset + 2, {'db_tx_attenuation' : db_tx_attenuation}

def _parse_dbm_tx_power(packet, offset):
    dbm_tx_power, = struct.unpack_from('<b', packet, offset)
    return offset + 1, {'dbm_tx_power' : dbm_tx_power}

def _parse_antenna(packet, offset):
    antenna, = struct.unpack_from('<B', packet, offset)
    return offset + 1, {'antenna' : antenna}

def _parse_db_antsignal(packet, offset):
    db_antsignal, = struct.unpack_from('<B', packet, offset)
    return offset + 1, {'db_antsignal' : db_antsignal}

def _parse_db_antnoise(packet, offset):
    db_antnoise, = struct.unpack_from('<B', packet, offset)
    return offset + 1, {'db_antnoise' : db_antnoise}

def _parse_rx_flags(packet, offset):
    offset = align(offset, 2)
    rx_flags, = struct.unpack_from('<H', packet, offset)
    return offset + 2, {'rx_flags' : rx_flags}

def _parse_tx_flags(packet, offset):
    tx_flags, = struct.unpack_from('<B', packet, offset)
    return offset + 1, {'tx_flags' : tx_flags}

def _parse_rts_retries(packet, offset):
    rts_retries, = struct.unpack_from('<B', packet, offset)
    return offset + 1, {'rts_retries' : rts_retries}

def _parse_data_retries(packet, offset):
    data_retries, = struct.unpack_from('<B', packet, offset)
    return offset + 1, {'data_retries' : data_retries}

def _parse_xchannel(packet, offset):
    xchannel_flags, xchannel_freq, xchannel_num, xchannel_maxpower = \
        struct.unpack_from('<QHBB', packet, offset)
    return offset + 8, {
        'xchannel_flags' : xchannel_flags,
        'xchannel_freq' : xchannel_freq,
        'xchannel_num' : xchannel_num,
        'xchannel_maxpower' : xchannel_maxpower
    }

def _parse_mcs(packet, offset):
    mcs_known, mcs_flags, mcs_index = \
        struct.unpack_from('<BBB', packet, offset)
    is_40 = (mcs_flags & 0x3) == 1
    short_gi = (mcs_flags & 0x04) != 0

    mcs_rate = mcs_rate_table[mcs_index][2 * is_40 + short_gi]
    return offset + 3, {
        'mcs_known': mcs_known,
        'mcs_flags': mcs_flags,
        'mcs_index': mcs_index,
        'mcs_rate': mcs_rate
    }

def _parse_radiotap_field(field_id, packet, offset):

    dispatch_table = [
        _parse_mactime,
        _parse_flags,
        _parse_rate,
        _parse_channel,
        _parse_fhss,
        _parse_dbm_antsignal,
        _parse_dbm_antnoise,
        _parse_lock_quality,
        _parse_tx_attenuation,
        _parse_db_tx_attenuation,
        _parse_dbm_tx_power,
        _parse_antenna,
        _parse_db_antsignal,
        _parse_db_antnoise,
        _parse_rx_flags,
        _parse_tx_flags,
        _parse_rts_retries,
        _parse_data_retries,
        _parse_xchannel,
        _parse_mcs,
    ]
    if field_id >= len(dispatch_table):
        return None, {}

    return dispatch_table[field_id](packet, offset)

def radiotap_parse(packet):
    """
    Parse out a the radiotap header from a packet.  Return a tuple of
    the fields as a dict (if any) and the new offset into packet.
    """
    radiotap_header_fmt = '<BBHI'
    radiotap_header_len = struct.calcsize(radiotap_header_fmt)

    if len(packet) < radiotap_header_len:
        return 0, {}

    header = struct.unpack_from(radiotap_header_fmt, packet)

    version, pad, radiotap_len, present = header
    if version != 0 or pad != 0 or radiotap_len > len(packet):
        return 0, {}

    # there may be multiple present bitmaps if high bit is set.
    # assemble them into one large bitmap
    count = 1
    offset = radiotap_header_len
    while present & (1 << (32 * count - 1)):
        next_present = struct.unpack_from("<I", packet[offset:])
        present |= next_present
        offset += 4

    radiotap = {}
    for i in range(0, 32 * count):
        if present & (1 << i):
            offset, fields = _parse_radiotap_field(i, packet, offset)
            radiotap.update(fields)
            if offset == radiotap_len or offset is None:
                break

    return radiotap_len, radiotap

def macstr(macbytes):
    return ':'.join(['%02x' % ord(k) for k in macbytes])

def ieee80211_parse(packet, offset):
    hdr_fmt = "<HH6s6s6sH"
    hdr_len = struct.calcsize(hdr_fmt)

    if len(packet) - offset < hdr_len:
        return 0, {}

    fc, duration, addr1, addr2, addr3, seq = \
        struct.unpack_from(hdr_fmt, packet, offset)

    return hdr_len, {
        'fc': fc,
        'duration': duration * .001024,
        'addr1': macstr(addr1),
        'addr2': macstr(addr2),
        'addr3': macstr(addr3),
        'seq': seq >> 4,
        'frag': seq & 3
    }
