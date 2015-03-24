#
# Copyright (c) 2012 Qualcomm Atheros, Inc.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
# To install the plugin:
#
# cp ath6kl.py ~/.trace-cmd/plugins/
#
# When making changes to the plugin use -V to see all python errors/warnings:
#
# trace-cmd report -V trace.dat

import tracecmd
import struct
import binascii

def hexdump(buf, prefix=None):
    s = binascii.b2a_hex(buf)
    s_len = len(s)
    result = ""

    if prefix == None:
        prefix = ""

    for i in range(s_len / 2):
        if i % 16 == 0:
            result = result + ("%s%04x: " % (prefix, i))

        result = result + (s[2*i] + s[2*i+1] + " ")

        if (i + 1) % 16 == 0:
            result = result + "\n"

    # FIXME: if len(s) % 16 == 0 there's an extra \n in the end

    return result

def wmi_event_bssinfo(pevent, trace_seq, event, buf):
    hdr = struct.unpack("<HBB6BH", buf[0:12])
    channel = hdr[0]
    frame_type = hdr[1]
    snr = hdr[2]
    bssid = hdr[3]
    ie_mask = hdr[4]

    trace_seq.puts("\t\t\tWMI_BSSINFO_EVENTID channel %d frame_type 0x%x snr %d ie_mask 0x%x\n" %
                   (channel, frame_type, snr, ie_mask))

wmi_event_handlers = [
    [0x1004, wmi_event_bssinfo ],
    ]

def wmi_cmd_set_bss_filter_handler(pevent, trace_seq, event, buf):
    hdr = struct.unpack("<BBHI", buf[0:8])
    bss_filter = hdr[0]
    ie_mask = hdr[3]

    trace_seq.puts("\t\t\tWMI_SET_BSS_FILTER_CMDID bss_filter 0x%x ie_mask 0x%08x\n" %
                   (bss_filter, ie_mask))

def wmi_cmd_set_probed_ssid_handler(pevent, trace_seq, event, buf):
    hdr = struct.unpack("<BBB", buf[0:3])
    entry_index = hdr[0]
    flag = hdr[1]
    ssid_len = hdr[2]

    # fmt = "<" + ssid_len + "s"
    # hdr = struct.unpack(fmt, buf[3:3 + ssid_len])

    trace_seq.puts("\t\t\tWMI_SET_PROBED_SSID_CMDID entry_index 0x%x flag 0x%08x ssid_len %d\n" %
                   (entry_index, flag, ssid_len))

    # FIXME: print SSID
    # for c in hdr[0]:
    #     print ascii(c)

wmi_cmd_handlers = [
    [9, wmi_cmd_set_bss_filter_handler ],
    [10, wmi_cmd_set_probed_ssid_handler ],
    ]

WMI_CMD_HDR_IF_ID_MASK = 0xf

def ath6kl_wmi_cmd_handler(pevent, trace_seq, event):
    buf_len = long(event['buf_len'])
    buf = event['buf'].data

    hdr = struct.unpack("<HHH", buf[0:6])
    cmd_id = hdr[0]
    if_idx = hdr[1] & WMI_CMD_HDR_IF_ID_MASK

    trace_seq.puts("id 0x%x len %d if_idx %d\n" % (cmd_id, buf_len, if_idx))

    for (wmi_id, handler) in wmi_cmd_handlers:
        if wmi_id == cmd_id:
            handler(pevent, trace_seq, event, buf[6:])
            break

def ath6kl_wmi_event_handler(pevent, trace_seq, event):
    buf_len = long(event['buf_len'])
    buf = event['buf'].data

    hdr = struct.unpack("<HHH", buf[0:6])
    cmd_id = hdr[0]
    if_idx = hdr[1] & WMI_CMD_HDR_IF_ID_MASK

    trace_seq.puts("id 0x%x len %d if_idx %d\n" % (cmd_id, buf_len, if_idx))

    for (wmi_id, handler) in wmi_event_handlers:
        if wmi_id == cmd_id:
            handler(pevent, trace_seq, event, buf[6:])
            break

def ath6kl_htc_tx_handler(pevent, trace_seq, event):
    buf_len = long(event['buf_len'])
    buf = event['buf'].data

    hdr = struct.unpack("<BBHBB", buf[0:6])
    endpoint = hdr[0]
    flags = hdr[1]
    payload_len = hdr[2]
    ctrl0 = hdr[3]
    ctrl1 = hdr[4]

    seqno = ctrl1

    trace_seq.puts("seqno %d endpoint %d payload_len %d flags 0x%x\n" %
                   (seqno, endpoint, payload_len, flags))

    if flags != 0:
        trace_seq.puts("\t\t\t\t\t\t")

    if flags & 0x1:
        trace_seq.puts(" NEED_CREDIT_UPDATE")

    if flags & 0x2:
        trace_seq.puts(" SEND_BUNDLE")

    if flags & 0x4:
        trace_seq.puts(" FIXUP_NETBUF")

    if flags != 0:
        trace_seq.puts("\n")

def ath6kl_htc_rx_handler(pevent, trace_seq, event):
    buf_len = long(event['buf_len'])
    buf = event['buf'].data

    hdr = struct.unpack("<BBHBB", buf[0:6])
    endpoint = hdr[0]
    flags = hdr[1]
    payload_len = hdr[2]
    ctrl0 = hdr[3]
    ctrl1 = hdr[4]

    seqno = ctrl1
    bundle_count = (flags & 0xf0) >> 4

    trace_seq.puts("seqno %d endpoint %d payload_len %d flags 0x%x bundle_count %d\n" %
                   (seqno, endpoint, payload_len, flags, bundle_count))

    if (flags & 0xf) != 0:
        trace_seq.puts("\t\t\t\t\t\t")

    if flags & 0x1:
        trace_seq.puts(" UNUSED")

    if flags & 0x2:
        trace_seq.puts(" TRAILER")

    if (flags & 0xf) != 0:
        trace_seq.puts("\n")

def ath6kl_sdio_handler(pevent, trace_seq, event):
    tx = long(event['tx'])
    addr = event['addr']
    flags = event['flags']

    buf_len = long(event['buf_len'])
    buf = event['buf'].data

    if tx == 1:
        direction = "tx"
    else:
        direction = "rx"

    trace_seq.puts("%s addr 0x%x flags 0x%x buf_len %d\n" %
                   (direction, addr, flags, buf_len))
    trace_seq.puts("%s\n" % hexdump(buf))

def ath6kl_sdio_scat_handler(pevent, trace_seq, event):
    tx = long(event['tx'])
    addr = long(event['addr'])
    flags = long(event['flags'])
    entries = long(event['entries'])
    total_len = long(event['total_len'])

    len_array_data = event['len_array'].data
    data = event['data'].data

    if tx == 1:
        direction = "tx"
    else:
        direction = "rx"

    trace_seq.puts("%s addr 0x%x flags 0x%x entries %d total_len %d\n" %
                   (direction, addr, flags, entries, total_len))

    offset = 0

    len_array = struct.unpack("<%dI" % entries, len_array_data[0:8])

    for i in range(entries):
        length = len_array[i]
        start = offset
        end = start + length

        trace_seq.puts("%s\n" % hexdump(data[start:end]))

        offset = offset + length

def register(pevent):
    pevent.register_event_handler("ath6kl", "ath6kl_wmi_cmd",
                                  lambda *args:
                                      ath6kl_wmi_cmd_handler(pevent, *args))
    pevent.register_event_handler("ath6kl", "ath6kl_wmi_event",
                                  lambda *args:
                                      ath6kl_wmi_event_handler(pevent, *args))
    pevent.register_event_handler("ath6kl", "ath6kl_htc_tx",
                                  lambda *args:
                                      ath6kl_htc_tx_handler(pevent, *args))
    pevent.register_event_handler("ath6kl", "ath6kl_htc_rx",
                                  lambda *args:
                                      ath6kl_htc_rx_handler(pevent, *args))
    pevent.register_event_handler("ath6kl", "ath6kl_sdio",
                                  lambda *args:
                                      ath6kl_sdio_handler(pevent, *args))
    pevent.register_event_handler("ath6kl", "ath6kl_sdio_scat",
                                  lambda *args:
                                      ath6kl_sdio_scat_handler(pevent, *args))
