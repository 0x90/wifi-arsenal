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
# trace-cmd plugin for ath10k, QCA Linux wireless driver


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

wmi_scan_event_names = [
    [0x1,  "WMI_SCAN_EVENT_STARTED" ],
    [0x2,  "WMI_SCAN_EVENT_COMPLETED" ],
    [0x4, "WMI_SCAN_EVENT_BSS_CHANNEL" ],
    [0x8,  "WMI_SCAN_EVENT_FOREIGN_CHANNEL"],
    [0x10, "WMI_SCAN_EVENT_DEQUEUED" ],
    [0x20, "WMI_SCAN_EVENT_PREEMPTED" ],
    [0x40, "WMI_SCAN_EVENT_START_FAILED" ],
    ]

def wmi_event_scan(pevent, trace_seq, event, buf):
    hdr = struct.unpack("<IIIIII", buf[0:24])
    event = hdr[0]
    reason = hdr[1]
    channel_freq = hdr[2]
    requestor = hdr[3]
    scan_id = hdr[4]
    vdev_id = hdr[5]

    trace_seq.puts("\t\t\t\tWMI_SCAN_EVENTID event 0x%x reason %d channel_freq %d requestor %d scan_id %d vdev_id %d\n" %
                   (event, reason, channel_freq, requestor, scan_id, vdev_id))

    for (i, name) in wmi_scan_event_names:
        if event == i:
            trace_seq.puts("\t\t\t\t\t%s" % name)

wmi_event_handlers = [
    [0x9000, wmi_event_scan ],
    ]

def wmi_cmd_start_scan_handler(pevent, trace_seq, event, buf):
    hdr = struct.unpack("<IIIIIIIIIIIIIII", buf[0:60])
    scan_id = hdr[0]

    trace_seq.puts("\t\t\t\tWMI_START_SCAN_CMDID scan_id %d\n" % (scan_id))

wmi_cmd_handlers = [
    [0x9000, wmi_cmd_start_scan_handler ],
    ]

def ath10k_wmi_cmd_handler(pevent, trace_seq, event):
    buf_len = long(event['buf_len'])
    buf = event['buf'].data

    # parse wmi header
    hdr = struct.unpack("<HH", buf[0:4])
    buf = buf[4:]

    cmd_id = hdr[0]

    trace_seq.puts("id 0x%x len %d\n" % (cmd_id, buf_len))

    for (wmi_id, handler) in wmi_cmd_handlers:
        if wmi_id == cmd_id:
            handler(pevent, trace_seq, event, buf)
            break

def ath10k_wmi_event_handler(pevent, trace_seq, event):
    buf_len = long(event['buf_len'])
    buf = event['buf'].data

    hdr = struct.unpack("<HH", buf[0:4])
    cmd_id = hdr[0]

    trace_seq.puts("id 0x%x len %d\n" % (cmd_id, buf_len))

    for (wmi_id, handler) in wmi_event_handlers:
        if wmi_id == cmd_id:
            handler(pevent, trace_seq, event, buf[4:])
            break

def ath10k_log_dbg_dump_handler(pevent, trace_seq, event):
    msg = event['msg']
    prefix = event['prefix']
    buf_len = long(event['buf_len'])
    buf = event['buf'].data

    trace_seq.puts("%s\n" % (msg))
    trace_seq.puts("%s\n" % hexdump(buf, prefix))

def register(pevent):
    pevent.register_event_handler("ath10k", "ath10k_wmi_cmd",
                                  lambda *args:
                                      ath10k_wmi_cmd_handler(pevent, *args))
    pevent.register_event_handler("ath10k", "ath10k_wmi_event",
                                  lambda *args:
                                      ath10k_wmi_event_handler(pevent, *args))
    pevent.register_event_handler("ath10k", "ath10k_log_dbg_dump",
                                  lambda *args:
                                      ath10k_log_dbg_dump_handler(pevent, *args))
