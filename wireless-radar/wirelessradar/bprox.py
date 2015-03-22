#!/usr/bin/env python
# -*- coding: utf-8 -*-
# this is a hack, needs lot's of love.
# performs a simple device inquiry, followed by a remote name request of each
# discovered device

import os
import sys
import struct, bluetooth
import bluetooth._bluetooth as bluez

class MajorDeviceClasses(object):
  UNKNOWN = 0
  COMPUTER = 1
  PHONE = 2
  NETWORK = 3
  AUDIOVIDEO = 4
  PERIPHERAL = 5
  IMAGING = 6
  MISCELLANEOUS = 7
  TOY = 8
  HEALTH = 9
  # Dictionary for classes descriptions
  CLASSES = {
    UNKNOWN: 'unknown',
    COMPUTER: 'computer',
    PHONE: 'phone',
    NETWORK: 'network',
    AUDIOVIDEO: 'audio-video',
    PERIPHERAL: 'peripheral',
    IMAGING: 'imaging',
    MISCELLANEOUS: 'miscellaneous',
    TOY: 'toy',
    HEALTH: 'health',
  }

class ServiceDeviceClasses(object):
  POSITIONING = 1       # 0x010000 >> 16
  NETWORKING = 2        # 0x020000 >> 16
  RENDERING = 4         # 0x040000 >> 16
  CAPTURING = 8         # 0x080000 >> 16
  OBJECT_TRANSFER = 16  # 0x100000 >> 16
  AUDIO = 32            # 0x200000 >> 16
  TELEPHONY = 64        # 0x400000 >> 16
  INFORMATION = 128     # 0x800000 >> 16
  # Dictionary for services descriptions
  SERVICE_CLASSES = {
    POSITIONING: 'positioning service',
    NETWORKING: 'networking service',
    RENDERING: 'rendering service',
    CAPTURING: 'capturing service',
    OBJECT_TRANSFER: 'object transfer service',
    AUDIO: 'audio service',
    TELEPHONY: 'telephony service',
    INFORMATION: 'information service',
  }

class BluetoothSupport(object):
  def get_device_name(self, address):
    "Retrieve device name"
    return bluetooth.lookup_name(address)

  def get_classes(self, device_class):
    "Return device minor, major class and services class"
    minor_class = (device_class & 0xff) >> 2  # Bits 02-07 Minor class bitwise
    major_class = (device_class >> 8) & 0x1f  # Bits 08-12 Major class bitwise
    services_class = (device_class >> 16)     # Bits 16-23 Service class
    return (minor_class, major_class, services_class)

  def get_device_type(self, major_class):
    "Return the device major class"
    if not MajorDeviceClasses.CLASSES.has_key(major_class):
      # Fallback to unknown class
      major_class = MajorDeviceClasses.UNKNOWN
    return MajorDeviceClasses.CLASSES[major_class]

  def get_services(self, address):
    "Return the list of the device's available services"
    return bluetooth.find_service(address=address)

  def get_services_from_class(self, service_class):
    "Return the enabled services for a device class"
    services = []
    for service, description in ServiceDeviceClasses.SERVICE_CLASSES.iteritems():
      if service_class & service:
        services.append(description)
    return services

def printpacket(pkt):
    for c in pkt:
        sys.stdout.write("%02x " % struct.unpack("B",c)[0])
    print()

def read_inquiry_mode(sock):
    """returns the current mode, or -1 on failure"""
    # save current filter
    old_filter = sock.getsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, 14)

    # Setup socket filter to receive only events related to the
    # read_inquiry_mode command
    flt = bluez.hci_filter_new()
    opcode = bluez.cmd_opcode_pack(bluez.OGF_HOST_CTL,
            bluez.OCF_READ_INQUIRY_MODE)
    bluez.hci_filter_set_ptype(flt, bluez.HCI_EVENT_PKT)
    bluez.hci_filter_set_event(flt, bluez.EVT_CMD_COMPLETE);
    bluez.hci_filter_set_opcode(flt, opcode)
    sock.setsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, flt )

    # first read the current inquiry mode.
    bluez.hci_send_cmd(sock, bluez.OGF_HOST_CTL,
            bluez.OCF_READ_INQUIRY_MODE )

    pkt = sock.recv(255)

    status,mode = struct.unpack("xxxxxxBB", pkt)
    if status != 0: mode = -1

    # restore old filter
    sock.setsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, old_filter )
    return mode

def write_inquiry_mode(sock, mode):
    """returns 0 on success, -1 on failure"""
    # save current filter
    old_filter = sock.getsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, 14)

    # Setup socket filter to receive only events related to the
    # write_inquiry_mode command
    flt = bluez.hci_filter_new()
    opcode = bluez.cmd_opcode_pack(bluez.OGF_HOST_CTL,
            bluez.OCF_WRITE_INQUIRY_MODE)
    bluez.hci_filter_set_ptype(flt, bluez.HCI_EVENT_PKT)
    bluez.hci_filter_set_event(flt, bluez.EVT_CMD_COMPLETE);
    bluez.hci_filter_set_opcode(flt, opcode)
    sock.setsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, flt )

    # send the command!
    bluez.hci_send_cmd(sock, bluez.OGF_HOST_CTL,
            bluez.OCF_WRITE_INQUIRY_MODE, struct.pack("B", mode) )

    pkt = sock.recv(255)

    status = struct.unpack("xxxxxxB", pkt)[0]

    # restore old filter
    sock.setsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, old_filter )
    if status != 0: return -1
    return 0

def device_inquiry_with_with_rssi(sock):
    btq = BluetoothSupport()
    # save current filter
    old_filter = sock.getsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, 14)

    # perform a device inquiry on bluetooth device #0
    # The inquiry should last 8 * 1.28 = 10.24 seconds
    # before the inquiry is performed, bluez should flush its cache of
    # previously discovered devices
    flt = bluez.hci_filter_new()
    bluez.hci_filter_all_events(flt)
    bluez.hci_filter_set_ptype(flt, bluez.HCI_EVENT_PKT)
    sock.setsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, flt )

    duration = 4
    max_responses = 255
    cmd_pkt = struct.pack("BBBBB", 0x33, 0x8b, 0x9e, duration, max_responses)
    bluez.hci_send_cmd(sock, bluez.OGF_LINK_CTL, bluez.OCF_INQUIRY, cmd_pkt)

    results = []

    done = False
    while not done:
        pkt = sock.recv(255)
        ptype, event, plen = struct.unpack("BBB", pkt[:3])
        if event == bluez.EVT_INQUIRY_RESULT_WITH_RSSI:
            pkt = pkt[3:]
            nrsp = struct.unpack("B", pkt[0])[0]
            for i in range(nrsp):
                addr = bluez.ba2str( pkt[1+6*i:1+6*i+6] )
                rssi = struct.unpack("b", pkt[1+13*nrsp+i])[0]
                devclass_raw = pkt[1+8*nrsp+3*i:1+8*nrsp+3*i+3]
                devclass = struct.unpack ("I", "%s\0" % devclass_raw)[0]
                name = btq.get_device_name(addr)
                minor, major, service = btq.get_classes(devclass)
                type =  btq.get_device_type(major)
                services = btq.get_services_from_class(service)
                srv = btq.get_services(addr)
                results.append( ( addr, rssi, devclass, name, type, services, srv ) )
                print("%s %d %x %s %s %s %s" % (addr, rssi, devclass, repr(name), type, '|'.join(services), repr(srv)))
        elif event == bluez.EVT_INQUIRY_COMPLETE:
            done = True
        elif event == bluez.EVT_CMD_STATUS:
            status, ncmd, opcode = struct.unpack("BBH", pkt[3:7])
            if status != 0:
                print("uh oh...")
                printpacket(pkt[3:7])
                done = True
        elif event == bluez.EVT_INQUIRY_RESULT:
            pkt = pkt[3:]
            nrsp = struct.unpack("B", pkt[0])[0]
            for i in range(nrsp):
                addr = bluez.ba2str( pkt[1+6*i:1+6*i+6] )
                results.append( ( addr, -1 ) )
                print("[%s] (no RRSI)" % addr)
        else:
            print("unrecognized packet type 0x%02x" % ptype)

    # restore old filter
    sock.setsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, old_filter )

    return results

def main():
    dev_id = 0
    try:
        sock = bluez.hci_open_dev(dev_id)
    except:
        print("error accessing bluetooth device...")
        sys.exit(1)

    try:
        mode = read_inquiry_mode(sock)
    except Exception as e:
        print("error reading inquiry mode.  ")
        print("Are you sure this a bluetooth 1.2 device?")
        print(e)
        sys.exit(1)
    #print("current inquiry mode is %d" % mode)

    if mode != 1:
        print("writing inquiry mode...")
        try:
            result = write_inquiry_mode(sock, 1)
        except Exception as e:
            print("error writing inquiry mode.  Are you sure you're root?")
            print(e)
            sys.exit(1)
        if result != 0:
            print("error while setting inquiry mode")
        print("result: %d" % result)

    device_inquiry_with_with_rssi(sock)

if __name__ == "__main__":
  main()
