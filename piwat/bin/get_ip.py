#!/usr/bin/python

import socket
import fcntl
import struct
import sys

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])

#If called from the command line, use arg as input for the interface name
if __name__ == '__main__':
    print get_ip_address(sys.argv[1])
