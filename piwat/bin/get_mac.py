#!/usr/bin/python

import fcntl, socket, struct, sys

def get_mac(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    return ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]

# This is now a command line utility
if __name__ == '__main__':
    answer = get_mac(sys.argv[1])
    print answer
