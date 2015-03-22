import array
import fcntl
import platform
import struct
import socket

import iface

SIOCGIFCONF = 0x8912

def get_ifaces():
    list = []
    
    try:
        file = open("/proc/net/dev")
        t = file.readlines()
        t = t[2:]
        for i in t:
            list.append(i.split(':')[0].lstrip())
            
        return list
    except IOError:
        buf_size = 1024
        struct_size = 32
        
        # Dirty hack to get it working at x86_64
        if (platform.architecture()[0] == '64bit'):
            struct_size = 40
       
        a = array.array('c', '\0' * buf_size)
        so = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        st = struct.pack('iL', buf_size, a.buffer_info()[0])
        
        outbytes = struct.unpack('iL', fcntl.ioctl(so, SIOCGIFCONF, st))[0]
        b = a.tostring()
        
        for i in range(0, outbytes, struct_size):
            ifname = b[i:i+struct_size].split('\0', 1)[0]
            list.append(ifname)
            
        return list
        

def get_wireless_ifaces():
    list = []
    ifaces = get_ifaces()
    
    for i in ifaces:
        temp = iface.IF(i)
        if temp.hasWExt():
            list.append(i)
            
    return list
