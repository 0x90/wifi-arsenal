import fcntl
import struct
import socket

SIOCGIFFLAGS = 0x8913   # get flags
SIOCSIFFLAGS = 0x8914   # set flags
SIOCGIFADDR = 0x8915    # get PA address

SIOCGIWNAME	= 0x8B01    # wireless extensions
SIOCSIWFREQ = 0x8B04    # set wireless channel
SIOCSIWMODE	= 0x8B06    # set wireless mode
SIOCGIWMODE = 0x8B07    # get wireless mode

IFF_UP = 0x1            # Interface is up.

IW_MODE_MANAGED = 0x2   # wireless mode auto
IW_MODE_MONITOR = 0x6   # wireless mode monitor

NONE = 0x0

class IF(object):
    def __init__(self, ifname):
        self.name = ifname
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
    def _call(self, func, data):
        try:
            result = fcntl.ioctl(self._sock, func, data)
        except IOError:
            return None
        return result
        
    def isUp(self):
        st = struct.pack('16sh', self.name, NONE)
        flags = struct.unpack('16sh', self._call(SIOCGIFFLAGS, st))[1]
        return (flags & IFF_UP) != 0
        
    def setIfaceUp(self):
        if (not self.isUp()):
            st = struct.pack('16sh', self.name, NONE)
            flags = struct.unpack('16sh', self._call(SIOCGIFFLAGS, st))[1]
            st = struct.pack('16sh', self.name, (flags-IFF_UP))
            self._call(SIOCSIFFLAGS, st)
            
    def setIfaceDown(self):
        if (self.isUp()):
            st = struct.pack('16sh', self.name, 0)
            flags = struct.unpack('16sh', self._call(SIOCGIFFLAGS, st))[1]
            st = struct.pack('16sh', self.name, (flags+IFF_UP))
            self._call(SIOCSIFFLAGS, st)
            
    def hasWExt(self):
        st = struct.pack('16sI', self.name, NONE)
        st = self._call(SIOCGIWNAME, st)
        return st != None
    
    def setWChannel(self, channel):
        if (channel < 1 or channel > 13):
            return
        st = struct.pack('16sihbb', self.name, channel, 0, 0, 0)
        self._call(SIOCSIWFREQ, st)
            
    def setWModeMonitor(self):
        st = struct.pack('16sI', self.name, IW_MODE_MONITOR)
        self._call(SIOCSIWMODE, st)
        
    def setWModeManaged(self):
        st = struct.pack('16sI', self.name, IW_MODE_MANAGED)
        self._call(SIOCSIWMODE, st)
        
    def isWModeMonitorSet(self):
        st = struct.pack('16sI', self.name, 0)
        st = self._call(SIOCGIWMODE, st)
        _, mode = struct.unpack('16sI', st)
        return mode == IW_MODE_MONITOR
