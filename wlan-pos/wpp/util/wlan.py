#!/usr/bin/env python
#import struct
#import array
#import errno
#import fcntl
#import socket
#import time
#import sys
#import os
import re
from subprocess import Popen, PIPE


_re_mode = (re.I | re.M | re.S)
pmodes = {
        1: #patt_rss: mac,rss
        'Address: ?(.*?)\n\
        .*Signal level=?:? ?(-\d\d*) *dBm',
        2: #patt_all: mac,essid,signal,noise,encryption
        'Address: ?(.*?)\n\
        .*ESSID: ?"?(.*?)"? *\n\
        .*Signal level=?:? ?(-\d\d*) ?dBm *Noise level ?=? ?(-\d\d*) ?dBm *\n\
        .*Encryption key:?=? ?(\w*) *\n',
        #FIXME
        #'.*Address: (([0-9A-Z]{2}:){5}[0-9A-Z]{2})'
}


def Run(cmd, include_stderr=False, return_pipe=False,
        return_obj=False, return_retcode=True):
    #tmpenv = os.environ.copy()
    #tmpenv["LC_ALL"] = "C"
    #tmpenv["LANG"] = "C"
    try:
        fp = Popen(cmd, shell=False, stdout=PIPE, stdin=None, stderr=None,
                  close_fds=False, cwd='/')#, env=tmpenv)
    except OSError, e:
        print "Running command %s failed: %s" % (str(cmd), str(e))
        return ""
    return fp.communicate()[0]


def scanWLAN_RE(ifname='wlan0', pmode=1):
    """
    *return: [ [mac1, rss1], [mac2, rss2], ... ]
    """

    cmd = [ 'sudo', 'iwlist', ifname, 'scan' ]
    results = Run(cmd)
    networks = results.split( 'Cell' )
    scan_result = []
    for cell in networks:
        #TODO:exception handling.
        #found = patt_rmap.findall(cell) 
        matched = re.compile(pmodes[pmode], _re_mode).search(cell) 
        # For re.findall's result - list
        #if isinstance(matched, list):
        #    scan_result = matched 
        # For re.search's result - either MatchObject or None,
        # and only the former has the attribute 'group(s)'.
        if matched is not None:
            # groups - all matched results corresponding to '()' 
            # field in the argument of re.compile().
            # group(0/1/2) - the whole section matched the expression/
            # the 1st/2nd matched field.
            # group() = group(0)
            found = list(matched.groups())
            # Move the 'essid' field to the end of 'found' list.
            # 2: found at least has mac,rss,essid.
            if len(found) > 2:
                found.append(found[1])
                found.pop(1)
            scan_result.append(found)
        else: continue
    return scan_result


def pack_wrq(buffsize):
    """ Packs wireless request data which is to be sent to kernel. """
    # ioctl needs address and size of our buffer, and looks itself for 
    # the pointer to the address in memory and the size of it.
    buff = array.array('c', '\0'*buffsize)
    caddr_t, length = buff.buffer_info()
    datastr = struct.pack('Pi', caddr_t, length)
    return buff, datastr


def _fcntl(request, args):
    sockfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        try:
            status = fcntl.ioctl(sockfd.fileno(), request, args)
        except IOError, (err_no, err_str):
            if err_no == errno.EBUSY: #16
                delay = 0.2
                print 'Fcntl.ioctl: %s, wait %.1f sec...' % (err_str, delay)
            elif err_no == errno.EPERM: #1
                print 'Fcntl.ioctl: %s! Try it as ROOT!' % err_str
            else: raise
        except: raise
        else: break
    return status


def syscall(ifname, request, data=None):
    """ Read information from ifname. """
    buff = 16 - len(ifname)
    ifreq = array.array('c', ifname + '\0'*buff)
    # put some additional data behind the interface name
    ifreq.extend(data)

    sockfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        try:
            status = fcntl.ioctl(sockfd.fileno(), request, ifreq)
        except IOError, (err_no, err_str):
            if err_no == errno.EBUSY: #16
                delay = 0.2
                print '%s, wait %.1f sec...' % (err_str, delay)
            elif err_no == errno.EPERM: #1
                print '\nFcntl.ioctl: %s! Please try it as ROOT(sudo)!\n' % err_str
                return (errno.EPERM, errno.EPERM)
            else: raise
        except: raise
        else: break

    return (status, ifreq[16:])


def parse_qual(fmt, data):
    """ return ONLY qual, siglevel. """
    value = struct.unpack(fmt, data[0:2])

    # take care of a tuple like (int, )
    if len(value) == 1: return value[0]
    else: return value


def parse_all(data):
    # Run through the stream until it is too short to contain a cmd
    aplist = []
    while (len(data) >= 4):
        # Unpack the header: length, cmd id
        length, cmd = struct.unpack('HH', data[:4])
        if length < 4: break;
        #print '%d, %x' % (length, cmd)
        # Put the events into their respective result data
        if cmd == 0x8B15: #SIOCGIWAP
            bssid = "%02X:%02X:%02X:%02X:%02X:%02X" % \
                    ( struct.unpack('6B', data[6:12]) )
        elif cmd == 0x8b07: # Operation mode
            length = 32
        elif cmd == 0x8c01: #Quality part of statistics (scan) 
            rss = struct.unpack("B", data[5])[0] - 256
            aplist.append([bssid, rss])
        data = data[length:]
    # For compatibility with offline code.
    #aplist = [ [bssid, str(rss)] for bssid, rss in aplist ]
    return aplist


def scanWLAN_OS(ifname='wlan0'):
    """
    return: return errno.EPERM(1) if WLAN resource access(fcntl.ioctl) not permitted. 
    """
    datastr = struct.pack("Pii", 0, 0, 0)
    # SIOCSIWSCAN
    status, result = syscall(ifname, 0x8B18, datastr)
    if result == errno.EPERM: return result

    repack = False
    bufflen = 4096
    buff, datastr = pack_wrq(bufflen)
    while True:
        if repack:
            buff, datastr = pack_wrq(bufflen)
        try:
            # SIOCGIWSCAN
            status, result = syscall(ifname, 0x8B19, datastr)
        except IOError, (err_no, err_str):
            if err_no == errno.E2BIG: #7
                print 'WLAN scannnig: %s, resizing buffer...' % err_str
                # Keep resizing the buffer until it's
                #  large enough to hold the scan
                pbuff, newlen = struct.unpack('Pi', datastr)
                if bufflen < newlen: bufflen = newlen
                else: bufflen = bufflen * 2
                repack = True
            elif err_no == errno.EAGAIN: #11
                delay = 0.3
                print 'WLAN scannnig: %s, wait %.1f sec...' % (err_str, delay)
                time.sleep(delay)
            else: raise
        except: raise
        else: break

    aplist = parse_all(buff.tostring())
    return aplist


if __name__ == "__main__":
    try:
        import psyco
        psyco.bind(Run)
        psyco.bind(scanWLAN_RE)
        #psyco.bind(pack_wrq)
        #psyco.bind(syscall)
        #psyco.bind(parse_all)
        #psyco.bind(scanWLAN_OS)
        #psyco.profile()
        #psyco.full(0.1)
    except ImportError:
        pass

    wlan = scanWLAN_RE(pmode=2)
    #time.sleep(2)
    #wlan = scanWLAN_OS()
    #if wlan == errno.EPERM: sys.exit(99)

    import chardet as cd
    print 'visible APs: %d' % len(wlan)
    print
    print '%-18s %3s %5s %-4s %-6s' % ('MAC (BSSID)', 'RSS', 'Noise', 'Key', 'ESSID')
    print '-' * 50
    wlan = [ (ap[1], ap) for ap in wlan ]
    sorted_rss = sorted(wlan)
    for rss, ap in sorted_rss:
        mac, rss, noise, key, essid = ap
        enc = cd.detect(essid)['encoding']
        if not enc is None:
            essid = essid.decode(enc)
        print '%-18s %3s %5s %-4s %-20s' % (mac, rss, noise, key, essid)
