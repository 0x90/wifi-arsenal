#!/usr/bin/env python

""" iw.py: iw interface

iw provides an interface to the iw command. Rather than have a single command,
iw is broken down here into related commands.
 
Using iw version 3.15+
Errors:
  -1 no permission to perform operation
 -16 device is busy
 -19 nic is not found
 -22 invalid value to argument
 -23 exceed # of open files
 -95 operation not permitted - note this could refer to invalid argument

TODO:
 parse iw phy <phy> info completely
 handle cases where sudo asks for password
 look into ctypes and /lib/libiw.so.30
 don't force all arguments to string i.e. convert in function
 look into using iwlist 
"""
__name__ = 'iw'
__license__ = 'GPL v3.0'
__version__ = '0.1.0'
__date__ = 'November 2014'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Development'

import os                # getuid()
import re                # regular expressions
import subprocess as sp  # executing commands

# constants error code
IW_PERMISSION =  -1
IW_BUSY       = -16
IW_NONIC      = -19
IW_INVALIDARG = -22
IW_EXCEED     = -23
IW_OPERATION  = -95

# supported channel widths
IW_CHWS = [None,'HT20','HT40+','HT40-']

# exception class
class IWException(Exception): pass

""" Returns the error code for the IW error """
def ecode(err): return int(err[err.find('(')+1:err.find(')')])

"""
 dev (iw dev)- list basic phy info on cards
"""
_IFACE_IFACE_   = 0
_IFACE_IFINDEX_ = 1
_IFACE_WDEV_    = 2
_IFACE_ADDR_    = 3
_IFACE_TYPE_    = 4
_IFACE_CH_      = 5
_CH_PATTERN_ = r'channel ([\d]*) \(([\d]*) MHz\), width: ([\d]*) MHz, center1: ([\d]*) MHz'
_CH_PATTERN_NOHT_ = r'channel ([\d]*) \(([\d]*) MHz\), width: ([\d]*) MHz \(no HT\), center1: ([\d]*) MHz'
_IFACE_CH_NUM_   = 0
_IFACE_CH_RF_    = 1
_IFACE_CH_WIDTH_ = 2
_IFACE_CH_CF_    = 3

def dev(nic=None):
    """ 
     a sub of iw for getting phy info (iw dev) on wireless cards
     if nic is None returns a dict of phys corresponding to the iw dev command
     otherwise returns a tuple dict (phy,interfaces) or None if it does not exist
    """
    p = sp.Popen(['iw','dev'],stdin=sp.PIPE,stdout=sp.PIPE,stderr=sp.PIPE)
    out,err = p.communicate()
    
    # phys is a dict of dicts with each phy the key
    phys = {}
    
    try:
        # split on phy# (removing first empty) gives us a 'line' for each phy
        for line in out.split('phy#')[1:]:
            # for each line, splitting on '\n\tInterface' gives a list of the 
            # form ['#',<interface1>,...<interfacen>] 
            line = line.split('\n\tInterface')
            phy = 'phy' + line[0]
            phys[phy] = []

            # for each interface, split by '\n\t\t'
            for interface in line[1:]:
                interface = interface.split('\n\t\t')
                iface = interface[_IFACE_IFACE_].strip()
                ifindex = int(interface[_IFACE_IFINDEX_].split(' ')[1])
                wdev = interface[_IFACE_WDEV_].split(' ')[1]
                addr = interface[_IFACE_ADDR_].split(' ')[1]
                ntype = interface[_IFACE_TYPE_].split(' ')[1]
                channel = None
                if len(interface) - 1 == _IFACE_CH_:
                    try:
                        ch = re.search(_CH_PATTERN_,interface[_IFACE_CH_]).groups()
                    except AttributeError:
                        ch = re.search(_CH_PATTERN_NOHT_,interface[_IFACE_CH_]).groups()
                    channel = {'ch':ch[_IFACE_CH_NUM_],
                               'rf':ch[_IFACE_CH_RF_],
                               'width':ch[_IFACE_CH_WIDTH_],
                               'cf':ch[_IFACE_CH_CF_]}
                phys[phy].append({'nic':iface,'addr':addr,'ifindex':ifindex,
                                  'wdev':wdev,'type':ntype,'channel':channel})               
        if not nic:return phys
        for phy in phys:
            for i in phys[phy]:
                if i['nic'] == nic: return phy,phys[phy]
        return None
    except Exception as e:
        raise IWException(e)
        
"""
 add/del add, del interface, virtual interface
 TODO:
  add flags
"""

def devadd(nic,vnic,mode='monitor'):
    """ a sub of iw for adding a virtual interface (default is monitor) """
    cmd = ['iw','dev',nic,'interface','add',vnic,'type',mode]
    if os.getuid() != 0: cmd.insert(0,'sudo')
    p = sp.Popen(cmd,stdin=sp.PIPE,stdout=sp.PIPE,stderr=sp.PIPE)
    out,err = p.communicate()
    if err: raise IWException(err.split(':')[1].strip())

def devdel(vnic):
    """ a sub of iw for deleting a virtual card """
    cmd = ['iw','dev',vnic,'del']
    if os.getuid() != 0: cmd.insert(0,'sudo')
    p = sp.Popen(cmd,stdin=sp.PIPE,stdout=sp.PIPE,stderr=sp.PIPE)
    out,err = p.communicate()
    if err: raise IWException(err.split(':')[1].strip())

def phyadd(phy,nic,mode='managed'):
    """ a sub of iw for adding a card using the phy """
    cmd = ['iw',phy,'interface','add',nic,'type',mode]
    if os.getuid() != 0: cmd.insert(0,'sudo')
    p = sp.Popen(cmd,stdin=sp.PIPE,stdout=sp.PIPE,stderr=sp.PIPE)
    out,err = p.communicate()
    if err: raise IWException(err.split(':')[1].strip()) 

""" channels """

def chget(phy):
    """
     returns list of supported channels on phy - a subset of the commmand
     iw phy <phy> info
    """
    cmd = ['iw','phy',phy,'info']
    p = sp.Popen(cmd,stdin=sp.PIPE,stdout=sp.PIPE,stderr=sp.PIPE)
    out,err = p.communicate()
    
    # split on '\n\t'
    ls = out.split('\n\t')
    
    # find the index(es) of "Frequencies", keeping in mind, there 
    # may be more than 1 depending on the # of bands in the card
    ch = []
    i = -1
    try:
        # rf is pattern to find channel # in a line like '* 2412 MHz [1] (15.0 dBm)'
        rf = r'\[([\d]*)\]'
        while True: # exception thrown after all '\TFrequencies:' found exits loop
            i = ls.index('\tFrequencies:',i+1)
            j = i + 1
            try:
                while True: # exception thrown after re returns None exits loop
                    ch.append(re.search(rf,ls[j]).group(1))
                    j += 1
            except AttributeError:    
                pass
    except ValueError:
        pass
    return ch

def chset(vnic,ch,chwidth=None):
    """ sets the specified channel of vnic - sudo iw dev vnic set channel ch [chwidth] """
    cmd = ['iw','dev',vnic,'set','channel',ch]
    if chwidth: cmd.append(chwidth)
    if os.getuid() != 0: cmd.insert(0,'sudo')
    p = sp.Popen(cmd,stdin=sp.PIPE,stdout=sp.PIPE,stderr=sp.PIPE)
    out,err = p.communicate()
    
    # two errors, one returned in error, other returned as usage in out
    if out:
        raise IWException("Invalid command <%s> (-22)" % ' '.join(cmd))
    elif err:
        raise IWException(err.split(':')[1].strip())

""" txpower """

def txpwrset(nic,pwr,option="fixed"):
    """ sets txpower of nic to pwr (dBm) with option = oneof {fixed|limit|auto} """
    # NOTE: does not work (at least on my cards)
    # confirm option is valid
    if not option in ['fixed','auto','limit']:
        raise IWException("option %s must be one of {fixed|limit|auto}" % option)

    cmd = ['iw','dev',nic,'set','txpower',option,str(pwr*100)]
    if os.getuid() != 0: cmd.insert(0,'sudo')
    p = sp.Popen(cmd,stdin=sp.PIPE,stdout=sp.PIPE,stderr=sp.PIPE)
    out,err = p.communicate()
    if err: raise IWException(err.split(':')[1].strip())

def txpwrget(nic):
    """ gets txpower of nic (in dBm) """ 
    cmd = ['iwlist',nic,'txpower']
    p = sp.Popen(cmd,stdin=sp.PIPE,stdout=sp.PIPE,stderr=sp.PIPE)
    out,err=p.communicate()
    if err: raise IWException(err)
    try:
        pwr = re.search(r'Current Tx-Power=([\d]*)',out).group(1)
    except AttributeError:
        # re error, raise an unknown
        raise IWException("Failed to get txpower of %s" % nic)
    else:
        return int(pwr)

def regset(region):
    """
     a sub of iw for setting regulatory domain to <region>
     NOTE: IOT take effect, reg set should be called first, then take the
     card and bring it back up
    """
    cmd = ['iw','reg','set',region]
    if os.getuid() != 0: cmd.insert(0,'sudo')
    p = sp.Popen(cmd,stdin=sp.PIPE,stdout=sp.PIPE,stderr=sp.PIPE)
    out,err = p.communicate()
    if err: raise IWException(err.split(':')[1].strip())

def regget(regOnly=True):
    """
     a sub of iw for retrieving regulatory domain info. if regOnly, will return
     the two-alphanumeric code for the current region, otherwise will return
     the entire output, leaving parsing up to the caller
    """
    cmd = ['iw','reg','get']
    p = sp.Popen(cmd,stdin=sp.PIPE,stdout=sp.PIPE,stderr=sp.PIPE)
    out,err = p.communicate()
    if err: raise IWException(err.split(':')[1].strip())
    if regOnly:
        try:
            return re.search(r'country (.*):',out).group(1)
        except AttributeError:
            # re error raise an unknown
            raise IWException("Failed to get regulatory domain")
    else:
        return out
