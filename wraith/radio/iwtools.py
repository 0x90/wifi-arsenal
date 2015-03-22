#!/usr/bin/env python

""" iwtools.py: network interface card tools 

Provides interfaces to several nic related command line programs. They are not
interfaces per se in that the functions do not directly do anything but rather 
pass data to and parse data from system commands. There are other changes in that 
errors from the programs will cause an exception and not print to stderr. Each one 
may behave differently than the command line. For instance iwtools.iwconfig always
expects a nic and offers the additional functionality of retrieving the value of 
a parameter for the given nic.

These have only been tested on a ubuntu platform. In an attempt to make as 
portable as possible, users may need to be modify if the file format or program 
output changes with upgrades or differs on other platforms.

There are several ways of enabling root for iw* programs. None are completely
desirable but the method I have chosen is to edit /etc/sudoers and add
(for each desired program) nopasswd. Note that this could lead to some problems 
with security. See below
  Cmnd_Alias	IWCONFIG = /sbin/iwconfig
  <username> ALL=NOPASSWD:IWCONFIG

Tested on Ubuntu 12.04 with net-tools 1.60, ifconfig 1.42, Wireless-Tools version 30
"""
__name__ = 'iwtools'
__license__ = 'GPL v3.0'
__version__ = '0.0.12'
__date__ = 'April 2014'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Development'

import os                # getuid & file hierarchy
import re                # regular expressions
import subprocess as sp  # executing commands

# exception class
class IWToolsException(Exception): pass

# the following functions assist in determining available network interfaces

def ifaces():
    """ ifaces: returns a list of names of current network interfaces cards """
    # read in devices from /proc/net/dev. After splitting on newlines, the first 
    # 2 lines are headers and the last line is empty so we remove them
    try:
        fin = open('/proc/net/dev','r')
        ns = fin.read().split('\n')[2:-1]
        fin.close()
    except Exception as e:
        raise IWToolsException('ifaces: %s' % e)
    
    # the remaining lines are <nicname>: p1 p2 ... p3, split on ':' & strip whitespace
    nics = []
    for n in ns: nics.append(n.split(':')[0].strip())
    return nics

def wifaces():
    """ wifaces: returns a list of names of current wireless network interface cards """
    wics = []
    for nic in ifaces():
        p = sp.Popen(["iwconfig",nic],stdout=sp.PIPE,stderr=sp.PIPE)
        out,err = p.communicate()
        if out: wics.append(nic)
    return wics

#### IFCONFIG

"""
 IFPatterns - change these if necessary to fit system output defined as a 
              tuple (Paramameter,reg exp)
"""
IFPatterns = [('Link encap',r'Link encap:([\w]*) '),
              ('HWaddr',r'HWaddr ([:|\w]*) '),
              ('MTU',r'MTU:([\d]*)'),
              ('Metric',r'Metric:([\d]*)'),
              ('RX packets',r'Rx packets:([\d]*)'),
              ('errors',r'errors:([\d]*)'),
              ('dropped',r'dropped:([\d]*)'),
              ('overruns',r'overruns:([\d]*)'),
              ('frames',r'frames:([\d]*)'),
              ('TX packets',r'Tx packets:([\d]*)'),
              ('errors',r'errors:([\d]*)'),
              ('dropped',r'dropped:([\d]*)'),
              ('overruns',r'overruns:([\d]*)'),
              ('carrier',r'carrier:([\d]*)'),
              ('collisions',r'collisions:([\d]*)'),
              ('txqueuelen',r'txqueuelen:([\d]*)'),
              ('RX bytes',r'Rx bytes:([\d]*)'),
              ('TX bytes',r'TX bytes:([\d]*)')]

def ifconfig(nic,setto=None):
    """
     ifconfig - not a full interface. This limited function allows user to turn
     specified card on or off or view output about card
    """
    if not setto:
        # return dictionary of paramater:value for <nic>
        p = sp.Popen(["ifconfig",nic],stdin=sp.PIPE,stdout=sp.PIPE,stderr=sp.PIPE)
        out,err = p.communicate()
        
        # if no err than card details were found
        if not err:
            details = {}
            for key,iwp in IFPatterns:
                try:
                    details[key] = re.search(iwp,out).group(1)
                except AttributeError:
                    details[key] = None
            return details
        else:
            # raise exception with err as msg
            raise IWToolsException(err)
    else:
        cmd = ['ifconfig',nic]
        if os.getuid() != 0: cmd.insert(0,'sudo')
        if setto == 'up': cmd.append('up')
        elif setto == 'down': cmd.append('down')
        else: raise IWToolsException('usage: ifconfig(nic,[{up|down}])')
        p = sp.Popen(cmd,stderr=sp.PIPE,stdout=sp.PIPE)
        out,err = p.communicate()
        if err: raise IWToolsException(err)

#### MACCHANGER

def sethwaddr(nic,setto=None):
    """
     nic: nic identifier
     setto: if None will set to a random mac address, otherwise will use setto
      as new mac to assume
     uses macchanger to set the hw addr. iwconfig was more 'finicky'
     will return the new mac
    """
    if not setto:
        cmd = ['macchanger','-a',nic]
    else:
        cmd = ['macchanger','-m',setto,nic]
    if os.getuid() != 0: cmd.insert(0,'sudo')
    p = sp.Popen(cmd,stderr=sp.PIPE,stdout=sp.PIPE)
    out,err = p.communicate()

    # parse out and err for success - macchanger error messages appear as
    # "[ERROR] ...:...:...". split on colon and send middle portion
    if err: raise IWToolsException(err.split(':')[1].strip())

    # verify newmac
    r = re.search(r'\nNew MAC: *([:|\w]*) ',out)
    if not r: raise IWToolsException("MAC Address did not change")
    return r.groups()[0]

def resethwaddr(nic):
    """ reset macaddr of nic to permanent addr """
    cmd = ['macchanger','-p',nic]
    if os.getuid() != 0: cmd.insert(0,'sudo')
    p = sp.Popen(cmd,stderr=sp.PIPE,stdout=sp.PIPE)
    out,err = p.communicate()
    if err: raise IWToolsException(err)

#### IWCONFIG

"""
 IWPatterns - change these if necessary to fit system output defined as a 
              tuple (Paramameter,reg exp)
"""
IWPatterns = [('ESSID',r'ESSID:([^\s]*) '),
              ('Standards',r'IEEE ([\.|\d|a|b|g|n]*) '),
              ('Mode',r'Mode:([\w]*)'),
              ('Frequency',r'Frequency:([\.|\d]*)'),
              ('AP',r'Access Point: ([:|\w|-]*)'),
              ('Bit Bate',r'Bit Rate=([\d]*) '),
              ('Tx-Power',r'Tx-Power=([\d]*) '),
              ('Retry',r'Retry  long limit:([\w]*)'),
              ('RTS Thr',r'RTS thr:([\w]*)'),
              ('Frag Thr',r'Fragment thr:([\w]*)'),
              ('PWR MGMT',r'Power Management:([\w]*)'),
              ('Link Qual',r'Link Quality=([/|\d]*)'),
              ('Sig Lvl',r'Signal level=([-|\d]*)'),
              ('Rx Invalid NWID',r'Rx invalid nwid:([\d]*) '),
              ('RX Invalid Crypt',r'Rx invalid crypt:([\d]*) '),
              ('Rx Invalid Frag',r'Rx invalid frag:([\d]*) '),
              ('Tx Excessive Retries',r'Tx excessive retries:([\d]*) '),
              ('Invalid Misc',r'Invalid misc:([\d]*) '),
              ('Missed Beacon',r'Missed beacon:([\d]*) ')]

def iwconfig(nic,param=None,val=None):
    """
     iwconfig - python interface to iwconfig (kind of) unlike iwconfig, this
     expects the name of card and is not a true interface, merely parses the
     output from the iwconfig command.
     ARGUMENTS:
       nic: name of interface
       p: parameter to set
       v: value to set p to
     uses:
        p and v are None: returns a dict of property->value 
        v is None: returns the value of property p
        p and v are instantiated: sets the value of property to value v
    """
    if not param and not val:
        # return dictionary of paramater:value for <nic>
        p = sp.Popen(["iwconfig",nic],stdin=sp.PIPE,stdout=sp.PIPE,stderr=sp.PIPE)
        out,err = p.communicate()
        
        # if no err than card details were found
        if not err:
            details = {}
            for key,iwp in IWPatterns:
                try:
                    details[key] = re.search(iwp,out).group(1)
                except AttributeError:
                    details[key] = None
            return details
        else:
            # raise exception with err as msg
            raise IWToolsException(err)
    elif param and not val:
        # return the val for param for <nic>
        p = sp.Popen(["iwconfig",nic],stdin=sp.PIPE,stdout=sp.PIPE,stderr=sp.PIPE)
        out,err = p.communicate()
        
        # if no err than card details were not found
        if not err:
            try:
                t = [(x,y) for x,y in IWPatterns if x == param][0]
                val = re.search(t[1],out).group(1)
            except IndexError:
                # param is not valid
                return None
            except AttributeError:
                # param has no value for this card
                return None
            else:
                return val
        else:
            # raise exception with err as msg
            raise IWToolsException(err)
    else:
        # set <nic>'s <param> to <val>
        # throw an exception if p and v are not set
        if type(param) != type(''): raise IWToolsException('param must be a string')
        if type(val) != type(''): raise IWToolsException('val must be a string')
        
        # will fail if user is not allowed to run iwconfig as root
        cmd = ['iwconfig',nic,param,val]
        if os.getuid() != 0: cmd.insert(0,'sudo')
        p = sp.Popen(cmd,stdin=sp.PIPE,stdout=sp.PIPE,stderr=sp.PIPE)
        out,err = p.communicate()
        if err: raise IWToolsException(err)

#### ADDITIONAL CARD DETAILS

def getdriver(nic):
    """ returns the driver for given nic """
    try:
        # find the driver for nic in driver's module, split on ':' and return
        ds = os.listdir('/sys/class/net/%s/device/driver/module/drivers' % nic)
        if len(ds) > 1: return "Unknown"
        return ds[0].split(':')[1]
    except OSError:
        return "Unknown"

def getchipset(driver):
    """
     returns the chipset for given driver (Thanks aircrack-ng team)
     NOTE: does not fully implement the airmon-ng getChipset where identification
      requires system commands
    """
    if not driver: return "Unknown"
    if driver == "Unknown": return "Unknown"
    if driver == "Otus" or driver == "arusb_lnx": return "AR9001U"
    if driver == "WiLink": return "TIWLAN"
    if driver == "ath9k_htc" or driver == "usb": return "AR9001/9002/9271"
    if driver.startswith("ath") or driver == "ar9170usb": return "Atheros"
    if driver == "zd1211rw_mac80211": return "ZyDAS 1211"
    if driver == "zd1211rw": return "ZyDAS"
    if driver.startswith("acx"): return "TI ACX1xx"
    if driver == "adm8211": return "ADMtek 8211"
    if driver == "at76_usb": return "Atmel"
    if driver.startswith("b43") or driver == "bcm43xx": return "Broadcom"
    if driver.startswith("p54") or driver == "prism54": return "PrismGT"
    if driver == "hostap": return "Prism 2/2.5/3"
    if driver == "r8180" or driver == "rtl8180": return "RTL8180/RTL8185"
    if driver == "rtl8187" or driver == "r8187": return "RTL8187"
    if driver == "rt2570" or driver == "rt2500usb": return "Ralink 2570 USB"
    if driver == "rt2400" or driver == "rt2400pci": return "Ralink 2400 PCI"
    if driver == "rt2500" or driver == "rt2500pci": return "Ralink 2560 PCI"
    if driver == "rt61" or driver == "rt61pci": return "Ralink 2561 PCI"
    if driver == "rt73" or driver == "rt73usb": return "Ralink 2573 USB"
    if driver == "rt2800" or driver == "rt2800usb" or driver == "rt3070sta": return "Ralink RT2870/3070"
    if driver == "ipw2100": return "Intel 2100B"
    if driver == "ipw2200": return "Intel 2200BG/2915ABG"
    if driver == "ipw3945" or driver == "ipwraw" or driver == "iwl3945": return "Intel 3945ABG"
    if driver == "ipw4965" or driver == "iwl4965": return "Intel 4965AGN"
    if driver == "iwlagn" or driver == "iwlwifi": return "Intel 4965/5xxx/6xxx/1xxx"
    if driver == "orinoco": return "Hermes/Prism"
    if driver == "wl12xx": return "TI WL1251/WL1271"
    if driver == "r871x_usb_drv": return "Realtek 81XX"
    return "UNK Chipset"

