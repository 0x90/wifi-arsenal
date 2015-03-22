#! /usr/bin/python

#############
# MODULES #
#############

import __builtin__
import os
import time
import datetime
import sys
import tty
import termios
import curses
import select 
import subprocess
import signal
import sys, getopt
import datetime
import random
import urllib
from subprocess import Popen, call, PIPE

appver="1.0, R.2"
apptitle="WiFi-Harvester"
appDesc="- The Network Detail Harvesting System"
appcreated="28 Feb 2014"
appupdated="24 Mar 2014"
appnote="Written By SY Chua, " + appcreated + ", Updated " + appupdated
appdescription="The Network Harvester is use to collect detailed information on Access Points / Wireless Stations"

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
    SBlack=CReset + '\033[0;30m'
    SRed=CReset + '\033[0;31m'
    SGreen=CReset + '\033[0;32m'
    SYellow=CReset + '\033[0;33m'
    SBlue=CReset + '\033[0;34m'
    SPink=CReset + '\033[0;35m'
    SCyan=CReset + '\033[0;36m'
    SWhite=CReset + '\033[0;37m'
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

def BeepSound():
    if __builtin__.ALERTSOUND=="Yes":
        sys.stdout.write("\a\r")
        sys.stdout.flush()

def read_a_key():
    stdinFileDesc = sys.stdin.fileno()
    oldStdinTtyAttr = termios.tcgetattr(stdinFileDesc)
    try:
        tty.setraw(stdinFileDesc)
        sys.stdin.read(1)
    finally:
        termios.tcsetattr(stdinFileDesc, termios.TCSADRAIN, oldStdinTtyAttr)

def CheckAdmin():
    if os.getuid() != 0:
        printc ("!!!",fcolor.BGreen + apptitle + " required administrator rights in order to run properly !","")
        printc ("!!!",fcolor.SGreen + "Log in as '" + fcolor.BRed + "root" + fcolor.SGreen + "' user or run '" + fcolor.BRed + "sudo ./" + __builtin__.ScriptName + fcolor.SGreen + "'","")
        exit_gracefully(1)

def AboutApplication():
    os.system('clear')
    WordColor=fcolor.BCyan
    print fcolor.BGreen + "             " + fcolor.BRed + "(            )                                     "
    print fcolor.BRed   + " (  (        )\ )      ( /(                         )           "
    print fcolor.BRed   + " " + fcolor.BYellow + ")" + fcolor.BRed + "\\" + fcolor.BYellow + ")" + fcolor.BRed + "" + fcolor.BYellow + ")" + fcolor.BRed + "(   '( ((" + fcolor.BYellow + ")" + fcolor.BRed + "" + fcolor.BYellow + "/" + fcolor.BRed + "( (    " + fcolor.BYellow + ")" + fcolor.BRed + "\\(" + fcolor.BYellow + ")" + fcolor.BRed + "" + fcolor.BYellow + ")" + fcolor.BRed + "   " + fcolor.BYellow + ")" + fcolor.BRed + " (    " + fcolor.BYellow + ")" + fcolor.BRed + "     (    ( " + fcolor.BYellow + "/" + fcolor.BRed + "(  (  (     "
    print fcolor.BRed   + "((_" + fcolor.BYellow + ")" + fcolor.BRed + "(" + fcolor.BYellow + ")" + fcolor.BRed + "\\ " + fcolor.BYellow + ")" + fcolor.BRed + " " + fcolor.BYellow + ")" + fcolor.BRed + "\\ " + fcolor.BYellow + "/" + fcolor.BRed + "(_" + fcolor.BYellow + ")" + fcolor.BRed + "" + fcolor.BYellow + ")" + fcolor.BRed + "" + fcolor.BYellow + ")" + fcolor.BRed + "\\  ((_" + fcolor.BYellow + ")" + fcolor.BRed + "\\ ( " + fcolor.BYellow + "/" + fcolor.BRed + "( " + fcolor.BYellow + ")" + fcolor.BRed + "(  " + fcolor.BYellow + "/" + fcolor.BRed + "((   " + fcolor.BYellow + ")" + fcolor.BRed + "" + fcolor.BYellow + ")" + fcolor.BRed + "\\(  " + fcolor.BYellow + ")" + fcolor.BRed + "\\(" + fcolor.BYellow + ")" + fcolor.BRed + "" + fcolor.BYellow + ")" + fcolor.BRed + "" + fcolor.BYellow + ")" + fcolor.BRed + "" + fcolor.BYellow + ")" + fcolor.BRed + "\\ " + fcolor.BYellow + ")" + fcolor.BRed + "(    "
    print WordColor + "_" + fcolor.BRed + "((" + fcolor.BYellow + ")" + fcolor.BRed + "" + fcolor.BYellow + ")" + fcolor.BRed + "\\" + WordColor + "_" + fcolor.BYellow + ")" + fcolor.BRed + "(|(" + WordColor + "_" + fcolor.BRed + "|" + WordColor + "_" + fcolor.BYellow + ")" + fcolor.BRed + "" + fcolor.BYellow + ")" + WordColor + "_" + fcolor.BRed + "((" + WordColor + "_" + fcolor.BYellow + ")" + fcolor.BRed + "  " + WordColor + "_" + fcolor.BRed + "((" + WordColor + "_" + fcolor.BYellow + ")" + fcolor.BRed + "" + fcolor.BYellow + ")" + fcolor.BRed + "(" + fcolor.BYellow + "_)" + fcolor.BRed  + "|" + fcolor.BRed + "(" + fcolor.BYellow + ")" + fcolor.BRed + "\\(" + fcolor.BYellow + "_)" + fcolor.BRed + "" + fcolor.BYellow + ")" + fcolor.BRed + "\\ " + fcolor.BYellow + "/" + fcolor.BRed + "((" + WordColor + "" + fcolor.BYellow + "_)" + fcolor.BRed + "\\(" + WordColor + "_" + fcolor.BYellow + ")" + fcolor.BRed + "" + fcolor.BYellow + ")" + fcolor.BRed + "" + fcolor.BYellow + "/" + fcolor.BRed + "" + fcolor.BYellow + "/" + fcolor.BRed + "((" + fcolor.BYellow + "_|" + fcolor.BRed + "(" + fcolor.BYellow + ")" + fcolor.BRed + "\\   "
    print WordColor + "\\ \\" + fcolor.BRed + "((" + WordColor + "_" + fcolor.BYellow + ")" + WordColor + "/ /(_) |_  (_) | || " + fcolor.BRed + "((" + WordColor + "_" + fcolor.BYellow + ")" + WordColor + "_ " + fcolor.BRed + "((" + WordColor + "_" + fcolor.BYellow + "))" + fcolor.BRed + "((" + WordColor + "_" + fcolor.BRed + "|" + WordColor + "_" + fcolor.BYellow + "))" + fcolor.BRed + "((" + WordColor + "_" + fcolor.BYellow + ") " + fcolor.BRed + "" + WordColor + "|_" + fcolor.BRed + "(" + WordColor + "_" + fcolor.BYellow + "))  " + fcolor.BRed + "((" + WordColor + "_" + fcolor.Yellow + ")  "
    print WordColor + " \ \/\/ / | | __| | | | __ / _` | '_\ V // -_|_-<  _/ -_)| '_|  "
    print WordColor + "  \_/\_/  |_|_|   |_| |_||_\__,_|_|  \_/ \___/__/\__\___||_|    "
    ShowSYWorks()
    print "";print ""
    print fcolor.BGreen + apptitle + " " + appver + fcolor.SGreen + " " + appDesc
    print fcolor.CReset + fcolor.White + appnote
    print ""
    DisplayDescription()
    print fcolor.BWhite + "Fans Page - " + fcolor.BBlue + "https://www.facebook.com/syworks" +fcolor.BWhite + " (SYWorks-Programming)"
    print fcolor.BWhite + "Tutorial  - " + fcolor.BBlue + "https://syworks.blogspot.com/" +fcolor.BWhite + ""
    print "";print ""
    printc ("x",fcolor.BRed + "Press a key to continue...","")
    DrawLine("_",fcolor.CReset + fcolor.Black,""); print ""

def GetOptionCommands(HeaderLine):
    if HeaderLine!="":
        DrawLine("_",fcolor.CReset + fcolor.Black,""); print ""
    printc ("+", fcolor.BBlue + "Command Selection Menu ","")
    Option1 = SelBColor + "C" + StdColor + " - Application " + SelColor + "C" + StdColor + "onfiguation\t\t"
    Option2 = SelBColor+ "D" + StdColor + " - Output " + SelColor + "D" + StdColor + "isplay\t\t"
    Option3 = SelBColor + "F" + StdColor + " - " + SelColor + "F" + StdColor + "ilter Network Display\t\t"
    Option4 = SelBColor + "H" + StdColor + " - " + SelColor + "H" + StdColor + "istory Logs\t\t"
    OptionA=Option1 + Option2 + Option3 + Option4
    Option1 = SelBColor + "M" + StdColor + " - " + SelColor + "M" + StdColor + "onitor MAC Addr / Names\t\t"
    Option2 = SelBColor + "L" + StdColor + " - " + SelColor + "L" + StdColor + "ookup MAC/Name Detail\t"
    Option3 = SelBColor + "A" + StdColor + " - " + SelColor + "A" + StdColor + "bout Application\t\t\t"
    Option4 = SelBColor + "X" + StdColor + " - E" + SelColor + "x" + StdColor + "it Application\t"
    OptionB=Option1 + Option2 + Option3 + Option4
    printc (" ", fcolor.BYellow + OptionA,"")
    printc (" ", fcolor.BYellow + OptionB,"")
    print ""
    usr_resp=AskQuestion("Enter your option : ",fcolor.SWhite + "<default = return>","U","ALL","1")
    DrawLine("_",fcolor.CReset + fcolor.Black,"");print "";
    if usr_resp=="ALL":
        return;
    if usr_resp=="X":
        usr_resp=AskQuestion(fcolor.BRed + "Are you sure you want to exit" + fcolor.BGreen,"y/N","U","N","1")
        if usr_resp=="Y":
            exit_gracefully(0)
        return;
    if usr_resp=="A":
        AboutApplication()
        DisplayPanel()
        return

    if usr_resp=="D":
        OptOutputDisplay()
        GetOptionCommands("")
        return;

    if usr_resp=="F":
        OptFilterDisplay("")

    if usr_resp=="C":
        OptConfiguration("")
    if usr_resp=="M":
        OptMonitorMAC("")
    if usr_resp=="L":
        OptInfoDisplay("")

    if usr_resp=="H":
        usr_resp=AskQuestion("Select Log ",STxt + "C" + NTxt + "onnection Cautious Log / " + "Default - " + STxt + "R" + NTxt + "eturn","U","ALL","1")
        if usr_resp=="C":
            if __builtin__.MSG_HistoryConnection!="":
                print ""
                printc ("i", "Connection Cautious Information History", "")
                print __builtin__.MSG_HistoryConnection
                DrawLine("_",fcolor.CReset + fcolor.Black,"")
                print ""
                printc ("x","","")
            else:
                print ""
                printc ("!!!", "Connection Cautious Information History Not Found", "")
                printc ("x","","")
                return "";
    return;

def WaitingCommands(Timer=0, ShowDisplay=1):
    usr_resp=""
    if Timer==0:
        if ShowDisplay==1:
            printl(fcolor.SGreen + "Press " + fcolor.BGreen + "Ctrl+C" + fcolor.SGreen + " to break..","0","")
        stdinFileDesc = sys.stdin.fileno()
        oldStdinTtyAttr = termios.tcgetattr(stdinFileDesc)
        tty.setraw(stdinFileDesc)
        usr_resp=sys.stdin.read(1)
        termios.tcsetattr(stdinFileDesc, termios.TCSADRAIN, oldStdinTtyAttr)
        if usr_resp=="\x03":
            printc (" ", fcolor.BRed + "\nInterrupted !!","")
            Result=AskQuestion("Yes or No, Null as 'N' (Lower casing)","y/N","U","N","1")
            if Result=="Y":
                return "Break"
            return ""
        if usr_resp=="\x0d":
            printc (" ", fcolor.BRed + "\nInterrupted - Enter Command !!","")
            return "";
 
        if usr_resp=="a":
            printc(" ","A pressed","")
        else:
            return ""
    else:
        try:
            t=int(Timer)
            bcolor=fcolor.SWhite
            pcolor=fcolor.BGreen
            tcolor=fcolor.SGreen
            PrintText2=""
            RunIWList()
            PrintText="Refreshing in " + str(Timer) + " seconds... Press " + fcolor.BYellow + "[Enter]" + fcolor.SGreen + " to input command..."
            while t!=0:
                s=bcolor + "[" + pcolor + str(t) + bcolor + "]" + __builtin__.tabspace + tcolor + PrintText + "\r"
                s=s.replace("%s",pcolor+str(PrintText2)+tcolor)
                sl=len(s)
                print s,
                sys.stdout.flush()
                time.sleep(1)
                s=""
                ss="\r"
                print "" + s.ljust(sl+2) + ss,
                sys.stdout.flush()
                t=t-1
                while sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
                    usr_resp = sys.stdin.readline()
                    if usr_resp:
                        GetOptionCommands("1")
                c1=bcolor + "[" + pcolor + "-" + bcolor + "]" + __builtin__.tabspace + tcolor + PrintText + "\r"
                c1=c1.replace("%s",pcolor+str(PrintText2)+tcolor)
                print c1,
                sys.stdout.flush()
        except KeyboardInterrupt:
            printc (" ", fcolor.BRed + "\nInterrupted !!","")
            Result=AskQuestion(fcolor.BRed + "Are you sure you want to exit"+ fcolor.BGreen,"y/N","U","N","1")
            if Result=="Y":
                return "Break"
            else:
                return "";

def DisplayClientDetail(DisplayTitle,DataList):
    tmpList = []
    CenterText(fcolor.BBlue, DisplayTitle + "     ")
    DrawLine("~",fcolor.CReset + fcolor.Black,""); print ""
    tmpList=DataList
    x=0
    RecordNum=0
    StnColor=fcolor.SGreen
    while x<len(DataList):
        RecordNum += 1
        DataValue0="";DataValue1="";DataValue2="";DataValue3="";DataValue4="";DataValue5="";DataValue6="";DataValue7="";DataValue8=""
        n=int(DataList[x])
        StnMAC=ListInfo_STATION[n]
        DataValue0 = StnColor + "Client Number   : " + fcolor.SRed + str(RecordNum)  + "\n"
        DataValue1= StnColor + "STATION MAC ID  : " + fcolor.SYellow + str(StnMAC).ljust(40) + StnColor + "Vendor      : " + fcolor.SCyan + str(__builtin__.ListInfo_COUI[n]) + "\n"    
        SignalRange=str(ListInfo_CBestQuality[n]) + " dBm" + StnColor + fcolor.CBold + " ["  + str(ListInfo_CQualityRange[n])  + StnColor + fcolor.CBold + "]" 
        DataValue2 = StnColor + "Power/Range     : " + StdColor + str(SignalRange) + "\t\t\t  " + StnColor + "Packets     : " + StdColor + str(ListInfo_CPackets[n]) + "\n"
        DataValue3 = StnColor + "First Time Seen : " + StdColor + str(ListInfo_CFirstSeen[n]).ljust(40) + StnColor + "Last Seen   : " + StdColor + str(ListInfo_CLastSeen[n]).ljust(41) + StnColor + "Duration    : " + StdColor + str(ListInfo_CElapse[n]) +"\n"
        if str(ListInfo_PROBE[n])!="":
            Probes=ListInfo_PROBE[n]
            Probes=str(Probes).replace(" / ",StnColor + " | " + StdColor)
            DataValue4 = StnColor + "Probes          : " + fcolor.SBlue + str(Probes) +"\n"
        AssocHistory=str(ListInfo_CBSSIDPrevList[n])
        AssocHistory=str(AssocHistory).replace("| Not Associated | ","").replace("Not Associated | ","").replace("  "," ").replace("|",StnColor + "|" + StdColor)
        DataValue5 = StnColor + "ESSID Connected : " + StdColor + str(ListInfo_CESSID[n]).ljust(40) + StnColor + "Last Active : " + StdColor + str(ListInfo_CTimeGapFull[n]) + StnColor + " - [ " + StdColor + str(ListInfo_CTimeGap[n]) + StnColor + " min ago ]" + "\n"
        DataValue6 = StnColor + "Connect History : " + StdColor + str(AssocHistory) +"\n"
        DataValue7=""
        DataValue= DataValue0 + DataValue1 + DataValue2 + DataValue3 + DataValue4 + DataValue5 + DataValue6 + DataValue7  
        print DataValue
        DisplayMACDetailFromFiles(StnMAC)
        x += 1

def RemoveUnwantMAC(MACAddr):
    sMAC=[]
    sMAC=MACAddr.split("/")
    ax=0
    lsMAC=len(sMAC)
    while ax<lsMAC:
        MAC_ADR=sMAC[ax]
        MAC_ADR=MAC_ADR.lstrip().rstrip()
        sMAC[ax]=MAC_ADR
        if MAC_ADR[:12]=="FF:FF:FF:FF:":
            sMAC[ax]=""
        if MAC_ADR[:6]=="33:33:":
            sMAC[ax]=""
        if MAC_ADR[:9]=="01:80:C2:":
            sMAC[ax]=""
        if MAC_ADR[:9]=="01:00:5E:":
            sMAC[ax]=""
        if MAC_ADR[:3]=="FF:":
            sMAC[ax]=""
        if MAC_ADR==str(__builtin__.SELECTED_MON_MAC):
            sMAC[ax]=""
        if MAC_ADR==str(__builtin__.SELECTED_MANIFACE_MAC):
            sMAC[ax]=""
        ax=ax+1
    ax=0
    NewMAC=""
    while ax<len(sMAC):
        if sMAC[ax]!="":
            NewMAC=NewMAC + str(sMAC[ax]) + " / "
        ax=ax+1
    if NewMAC[-3:]==" / ":
        NewMAC=NewMAC[:-3]
    return NewMAC

def DisplayBSSIDDetail():
    CenterText(fcolor.BWhite + fcolor.BGBlue, "MATCHED ACCESS POINT LISTING [ " + str(len(__builtin__.ShowBSSIDList)) + " ]")
    RecordNum=0
    i=0
    while i < len(__builtin__.ShowBSSIDList):
        RecordNum += 1
        n=__builtin__.ShowBSSIDList[i]
        ESSID=str(ListInfo_ESSID[n])
        BSSID=str(ListInfo_BSSID[n])
        DBSSID=str(BSSID).ljust(40)
        DESSID=str(ESSID).ljust(95)
        if ESSID=="":
            DESSID=fcolor.SBlack + "<<NO NAME>>" + str(DESSID)[11:]
        DataValue1= lblColor + "AP MAC  [BSSID] : " + fcolor.BYellow + str(DBSSID) + lblColor + "Vendor      : " + VendorColor + str(ListInfo_BSSID_OUI[n]) + "\n"
        QualityRange=str(ListInfo_Quality[n])
        if QualityRange!="-":
            QualityRange=lblColor + " - " + StdColor + str(QualityRange)
        else:
            QualityRange=""
        SignalRange=str(ListInfo_BestQuality[n]) + " dBm" + lblColor + fcolor.CBold + " ["  + str(ListInfo_QualityRange[n])  + lblColor + "]"  + str(QualityRange)
        DataValue2 = lblColor + "AP Name [ESSID] : " + fcolor.BPink + str(DESSID) + lblColor + "Power       : " + StdColor + str(SignalRange) + "\n"                 # + lblColor + "Signal  : " + StdColor + str(ListInfo_BestSignal[n]).ljust(15) + lblColor + "Noise  : " + StdColor + str(ListInfo_BestNoise[n]) + "\n"
        Privacy=str(ListInfo_Privacy[n]) + " / " + str(ListInfo_Cipher[n]) + " / " + str(ListInfo_Auth[n])
        DataValue3 = lblColor + "Encryption Type : " + StdColor + Privacy.ljust(40) + lblColor + "Beacon      : " + StdColor + str(ListInfo_Beacon[n]).ljust(15) + lblColor + "Data     : " + StdColor + str(ListInfo_Data[n]).ljust(15) + lblColor + "Total Data  : " + StdColor + str(ListInfo_Total[n]) + "\n"
        MaxRate=str(ListInfo_MaxRate[n]) + " Mb/s"
        ChannelFreq=str(ListInfo_Channel[n]) + " / " + str(ListInfo_Freq[n]) + " GHz"
        LastBeacon=str(ListInfo_LastBeacon[n])
        if LastBeacon!="-" and LastBeacon!="":
            LastBeacon = LastBeacon + " ago"
        LastBeacon=str(LastBeacon).ljust(41)
        DataValue4 = lblColor + "Channel / Freq. : " + StdColor + str(ChannelFreq).ljust(40) + lblColor + "Max. Rate   : " + StdColor + str(MaxRate).ljust(15) + lblColor + "Cloaked? : " + StdColor + str(ListInfo_Cloaked[n]).ljust(15) + lblColor  + "Mode        : " + StdColor + str(ListInfo_Mode[n]) + "\n"
        GPSLoc=str(ListInfo_GPSBestLat[n]) + " / " + str(ListInfo_GPSBestLon[n])
        BitRate=ListInfo_BitRate[n].replace("|",lblColor + "|" + StdColor)
        DataValue5 = lblColor + "Bit Rates       : " + StdColor + str(BitRate) + "\n"
        DataValue6 = lblColor + "GPS Lat/Long    : " + StdColor + GPSLoc.ljust(40) + lblColor + "Last Beacon : " + StdColor + str(LastBeacon) + lblColor + "Last Active : " + StdColor + str(ListInfo_SSIDTimeGapFull[n]) + lblColor + " - [ " + StdColor + str(ListInfo_SSIDTimeGap[n]) + lblColor + " min ago ]" + "\n"
        DataValue7 = lblColor + "First Time Seen : " + StdColor + str(ListInfo_FirstSeen[n]).ljust(40) + lblColor + "Last Seen   : " + StdColor + str(ListInfo_LastSeen[n]).ljust(41) + lblColor + "Duration    : " + StdColor + str(ListInfo_SSIDElapse[n]) +"\n"
        Cipher=""
        if __builtin__.ListInfo_PairwiseCipher[n]!="-":
            Cipher=Cipher + __builtin__.ListInfo_PairwiseCipher[n] + " (Pairwise) / "
        if __builtin__.ListInfo_GroupCipher[n]!="-":
            Cipher=Cipher + __builtin__.ListInfo_GroupCipher[n] + " (Group) / "
        if Cipher=="":
            Cipher="-"
        else:
            if Cipher[-3:]==" / ":
                Cipher=Cipher[:-3]
        Cipher=str(str(Cipher).ljust(41)).replace("/",lblColor + "/" + StdColor)
        DataValue8=""
        if str(ListInfo_Privacy[n]).find("WPA")!=-1:
            if str(ListInfo_WPAVer[n])!="-" or str(ListInfo_AuthSuite[n])!="-" or str(ListInfo_PairwiseCipher[n])!="-" or str(ListInfo_GroupCipher[n])!="-":
                DataValue8 = lblColor + "WPA Information : " + StdColor + str(ListInfo_WPAVer[n]).ljust(40) + lblColor + "Cipher      : " + StdColor + str(Cipher) + lblColor + "Auth        : " + StdColor + str(ListInfo_AuthSuite[n]) + "\n"
        if ListInfo_ConnectedClient[n]=="" or ListInfo_ConnectedClient[n]=="0":
            ClientText="No client associated"
        else:
            ClientText=ListInfo_ConnectedClient[n]
        WPSInfo="Not Enabled"
        if ListInfo_WPS[n]!="-":
            WPSLock=""
            if ListInfo_WPSLock[n]!="No":
                WPSLock=lblColor + " / " + StdColor + "Locked"
            WPSInfo=ListInfo_WPS[n] + lblColor + " / Ver : " + StdColor + ListInfo_WPSVer[n] + WPSLock
        DataValue9 = lblColor + "Connected Client: " + StdColor + str(ClientText).ljust(40) + lblColor + "WPS Enabled : " + StdColor + str(WPSInfo) + "\n"
        k=0
        ConnectedClient= []
        PrevConnectedClient= []
        UnassociatedClient= []
        while k < len(__builtin__.ListInfo_STATION):
            if __builtin__.ListInfo_CBSSID[k]==BSSID:
                ConnectedClient.append (str(k))
            if str(__builtin__.ListInfo_CBSSIDPrevList[k]).find(BSSID)!=-1 and str(__builtin__.ListInfo_CBSSID[k])!=BSSID:
                if __builtin__.ListInfo_CBSSID[k]!=BSSID:
                    PrevConnectedClient.append (str(k))
            if ESSID!="" and __builtin__.ListInfo_PROBE[k].find(ESSID)!=-1 and __builtin__.ListInfo_CBSSID[k]!=BSSID:
                UnassociatedClient.append (str(k))
            k += 1
        DataValue10=""
        DataValue11=""
        if len(UnassociatedClient)>0:
            DataValue10 = lblColor + "Unassociated    : " + StdColor + str(len(UnassociatedClient)) + " station which is not associated with Access Point but probing for " + fcolor.BPink + str(ESSID) + "\n"
        if len(PrevConnectedClient)>0:
            DataValue11 = lblColor + "Prev. Connection: " + StdColor + str(len(PrevConnectedClient)) + "\n"

        RecNo=str(RecordNum)
        if str(ListInfo_Enriched[n])!="":
            RecNo=RecNo + " *"
        RecNo=str(str(RecNo).ljust(40)).replace(" *",fcolor.SCyan + " *")
        RecType=""
        if str(__builtin__.ListInfo_STATION).find(BSSID)!=-1:
            RecType=fcolor.BRed + "The MAC Address is detected to be both an Access Point & Station"
        CenterText(fcolor.BBlack + fcolor.BGWhite, "MAC ADDRESS [ " + str(BSSID) + "] DETAILED INFORMATION - RECORD " + str(RecordNum) + "/" + str(len(__builtin__.ShowBSSIDList)))
        print ""
        DataValue0 = lblColor + "Access Point No.: " + fcolor.BRed + str(RecNo) + str(RecType) + "\n"
        DataValue= DataValue0 + DataValue1 + DataValue2 + DataValue3 + DataValue4 + DataValue5 + DataValue6 + DataValue7  + DataValue8 + DataValue9 + DataValue10 + DataValue11
        print DataValue
        DisplayMACDetailFromFiles(BSSID)
        if len(ConnectedClient)>0:
            DisplayClientDetail("Associated Client",ConnectedClient)
        if len(PrevConnectedClient)>0:
            DisplayClientDetail("Clients Previously Connected To Access Point",PrevConnectedClient)
        if len(UnassociatedClient)>0:
            DisplayClientDetail("Unassociated Client Probing For SSID [" + str(ESSID) + "]",UnassociatedClient)
        i += 1
    return

def DisplayConnectedBSSID(DisplayTitle,DataList):
    CenterText(fcolor.BPink, DisplayTitle + "     ")
    DrawLine("~",fcolor.CReset + fcolor.Black,""); print ""
    tmpList=DataList
    x=0
    RecordNum=0
    APColor=fcolor.SGreen
    while x<len(DataList):
        RecordNum += 1
        DataValue0="";DataValue1="";DataValue2="";DataValue3="";DataValue4="";DataValue5="";DataValue6="";DataValue7="";DataValue8=""
        APMAC=DataList[x]
        if len(APMAC)==17:
            APLoc=str(ListInfo_BSSID).find(str(APMAC))
            n=int(APLoc) -2
            n=n/21
            ESSID=str(ListInfo_ESSID[n])
            BSSID=str(ListInfo_BSSID[n])
            DBSSID=str(BSSID).ljust(40)
            DESSID=str(ESSID).ljust(95)
            if ESSID=="":
                DESSID=fcolor.SBlack + "<<NO NAME>>" + str(DESSID)[11:]
            DataValue1= APColor + "AP MAC  [BSSID] : " + fcolor.SYellow + str(DBSSID) + APColor + "Vendor      : " + fcolor.SCyan + str(ListInfo_BSSID_OUI[n]) + "\n"
            QualityRange=str(ListInfo_Quality[n])
            if QualityRange!="-":
                QualityRange=APColor + " - " + StdColor + str(QualityRange)
            else:
                QualityRange=""
            SignalRange=str(ListInfo_BestQuality[n]) + " dBm" + APColor + " ["  + str(ListInfo_QualityRange[n])  + APColor + "]"  + str(QualityRange)
            DataValue2 = APColor + "AP Name [ESSID] : " + fcolor.SPink + str(DESSID) + APColor + "Power       : " + StdColor + str(SignalRange) + "\n"                 # + APColor + "Signal  : " + StdColor + str(ListInfo_BestSignal[n]).ljust(15) + APColor + "Noise  : " + StdColor + str(ListInfo_BestNoise[n]) + "\n"
            Privacy=str(ListInfo_Privacy[n]) + " / " + str(ListInfo_Cipher[n]) + " / " + str(ListInfo_Auth[n])
            DataValue3 = APColor + "Encryption Type : " + StdColor + Privacy.ljust(40) + APColor + "Beacon      : " + StdColor + str(ListInfo_Beacon[n]).ljust(15) + APColor + "Data     : " + StdColor + str(ListInfo_Data[n]).ljust(15) + APColor + "Total Data  : " + StdColor + str(ListInfo_Total[n]) + "\n"
            MaxRate=str(ListInfo_MaxRate[n]) + " Mb/s"
            ChannelFreq=str(ListInfo_Channel[n]) + " / " + str(ListInfo_Freq[n]) + " GHz"
            LastBeacon=str(ListInfo_LastBeacon[n])
            if LastBeacon!="-" and LastBeacon!="":
                LastBeacon = LastBeacon +  " ago"
            LastBeacon=str(LastBeacon).ljust(40)
            DataValue4 = APColor + "Channel / Freq. : " + StdColor + str(ChannelFreq).ljust(40) + APColor + "Max. Rate   : " + StdColor + str(MaxRate).ljust(15) + APColor + "Cloaked? : " + StdColor + str(ListInfo_Cloaked[n]).ljust(15) + APColor  + "Mode        : " + StdColor + str(ListInfo_Mode[n]) + "\n"
            GPSLoc=str(ListInfo_GPSBestLat[n]) + " / " + str(ListInfo_GPSBestLon[n])
            BitRate=ListInfo_BitRate[n].replace("|",APColor + "|" + StdColor)
            DataValue5 = APColor + "Bit Rates       : " + StdColor + str(BitRate) + "\n"
            DataValue6 = APColor + "GPS Lat/Long    : " + StdColor + GPSLoc.ljust(40) + APColor + "Last Beacon : " + StdColor + str(LastBeacon) + APColor + " Last Active : " + StdColor + str(ListInfo_SSIDTimeGapFull[n]) + APColor + " - [ " + StdColor + str(ListInfo_SSIDTimeGap[n]) + APColor + " min ago ]" + "\n"
            DataValue7 = APColor + "First Time Seen : " + StdColor + str(ListInfo_FirstSeen[n]).ljust(40) + APColor + "Last Seen   : " + StdColor + str(ListInfo_LastSeen[n]).ljust(40) + APColor + " Duration    : " + StdColor + str(ListInfo_SSIDElapse[n]) +"\n"
            Cipher=""
            if __builtin__.ListInfo_PairwiseCipher[n]!="-":
                Cipher=Cipher + __builtin__.ListInfo_PairwiseCipher[n] + " (Pairwise) / "
            if __builtin__.ListInfo_GroupCipher[n]!="-":
                Cipher=Cipher + __builtin__.ListInfo_GroupCipher[n] + " (Group) / "
            if Cipher=="":
                Cipher="-"
            else:
                if Cipher[-3:]==" / ":
                    Cipher=Cipher[:-3]
            Cipher=str(str(Cipher).ljust(41)).replace("/",APColor + "/" + StdColor)
            DataValue8=""
            if str(ListInfo_Privacy[n]).find("WPA")!=-1:
                if str(ListInfo_WPAVer[n])!="-" or str(ListInfo_AuthSuite[n])!="-" or str(ListInfo_PairwiseCipher[n])!="-" or str(ListInfo_GroupCipher[n])!="-":
                    DataValue8 = APColor + "WPA Information : " + StdColor + str(ListInfo_WPAVer[n]).ljust(40) + APColor + "Cipher      : " + StdColor + str(Cipher) + APColor + "Auth        : " + StdColor + str(ListInfo_AuthSuite[n]) + "\n"
            if ListInfo_ConnectedClient[n]=="" or ListInfo_ConnectedClient[n]=="0":
                ClientText="No client associated"
            else:
                ClientText=ListInfo_ConnectedClient[n]
            WPSInfo="Not Enabled"
            if ListInfo_WPS[n]!="-":
                WPSLock=""
                if ListInfo_WPSLock[n]!="No":
                    WPSLock=APColor + " / " + StdColor + "Locked"
                WPSInfo=ListInfo_WPS[n] + APColor + " / Ver : " + StdColor + ListInfo_WPSVer[n] + WPSLock
            DataValue9 = APColor + "Connected Client: " + StdColor + str(ClientText).ljust(40) + APColor + "WPS Enabled : " + StdColor + str(WPSInfo) + "\n"
            k=0
            ConnectedClient= []
            PrevConnectedClient= []
            UnassociatedClient= []
            while k < len(__builtin__.ListInfo_STATION):
                if __builtin__.ListInfo_CBSSID[k]==BSSID:
                    ConnectedClient.append (str(k))
                if str(__builtin__.ListInfo_CBSSIDPrevList[k]).find(BSSID)!=-1 and str(__builtin__.ListInfo_CBSSID[k])!=BSSID:
                    if __builtin__.ListInfo_CBSSID[k]!=BSSID:
                        PrevConnectedClient.append (str(k))
                if ESSID!="" and __builtin__.ListInfo_PROBE[k].find(ESSID)!=-1 and __builtin__.ListInfo_CBSSID[k]!=BSSID:
                    UnassociatedClient.append (str(k))
                k += 1
            DataValue10=""
            DataValue11=""
            if len(UnassociatedClient)>0:
                DataValue10 = APColor + "Unassociated    : " + StdColor + str(len(UnassociatedClient)) + " station which is not associated with Access Point but probing for " + fcolor.BPink + str(ESSID) + "\n"
            if len(PrevConnectedClient)>0:
                DataValue11 = APColor + "Prev. Connection: " + StdColor + str(len(PrevConnectedClient)) + "\n"
            RecNo=str(RecordNum)
            if str(ListInfo_Enriched[n])!="":
                RecNo=RecNo + " *"
            RecNo=str(str(RecNo).ljust(40)).replace(" *",fcolor.SCyan + " *")
            RecType=""
            if str(__builtin__.ListInfo_STATION).find(BSSID)!=-1:
                RecType=fcolor.BRed + "The MAC Address is detected to be both an Access Point & Station"

            DataValue0 = APColor + "Access Point No.: " + fcolor.SRed + str(RecNo) + str(RecType) + "\n"
            DataValue= DataValue0 + DataValue1 + DataValue2 + DataValue3 + DataValue4 + DataValue5 + DataValue6 + DataValue7  + DataValue8 + DataValue9 + DataValue10 + DataValue11
            print DataValue
            DisplayMACDetailFromFiles(BSSID)
        x += 1

def DisplayStationDetail():
    CenterText(fcolor.BWhite + fcolor.BGBlue, "MATCHED STATIONS LISTING [ " + str(len(__builtin__.ShowStationList)) + " ]")
    x=0
    StnColor=fcolor.SGreen
    RecordNum=0
    while x < len(__builtin__.ShowStationList):
        RecordNum += 1
        DataValue0="";DataValue1="";DataValue2="";DataValue3="";DataValue4="";DataValue5="";DataValue6="";DataValue7="";DataValue8=""
        n=int(__builtin__.ShowStationList[x])
        StnMAC=ListInfo_STATION[n]
        CBSSID=ListInfo_CBSSID[n]
        OUITxt=Check_OUI(ListInfo_CBSSID[x])
        DataValue0 = lblColor + "Client Number   : " + fcolor.BRed + str(RecordNum)  + "\n"
        DataValue1= lblColor + "STATION MAC ID  : " + fcolor.BYellow + str(StnMAC).ljust(40) + lblColor + "Vendor      : " + fcolor.BCyan + str(__builtin__.ListInfo_COUI[n]) + "\n"    
        SignalRange=str(ListInfo_CBestQuality[n]) + " dBm" + lblColor + fcolor.CBold + " ["  + str(ListInfo_CQualityRange[n])  + lblColor + fcolor.CBold + "]" 
        DataValue2 = lblColor + "Power/Range     : " + StdColor + str(SignalRange) + "\t\t\t  " + lblColor + "Packets     : " + StdColor + str(ListInfo_CPackets[n]) + "\n"
        DataValue3 = lblColor + "First Time Seen : " + StdColor + str(ListInfo_CFirstSeen[n]).ljust(40) + lblColor + "Last Seen   : " + StdColor + str(ListInfo_CLastSeen[n]).ljust(41) + lblColor + "Duration    : " + StdColor + str(ListInfo_CElapse[n]) +"\n"
        CntBSSID=CBSSID
        if str(CntBSSID).find("Not Associated")!=-1:
            CntBSSID="<Not Associated>"
            CntBSSID=fcolor.SBlack + str(CntBSSID).ljust(40)
        else:
            CntBSSID=fcolor.BWhite+ str(CntBSSID).ljust(40)
        DataValue4= lblColor + "Connected BSSID : " + str(CntBSSID) + lblColor + "Vendor      : " + fcolor.SCyan + str(OUITxt) + "\n"    
        CntESSID=ListInfo_CESSID[n]
        if CntESSID=="" and str(CntBSSID).find("Not Associated")==-1:
            CntESSID=fcolor.SBlack + "<<NO NAME>>".ljust(40)
        else:
            CntESSID=fcolor.BPink + ListInfo_CESSID[n].ljust(40)
        DataValue5 = lblColor + "ESSID Connected : " + StdColor + str(CntESSID) + lblColor + "Last Active : " + StdColor + str(ListInfo_CTimeGapFull[n]) + lblColor + " - [ " + StdColor + str(ListInfo_CTimeGap[n]) + lblColor + " min ago ]" + "\n"

        if str(ListInfo_PROBE[n])!="":
            Probes=ListInfo_PROBE[n]
            Probes=str(Probes).replace(" / ",lblColor + " | " + fcolor.SBlue)
            DataValue6 = lblColor + "Probes          : " + fcolor.SBlue + str(Probes) +"\n"
        AssocHistory=str(ListInfo_CBSSIDPrevList[n])
        AssocHistory=str(AssocHistory).replace("| Not Associated) | ","").replace("Not Associated | ","").replace("  "," ").replace("|",lblColor + "|" + StdColor)

        DataValue7 = lblColor + "Connect History : " + StdColor + str(AssocHistory) +"\n"
        DataValue8=""
        CenterText(fcolor.BBlack + fcolor.BGWhite, "STATION MAC ADDRESS [ " + str(StnMAC) + "] DETAILED INFORMATION - RECORD " + str(RecordNum) + "/" + str(len(__builtin__.ShowStationList)))
        print ""
        DataValue= DataValue0 + DataValue1 + DataValue2 + DataValue3 + DataValue4 + DataValue5 + DataValue6 + DataValue7  + DataValue8
        print DataValue
        DisplayMACDetailFromFiles(StnMAC)
        AssocHistory=RemoveColor(AssocHistory)
        ConnectedBSSID = []
        ConnectedBSSID= str(AssocHistory).replace(" ","").split('|')
        if len(ConnectedBSSID)>1:
            DisplayConnectedBSSID("Related Access Point Information",ConnectedBSSID)
        DrawLine("_",fcolor.CReset + fcolor.Black,""); print ""
        x += 1
    return

def OptInfoDisplay(HeaderLine):
    MatchBSSIDCt=0
    MatchStationCt=0
    __builtin__.ShowBSSIDList = []
    __builtin__.ShowStationList = []
    __builtin__.ShowBSSIDList2 = []
    __builtin__.ShowStationList2 = []
    SELECTTYPE=""
    SearchVal=""
    if HeaderLine!="":
        DrawLine("_",fcolor.CReset + fcolor.Black,""); print ""
    printc ("+", fcolor.BBlue + "Information Lookup Menu","")
    print fcolor.BWhite + tabspacefull + "Monitor Interface  : " +  fcolor.BGreen + str(__builtin__.SELECTED_MON_MAC).ljust(20) + fcolor.BWhite + " [" + fcolor.BRed + str(__builtin__.SELECTED_MON) + fcolor.BWhite + "]"
    print fcolor.BWhite + tabspacefull +"Managed Interface  : " +  fcolor.BGreen + str(__builtin__.SELECTED_MANIFACE_MAC).ljust(20) + fcolor.BWhite + " [" + fcolor.BRed + str(__builtin__.SELECTED_MANIFACE) + fcolor.BWhite + "]"
    print tabspacefull + StdColor + "Information Lookup allow user to search for MAC address of Access Point and Wireless Station detected. "
    print tabspacefull + StdColor + "It also allow user to search for SSID of Access Point and also Probe name broadcasted from Wireless station."
    print tabspacefull + StdColor + "User can also search for partial MAC or Name by adding '*' infront / back of the search variable."
    print tabspacefull + StdColor + "Once information is found, it will display the full detail of the devices including it association with Access Point/Station."
    print ""
    Option1 = tabspacefull + SelBColor + "1" + StdColor + "/" + SelBColor + "M" + StdColor + " - " + SelColor + "M" + StdColor + "AC Address\n"
    Option2 = tabspacefull + SelBColor + "2" + StdColor + "/" + SelBColor + "N" + StdColor + " - " + SelColor + "N" + StdColor + "ames of Access Point / Probes\n"
    OptionA=Option1 + Option2
    print OptionA
    usr_resp=AskQuestion("Choose an option / " + STxt + "R" + NTxt + "eturn","M / N","U","RETURN","1")
    if usr_resp=="RETURN" or usr_resp=="R":
        DrawLine("_",fcolor.CReset + fcolor.Black,""); print ""
        return;
    if usr_resp=="1" or usr_resp=="M":
        print ""
        SELECTTYPE="MAC"
        usr_resp=AskQuestion("Enter the MAC to lookup for","xx:xx:xx:xx:xx:xx","U"," ","")
        __builtin__.SearchType="0"
        __builtin__.SearchTypelbl="Exact"
        if len(usr_resp)>17 :
            printc ("!!","Search MAC should not be more than 17 characters !","")
            DrawLine("_",fcolor.CReset + fcolor.Black,""); print "";OptInfoDisplay("")
            return;
        elif len(usr_resp)>1:
            if str(usr_resp)[:1]=="*" and str(usr_resp)[-1:]=="*":
                __builtin__.SearchType="1"      # Find Match
                __builtin__.SearchTypelbl="Containing"
            if str(usr_resp)[:1]!="*" and str(usr_resp)[-1:]=="*":
                __builtin__.SearchType="2"      # Match beginning
                __builtin__.SearchTypelbl="Begining With"
            if str(usr_resp)[:1]=="*" and str(usr_resp)[-1:]!="*":
                __builtin__.SearchType="3"      # Match ending
                __builtin__.SearchTypelbl="Ending With"
            SearchVal=str(usr_resp).replace("*","")
            __builtin__.SearchLen=len(SearchVal)
            printc (".",fcolor.BWhite + "Search MAC Criteria : " + fcolor.BRed + str(SearchVal) + fcolor.SWhite + " (" + str(__builtin__.SearchTypelbl) + ")" ,"")
            i=0
            while i < len(ListInfo_BSSID):
                ToDisplay = 0
                if __builtin__.SearchType=="0" and str(ListInfo_BSSID[i])==SearchVal:
                    __builtin__.ShowBSSIDList.append (i)
                    __builtin__.ShowBSSIDList2.append (ListInfo_BSSID[i])
                    MatchBSSIDCt += 1
                    ToDisplay=1
                if __builtin__.SearchType=="1" and str(ListInfo_BSSID[i]).find(SearchVal)!=-1:
                    __builtin__.ShowBSSIDList.append (i)
                    __builtin__.ShowBSSIDList2.append (ListInfo_BSSID[i])
                    MatchBSSIDCt += 1
                    ToDisplay=1
                if __builtin__.SearchType=="2" and str(ListInfo_BSSID[i])[:__builtin__.SearchLen]==SearchVal:
                    __builtin__.ShowBSSIDList.append (i)
                    __builtin__.ShowBSSIDList2.append (ListInfo_BSSID[i])
                    MatchBSSIDCt += 1
                    ToDisplay=1
                if __builtin__.SearchType=="3" and str(ListInfo_BSSID[i])[-__builtin__.SearchLen:]==SearchVal:
                    __builtin__.ShowBSSIDList.append (i)
                    __builtin__.ShowBSSIDList2.append (ListInfo_BSSID[i])
                    MatchBSSIDCt += 1
                    ToDisplay=1

                if ToDisplay==1:
                    print tabspacefull + fcolor.SGreen + "Found Match : " + fcolor.SWhite + str(ListInfo_BSSID[i]) + fcolor.SGreen + " (BSSID)"
                i += 1
            i=0
            while i < len(ListInfo_STATION):
                ToDisplay = 0
                if __builtin__.SearchType=="0" and str(ListInfo_STATION[i])==SearchVal:
                    __builtin__.ShowStationList.append (i)
                    __builtin__.ShowStationList2.append (ListInfo_STATION[i])
                    MatchStationCt += 1
                    ToDisplay=1
                if __builtin__.SearchType=="1" and str(ListInfo_STATION[i]).find(SearchVal)!=-1:
                    __builtin__.ShowStationList.append (i)
                    __builtin__.ShowStationList2.append (ListInfo_STATION[i])
                    MatchStationCt += 1
                    ToDisplay=1
                if __builtin__.SearchType=="2" and str(ListInfo_STATION[i])[:__builtin__.SearchLen]==SearchVal:
                    __builtin__.ShowStationList.append (i)
                    __builtin__.ShowStationList2.append (ListInfo_STATION[i])
                    MatchStationCt += 1
                    ToDisplay=1
                if __builtin__.SearchType=="3" and str(ListInfo_STATION[i])[-__builtin__.SearchLen:]==SearchVal:
                    __builtin__.ShowStationList.append (i)
                    __builtin__.ShowStationList2.append (ListInfo_STATION[i])
                    MatchStationCt += 1
                    ToDisplay=1
                if ToDisplay==1:
                    print tabspacefull + fcolor.SGreen + "Found Match : " + fcolor.SWhite + str(ListInfo_STATION[i]) + fcolor.SGreen + " (Station)"
                i += 1
    if usr_resp=="2" or usr_resp=="N":
        print ""
        SELECTTYPE="NAME"
        usr_resp=AskQuestion("Enter the Name to lookup for","",""," ","")
        __builtin__.SearchType="0"
        __builtin__.SearchTypelbl="Exact"
        if len(usr_resp)>32 :
            printc ("!!","Search Name should not be more than 32 characters !","")
        elif len(usr_resp)>1:
            if str(usr_resp)[:1]=="*" and str(usr_resp)[-1:]=="*":
                __builtin__.SearchType="1"      # Find Match
                __builtin__.SearchTypelbl="Containing"
            if str(usr_resp)[:1]!="*" and str(usr_resp)[-1:]=="*":
                __builtin__.SearchType="2"      # Match beginning
                __builtin__.SearchTypelbl="Begining With"
            if str(usr_resp)[:1]=="*" and str(usr_resp)[-1:]!="*":
                __builtin__.SearchType="3"      # Match ending
                __builtin__.SearchTypelbl="Ending With"
            SearchVal=str(usr_resp).replace("*","")
            __builtin__.SearchLen=len(SearchVal)
            printc (".",fcolor.BWhite + "Search Name Criteria : " + fcolor.BRed + str(SearchVal) + fcolor.SWhite + " (" + str(__builtin__.SearchTypelbl) + ")" ,"")
            i=0
            while i < len(ListInfo_BSSID):
                ToDisplay = 0
                UESSID=str(ListInfo_ESSID[i]).upper()
                USearchVal=str(SearchVal).upper()

                if __builtin__.SearchType=="0" and str(UESSID)==USearchVal:
                    __builtin__.ShowBSSIDList.append (i)
                    MatchBSSIDCt += 1
                    ToDisplay=1
                if __builtin__.SearchType=="1" and str(UESSID).find(USearchVal)!=-1:
                    __builtin__.ShowBSSIDList.append (i)
                    MatchBSSIDCt += 1
                    ToDisplay=1
                if __builtin__.SearchType=="2" and str(UESSID)[:__builtin__.SearchLen]==USearchVal:
                    __builtin__.ShowBSSIDList.append (i)
                    MatchBSSIDCt += 1
                    ToDisplay=1
                if __builtin__.SearchType=="3" and str(UESSID)[-__builtin__.SearchLen:]==USearchVal:
                    __builtin__.ShowBSSIDList.append (i)
                    MatchBSSIDCt += 1
                    ToDisplay=1
                if ToDisplay==1:
                    print tabspacefull + fcolor.SGreen + "Found Match : " + fcolor.SWhite + str(ListInfo_BSSID[i]) + fcolor.SGreen + " (ESSID)\t\tESSID : " + fcolor.SPink + str(ListInfo_ESSID[i])
                i += 1
            i=0
            while i < len(ListInfo_STATION):
                ToDisplay = 0
                ProbeData=[]
                ProbeData=str(ListInfo_PROBE[i]).split(" / ")
                j=0 
                while j<len(ProbeData):
                    ToDisplay=0;FoundProbe=""
                    UProbeData=str(ProbeData[j]).upper()
                    USearchVal=str(SearchVal).upper()
                    if __builtin__.SearchType=="0" and str(UProbeData)==USearchVal:
                        FoundProbe=str(ProbeData[j])
                        __builtin__.ShowStationList.append (i)
                        __builtin__.ShowStationList2.append (ListInfo_STATION[i])
                        MatchStationCt += 1
                        ToDisplay=1
                        j=len(ProbeData)
                    if __builtin__.SearchType=="1" and str(UProbeData).find(USearchVal)!=-1:
                        FoundProbe=str(ProbeData[j])
                        __builtin__.ShowStationList.append (i)
                        __builtin__.ShowStationList2.append (ListInfo_STATION[i])
                        MatchStationCt += 1
                        ToDisplay=1
                        j=len(ProbeData)
                    if __builtin__.SearchType=="2" and str(UProbeData)[:__builtin__.SearchLen]==USearchVal:
                        FoundProbe=str(ProbeData[j])
                        __builtin__.ShowStationList.append (i)
                        __builtin__.ShowStationList2.append (ListInfo_STATION[i])
                        MatchStationCt += 1
                        ToDisplay=1
                        j=len(ProbeData)
                    if __builtin__.SearchType=="3" and str(UProbeData)[-__builtin__.SearchLen:]==USearchVal:
                        FoundProbe=str(ProbeData[j])
                        __builtin__.ShowStationList.append (i)
                        __builtin__.ShowStationList2.append (ListInfo_STATION[i])
                        MatchStationCt += 1
                        ToDisplay=1
                        j=len(ProbeData)
                    j += 1
                  
                if ToDisplay==1:
                    print tabspacefull + fcolor.SGreen + "Found Match : " + fcolor.SWhite + str(ListInfo_STATION[i]) + fcolor.SGreen + " (Station Probe)\tProbe : " + fcolor.SBlue + str(FoundProbe)
                i += 1
    if MatchBSSIDCt>0 or MatchStationCt>0:
        if MatchBSSIDCt>0:
            printc ("i","Total BSSID Matched   : " + fcolor.BRed + str(MatchBSSIDCt),"")
        if MatchStationCt>0:
            printc ("i","Total Station Matched : " + fcolor.BRed + str(MatchStationCt),"")
        print ""
        printc ("x","Press any key to display the listing detail...","")
    else:
        if SELECTTYPE=="MAC":
            printc ("!!","The specified MAC address was not found in current listing !!!","")
        if SELECTTYPE=="NAME":
            printc ("!!","The specified Name was not found in current listing !!!","")
        print ""
        if SearchVal!="":
            usr_resp=AskQuestion(fcolor.BGreen + "Do you want to try to search the database files" + fcolor.BGreen,"Y/n","U","Y","1")
            if usr_resp=="Y":
                if SELECTTYPE=="MAC":
                    SearchDBFiles("MAC", SearchVal,__builtin__.SearchLen,__builtin__.SearchType,__builtin__.SearchTypelbl)
                    OptInfoDisplay("")
                    return;
                if SELECTTYPE=="NAME":
                    SearchDBFiles("NAME", SearchVal,__builtin__.SearchLen,__builtin__.SearchType,__builtin__.SearchTypelbl)
                    OptInfoDisplay("")
                    return;
            else:
                OptInfoDisplay("1")
                return;
        else:
            OptInfoDisplay("1")
            return;

    if MatchBSSIDCt>0:
        DisplayBSSIDDetail()
    if MatchStationCt>0:
        DisplayStationDetail()
    usr_resp=AskQuestion(fcolor.BGreen + "Do you want to try to search the database files" + fcolor.BGreen,"Y/n","U","Y","1")
    if usr_resp=="Y":
        if SELECTTYPE=="MAC":
            SearchDBFiles("MAC", SearchVal,__builtin__.SearchLen,__builtin__.SearchType,__builtin__.SearchTypelbl)
        if SELECTTYPE=="NAME":
            SearchDBFiles("NAME", SearchVal,__builtin__.SearchLen,__builtin__.SearchType,__builtin__.SearchTypelbl)
    OptInfoDisplay("")
    return;

def OptFilterDisplay(HeaderLine):
    if HeaderLine!="":
        DrawLine("_",fcolor.CReset + fcolor.Black,""); print ""
    GetFilterDetail()
    printc ("+", fcolor.BBlue + "Filtering Menu ","")
    print StdColor + tabspacefull + "This option user to filter encryption type, signal range, channel, having clients and WPS enabled access point."
    print StdColor + tabspacefull + "It also enable filtering of probes, signal range, associated and unassociated station."
    print ""
    Option1 = tabspacefull + SelBColor + "1" + StdColor + "/" + SelBColor + "A" + StdColor + " - " + SelColor + "A" + StdColor + "ccess Point\n"
    Option2 = tabspacefull + SelBColor + "2" + StdColor + "/" + SelBColor + "S" + StdColor + " - " + SelColor + "S" + StdColor + "tation / Client\n"
    Option3 =tabspacefull + SelBColor + "3" + StdColor + "/" + SelBColor + "U" + StdColor + " - " + SelColor + "U" + StdColor + "nassociated Station\n"
    Option4=""
    if __builtin__.DisplayAllFilter!="":
        Option4 = tabspacefull + SelBColor + "9" + StdColor + "/" + SelBColor + "X" + StdColor + " - " + SelColor + "" + StdColor + "Clear All Filters\n"
    OptionA=Option1 + Option2 + Option3  + Option4
    print OptionA
    if __builtin__.DisplayAllFilter!="":
        print __builtin__.DisplayAllFilter
    usr_resp=AskQuestion("Choose an option / " + STxt + "R" + NTxt + "eturn","A / S / U" ,"U","RETURN","1")
    if usr_resp=="9" or usr_resp=="X":
            __builtin__.NETWORK_PROBE_FILTER="ALL"
            __builtin__.NETWORK_UPROBE_FILTER="ALL"
            __builtin__.NETWORK_ASSOCIATED_FILTER="ALL"
            __builtin__.NETWORK_UNASSOCIATED_FILTER="ALL"
            __builtin__.NETWORK_CSIGNAL_FILTER="ALL"
            __builtin__.NETWORK_UCSIGNAL_FILTER="ALL"
            __builtin__.NETWORK_FILTER="ALL"
            __builtin__.NETWORK_SIGNAL_FILTER="ALL"
            __builtin__.NETWORK_CHANNEL_FILTER="ALL"
            __builtin__.NETWORK_WPS_FILTER="ALL"
            __builtin__.NETWORK_CLIENT_FILTER="ALL"
            printc (" ","All Filters Cleared !","")
            OptFilterDisplay("1")
            return;

    if usr_resp=="RETURN":
        DrawLine("_",fcolor.CReset + fcolor.Black,""); print ""
        return;
    if usr_resp=="A" or usr_resp=="1":
        Option1 = "\n" + tabspacefull + fcolor.BWhite + "Filtering On Access Point\n"
        Option2 = tabspacefull + SelBColor + "1" + StdColor + "/" + SelBColor + "E" + StdColor + " - " + SelColor + "E" + StdColor + "ncryption Type\n"
        Option3 = tabspacefull + SelBColor + "2" + StdColor + "/" + SelBColor + "S" + StdColor + " - " + SelColor + "S" + StdColor + "ignal Range\n"
        Option4 = tabspacefull + SelBColor + "3" + StdColor + "/" + SelBColor + "N" + StdColor + " - Cha" + SelColor + "n" + StdColor + "nel\n"
        Option5 = tabspacefull + SelBColor + "4" + StdColor + "/" + SelBColor + "C" + StdColor + " - " + SelColor + "C" + StdColor + "lient\n"
        Option6 = tabspacefull + SelBColor + "5" + StdColor + "/" + SelBColor + "W" + StdColor + " - " + SelColor + "W" + StdColor + "PS\n"
        Option7 = tabspacefull + SelBColor + "9" + StdColor + "/" + SelBColor + "X" + StdColor + " - " + SelColor + "" + StdColor + "Clear Filter\n"
        OptionA=Option1 + Option2 + Option3 + Option4 + Option5 + Option6 + Option7
        print OptionA
        usr_resp=AskQuestion("Choose an option / " + STxt + "R" + NTxt + "eturn","E/S/C/N/W/X","U","RETURN","1")
        if usr_resp=="RETURN":
            OptFilterDisplay("1")
            return
        print ""
        if usr_resp=="9" or usr_resp=="X":
            __builtin__.NETWORK_FILTER="ALL"
            __builtin__.NETWORK_SIGNAL_FILTER="ALL"
            __builtin__.NETWORK_CHANNEL_FILTER="ALL"
            __builtin__.NETWORK_WPS_FILTER="ALL"
            __builtin__.NETWORK_CLIENT_FILTER="ALL"
            printc (" ","Access Point Filtration Cleared !","")
            OptFilterDisplay("1")
            return;
        if usr_resp=="1" or usr_resp=="E":
            if __builtin__.NETWORK_FILTER!="ALL":
                printc (" " , fcolor.BWhite + "Current Filter = " + SelBColor + str(__builtin__.NETWORK_FILTER), "")
            usr_resp=AskQuestion("Enter Encryption Filter",STxt + "WPA " + NTxt + "/ " + STxt + "WEP" + NTxt + " / " + STxt + "OPN" + NTxt + " / " + STxt + "OTH" + NTxt + " / " + STxt + "ALL","U","ALL","1")
            if usr_resp=="ALL":
                __builtin__.NETWORK_FILTER="ALL"
                OptFilterDisplay("1")
                return;
            else:
                __builtin__.NETWORK_FILTER=str(usr_resp)
                OptFilterDisplay("1")
                return;
        elif usr_resp=="2" or usr_resp=="S":
            Option1 = tabspacefull + fcolor.BWhite + "Filtering On Signal Range (Access Point)\n"
            Option2 = tabspacefull + SelBColor + "1" + StdColor + "/" + SelBColor + "V" + StdColor + " - " + SelColor + "V" + StdColor + "Good\n"
            Option3 = tabspacefull + SelBColor + "2" + StdColor + "/" + SelBColor + "G" + StdColor + " - " + SelColor + "G" + StdColor + "ood\n"
            Option4 = tabspacefull + SelBColor + "3" + StdColor + "/" + SelBColor + "A" + StdColor + " - " + SelColor + "A" + StdColor + "verage\n"
            Option5 = tabspacefull + SelBColor + "4" + StdColor + "/" + SelBColor + "P" + StdColor + " - " + SelColor + "P" + StdColor + "oorS\n"
            Option6 = tabspacefull + SelBColor + "5" + StdColor + "/" + SelBColor + "U" + StdColor + " - " + SelColor + "U" + StdColor + "nknown\n"
            Option7 = tabspacefull + SelBColor + "9" + StdColor + "/" + SelBColor + "X" + StdColor + " - " + SelColor + "" + StdColor + "Clear Filter\n"
            OptionA=Option1 + Option2 + Option3 + Option4 + Option5 + Option6 + Option7
            print OptionA
            if __builtin__.NETWORK_SIGNAL_FILTER!="ALL":
                printc (" " , fcolor.BWhite + "Current Filter = " + SelBColor + str(NETWORK_SIGNAL_FILTER), "")
            usr_resp=AskQuestion("Choose an option / " + STxt + "R" + NTxt + "eturn","V/G/A/P/U/X","U","RETURN","1")
            if usr_resp=="1" or usr_resp=="VGOOD" or usr_resp=="V":
                __builtin__.NETWORK_SIGNAL_FILTER="V.Good"
            if usr_resp=="2" or usr_resp=="GOOD" or usr_resp=="G":
                __builtin__.NETWORK_SIGNAL_FILTER="Good"
            if usr_resp=="3" or usr_resp=="AVERAGE" or usr_resp=="A":
                __builtin__.NETWORK_SIGNAL_FILTER="Average"
            if usr_resp=="4" or usr_resp=="POOR" or usr_resp=="P":
                __builtin__.NETWORK_SIGNAL_FILTER="Poor"
            if usr_resp=="5" or usr_resp=="UNKNOWN" or usr_resp=="U":
                __builtin__.NETWORK_SIGNAL_FILTER="Unknown"
            if usr_resp=="9" or usr_resp=="X":
                __builtin__.NETWORK_SIGNAL_FILTER="ALL"
            OptFilterDisplay("1")
            return;
        elif usr_resp=="3" or usr_resp=="N":
            if __builtin__.NETWORK_CHANNEL_FILTER!="ALL":
                printc (" " , fcolor.BWhite + "Current Filter = " + SelBColor + str(NETWORK_CHANNEL_FILTER), "")
            __builtin__.NETWORK_CHANNEL_FILTER=AskQuestion("Enter Channel to Filter","Numbers","N","ALL","1")
            OptFilterDisplay("1")
            return;
        elif usr_resp=="4" or usr_resp=="C":
            if __builtin__.NETWORK_CLIENT_FILTER!="ALL":
                printc (" " , fcolor.BWhite + "Current Filter = " + SelBColor + str(NETWORK_CLIENT_FILTER), "")
            usr_resp=AskQuestion("Display of Access Point with Clients",SelBColor + "1" + StdColor + "-" + SelColor + "Y" + StdColor + "es / " + SelBColor + "2" + StdColor + "-" + SelColor + "N" + StdColor + "o / Default ~ ALL","U","ALL","1")
            __builtin__.NETWORK_CLIENT_FILTER="ALL"
            if usr_resp=="1" or usr_resp=="Y" or usr_resp=="YES":
                __builtin__.NETWORK_CLIENT_FILTER="Yes"
            if usr_resp=="2" or usr_resp=="N" or usr_resp=="NO":
                __builtin__.NETWORK_CLIENT_FILTER="No"
            OptFilterDisplay("1")
            return;
        elif usr_resp=="5" or usr_resp=="W":
            if __builtin__.NETWORK_WPS_FILTER!="ALL":
                printc (" " , fcolor.BWhite + "Current Filter = " + SelBColor + str(NETWORK_WPS_FILTER), "")
            usr_resp=AskQuestion("Display only Access Point with WPS",SelBColor + "1" + StdColor + "-" + SelColor + "Y" + StdColor + "es / " + SelBColor + "2" + StdColor + "-" + SelColor + "N" + StdColor + "o / Default ~ ALL","U","ALL","1")
            __builtin__.NETWORK_WPS_FILTER="ALL"
            if usr_resp=="1" or usr_resp=="Y" or usr_resp=="YES":
                __builtin__.NETWORK_WPS_FILTER="Yes"
            if usr_resp=="2" or usr_resp=="N" or usr_resp=="NO":
                __builtin__.NETWORK_WPS_FILTER="No"
            OptFilterDisplay("1")
            return;
    if usr_resp=="2" or usr_resp=="S":
        Option1 = "\n" + tabspacefull + fcolor.BWhite + "Filtering On Stations\n"
        Option2 = tabspacefull + SelBColor + "1" + StdColor + "/" + SelBColor + "P" + StdColor + " - " + SelColor + "P" + StdColor + "robes\n"
        Option3 = tabspacefull + SelBColor + "2" + StdColor + "/" + SelBColor + "S" + StdColor + " - " + SelColor + "S" + StdColor + "ignal Range\n"
        Option4 = tabspacefull + SelBColor + "3" + StdColor + "/" + SelBColor + "A" + StdColor + " - " + SelColor + "A" + StdColor + "ssociated Station\n"
        Option5 = tabspacefull + SelBColor + "4" + StdColor + "/" + SelBColor + "U" + StdColor + " - " + SelColor + "U" + StdColor + "nassociated Station\n"
        Option6 = tabspacefull + SelBColor + "9" + StdColor + "/" + SelBColor + "X" + StdColor + " - " + SelColor + "" + StdColor + "Clear Filter\n"
        OptionA=Option1 + Option2 + Option3 + Option4 + Option5 + Option6
        print OptionA
        usr_resp=AskQuestion("Choose an option / " + STxt + "R" + NTxt + "eturn","P/S/A/U/X","U","RETURN","1")
        if usr_resp=="RETURN":
            OptFilterDisplay("1")
            return
        print ""
        if usr_resp=="9" or usr_resp=="X":
            __builtin__.NETWORK_PROBE_FILTER="ALL"
            __builtin__.NETWORK_ASSOCIATED_FILTER="ALL"
            __builtin__.NETWORK_UNASSOCIATED_FILTER="ALL"
            __builtin__.NETWORK_CSIGNAL_FILTER="ALL"
            printc (" ","Station Filtration Cleared !","")
            OptFilterDisplay("1")
            return;
        elif usr_resp=="1" or usr_resp=="P":
            if __builtin__.NETWORK_PROBE_FILTER!="ALL":
                printc (" " , fcolor.BWhite + "Current Filter = " + SelBColor + str(NETWORK_PROBE_FILTER), "")
            usr_resp=AskQuestion("Display only if station having probe names",SelBColor + "1" + StdColor + "-" + SelColor + "Y" + StdColor + "es / " + SelBColor + "2" + StdColor + "-" + SelColor + "N" + StdColor + "o / Default ~ ALL","U","ALL","1")
            __builtin__.NETWORK_PROBE_FILTER="ALL"
            if usr_resp=="1" or usr_resp=="Y" or usr_resp=="YES":
                __builtin__.NETWORK_PROBE_FILTER="Yes"
            if usr_resp=="2" or usr_resp=="N" or usr_resp=="NO":
                __builtin__.NETWORK_PROBE_FILTER="No"
            OptFilterDisplay("1")
            return
        elif usr_resp=="2" or usr_resp=="S":
            Option1 = tabspacefull + fcolor.BWhite + "Filtering On Signal Range (Station)\n"
            Option2 = tabspacefull + SelBColor + "1" + StdColor + "/" + SelBColor + "V" + StdColor + " - " + SelColor + "V" + StdColor + "Good\n"
            Option3 = tabspacefull + SelBColor + "2" + StdColor + "/" + SelBColor + "G" + StdColor + " - " + SelColor + "G" + StdColor + "ood\n"
            Option4 = tabspacefull + SelBColor + "3" + StdColor + "/" + SelBColor + "A" + StdColor + " - " + SelColor + "A" + StdColor + "verage\n"
            Option5 = tabspacefull + SelBColor + "4" + StdColor + "/" + SelBColor + "P" + StdColor + " - " + SelColor + "P" + StdColor + "oorS\n"
            Option6 = tabspacefull + SelBColor + "5" + StdColor + "/" + SelBColor + "U" + StdColor + " - " + SelColor + "U" + StdColor + "nknown\n"
            Option7 = tabspacefull + SelBColor + "9" + StdColor + "/" + SelBColor + "X" + StdColor + " - " + SelColor + "" + StdColor + "Clear Filter\n"
            OptionA=Option1 + Option2 + Option3 + Option4 + Option5 + Option6 + Option7
            print OptionA
            if __builtin__.NETWORK_CSIGNAL_FILTER!="ALL":
                printc (" " , fcolor.BWhite + "Current Filter = " + SelBColor + str(NETWORK_CSIGNAL_FILTER), "")
            usr_resp=AskQuestion("Choose an option / " + STxt + "R" + NTxt + "eturn","V/G/A/P/U/X","U","RETURN","1")
            if usr_resp=="RETURN":
                OptFilterDisplay("1")
                return
            if usr_resp=="1" or usr_resp=="VGOOD" or usr_resp=="V":
                __builtin__.NETWORK_CSIGNAL_FILTER="V.Good"
            if usr_resp=="2" or usr_resp=="GOOD" or usr_resp=="G":
                __builtin__.NETWORK_CSIGNAL_FILTER="Good"
            if usr_resp=="3" or usr_resp=="AVERAGE" or usr_resp=="A":
                __builtin__.NETWORK_CSIGNAL_FILTER="Average"
            if usr_resp=="4" or usr_resp=="POOR" or usr_resp=="P":
                __builtin__.NETWORK_CSIGNAL_FILTER="Poor"
            if usr_resp=="5" or usr_resp=="UNKNOWN" or usr_resp=="U":
                __builtin__.NETWORK_CSIGNAL_FILTER="Unknown"
            if usr_resp=="9" or usr_resp=="X":
                __builtin__.NETWORK_CSIGNAL_FILTER="ALL"
            OptFilterDisplay("1")
            return;
        elif usr_resp=="3" or usr_resp=="A":
            if __builtin__.NETWORK_ASSOCIATED_FILTER!="ALL":
                printc (" " , fcolor.BWhite + "Current Filter (Associated) = " + SelBColor + str(NETWORK_ASSOCIATED_FILTER), "")
            usr_resp=AskQuestion("Display only if station associated",SelBColor + "1" + StdColor + "-" + SelColor + "Y" + StdColor + "es / " + SelBColor + "2" + StdColor + "-" + SelColor + "N" + StdColor + "o / Default ~ ALL","U","ALL","1")
            __builtin__.NETWORK_ASSOCIATED_FILTER="ALL"
            __builtin__.NETWORK_UNASSOCIATED_FILTER="ALL"
            if usr_resp=="1" or usr_resp=="Y" or usr_resp=="YES":
                __builtin__.NETWORK_ASSOCIATED_FILTER="Yes"
                __builtin__.NETWORK_UNASSOCIATED_FILTER="No"
            if usr_resp=="2" or usr_resp=="N" or usr_resp=="NO":
                __builtin__.NETWORK_ASSOCIATED_FILTER="No"
                __builtin__.NETWORK_UNASSOCIATED_FILTER="Yes"
            OptFilterDisplay("1")
            return
        elif usr_resp=="4" or usr_resp=="U":
            if __builtin__.NETWORK_UNASSOCIATED_FILTER!="ALL":
                printc (" " , fcolor.BWhite + "Current Filter (Unassociated) = " + SelBColor + str(NETWORK_UNASSOCIATED_FILTER), "")
            usr_resp=AskQuestion("Display only if station is not associated",SelBColor + "1" + StdColor + "-" + SelColor + "Y" + StdColor + "es / " + SelBColor + "2" + StdColor + "-" + SelColor + "N" + StdColor + "o / Default ~ ALL","U","ALL","1")
            __builtin__.NETWORK_UNASSOCIATED_FILTER="ALL"
            __builtin__.NETWORK_ASSOCIATED_FILTER="ALL"
            if usr_resp=="1" or usr_resp=="Y" or usr_resp=="YES":
                __builtin__.NETWORK_ASSOCIATED_FILTER="No"
                __builtin__.NETWORK_UNASSOCIATED_FILTER="Yes"
            if usr_resp=="2" or usr_resp=="N" or usr_resp=="NO":
                __builtin__.NETWORK_ASSOCIATED_FILTER="Yes"
                __builtin__.NETWORK_UNASSOCIATED_FILTER="No"
            OptFilterDisplay("1")
            return
    if usr_resp=="3" or usr_resp=="U":
        Option1 = "\n" + tabspacefull + fcolor.BWhite + "Filtering On Unassociated Station\n"
        Option2 = tabspacefull + SelBColor + "1" + StdColor + "/" + SelBColor + "P" + StdColor + " - " + SelColor + "P" + StdColor + "robes\n"
        Option3 = tabspacefull + SelBColor + "2" + StdColor + "/" + SelBColor + "S" + StdColor + " - " + SelColor + "S" + StdColor + "ignal Range\n"
        Option4 = tabspacefull + SelBColor + "9" + StdColor + "/" + SelBColor + "X" + StdColor + " - " + SelColor + "" + StdColor + "Clear Filter\n"
        OptionA=Option1 + Option2 + Option3 + Option4 
        print OptionA
        usr_resp=AskQuestion("Choose an option / " + STxt + "R" + NTxt + "eturn","P/S/A/U/X","U","RETURN","1")
        if usr_resp=="RETURN":
            OptFilterDisplay("1")
            return
        print ""
        if usr_resp=="9" or usr_resp=="X":
            __builtin__.NETWORK_UPROBE_FILTER="ALL"
            __builtin__.NETWORK_UCSIGNAL_FILTER="ALL"
            printc (" ","Station Filtration Cleared !","")
            OptFilterDisplay("1")
            return;
        elif usr_resp=="1" or usr_resp=="P":
            if __builtin__.NETWORK_UPROBE_FILTER!="ALL":
                printc (" " , fcolor.BWhite + "Current Filter = " + SelBColor + str(NETWORK_UPROBE_FILTER), "")
            usr_resp=AskQuestion("Display only if unassociated station having probe names",SelBColor + "1" + StdColor + "-" + SelColor + "Y" + StdColor + "es / " + SelBColor + "2" + StdColor + "-" + SelColor + "N" + StdColor + "o / Default ~ ALL","U","ALL","1")
            __builtin__.NETWORK_UPROBE_FILTER="ALL"
            if usr_resp=="1" or usr_resp=="Y" or usr_resp=="YES":
                __builtin__.NETWORK_UPROBE_FILTER="Yes"
            if usr_resp=="2" or usr_resp=="N" or usr_resp=="NO":
                __builtin__.NETWORK_UPROBE_FILTER="No"
            OptFilterDisplay("1")
            return
        elif usr_resp=="2" or usr_resp=="S":
            Option1 = tabspacefull + fcolor.BWhite + "Filtering On Signal Range (Station)\n"
            Option2 = tabspacefull + SelBColor + "1" + StdColor + "/" + SelBColor + "V" + StdColor + " - " + SelColor + "V" + StdColor + "Good\n"
            Option3 = tabspacefull + SelBColor + "2" + StdColor + "/" + SelBColor + "G" + StdColor + " - " + SelColor + "G" + StdColor + "ood\n"
            Option4 = tabspacefull + SelBColor + "3" + StdColor + "/" + SelBColor + "A" + StdColor + " - " + SelColor + "A" + StdColor + "verage\n"
            Option5 = tabspacefull + SelBColor + "4" + StdColor + "/" + SelBColor + "P" + StdColor + " - " + SelColor + "P" + StdColor + "oorS\n"
            Option6 = tabspacefull + SelBColor + "5" + StdColor + "/" + SelBColor + "U" + StdColor + " - " + SelColor + "U" + StdColor + "nknown\n"
            Option7 = tabspacefull + SelBColor + "9" + StdColor + "/" + SelBColor + "X" + StdColor + " - " + SelColor + "" + StdColor + "Clear Filter\n"
            OptionA=Option1 + Option2 + Option3 + Option4 + Option5 + Option6 + Option7
            print OptionA
            if __builtin__.NETWORK_UCSIGNAL_FILTER!="ALL":
                printc (" " , fcolor.BWhite + "Current Filter = " + SelBColor + str(NETWORK_UCSIGNAL_FILTER), "")
            usr_resp=AskQuestion("Choose an option / " + STxt + "R" + NTxt + "eturn","V/G/A/P/U/X","U","RETURN","1")
            if usr_resp=="RETURN":
                OptFilterDisplay("1")
                return
            if usr_resp=="1" or usr_resp=="VGOOD" or usr_resp=="V":
                __builtin__.NETWORK_UCSIGNAL_FILTER="V.Good"
            if usr_resp=="2" or usr_resp=="GOOD" or usr_resp=="G":
                __builtin__.NETWORK_UCSIGNAL_FILTER="Good"
            if usr_resp=="3" or usr_resp=="AVERAGE" or usr_resp=="A":
                __builtin__.NETWORK_UCSIGNAL_FILTER="Average"
            if usr_resp=="4" or usr_resp=="POOR" or usr_resp=="P":
                __builtin__.NETWORK_UCSIGNAL_FILTER="Poor"
            if usr_resp=="5" or usr_resp=="UNKNOWN" or usr_resp=="U":
                __builtin__.NETWORK_UCSIGNAL_FILTER="Unknown"
            if usr_resp=="9" or usr_resp=="X":
                __builtin__.NETWORK_UCSIGNAL_FILTER="ALL"
            OptFilterDisplay("1")
            return;
def OptConfiguration(HeaderLine):
    if HeaderLine!="":
        DrawLine("_",fcolor.CReset + fcolor.Black,""); print ""
    printc ("+", fcolor.BBlue + "Application Configuation","")
    Option0 = tabspacefull + SelBColor + "0" + StdColor + "/" + SelBColor + "C" + StdColor + " - " + SelColor + "C" + StdColor + "hange Regulatory Domain\t" + fcolor.SGreen + "[ Current : " + str(GetRegulatoryDomain()) + " ]\n"
    Option1 = tabspacefull + SelBColor + "1" + StdColor + "/" + SelBColor + "R" + StdColor + " - " + SelColor + "R" + StdColor + "efresh rate of details\t" + fcolor.SGreen + "[ Current : " + str(__builtin__.TIMEOUT) + " sec ]\n"
    Option2 = tabspacefull + SelBColor + "2" + StdColor + "/" + SelBColor + "T" + StdColor + " - " + SelColor + "T" + StdColor + "ime before removing Access Point/Station\t" + fcolor.SGreen + "[ Current : " + str(REMOVE_AFTER_MIN) + " min ]\n"
    Option3 = tabspacefull + SelBColor + "3" + StdColor + "/" + SelBColor + "H" + StdColor + " - " + SelColor + "H" + StdColor + "ide inactive Access Point\t" + fcolor.SGreen + "[ Access Point : " + str(__builtin__.HIDE_INACTIVE_SSID) + " / Station : " + str(__builtin__.HIDE_INACTIVE_STN) + " ]\n"
    Option4 = tabspacefull + SelBColor + "4" + StdColor + "/" + SelBColor + "B" + StdColor + " - " + SelColor + "B" + StdColor + "eep if alert found\t\t" + fcolor.SGreen + "[ Current : " + str(__builtin__.ALERTSOUND) + " ]\n"

    Option5 = tabspacefull + SelBColor + "9" + StdColor + "/" + SelBColor + "W" + StdColor + " - " + SelColor + "W" + StdColor + "rite Configuration\n"
    OptionA=Option0 + Option1 + Option2 + Option3  + Option4 + Option5
    print OptionA
    usr_resp=AskQuestion("Choose an option","C/R/T/H/B/W","U","RETURN","1")
    if usr_resp=="RETURN":
        DrawLine("_",fcolor.CReset + fcolor.Black,""); print ""
        return;
    if usr_resp=="0" or usr_resp=="C":
        ChangeRegulatoryDomain()
    if usr_resp=="9" or usr_resp=="W":
        SaveConfig()
    if usr_resp=="1" or usr_resp=="R":
        usr_resp=AskQuestion("Refresh detail after number of seconds " + fcolor.SGreen + "[Current : " + str(__builtin__.TIMEOUT) + "]" ,"Default 20","N","20","1")
        __builtin__.TIMEOUT=usr_resp
    if usr_resp=="2" or usr_resp=="T":
        usr_resp=AskQuestion("Number of minutes before removing inactive AP/Station " + fcolor.SGreen + "[Current : " + str(REMOVE_AFTER_MIN) + "]" ,"Default 1","N","1","1")
        __builtin__.REMOVE_AFTER_MIN=usr_resp
    if usr_resp=="3" or usr_resp=="H":
        usr_resp=AskQuestion("Select " + fcolor.BRed + "A" + fcolor.BYellow + "ccess Point / " + fcolor.BRed + "S" + fcolor.BYellow + "tation" ,"A/S","U","Y","1")
        if usr_resp=="A":
            usr_resp=AskQuestion("Hide Inactive Access Point " + fcolor.SGreen + "[Current : " + str(__builtin__.HIDE_INACTIVE_SSID) + "]" ,"Y/n","U","Y","1")
            if usr_resp=="N":
                __builtin__.HIDE_INACTIVE_SSID="No"
            else:
                __builtin__.HIDE_INACTIVE_SSID="Yes"
        if usr_resp=="S":
            usr_resp=AskQuestion("Hide Inactive Station " + fcolor.SGreen + "[Current : " + str(__builtin__.HIDE_INACTIVE_STN) + "]" ,"Y/n","U","Y","1")
            if usr_resp=="N":
                __builtin__.HIDE_INACTIVE_STN="No"
            else:
                __builtin__.HIDE_INACTIVE_STN="Yes"
    if usr_resp=="4" or usr_resp=="B":
        usr_resp=AskQuestion("Beep if Alert Found " + fcolor.SGreen + "- Current = " + str(__builtin__.ALERTSOUND) + " " + fcolor.BGreen,"Y/n","U","Y","1")
        if usr_resp=="Y":
            __builtin__.ALERTSOUND="Yes"
        elif usr_resp=="N":
            __builtin__.ALERTSOUND="No"
    OptConfiguration("1")
    return

def OptMonitorMAC(HeaderLine):
    if HeaderLine!="":
        DrawLine("_",fcolor.CReset + fcolor.Black,""); print ""
    print ""
    MonitoringMACStr=""
    __builtin__.MonitoringMACList=[]
    GetMonitoringMAC()
    Skip=""
    printc ("+",fcolor.BBlue + "MAC / Names Monitoring Setting","")
    print  tabspacefull + StdColor + "Monitoring Setting allow user to monitor MAC address and Name of Access Point/Station/Probes."
    print  tabspacefull + StdColor + "Once the specified MAC addresses / Names were detected, it will display the detail."
    print  tabspacefull + StdColor + "User can also set alert beep if speficied items is spotted. [Application Configuration] --> [Beep if alert found]"
    print ""
    DisplayMonitoringMAC()
    Option1 = tabspacefull + SelBColor + "1" + StdColor + "/" + SelBColor + "M" + StdColor + " - " + SelColor + "M" + StdColor + "AC Address [BSSID/STATION]\n"
    Option2 = tabspacefull + SelBColor + "2" + StdColor + "/" + SelBColor + "N" + StdColor + " - " + SelColor + "N" + StdColor + "ame of Access Point/Probe Names\n"
    Option3 = tabspacefull + SelBColor + "9" + StdColor + "/" + SelBColor + "C" + StdColor + " - " + SelColor + "C" + StdColor + "lear all Monitoring Items\n"
    OptionA=Option1 + Option2 + Option3
    print OptionA
    usr_resp=AskQuestion("Select Monitoring Type : ",STxt + "M" + NTxt + "AC Address / " + STxt + "N" + NTxt + "ames (ESSID & Probe) / " + STxt + "C" + NTxt + "lear All Monitoring Items / " + "Default - " + STxt + "R" + NTxt + "eturn","U","RETURN","1")
    if usr_resp=="C" or usr_resp=="9":
        open(MonitorMACfile,"w").write("")
        __builtin__.MonitoringMACList=[]
        __builtin__.MonitoringNameList=[]
        printc ("i",fcolor.BRed + "All items cleared from the monitoring list..","")
        OptMonitorMAC("1")
        return
    if usr_resp=="M" or usr_resp=="1":
        usr_resp=AskQuestion("Select an option : ",STxt + "A" + NTxt + "dd MAC Address / " + STxt + "D" + NTxt + "elete MAC Address / " + STxt + "C" + NTxt + "lear All MAC Address / "   + "Default - " + STxt + "R" + NTxt + "eturn","U","ALL","1")
        if usr_resp=="ALL":
            return
        if usr_resp=="A":
            usr_resp=AskQuestion("Enter the MAC Address to monitor (xx:xx:xx:xx:xx:xx) " ,"","U","","1")
            if len(usr_resp)==17:
                x=0
                while x < len(__builtin__.MonitoringMACList):
                    if usr_resp==__builtin__.MonitoringMACList[x]:
                        Skip=1
                    x=x+1
                if Skip!=1:
                    __builtin__.MonitoringMACList.append (str(usr_resp))
                    printc ("i",fcolor.SGreen + "The MAC Address " + fcolor.BYellow + str(usr_resp) + fcolor.SGreen + " added to monitoring list..","")
                    SaveMonitoringMAC()
                else:
                    printc ("!",fcolor.SRed + "The MAC Address " + fcolor.BYellow + str(usr_resp) + fcolor.SRed + " already exist !!","")
            else:
                if usr_resp!="":
                    printc ("!",fcolor.SRed + "The MAC Address " + fcolor.BYellow + str(usr_resp) + fcolor.SRed + " is invalid !!","")
        if usr_resp=="D":
            usr_resp=AskQuestion("Enter the MAC Address to remove (xx:xx:xx:xx:xx:xx) " ,"","U","","")
            if len(usr_resp)==17:
                if usr_resp in __builtin__.MonitoringMACList:
                    __builtin__.MonitoringMACList.remove (str(usr_resp))
                    printc ("i",fcolor.SGreen + "The MAC Address " + fcolor.BYellow + str(usr_resp) + fcolor.SGreen + " deleted to monitoring list..","")
                    SaveMonitoringMAC()

                else:
                    printc ("!",fcolor.SRed + "The MAC Address " + fcolor.BYellow + str(usr_resp) + fcolor.SRed + " does not exist !!","")
            else:
                if usr_resp!="":
                    printc ("!",fcolor.SRed +  "The MAC Address " + fcolor.BYellow + str(usr_resp) + fcolor.SRed + " is invalid !!","")
        if usr_resp=="C":
            open(MonitorMACfile,"w").write("")
            __builtin__.MonitoringMACList=[]
            printc ("i",fcolor.SGreen + "All MAC Addresses cleared from the monitoring list..","")
        OptMonitorMAC("1")
        return
    if usr_resp=="N" or usr_resp=="2":
        usr_resp=AskQuestion("Select an option : ",STxt + "A" + NTxt + "dd ESSID/Probe Name / " + STxt + "D" + NTxt + "elete ESSID/Probe Name / " + STxt + "C" + NTxt + "lear All Names / "   + "Default - " + STxt + "R" + NTxt + "eturn","U","ALL","1")
        if usr_resp=="ALL":
            return
        if usr_resp=="A":
            usr_resp=AskQuestion("Enter the Name to Monitor" ,"","","","1")
            if len(usr_resp)>0:
                x=0
                while x < len(__builtin__.MonitoringNameList):
                    if usr_resp.upper()==__builtin__.MonitoringNameList[x].upper():
                        Skip=1
                    x=x+1
                if Skip!=1:
                    __builtin__.MonitoringNameList.append (str(usr_resp))
                    printc ("i",fcolor.SGreen + "The Name " + fcolor.BYellow + str(usr_resp) + fcolor.SGreen + " added to monitoring list..","")
                    SaveMonitoringMAC()
                else:
                    printc ("!",fcolor.SRed + "The Name " + fcolor.BYellow + str(usr_resp) + fcolor.SRed + " already exist !!","")
        if usr_resp=="D":
            usr_resp=AskQuestion("Enter the Name to Remove" ,"","","","")
            if len(usr_resp)>0:
                if usr_resp in __builtin__.MonitoringNameList:
                    __builtin__.MonitoringNameList.remove (str(usr_resp))
                    print "__builtin__.MonitoringNameList : " + str(__builtin__.MonitoringNameList)
                    printc ("i",fcolor.SGreen + "The Name " + fcolor.BYellow + str(usr_resp) + fcolor.SGreen + " deleted to monitoring list..","")
                    SaveMonitoringMAC()
                else:
                    printc ("!",fcolor.SRed + "The Name " + fcolor.BYellow + str(usr_resp) + fcolor.SRed + " does not exist !!","")
            else:
                if usr_resp!="":
                    printc ("!",fcolor.SRed +  "The Name " + fcolor.BYellow + str(usr_resp) + fcolor.SRed + " is invalid !!","")
        if usr_resp=="C":
            open(MonitorMACfile,"w").write("")
            __builtin__.MonitoringNameList=[]
            printc ("i",fcolor.SGreen + "All Names are cleared from the monitoring list..","")
        OptMonitorMAC("1")
        return

    if usr_resp!="M" and usr_resp!="N" and usr_resp!="C":
        DrawLine("_",fcolor.CReset + fcolor.Black,""); print ""
        return

def OptOutputDisplay():
    printc ("+", fcolor.BBlue + "Change Listing Display ","")
    print tabspacefull + StdColor + "This option allow user to switch display on the various viewing type of access point and station information.";print ""
    Option1 = tabspacefull + SelBColor + "0" + StdColor + "/" + SelBColor + "H" + StdColor + " - " + SelColor + "H" + StdColor + "ide both Access Points & Stations Listing Display\n"
    Option2 = tabspacefull + SelBColor + "1" + StdColor + "/" + SelBColor + "A" + StdColor + " - Display " + SelColor + "A" + StdColor + "ccess Points Listing Only\n"
    Option3 = tabspacefull + SelBColor + "2" + StdColor + "/" + SelBColor + "S" + StdColor + " - Display " + SelColor + "S" + StdColor + "tations Listing Only\n"
    Option4 = tabspacefull + SelBColor + "3" + StdColor + "/" + SelBColor + "B" + StdColor + " - Dispay " + SelColor + "B" + StdColor + "oth Access Points & Stations Listing (Seperated View)\n"
    Option5 = tabspacefull + SelBColor + "4" + StdColor + "/" + SelBColor + "P" + StdColor + " - Advanced View with " + SelColor + "P" + StdColor + "robes Request (Merging associated Stations with Access Points) - " + fcolor.BYellow + "[Recommended]\n"
    Option6 = tabspacefull + SelBColor + "5" + StdColor + "/" + SelBColor + "O" + StdColor + " - Advanced View with" + SelColor + "o" + StdColor + "ut probing request (Merging associated Stations with Access Points)\n"
    Option7 = "\n"
    Option8 = tabspacefull + SelBColor + "6" + StdColor + "/" + SelBColor + "C" + StdColor + " - Display one time bar " + SelColor + "c" + StdColor + "hart of Access Points information\n"
    Option9 = tabspacefull + SelBColor + "9" + StdColor + "/" + SelBColor + "W" + StdColor + " - " + SelColor + "W" + StdColor + "rite option to configuration file.\n"
    OptionA=Option1 + Option2 + Option3 + Option4  + Option5 + Option6 + Option7 + Option8 + Option9
    print OptionA
    printc (" " , fcolor.BWhite + "Current Setting = " + SelBColor + str(__builtin__.NETWORK_VIEW), "")
    usr_resp=AskQuestion("Choose an option / " + STxt + "R" + NTxt + "eturn","","U","ALL","1")
    if usr_resp=="9" or usr_resp=="W":
        SaveConfig()
    DrawLine("_",fcolor.CReset + fcolor.Black,"");print "";
    if usr_resp=="0" or usr_resp=="1" or usr_resp=="2" or usr_resp=="3" or usr_resp=="4"  or usr_resp=="5":
      __builtin__.NETWORK_VIEW=usr_resp
    if usr_resp=="H" or usr_resp=="A" or usr_resp=="S" or usr_resp=="B" or usr_resp=="P"  or usr_resp=="O" or usr_resp=="6" or usr_resp=="C":
        if usr_resp=="H":
            __builtin__.NETWORK_VIEW="0"
        if usr_resp=="A":
            __builtin__.NETWORK_VIEW="1"
        if usr_resp=="S":
            __builtin__.NETWORK_VIEW="2"
        if usr_resp=="B":
            __builtin__.NETWORK_VIEW="3"
        if usr_resp=="P":
            __builtin__.NETWORK_VIEW="4"
        if usr_resp=="0":
            __builtin__.NETWORK_VIEW="5"
        if usr_resp=="C" or usr_resp=="6":
            DisplayNetworkChart()
        DrawLine("_",fcolor.CReset + fcolor.Black,""); print ""
        return;

def printc(PrintType, PrintText,PrintText2):
    """
    Function	   : Displaying text with pre-defined icon and color
    Usage of printc:
        PrintType      - Type of Icon to display
        PrintText      - First sentence to display
        PrintText2     - Second sentence, "?" as reply text, "@"/"@^" as time in seconds
    Examples       : Lookup DemoOnPrintC() for examples
    """
    ReturnOut=""
    bcolor=fcolor.SWhite
    pcolor=fcolor.BGreen
    tcolor=fcolor.SGreen
    if PrintType=="i":
        pcolor=fcolor.BBlue
        tcolor=fcolor.BWhite
    if PrintType=="H":
        pcolor=fcolor.BBlue
        tcolor=fcolor.BWhite
        hcolor=fcolor.BUBlue
    if PrintType=="!":
        pcolor=fcolor.BRed
        tcolor=fcolor.BYellow
    if PrintType=="!!":
        PrintType="!"
        pcolor=fcolor.BRed
        tcolor=fcolor.SRed
    if PrintType=="!!!":
        PrintType="!"
        pcolor=fcolor.BRed
        tcolor=fcolor.BRed
    if PrintType==".":
        pcolor=fcolor.BGreen
        tcolor=fcolor.SGreen
    if PrintType=="-":
        pcolor=fcolor.SWhite
        tcolor=fcolor.SWhite
    if PrintType=="--":
        PrintType="-"
        pcolor=fcolor.BWhite
        tcolor=fcolor.BWhite
    if PrintType=="..":
        PrintType="."
        pcolor=fcolor.BGreen
        tcolor=fcolor.BGreen
    if PrintType==">" or PrintType=="+":
        pcolor=fcolor.BCyan
        tcolor=fcolor.BCyan
    if PrintType==" ":
        pcolor=fcolor.BYellow
        tcolor=fcolor.Green
    if PrintType=="  ":
        pcolor=fcolor.BYellow
        tcolor=fcolor.BGreen
    if PrintType=="?":
        pcolor=fcolor.BYellow
        tcolor=fcolor.BGreen
    if PrintType=="x":
        pcolor=fcolor.BRed
        tcolor=fcolor.BBlue
    if PrintType=="*":
        pcolor=fcolor.BYellow
        tcolor=fcolor.BPink
    if PrintType=="@" or PrintType=="@^":
        pcolor=fcolor.BRed
        tcolor=fcolor.White
    firstsixa=""
    if PrintText!="":
        tscolor=fcolor.Blue
        ts = time.time()
        DateTimeStamp=datetime.datetime.fromtimestamp(ts).strftime('%d/%m/%Y %H:%M:%S')
        TimeStamp=datetime.datetime.fromtimestamp(ts).strftime('%H:%M:%S')
        DateStamp=datetime.datetime.fromtimestamp(ts).strftime('%d/%m/%Y')
        PrintText=PrintText.replace("%dt -",tscolor + DateTimeStamp + " -" + tcolor)
        PrintText=PrintText.replace("%dt",tscolor + DateTimeStamp + tcolor)
        PrintText=PrintText.replace("%t -",tscolor + TimeStamp + " -" + tcolor)
        PrintText=PrintText.replace("%t",tscolor + TimeStamp + tcolor)
        PrintText=PrintText.replace("%d -",tscolor + DateStamp + " -" + tcolor)
        PrintText=PrintText.replace("%d",tscolor + DateStamp + tcolor)
        PrintText=PrintText.replace("%an",tscolor + ScriptName + tcolor)
        if "%cs" in PrintText:
            PrintText=PrintText.replace("%cs",tscolor + PrintText2 + tcolor)
            PrintText2=""
        lPrintText=len(PrintText) 
        if lPrintText>6:
            firstsix=PrintText[:6].lower()
            firstsixa=firstsix
            if firstsix=="<$rs$>":
                ReturnOut="1"
                lPrintText=lPrintText-6
                PrintText=PrintText[-lPrintText:]
    if __builtin__.PrintToFile=="1" and PrintType!="@" and PrintType!="x" and PrintType!="@^" and firstsixa!="<$rs$>":
        PrintTypep=PrintType
        if PrintTypep=="  " or PrintTypep==" ":
            PrintTypep="   " + __builtin__.tabspace
        else:
            PrintTypep="[" + PrintType + "]  "
        open(LogFile,"a+b").write(RemoveColor(PrintTypep) + RemoveColor(str(PrintText.lstrip().rstrip())) + "\n")
    if PrintType=="x":
        if PrintText=="":
            PrintText="Press Any Key To Continue..."
        c1=bcolor + "[" + pcolor + PrintType + bcolor + "]" + __builtin__.tabspace + tcolor + PrintText
        print c1,
        sys.stdout.flush()
        read_a_key()
        print ""
        return
    if PrintType=="H":
        c1=bcolor + "[" + pcolor + "i" + bcolor + "]" + __builtin__.tabspace + hcolor + PrintText + fcolor.CReset 
        if ReturnOut!="1":
            print c1
            return c1
        else:
            return c1
    if PrintType=="@" or PrintType=="@^":
        if PrintText2=="":
            PrintText2=5
        t=int(PrintText2)
        while t!=0:
            s=bcolor + "[" + pcolor + str(t) + bcolor + "]" + __builtin__.tabspace + tcolor + PrintText + "\r"
            s=s.replace("%s",pcolor+str(PrintText2)+tcolor)
            sl=len(s)
            print s,
            sys.stdout.flush()
            time.sleep(1)
            s=""
            ss="\r"
            print "" + s.ljust(sl+2) + ss,
            sys.stdout.flush()
            if PrintType=="@^":
                t=t-1
                while sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
                    line = sys.stdin.readline()
                    print "line : " + line
                    if line:
                        print bcolor + "[" + fcolor.BRed + "!" + bcolor + "]" + __builtin__.tabspace + fcolor.Red + "Interupted by User.." + fcolor.Green
                        return
            else:
                t=t-1            
        c1=bcolor + "[" + pcolor + "-" + bcolor + "]" + __builtin__.tabspace + tcolor + PrintText + "\r"
        c1=c1.replace("%s",pcolor+str(PrintText2)+tcolor)
        print c1,
        sys.stdout.flush()
        return
    if PrintType=="?":
        if PrintText2!="":
            usr_resp=raw_input(bcolor + "[" + pcolor + PrintType + bcolor + "]" + __builtin__.tabspace + tcolor + PrintText + " ( " + pcolor + PrintText2 + tcolor + " ) : " + fcolor.BWhite)
            return usr_resp;
        else:
            usr_resp=raw_input(bcolor + "[" + pcolor + PrintType + bcolor + "]" + __builtin__.tabspace + tcolor + PrintText + " : " + fcolor.BWhite)
            return usr_resp;
    if PrintType==" " or PrintType=="  ":
        if ReturnOut!="1":
            print bcolor + "   " + __builtin__.tabspace + tcolor + PrintText + PrintText2
        else:
            return bcolor + "   " + __builtin__.tabspace + tcolor + PrintText + PrintText2
    else:
        if ReturnOut!="1":
            print bcolor + "[" + pcolor + PrintType + bcolor + "]" + __builtin__.tabspace + tcolor + PrintText + PrintText2
        else:
            return bcolor + "[" + pcolor + PrintType + bcolor + "]" + __builtin__.tabspace + tcolor + PrintText + PrintText2

def AskQuestion(QuestionText, ReplyText, ReplyType, DefaultReply, DisplayReply):
    """
    Function	        : Question for user input. Quite similar to printc("?") function
    Usage of AskQuestion:
        QuestionText    - Question Text to ask
        ReplyText       - The reply text. Ex : "Y/n")
    Examples            : Lookup DemoAskQuestion() for examples
    """
    if DisplayReply=="":
        DisplayReply=1

    bcolor=fcolor.SWhite
    pcolor=fcolor.BYellow
    tcolor=fcolor.BGreen
    if ReplyText!="":
        usr_resp=raw_input(bcolor + "[" + pcolor + "?" + bcolor + "]" + __builtin__.tabspace + tcolor + QuestionText + " ( " + pcolor + ReplyText + tcolor + " ) : " + fcolor.BWhite)
    else:
        usr_resp=raw_input(bcolor + "[" + pcolor + "?" + bcolor + "]" + __builtin__.tabspace + tcolor + QuestionText + " : " + fcolor.BWhite)
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
                usr_resp=raw_input(bcolor + "[" + pcolor + "?" + bcolor + "]" + __builtin__.tabspace + tcolor + QuestionText + " ( " + pcolor + ReplyText + tcolor + " ) : " + fcolor.BWhite)
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
        sys.stdout.write(bcolor + "[" + icolor + str(IconDisplay) + bcolor + "]" + __builtin__.tabspace + DisplayText)
        sys.stdout.flush()
    return str(PrevIconCount);

def CenterText(CTxtColor, DisplayText):
    curses.setupterm()
    TWidth=curses.tigetnum('cols')
    DisplayTextL=len(DisplayText) 
    HWidth=(TWidth / 2) - (DisplayTextL / 2)
    SPA=" " * HWidth 
    SWidth=TWidth - (HWidth + DisplayTextL)
    SPA2=" " * SWidth 
    print CTxtColor + SPA + DisplayText + SPA2 + "" + fcolor.CReset

def printd(PrintText):
    if __builtin__.DEBUG==1:
        print fcolor.CDebugB  + "[DBG]  " + fcolor.CDebug + PrintText  + fcolor.CReset
    if __builtin__.DEBUG==2:
        print fcolor.CDebugB + "[DBG]  " + fcolor.CDebug + PrintText + fcolor.CReset
        print fcolor.CReset + fcolor.White + "       [Break - Press Any Key To Continue]" + fcolor.CReset
        read_a_key()

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

def CombineListing(List1, List2, List3, List4, List5, List6, List7, List8):

    __builtin__.MergedList=[]
    __builtin__.MergedSpaceList=[]
    __builtin__.TitleList=[]
    CombineText="";ListMax1=0;ListMax2=0;ListMax3=0;ListMax4=0;ListMax5=0;ListMax6=0;ListMax7=0;ListMax8=0;x=0
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
    __builtin__.MergedSpaceList.append(5)
    __builtin__.MergedSpaceList.append(ListMax1)
    __builtin__.MergedSpaceList.append(ListMax2)
    __builtin__.MergedSpaceList.append(ListMax3)
    __builtin__.MergedSpaceList.append(ListMax4)
    __builtin__.MergedSpaceList.append(ListMax5)
    __builtin__.MergedSpaceList.append(ListMax6)
    __builtin__.MergedSpaceList.append(ListMax7)
    __builtin__.MergedSpaceList.append(ListMax8)

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
        __builtin__.MergedList.append(str(CombineText))
        i = i + 1
    return i;

def QuestionFromList(ListTitle,ListTitleSpace,ListUse,AskQuestion,RtnType):
    __builtin__.ListingIndex=""
    bcolor=fcolor.SWhite
    pcolor=fcolor.BYellow
    ttcolor=fcolor.BBlue
    lcolor=fcolor.SYellow
    scolor=fcolor.BRed
    tcolor=fcolor.BGreen
    x=0
    sn=0
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
        __builtin__.ListingIndex=usr_resp
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
        __builtin__.ListingIndex=usr_resp
        return usr_resp;

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

def MoveInstallationFiles(srcPath,dstPath):
    import shutil
    listOfFiles = os.listdir(srcPath)
    listOfFiles.sort()
    for f in listOfFiles:
        if f!=".git" and f!=".gitignore":
            srcfile = srcPath + f
            dstfile = dstPath + f
            if f==__builtin__.ScriptName:
                shutil.copy2(srcfile, "/usr/sbin/" + str(__builtin__.ScriptName))
                printd("Copy to " + "/usr/sbin/" + str(__builtin__.ScriptName))
                result=os.system("chmod +x /usr/sbin/" + __builtin__.ScriptName + " > /dev/null 2>&1")
                printd("chmod +x " + "/usr/sbin/" + str(__builtin__.ScriptName))
            if os.path.exists(dstfile):
                os.remove(dstfile)
            shutil.move(srcfile, dstfile)
            print fcolor.SGreen + "        Moving " + fcolor.CUnderline + f + fcolor.CReset + fcolor.SGreen + " to " + dstfile
            if f==__builtin__.ScriptName:
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
    github="https://github.com/SYWorks/wifi-harvester.git"
    Updatetmpdir="/tmp/git-update-wh/"
    DownloadedScriptLocation=Updatetmpdir + __builtin__.ScriptName
    dstPath=os.getcwd() + "/"
    dstPath=appdir
    dstScript=dstPath + __builtin__.ScriptName

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
                   __builtin__.DScriptName = For Display
    """

    __builtin__.ScriptName=os.path.basename(__file__)
    __builtin__.DScriptName="./" + __builtin__.ScriptName
    appdir=os.path.realpath(os.path.dirname(sys.argv[0]))
    __builtin__.FullScriptName=str(appdir) + "/" + str(__builtin__.ScriptName)
    printd("__builtin__.FullScriptName : " + __builtin__.FullScriptName)
    printd("ScriptName : " + str(__builtin__.ScriptName))



def ShowBanner():
    wordart = random.randrange(1,8+1)
    if wordart == 1:
        print fcolor.BGreen + """ __          ___  __ _   _    _                           _            
 \ \        / (_)/ _(_) | |  | |                         | |           
  \ \  /\  / / _| |_ _  | |__| | __ _ _ ____   _____  ___| |_ ___ _ __ 
   \ \/  \/ / | |  _| | |  __  |/ _` | '__\ \ / / _ \/ __| __/ _ \ '__|
    \  /\  /  | | | | | | |  | | (_| | |   \ V /  __/\__ \ ||  __/ |   
     \/  \/   |_|_| |_| |_|  |_|\__,_|_|    \_/ \___||___/\__\___|_|   """
        return
    if wordart == 2:
        print fcolor.BGreen + """ _    _ _  __ _   _   _                           _            
| |  | (_)/ _(_) | | | |                         | |           
| |  | |_| |_ _  | |_| | __ _ _ ____   _____  ___| |_ ___ _ __ 
| |/\| | |  _| | |  _  |/ _` | '__\ \ / / _ \/ __| __/ _ \ '__|
\  /\  / | | | | | | | | (_| | |   \ V /  __/\__ \ ||  __/ |   
 \/  \/|_|_| |_| \_| |_/\__,_|_|    \_/ \___||___/\__\___|_|          """
        return
    if wordart == 3:
        print fcolor.BGreen + """
 __      __.__  _____.__    ___ ___                                     __                
/  \    /  \__|/ ____\__|  /   |   \_____ __________  __ ____   _______/  |_  ___________ 
\   \/\/   /  \   __\|  | /    ~    \__  \\_  __ \  \/ // __ \ /  ___/\   __\/ __ \_  __  \\
 \        /|  ||  |  |  | \    Y    // __ \|  | \/\   /\  ___/ \___ \  |  | \  ___/|  | \/
  \__/\  / |__||__|  |__|  \___|_  /(____  /__|    \_/  \___  >____  > |__|  \___  >__|   
       \/                        \/      \/                 \/     \/            \/       """
        return
    if wordart == 4:
        print fcolor.BGreen + """ __    __ _  __ _                                   _            
/ / /\ \ (_)/ _(_)   /\  /\__ _ _ ____   _____  ___| |_ ___ _ __ 
\ \/  \/ / | |_| |  / /_/ / _` | '__\ \ / / _ \/ __| __/ _ \ '__|
 \  /\  /| |  _| | / __  / (_| | |   \ V /  __/\__ \ ||  __/ |   
  \/  \/ |_|_| |_| \/ /_/ \__,_|_|    \_/ \___||___/\__\___|_|           """
        return
    if wordart == 5:
        print fcolor.BGreen + """ __        ___  __ _   _   _                           _            
 \ \      / (_)/ _(_) | | | | __ _ _ ____   _____  ___| |_ ___ _ __ 
  \ \ /\ / /| | |_| | | |_| |/ _` | '__\ \ / / _ \/ __| __/ _ \ '__|
   \ V  V / | |  _| | |  _  | (_| | |   \ V /  __/\__ \ ||  __/ |   
    \_/\_/  |_|_| |_| |_| |_|\__,_|_|    \_/ \___||___/\__\___|_|           """
        return
    if wordart == 6:
        print fcolor.BGreen + """ ________ __ _______ __   _______                                __              
|  |  |  |__|    ___|__| |   |   |.---.-.----.--.--.-----.-----.|  |_.-----.----.
|  |  |  |  |    ___|  | |       ||  _  |   _|  |  |  -__|__ --||   _|  -__|   _|
|________|__|___|   |__| |___|___||___._|__|  \___/|_____|_____||____|_____|__|          """
        return
    if wordart == 7:
        print fcolor.BGreen + """ _  _  _ _ _______ _    _     _                                             
| || || (_|_______|_)  | |   | |                            _               
| || || |_ _____   _   | |__ | | ____  ____ _   _ ____  ___| |_  ____  ____ 
| ||_|| | |  ___) | |  |  __)| |/ _  |/ ___) | | / _  )/___)  _)/ _  )/ ___)
| |___| | | |     | |  | |   | ( ( | | |    \ V ( (/ /|___ | |_( (/ /| |    
 \______|_|_|     |_|  |_|   |_|\_||_|_|     \_/ \____|___/ \___)____)_|            """
        return
    if wordart == 8:
        print fcolor.BGreen + """ _  _  _ _ _______ _    _     _                                             
| || || (_|_______|_)  | |   | |                            _               
| || || |_ _____   _   | |__ | | ____  ____ _   _ ____  ___| |_  ____  ____ 
| ||_|| | |  ___) | |  |  __)| |/ _  |/ ___) | | / _  )/___)  _)/ _  )/ ___)
| |___| | | |     | |  | |   | ( ( | | |    \ V ( (/ /|___ | |_( (/ /| |    
 \______|_|_|     |_|  |_|   |_|\_||_|_|     \_/ \____|___/ \___)____)_|            """
        return

                                                                                  
def ShowSYWorks():
    print fcolor.BWhite + " _  _  _  _  _  _  _    _  _  _  _  _  _  _  _  _  _  _ "
    WordColor=fcolor.BUBlue
    BubbleColor=fcolor.SBlue
    BC1="|"
    BC2="|"
    DisplayTxt = BubbleColor + BC1 + WordColor + "S" + fcolor.CReset + BubbleColor + BC1 + BC2 + WordColor + "Y" + fcolor.CReset + BubbleColor + BC1 + BC2 + WordColor + "W" + fcolor.CReset + BubbleColor + BC1 + BC2 + WordColor + "O" + fcolor.CReset + BubbleColor + BC1 + BC2 + WordColor + "R" + fcolor.CReset + BubbleColor + BC1 + BC2 + WordColor + "K" + fcolor.CReset + BubbleColor + BC1 + BC2 + WordColor + "S" + fcolor.CReset + BubbleColor + BC2 + "  " + BC1 + WordColor + "P" + fcolor.CReset + BubbleColor + BC1 + BC2 + WordColor + "R" + fcolor.CReset + BubbleColor + BC1 + BC2 + WordColor + "O" + fcolor.CReset + BubbleColor + BC1 + BC2 + WordColor + "G" + fcolor.CReset + BubbleColor + BC1 + BC2 + WordColor + "R" + fcolor.CReset + BubbleColor + BC1 + BC2 + WordColor + "A" + fcolor.CReset + BubbleColor + BC1 + BC2 + WordColor + "M" + fcolor.CReset + BubbleColor + BC1 + BC2 + WordColor + "M" + fcolor.CReset + BubbleColor + BC1 + BC2 + WordColor + "I" + fcolor.CReset + BubbleColor + BC1 + BC2 + WordColor + "N" + fcolor.CReset + BubbleColor + BC1 + BC2 + WordColor + "G" + fcolor.CReset + BubbleColor + BC2
    sys.stdout.write(DisplayTxt)
    sys.stdout.flush()

def DisplayAppDetail():
    ShowBanner()
    ShowSYWorks()
    print "";print ""
    print fcolor.BGreen + apptitle + " " + appver + fcolor.SGreen + " " + appDesc
    print fcolor.CReset + fcolor.SWhite + appnote
    print ""

def DisplayDisclaimer():
    printc ("!!!","Legal  Disclaimer :- " + fcolor.Red + "FOR EDUCATIONAL PURPOSES ONLY !!","")
    print fcolor.SWhite + " Usage of this application for attacking target without prior mutual consent is illegal. It is the"
    print fcolor.SWhite + " end user's responsibility to obey all applicable local, state and  federal laws. Author assume no"
    print fcolor.SWhite + " liability and are not responsible for any misuse or damage caused by this application."
    print ""

def DisplayFullDescription():
    print fcolor.BRed + " Description : "
    print fcolor.SGreen + " "
    print fcolor.SWhite + " "
    print fcolor.SWhite + " "
    print fcolor.SWhite + " "
    print fcolor.SWhite + " "
    print fcolor.BWhite + " "
    print ""

def DisplayDescription():
    print fcolor.BRed + "Description : "
    print fcolor.SWhite + " The Network Harvestor is use to collect detail information on the surrounding Access Points / Stations"
    print fcolor.SWhite + " such as MAC address, SSID, Encryption Type, Channels, Signal Range, Probes and association information"
    print fcolor.SWhite + " of the wireless stations.. "
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
    print ""
#    print fcolor.BWhite + "    -l  --loop" + fcolor.BBlue + " <arg>\t" + fcolor.CReset + fcolor.White + "- Run the number of loop before exiting"
    print fcolor.BWhite + "    -i  --iface" + fcolor.BBlue + " <arg>\t" + fcolor.CReset + fcolor.White + "- Set Interface to use"
    print fcolor.BWhite + "    -t  --timeout" + fcolor.BBlue + " <arg>\t" + fcolor.CReset + fcolor.White + "- Duration to capture before analysing the captured data"
    print ""
    print fcolor.BGreen + "Examples: " + fcolor.BYellow + "" + DScriptName + fcolor.BWhite + " --update"
    print fcolor.BGreen + "          " + fcolor.BYellow + "" + DScriptName + fcolor.BWhite + " -i " + fcolor.BBlue + "wlan0" 
    print fcolor.BGreen + "          " + fcolor.BYellow + "" + DScriptName + fcolor.BWhite + " --iface " + fcolor.BBlue + "wlan1" 
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
    print fcolor.BWhite + "    -t  --timeout" + fcolor.BBlue + " <arg>\t" + fcolor.CReset + fcolor.White + "- Duration to capture before analysing the captured data"
    print ""
    print fcolor.BGreen + "Examples: " + fcolor.BYellow + "" + DScriptName + fcolor.BWhite + " --update"
    print fcolor.BGreen + "          " + fcolor.BYellow + "" + DScriptName + fcolor.BWhite + " -i " + fcolor.BBlue + "wlan0"
    print fcolor.BGreen + "          " + fcolor.BYellow + "" + DScriptName + fcolor.BWhite + " --iface " + fcolor.BBlue + "wlan1"
    print ""
    DrawLine("-",fcolor.CReset + fcolor.Black,"")
    print ""

def GetParameter(cmdDisplay):
    """
   cmdDisplay = "0" : Does not display help if not specified
                "1" : Display help even not specified
                "2" : Display Help, exit if error
    """
    __builtin__.ReadPacketOnly=""
    __builtin__.LoopCount=99999999
    __builtin__.SELECTED_IFACE=""
    __builtin__.SELECTED_MON=""
    __builtin__.PRINTTOFILE=""
    __builtin__.ASSIGNED_MAC=""
    __builtin__.SPOOF_MAC=""
    __builtin__.AllArguments=""
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
                elif arg=="-ro":
                    Err=0
                    __builtin__.ReadPacketOnly="1"
                elif arg=="--update":
                    Err=0
                    GetUpdate("1")
                    exit()
                elif arg=="--remove":
                    Err=0
                    UninstallApplication()
                    exit()
                elif arg=="--spoof":
                    __builtin__.AllArguments=__builtin__.AllArguments + fcolor.BWhite + "Spoof MAC\t\t:  " + fcolor.BRed + "Enabled\n"
                    __builtin__.SPOOF_MAC="1"
                    Err=0
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
                                    __builtin__.ASSIGNED_MAC=i2str 
                                    __builtin__.AllArguments=__builtin__.AllArguments + fcolor.BWhite + "Selected MAC\t\t:  " + fcolor.BRed + i2str + "\n"
                                    __builtin__.SPOOF_MAC="1"
                                else:
                                    printc("!!!","Invalid MAC Address set [ " + fcolor.BWhite + i2str + fcolor.BRed + " ] !","")  
                                    Err=1
                            else:
                                printc("!!!","Invalid MAC Address set [ " + fcolor.BWhite + i2str + fcolor.BRed + " ] !","")  
                                Err=1
                        else:
                            printc("!!!","Invalid MAC Address set [ " + fcolor.BWhite + i2str + fcolor.BRed + " ] !","")  
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
                                __builtin__.TIMEOUT=i2str
                                __builtin__.AllArguments=__builtin__.AllArguments + fcolor.BWhite + "Timeout (Seconds)\t:  " + fcolor.BRed + str(__builtin__.TIMEOUT) + "\n"
                                if float(__builtin__.TIMEOUT)<20:
				    __builtin__.AllArguments=__builtin__.AllArguments + fcolor.SWhite + "\t\t\t:  Timeout second set may be to low for detection.\n"
                            else:
                                printc("!!!","Invalid timeout variable set [ " + fcolor.BWhite + i2str + fcolor.BRed + " ] !","")  
                                Err=1
                        else:
                            printc("!!!","Invalid timeout variable set [ " + fcolor.BWhite + i2str + fcolor.BRed + " ] !","")  
                            Err=1
                elif arg=="-l" or arg=="--loop":
                    i=i2
                    if i2str=="":
                        printc("!!!","Invalid __builtin__.LoopCount variable set !","")  
                        Err=1
                    else:
                        Err=0
                        if i2str[:1]!="-":
                            if i2str.isdigit():
                                __builtin__.LoopCount=i2str
                                if float(__builtin__.LoopCount)<1:
				    __builtin__.AllArguments=__builtin__.AllArguments + fcolor.SWhite + "\t\t\t:  Minimum loop count is 1.\n"
                                    __builtin__.LoopCount=1
                                __builtin__.AllArguments=__builtin__.AllArguments + fcolor.BWhite + "Loop Count\t\t:  " + fcolor.BRed + str(__builtin__.LoopCount) + "\n"

                            else:
                                printc("!!!","Invalid loop count variable set [ " + fcolor.BWhite + i2str + fcolor.BRed + " ] !","")  
                                Err=1
                        else:
                            printc("!!!","Invalid loop count variable set [ " + fcolor.BWhite + i2str + fcolor.BRed + " ] !","")  
                            Err=1
                elif arg=="-i" or arg=="--iface":
                    i=i2
                    if i2str=="":
                        printc("!!!","Invalid Interface variable set !","")  
                        Err=1
                    else:
                        Err=0
                        if i2str[:1]!="-":
                            __builtin__.SELECTED_IFACE=i2str
                            __builtin__.AllArguments=__builtin__.AllArguments + fcolor.BWhite + "Selected interface\t:  " + fcolor.BRed + i2str + "\n"
                        else:
                            printc("!!!","Invalid Interface variable set [ " + fcolor.BWhite + i2str + fcolor.BRed + " ] !","")  
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
        if __builtin__.AllArguments!="":
            print fcolor.BYellow + "Parameter set:"
            print __builtin__.AllArguments
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


def GetFileLine(filename,omitblank):
    __builtin__.TotalLine=0
    __builtin__.UsableLine=0
    if omitblank=="":
        omitblank="0"

    if omitblank=="1":
        with open(filename, 'r') as f: 
            lines = len(list(filter(lambda x: x.strip(), f)))
        __builtin__.TotalLine=lines
        __builtin__.UsableLine=lines
    if omitblank=="0":
        with open(filename) as f:
            lines=len(f.readlines())
        __builtin__.TotalLine=lines
        __builtin__.UsableLine=lines
    if omitblank=="2":
        lines=0
	with open(filename,"r") as f:
	    for line in f:
                sl=len(line.replace("\n",""))
                if sl>0:
                    __builtin__.TotalLine=__builtin__.TotalLine+1
                    if sl>=8 and sl<=63:
                        lines=lines+1
                        __builtin__.UsableLine=lines
    return lines

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
        Ask=AskQuestion ("Do you want to delete all the Database files created ?","y/N","","N","")
        if Ask=="Y":
            Delfile (__builtin__.FilenameHeader + "*.*","1")

        printc ("i", "Application successfully removed !!","")
        exit(0)
    else:
        printc ("i",fcolor.BWhite + "Uninstall aborted..","")
        exit(0)


def SelectInterfaceToUse():
    printc ("i", fcolor.BRed + "Wireless Adapter Selection","")
    Result = GetInterfaceList("MAN")
    if Result==0:
        printc ("!", fcolor.SRed + "No wireless adapter adapter found !!","")
        exit()

    Result = CombineListing(__builtin__.IFaceList, __builtin__.MACList,__builtin__.UpDownList,__builtin__.IEEEList,__builtin__.StatusList,__builtin__.ModeList,"","")
    if int(Result)>1:
        __builtin__.TitleList=['Sel','Iface','MAC Address','Up ?', 'IEEE','Status','Mode','','']
        Result=QuestionFromList(__builtin__.TitleList, __builtin__.MergedSpaceList,__builtin__.MergedList,"Select the interface from the list","0")
        if Result=="0":
                 Result=AskQuestion(fcolor.SGreen + "You need to select a interface to use," + fcolor.BGreen + " retry ?","Y/n","U","Y","1")
                 if Result=="Y":
                     Result=SelectInterfaceToUse()
                     return Result
                 else:
                     exit(0)
        Result=int(Result)-1
        __builtin__.SELECTED_IFACE=__builtin__.IFaceList[int(Result)]
    else:
        __builtin__.SELECTED_IFACE=__builtin__.IFaceList[0]
    return __builtin__.SELECTED_IFACE;

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

def SelectMonitorToUse():
    time.sleep (0)
    MonCt = GetInterfaceList("MON")
    if MonCt==0:
        printc ("i", fcolor.BRed + "Monitoring Adapter Selection","")
    MonCt = GetInterfaceList("MON")
    if MonCt==0:
        printc ("!", fcolor.SRed + "No monitoring adapter found !!","")
        exit()


    Result = CombineListing(__builtin__.IFaceList, __builtin__.MACList,__builtin__.UpDownList,__builtin__.IEEEList,__builtin__.StatusList,"","","")
    if int(Result)>1:
        __builtin__.TitleList=['Sel','Iface','MAC Address','Up ?', 'IEEE','Status','','','']
        Result=QuestionFromList(__builtin__.TitleList, __builtin__.MergedSpaceList,__builtin__.MergedList,"Select the monitoring interface from the list","0")
        if Result=="0":
                 Result=AskQuestion(fcolor.SGreen + "You need to select a monitoring interface to use," + fcolor.BGreen + " retry ?","Y/n","U","Y","1")
                 if Result=="Y":
                     Result=SelectMonitorToUse()
                     return Result
                 else:
                     exit(0)
        Result=int(Result)-1
        __builtin__.SELECTED_MON=__builtin__.IFaceList[int(Result)]
    else:
        __builtin__.SELECTED_MON=__builtin__.IFaceList[0]
    return __builtin__.SELECTED_MON;

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

def exit_gracefully(code=0):
    KillAllMonitor()
    printc (" ","","")
    printc ("*", fcolor.BRed + "Application shutdown !!","")
    if __builtin__.TimeStart!="":
        result=DisplayTimeStamp("summary-a","")
    if __builtin__.PrintToFile=="1":
        print fcolor.BGreen + "     Result Log\t: " + fcolor.SGreen + LogFile
        open(LogFile,"a+b").write("\n\n")
    __builtin__.PrintToFile="0"
    print ""
    MonCt = GetInterfaceList("MON")
    X=0
    while X<MonCt:
        PM=len(__builtin__.MONList)
        Y=0
        while Y<PM:
            if __builtin__.MONList[Y]==__builtin__.IFaceList[X]:
                __builtin__.IFaceList[Y]=""
            Y=Y+1
        X=X+1
    PM=len(__builtin__.IFaceList)
    Y=0
    while Y<PM:
        if __builtin__.IFaceList[Y]!="":
            printc (".", fcolor.BGreen + "Stopping [ " + fcolor.BRed + str(__builtin__.IFaceList[Y]) + fcolor.BGreen + " ] ....","") 
            ps=subprocess.Popen("airmon-ng  check kill  > /dev/null 2>&1", shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'))
            ps.wait()
            ps=subprocess.Popen("airmon-ng stop " + str(__builtin__.IFaceList[Y]) + " > /dev/null 2>&1", shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'))
            ps.wait()
            time.sleep(0.1)
        Y=Y+1
    ps=subprocess.Popen("killall 'airodump-ng' > /dev/null 2>&1" , shell=True, stdout=subprocess.PIPE)	
    time.sleep(0.1)
    ps=subprocess.Popen("killall 'tshark' > /dev/null 2>&1" , shell=True, stdout=subprocess.PIPE)	
    time.sleep(0.1)
    if __builtin__.ERRORFOUND!=1:
        print ""
        print fcolor.BWhite + "Please support by liking my page at " + fcolor.BBlue + "https://www.facebook.com/syworks" +fcolor.BWhite + " (SYWorks-Programming)"

    print fcolor.BRed + __builtin__.ScriptName + " Exited." 
    print ''
    exit(code)

def AddTime(tm, secs):
    fulldate = datetime.datetime(tm.year, tm.month, tm.day, tm.hour, tm.minute, tm.second)
    fulldate = fulldate + datetime.timedelta(seconds=secs)
    return fulldate

def Percent(val, digits):
    val *= 10 ** (digits + 2)
    return '{1:.{0}f} %'.format(digits, floor(val) / 10 ** digits)

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
    ps=subprocess.Popen("ifconfig " + str(__builtin__.SELECTED_IFACE) + " | grep 'HWaddr' | tr -s ' ' | cut -d ' ' -f5" , shell=True, stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'))	
    MACADDR=ps.stdout.read().replace("\n","").upper().replace("-",":")
    MACADDR=MACADDR[:17]
    if str(MACADDR)!=ASSIGNED_MAC:
        printc ("i",fcolor.BRed + "Spoofing [ " + str(__builtin__.SELECTED_IFACE) + " ] MAC Address","")
        printc (" ",fcolor.BBlue + "Existing MAC\t: " + fcolor.BWhite + str(MACADDR),"")
        printc (" ",fcolor.BBlue + "Spoof MAC\t\t: " + fcolor.BWhite +  str(ASSIGNED_MAC),"")
        Result=MACADDR
        Ask=AskQuestion("Continue to spoof the MAC Address ?","Y/n","U","Y","0")
        if Ask=="Y":
            ps=subprocess.Popen("ifconfig " + str(__builtin__.SELECTED_IFACE) + " down hw ether " + str(ASSIGNED_MAC) + " > /dev/null 2>&1" , shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'))
            ps=subprocess.Popen("ifconfig " + str(__builtin__.SELECTED_IFACE) + " up > /dev/null 2>&1" , shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'))
            time.sleep(1)
            ps=subprocess.Popen("ifconfig " + str(__builtin__.SELECTED_IFACE) + " | grep 'HWaddr' | tr -s ' ' | cut -d ' ' -f5" , shell=True, stdout=subprocess.PIPE)
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
                    Result=SpoofMAC(__builtin__.SELECTED_IFACE,"")
                    return Result;
                else:
                    printc (" ",fcolor.BRed + "You choose to abort spoofing of MAC address.","")
                    printc (" ",fcolor.BBlue + "Using MAC Address [ " + fcolor.BYellow + str(NEWADDR) + fcolor.BBlue + " ]","")
                    return Result
        else:
            printc (" ",fcolor.BRed + "You choose to abort spoofing of MAC address.","")
            printc (" ",fcolor.BBlue + "Using MAC Address [ " + fcolor.BYellow + str(MACADDR) + fcolor.BBlue + " ]","")
    return Result

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

def IsAscii(inputStr):
    return all(ord(c) < 127 and ord(c) > 31 for c in inputStr)

def CheckSSIDChr(ESSID_Name):
    if IsAscii(ESSID_Name)==False:
        ESSID_Name=""
    return ESSID_Name

def IsProgramExists(program):
    """
	Check if program exist
    """
    proc = Popen(['which', program], stdout=PIPE, stderr=PIPE)
    txt = proc.communicate()
    if txt[0].strip() == '' and txt[1].strip() == '':
	return False
    if txt[0].strip() != '' and txt[1].strip() == '':
	return True
    return not (txt[1].strip() == '' or txt[1].find('no %s in' % program) != -1)

def DownloadFile(sURL,FileLoc,ToDisplay):
  try:
    if ToDisplay=="1":
        printc ("..","Downloading file from " + fcolor.BBlue + str(sURL),"")
    urllib.urlretrieve(sURL,FileLoc)
    if IsFileDirExist(__builtin__.MACOUI)=="F":
        printc ("i","File successfully saved to " + FileLoc,"")
    else:
        printc ("!!!","File failed to save. Please do it manually.","")
    return;
  except:
    printc ("!!!","Error downloading... please make sure you run as root and have internet access.","")

def CheckRequiredFiles():
    MISSING_FILE=0
    ERROR_MSG=""
    for req_file in __builtin__.RequiredFiles:
        if IsProgramExists(req_file): continue
	ERROR_MSG= ERROR_MSG + str(printc (" ","<$rs$>" + fcolor.SGreen + "Required file not found - " + fcolor.BRed + str(req_file) + "\n",""))
        MISSING_FILE += 1
    if MISSING_FILE!=0:
        TXT_1=""
        TXT_2="was"
        if MISSING_FILE>1:
            TXT_1="s"
            TXT_2="were"
        print ""
	printc ("!!!",fcolor.BGreen + "The following file" + TXT_1 + " required by " + apptitle + " " + TXT_2 + " not found:- " ,"")
        print ERROR_MSG
        print ""
        printc ("..","Developer does not provide any support on how you could install all these application.","")
        printc ("..","To save the hassle, run this script on Backtrack/Kali Linux as all these required applications are already preinstalled.","")
        __builtin__.ERRORFOUND=1
        exit_gracefully(1)
    if IsFileDirExist(__builtin__.MACOUI)!="F":
        printc ("!!!","MAC OUI Database (Optional) not found !","")
        printc ("  ",fcolor.SGreen + "Database can be downloaded at " + fcolor.SBlue + "https://raw.githubusercontent.com/SYWorks/Database/master/mac-oui.db","")
        printc ("  ",fcolor.SGreen + "Copy the download file " + fcolor.BGreen + "mac-oui.db" + fcolor.SGreen +" and copy it to " + fcolor.BRed + dbdir + "\n\n","")
        usr_resp=AskQuestion(fcolor.BGreen + "Or do you prefer to download it now ?" + fcolor.BGreen,"Y/n","U","Y","1")
        if usr_resp=="Y":
            DownloadFile("https://raw.githubusercontent.com/SYWorks/Database/master/mac-oui.db",dbdir + "mac-oui.db","1")
        print ""
        printc ("x","Press any key to continue...","")
    if IsFileDirExist(DBFile1)!="F":
        WriteData="Station;Connected BSSID;AP First Seen;Client First Seen;Reported;Hotspot ESSID;\n"
        open(DBFile1,"a+b").write(WriteData)
    if IsFileDirExist(DBFile2)!="F":
        WriteData="BSSID;Enriched;Mode;First Seen;Last Seen;Channel;Privacy;Cipher;Authentication;Max Rate;Bit Rates;Power;GPS Lat;GPS Lon;GPS Alt;WPS;WPS Ver;Reported;ESSID;\n"
        open(DBFile2,"a+b").write(WriteData)
    if IsFileDirExist(DBFile3)!="F":
        WriteData="Station;Connected BSSID;First Seen;Last Seen;Power;Reported;Connected ESSID;\n"
        open(DBFile3,"a+b").write(WriteData)
    if IsFileDirExist(DBFile4)!="F":
        WriteData="Station;Reported;Probes Name;\n"
        open(DBFile4,"a+b").write(WriteData)
    if IsFileDirExist(DBFile5)!="F":
        WriteData="Station;Connected BSSID;Connected ESSID;\n"
        open(DBFile5,"a+b").write(WriteData)
    if IsFileDirExist(DBFile6)!="F":
        WriteData="Station;Initial BSSID;New BSSID;Reported;Initial ESSID;New ESSID;\n"
        open(DBFile6,"a+b").write(WriteData)

def CheckAppLocation():
    import shutil
    cpath=0
    if os.path.exists(appdir)==True:
        printd ("[" + appdir + "] exist..")
    else:
        printd ("[" + appdir + "] does not exist..")
        result=MakeTree(appdir,"")
        cpath=1
    if os.path.exists(dbdir)==True:
        printd ("[" + dbdir + "] exist..")
    else:
        printd ("[" + dbdir + "] does not exist..")
        result=MakeTree(dbdir,"")
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
        cpath=1
    if os.path.exists("/usr/sbin/" + ScriptName)==False:
        printd("File Not found in " + "/usr/sbin/" + str(ScriptName))
        printd("Copy file from [" + str(CurFileLocation) + "] to [" + "/usr/sbin/" + str(ScriptName) + " ]")
        shutil.copy2(CurFileLocation, "/usr/sbin/" + str(ScriptName))
        result=os.system("chmod +x " + "/usr/sbin/" + str(ScriptName) + " > /dev/null 2>&1")
        cpath=1
    if PathList!="":
        printd("PathList : " + str(PathList))
        for path in PathList:
            newPath=appdir + path
            printd("Checking : " + str(newPath))
            if os.path.exists(newPath)==False:
                printd("Path [ " + str(newPath) + " ] not found.")
                cpath=1
                result=MakeTree(newPath,"")
                cpath=1
    if cpath==1:
        print ""
        printc ("i",fcolor.BWhite + "You can now run " + fcolor.BRed + ScriptName + fcolor.BWhite + " from " + fcolor.BRed + appdir + fcolor.BWhite + " by doing the following :","")
        printc (" ",fcolor.BGreen + "cd " + appdir,"")
        printc (" ",fcolor.BGreen + "./" + ScriptName,"")
        print ""
        printc ("x","","")


def GetRegulatoryDomain():
    ps=subprocess.Popen("iw reg get | grep -i 'country' | awk '{print $2}' | sed 's/://g'" , shell=True, stdout=subprocess.PIPE)	
    CurrentReg=ps.stdout.read().replace("\n","").lstrip().rstrip()
    return CurrentReg;

def ChangeRegulatoryDomain():
    DrawLine("_",fcolor.CReset + fcolor.Black,"");print "";
    printc ("+",fcolor.BBlue + "Regulatory Domain Configuration","")
    printc (" " ,StdColor + "For a updated list,you may wish to download it from http://linuxwireless.org/download/wireless-regdb.","")

    printc (" " ,StdColor + "Below is the current Regulatory Domain for this system :","")
    print ""
    ps=subprocess.Popen("iw reg get" , shell=True, stdout=subprocess.PIPE)	
    CurrentReg=ps.stdout.read().replace("\n","\n   " + __builtin__.tabspace)
    CurrentReg=tabspacefull + CurrentReg
    print fcolor.SGreen + CurrentReg
    printc (" ", StdColor + "Most frequency country code [ " + fcolor.BYellow + "BR" + StdColor +" ]/ [" + fcolor.BYellow + "BO" + StdColor + "] / [" + fcolor.BYellow + "JP" + StdColor + "] ","")
    CountryCode=AskQuestion ("Enter A New Country Code ",fcolor.SWhite + "Default - " + fcolor.BYellow + "JP","U","JP","1")
    if CountryCode!="" and len(CountryCode)==2:
        ps=subprocess.Popen("iw reg set " + str(CountryCode) , shell=True, stdout=subprocess.PIPE)	
    else:
        printc ("!", fcolor.SRed + "You have entered an invalid Country Code, setting skipped","")
        print ""

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
                    printc (".",fcolor.SGreen + "Creating path [ " + fcolor.SRed + splitpath + fcolor.SGreen + " ] ...","")
                os.mkdir(splitpath, 0755)
                RtnResult=True
        printc (".",fcolor.SGreen + "Path [ " + fcolor.SRed + dirName + fcolor.SGreen + " ] created...","")
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

def GetInterfaceList(cmdMode):
    if cmdMode=="":
        cmdMode="ALL"
    proc  = Popen("ifconfig -a", shell=True, stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'))
    IFACE = "";IEEE = "";MODE = "";MACADDR="";IPADDR="";IPV6ADDR = "";BCAST="";MASK="";STATUS="";IFUP="";LANMODE="";GATEWAY="";IFaceCount=0
    __builtin__.IFaceList = []
    __builtin__.IEEEList = []
    __builtin__.ModeList = []
    __builtin__.MACList = []
    __builtin__.IPList = []
    __builtin__.IPv6List = []
    __builtin__.BCastList = []
    __builtin__.MaskList = []
    __builtin__.StatusList = []
    __builtin__.UpDownList = []
    __builtin__.ISerialList = []
    for line in proc.communicate()[0].split('\n'):
        if len(line) == 0: continue
	if ord(line[0]) != 32:
            printd ("Line : " + str(line))
            IFACE = line[:line.find(' ')]
            IFACE2=IFACE[:2].upper()
#            print "IFACE : " + str(IFACE)
#            print "IFACE2 : " + str(IFACE2)
#            printc ("x","","")

            if IFACE2!="ET" and IFACE2!="LO" and IFACE2!="VM" and IFACE2!="PP" and IFACE2!="AT" and IFACE2!="EN":
                ps=subprocess.Popen("iwconfig " + str(IFACE) + "| grep -i 'Mode:' | tr -s ' ' | egrep -o 'Mode:..................' | cut -d ' ' -f1 | cut -d ':' -f2" , shell=True, stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'))	
                MODEN=ps.stdout.read().replace("\n","")
                MODE=MODEN.upper()
                ps=subprocess.Popen("iwconfig " + str(IFACE) + "| grep -o 'IEEE..........................' | cut -d ' ' -f2" , shell=True, stdout=subprocess.PIPE)	
                IEEE=ps.stdout.read().replace("\n","").upper().replace("802.11","802.11 ")
                LANMODE="WLAN"
            else:
                MODE="NIL";MODEN="Nil";IEEE="802.3";LANMODE="LAN"
            if IFACE2=="LO":
                MODE="LO";MODEN="Loopback";IEEE="Nil";LANMODE="LO"
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
            if cmdMode=="ALL":
                IFaceCount=IFaceCount+1
                __builtin__.ModeList.append(str(MODEN))
                __builtin__.IFaceList.append(IFACE)
                __builtin__.IEEEList.append(IEEE)
                __builtin__.MACList.append(MACADDR)
                __builtin__.IPList.append(IPADDR)
                __builtin__.IPv6List.append(IPV6ADDR)
                __builtin__.BCastList.append(BCAST)
                __builtin__.MaskList.append(MASK)
                __builtin__.StatusList.append(STATUS)
                __builtin__.UpDownList.append(IFUP)
                __builtin__.ISerialList.append(str(IFaceCount))
            if MODE=="MANAGED":
                if cmdMode=="MAN":
                    IFaceCount=IFaceCount+1
                    __builtin__.ModeList.append(MODEN)
                    __builtin__.IFaceList.append(IFACE)
                    __builtin__.IEEEList.append(IEEE)
                    __builtin__.MACList.append(MACADDR)
                    __builtin__.IPList.append(IPADDR)
                    __builtin__.IPv6List.append(IPV6ADDR)
                    __builtin__.BCastList.append(BCAST)
                    __builtin__.MaskList.append(MASK)
                    __builtin__.StatusList.append(STATUS)
                    __builtin__.UpDownList.append(IFUP)
                    __builtin__.ISerialList.append(str(IFaceCount))
            if MODE=="MONITOR":
                if cmdMode=="MON":
                    IFaceCount=IFaceCount+1
                    __builtin__.ModeList.append(MODEN)
                    __builtin__.IFaceList.append(IFACE)
                    __builtin__.IEEEList.append(IEEE)
                    __builtin__.MACList.append(MACADDR)
                    __builtin__.IPList.append(IPADDR)
                    __builtin__.IPv6List.append(IPV6ADDR)
                    __builtin__.BCastList.append(BCAST)
                    __builtin__.MaskList.append(MASK)
                    __builtin__.StatusList.append(STATUS)
                    __builtin__.UpDownList.append(IFUP)
                    __builtin__.ISerialList.append(str(IFaceCount))
            if MODE=="MASTER":
                if cmdMode=="MAS":
                    IFaceCount=IFaceCount+1
                    __builtin__.ModeList.append(MODEN)
                    __builtin__.IFaceList.append(IFACE)
                    __builtin__.IEEEList.append(IEEE)
                    __builtin__.MACList.append(MACADDR)
                    __builtin__.IPList.append(IPADDR)
                    __builtin__.IPv6List.append(IPV6ADDR)
                    __builtin__.BCastList.append(BCAST)
                    __builtin__.MaskList.append(MASK)
                    __builtin__.StatusList.append(STATUS)
                    __builtin__.UpDownList.append(IFUP)
                    __builtin__.ISerialList.append(str(IFaceCount))
            if MODE=="AD-HOC":
                if cmdMode=="ADH":
                    IFaceCount=IFaceCount+1
                    __builtin__.ModeList.append(MODEN)
                    __builtin__.IFaceList.append(IFACE)
                    __builtin__.IEEEList.append(IEEE)
                    __builtin__.MACList.append(MACADDR)
                    __builtin__.IPList.append(IPADDR)
                    __builtin__.IPv6List.append(IPV6ADDR)
                    __builtin__.BCastList.append(BCAST)
                    __builtin__.MaskList.append(MASK)
                    __builtin__.StatusList.append(STATUS)
                    __builtin__.UpDownList.append(IFUP)
                    __builtin__.ISerialList.append(str(IFaceCount))
            if cmdMode=="IP" and BCAST!="":
                if IPV6ADDR!="" or IPADDR!="":
                    IFaceCount=IFaceCount+1
                    __builtin__.ModeList.append(MODEN)
                    __builtin__.IFaceList.append(IFACE)
                    __builtin__.IEEEList.append(IEEE)
                    __builtin__.MACList.append(MACADDR)
                    __builtin__.IPList.append(IPADDR)
                    __builtin__.IPv6List.append(IPV6ADDR)
                    __builtin__.BCastList.append(BCAST) 
                    __builtin__.MaskList.append(MASK)
                    __builtin__.StatusList.append(STATUS)
                    __builtin__.UpDownList.append(IFUP)
                    __builtin__.ISerialList.append(str(IFaceCount))
            if cmdMode=="CON" and IPADDR!="" and GATEWAY!="" and BCAST!="":
                IFaceCount=IFaceCount+1
                __builtin__.ModeList.append(MODEN)
                __builtin__.IFaceList.append(IFACE)
                __builtin__.IEEEList.append(IEEE)
                __builtin__.MACList.append(MACADDR)
                __builtin__.IPList.append(IPADDR)
                __builtin__.IPv6List.append(IPV6ADDR)
                __builtin__.BCastList.append(BCAST) 
                __builtin__.MaskList.append(MASK)
                __builtin__.StatusList.append(STATUS)
                __builtin__.UpDownList.append(IFUP)
                __builtin__.ISerialList.append(str(IFaceCount))

            if cmdMode=="WLAN" and LANMODE=="WLAN":
                IFaceCount=IFaceCount+1
                __builtin__.ModeList.append(MODEN)
                __builtin__.IFaceList.append(IFACE)
                __builtin__.IEEEList.append(IEEE)
                __builtin__.MACList.append(MACADDR)
                __builtin__.IPList.append(IPADDR)
                __builtin__.IPv6List.append(IPV6ADDR)
                __builtin__.BCastList.append(BCAST) 
                __builtin__.MaskList.append(MASK)
                __builtin__.StatusList.append(STATUS)
                __builtin__.UpDownList.append(IFUP)
                __builtin__.ISerialList.append(str(IFaceCount))

            if cmdMode=="LAN" and LANMODE=="LAN":
                IFaceCount=IFaceCount+1
                __builtin__.ModeList.append(MODEN)
                __builtin__.IFaceList.append(IFACE)
                __builtin__.IEEEList.append(IEEE)
                __builtin__.MACList.append(MACADDR)
                __builtin__.IPList.append(IPADDR)
                __builtin__.IPv6List.append(IPV6ADDR)
                __builtin__.BCastList.append(BCAST) 
                __builtin__.MaskList.append(MASK)
                __builtin__.StatusList.append(STATUS)
                __builtin__.UpDownList.append(IFUP)
                __builtin__.ISerialList.append(str(IFaceCount))

            if cmdMode=="LOOP" and LANMODE=="LO":
                IFaceCount=IFaceCount+1
                __builtin__.ModeList.append(MODEN)
                __builtin__.IFaceList.append(IFACE)
                __builtin__.IEEEList.append(IEEE)
                __builtin__.MACList.append(MACADDR)
                __builtin__.IPList.append(IPADDR)
                __builtin__.IPv6List.append(IPV6ADDR)
                __builtin__.BCastList.append(BCAST) 
                __builtin__.MaskList.append(MASK)
                __builtin__.StatusList.append(STATUS)
                __builtin__.UpDownList.append(IFUP)
                __builtin__.ISerialList.append(str(IFaceCount))
    return IFaceCount;


def Now():
    from datetime import datetime
    timefmt="%Y-%m-%d %H:%M:%S"
    TimeNow=time.strftime(timefmt)
    RtnStr=str(TimeNow)
    return RtnStr;

def ReportNow():
    RtnStr=fcolor.SCyan + "  Reported : " + Now() + "\n"
    return RtnStr;

def GetSec(timestr):
    timestr=str(timestr)
    l = timestr.split(':')
    return int(l[0]) * 3600 + int(l[1]) * 60 + int(l[2])

def GetMin(timestr):
    timestr=str(timestr)
    l = timestr.split(':')
    return int(l[0]) * 360 + int(l[1])

def ConvertDateFormat(strTime,dtFormat):
    from datetime import datetime
    timefmt="%Y-%m-%d %H:%M:%S"
    TimeNow=time.strftime(timefmt)
    strTime=str(strTime)

    DTStr=""
    if len(str(strTime))!=24:
        strTime=datetime.strptime(TimeNow, timefmt)
        return strTime;
    if str(strTime[3:4])!=" " or str(strTime[7:8])!=" " or str(strTime[10:11])!=" " or str(strTime[13:14])!=":" or str(strTime[16:17])!=":" or str(strTime[19:20])!=" " :
        print "<> : " + str(len(strTime))
        strTime=datetime.strptime(TimeNow, timefmt)
        return strTime;
    if strTime!="": 
        DTStr=str(datetime.strptime(strTime, dtFormat))
        DTStr=datetime.strptime(DTStr, timefmt)
    return str(DTStr)

def CalculateTime(StartTime,EndTime):
    from datetime import datetime
    timefmt="%Y-%m-%d %H:%M:%S"
    TimeNow=time.strftime(timefmt)
    StartTime=str(StartTime)
    EndTime=str(EndTime)
    if EndTime=="":
        EndTime=TimeNow
    if len(str(StartTime))!=19:
        StartTime=TimeNow
    if str(StartTime[4:5])!="-" or str(StartTime[7:8])!="-" or str(StartTime[10:11])!=" " or str(StartTime[13:14])!=":" or str(StartTime[16:17])!=":":
        StartTime=TimeNow

    if len(str(EndTime))!=19:
        EndTime=StartTime
    if str(EndTime[4:5])!="-" or str(EndTime[7:8])!="-" or str(EndTime[10:11])!=" " or str(EndTime[13:14])!=":" or str(EndTime[16:17])!=":":
        EndTime=StartTime
    StartTime=datetime.strptime(StartTime, timefmt)
    EndTime=datetime.strptime(EndTime, timefmt)
    TimeNow=datetime.strptime(TimeNow,timefmt)
    __builtin__.ElapsedTime = EndTime - StartTime
    __builtin__.TimeGap=TimeNow - EndTime
    __builtin__.TimeGapFull=__builtin__.TimeGap
    __builtin__.ElapsedTime=str(__builtin__.ElapsedTime)
    __builtin__.TimeGap=GetMin(__builtin__.TimeGap)
    return __builtin__.ElapsedTime;

def DisplayTimeStamp(cmdDisplayType,cmdTimeFormat):
    cmdDisplayType=cmdDisplayType.lower()
    if cmdTimeFormat=="":
        timefmt="%Y-%m-%d %H:%M:%S"
    else:
         timefmt=cmdTimeFormat
    if cmdDisplayType=="start":
        __builtin__.TimeStop=""
        __builtin__.DTimeStop=""
        __builtin__.DTimeStart=time.strftime(timefmt)
        printc ("  ",lblColor + "Started\t: " + txtColor + str(__builtin__.DTimeStart),"")
        __builtin__.TimeStart=datetime.datetime.now()
        return __builtin__.DTimeStart;
    if cmdDisplayType=="start-h":
        __builtin__.TimeStop=""
        __builtin__.DTimeStop=""
        __builtin__.DTimeStart=time.strftime(timefmt)
        __builtin__.TimeStart=datetime.datetime.now()
        return __builtin__.DTimeStart;
    if cmdDisplayType=="stop":
        __builtin__.DTimeStop=time.strftime(timefmt)
        printc ("  ",lblColor + "Stopped\t: " + txtColor + str(__builtin__.DTimeStop),"")
        __builtin__.TimeStop=datetime.datetime.now()
        return __builtin__.DTimeStop;
    if cmdDisplayType=="stop-h":
        __builtin__.DTimeStop=time.strftime(timefmt)
        __builtin__.TimeStop=datetime.datetime.now()
        return __builtin__.DTimeStop;
    if __builtin__.TimeStart!="":
        if cmdDisplayType=="summary" or cmdDisplayType=="summary-a":
            if __builtin__.TimeStop=="":
                __builtin__.TimeStop=datetime.datetime.now()
                __builtin__.DTimeStop=time.strftime(timefmt)
            ElapsedTime = __builtin__.TimeStop - __builtin__.TimeStart
	    ElapsedTime=str(ElapsedTime)
	    ElapsedTime=ElapsedTime[:-4]
            if cmdDisplayType=="summary-a":
                printc ("  ",lblColor + "Started\t: " + txtColor + str(__builtin__.DTimeStart),"")
                printc ("  ",lblColor + "Stopped\t: " + txtColor + str(__builtin__.DTimeStop),"")
	        printc ("  ",lblColor + "Time Spent\t: " + fcolor.BRed + str(ElapsedTime),"")
            if cmdDisplayType=="summary":
	        printc ("  ",lblColor + "Time Spent\t: " + fcolor.BRed + str(ElapsedTime),"")
        return ElapsedTime;

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

def RewriteCSV():
    FoundClient=""
    open(__builtin__.NewCaptured_CSV,"wb").write("" )
    if IsFileDirExist(__builtin__.Captured_CSV)=="F":
        DelFile (__builtin__.NewCaptured_CSV,1)
        DelFile (__builtin__.Client_CSV,1)
        DelFile (__builtin__.SSID_CSV,1)

        with open(__builtin__.Captured_CSV,"r") as f:
            for line in f:
                line=line.replace("\n","").replace("\00","")
                open(__builtin__.NewCaptured_CSV,"a+b").write(line + "\n")
                if line.find("Station MAC, First time seen, Last time seen")!=-1:
                   FoundClient="1"
                if FoundClient=="" and line.find("BSSID, First time seen, Last time seen, channel")==-1:
                    if len(line)>20:
                        open(__builtin__.SSID_CSV,"a+b").write(line + "\n")
                if FoundClient=="1" and line.find("Station MAC, First time seen, Last time seen")==-1:
                    if len(line)>20:
                        open(__builtin__.Client_CSV,"a+b").write(line + "\n")
    open(__builtin__.NewCaptured_Kismet,"wb").write("" )
    if IsFileDirExist(__builtin__.Captured_Kismet)=="F":
        with open(__builtin__.Captured_Kismet,"r") as f:
            for line in f:
                line=line.replace("\n","")
                line=line.replace("\00","")
                open(__builtin__.NewCaptured_Kismet,"a+b").write(line + "\n")

def DisplayClientList():
    x=0
    if __builtin__.NETWORK_VIEW=="2" or __builtin__.NETWORK_VIEW=="3":
        DisplayClientCount=0
        ToDisplayClient="1"
        DislpayNotShownClient=0
     
        SkipClient=""
        GetFilterDetail()
        InfoColor=fcolor.SGreen
        CenterText(fcolor.BWhite + fcolor.BGGreen, "S T A T I O N S      L I S T I N G")

        print fcolor.BWhite + "STATION            BSSID\t\tPWR  Range\tLast Seen             Time Gap  ESSID                           OUI"
        DrawLine("^",fcolor.CReset + fcolor.Black,"")

        while x < len(ListInfo_STATION):
            ToDisplayClient="1"
            if ToDisplayClient=="1" and __builtin__.NETWORK_PROBE_FILTER!="ALL":
                ToDisplayClient=""
                if __builtin__.NETWORK_PROBE_FILTER=="Yes":
                    if len(ListInfo_PROBE[x])>0:
                        ToDisplayClient="1"
                elif __builtin__.NETWORK_PROBE_FILTER=="No":
                    if len(ListInfo_PROBE[x])==0:
                        ToDisplayClient="1"
            if ToDisplayClient=="1" and __builtin__.NETWORK_ASSOCIATED_FILTER!="ALL":
                ToDisplayClient=""
                if __builtin__.NETWORK_ASSOCIATED_FILTER=="Yes":
                    if ListInfo_CBSSID[x].find("Not Associated")==-1:
                        ToDisplayClient="1"
                if __builtin__.NETWORK_ASSOCIATED_FILTER=="No":
                    if ListInfo_CBSSID[x].find("Not Associated")!=-1:
                        ToDisplayClient="1"
            if ToDisplayClient=="1" and __builtin__.NETWORK_UNASSOCIATED_FILTER!="ALL":
                ToDisplayClient=""
                if __builtin__.NETWORK_UNASSOCIATED_FILTER=="Yes":
                    if ListInfo_CBSSID[x].find("Not Associated")!=-1:
                        ToDisplayClient="1"
                if __builtin__.NETWORK_UNASSOCIATED_FILTER=="No":
                    if ListInfo_CBSSID[x].find("Not Associated")==-1:
                        ToDisplayClient="1"
            if  ToDisplayClient=="1" and __builtin__.NETWORK_CSIGNAL_FILTER!="ALL":
                ToDisplayClient=""    
                if ListInfo_CQualityRange[x].find(__builtin__.NETWORK_CSIGNAL_FILTER)!=-1:
                    ToDisplayClient="1"
            if __builtin__.HIDE_INACTIVE_STN=="No":                
                InfoColor=fcolor.SGreen
            else:
                InfoColor=fcolor.SWhite
            MACCOLOR=InfoColor
            SELFMAC=""
            if ListInfo_STATION[x]==__builtin__.SELECTED_MANIFACE_MAC or ListInfo_STATION[x]==__builtin__.SELECTED_MON_MAC:
                MACCOLOR=fcolor.BRed
                SELFMAC=fcolor.BWhite + " [ " + fcolor.BRed + "Your Interface MAC" + fcolor.BWhite + " ]"
            CBSSID=ListInfo_CBSSID[x]
            CBSSID=str(CBSSID).replace("Not Associated","Not Associated")
            if ToDisplayClient=="1":
                if int(__builtin__.ListInfo_CTimeGap[x]) > int(__builtin__.REMOVE_AFTER_MIN):
                    if __builtin__.HIDE_INACTIVE_STN!="Yes":
                        DisplayClientCount=DisplayClientCount+1
                        ToDisplayClient=""
                        print fcolor.SBlack + str(ListInfo_STATION[x]) + "  " + str(CBSSID) + "\t" + str(ListInfo_CBestQuality[x]).ljust(5) + RemoveColor(str(ListInfo_CQualityRange[x])) + "\t" + str(ListInfo_CLastSeen[x]).ljust(22) + str(ListInfo_CTimeGapFull[x]).ljust(10) + "" + str(ListInfo_CESSID[x]).ljust(32) + str(ListInfo_COUI[x])+ RemoveColor(str(SELFMAC))
                        if ListInfo_PROBE[x]!="":
                            print fcolor.SBlack + "    Probe : " + str(ListInfo_PROBE[x])
                    else:
                        DislpayNotShownClient=DislpayNotShownClient+1
                        ToDisplayClient=""
            if ToDisplayClient=="1":
                DisplayClientCount=DisplayClientCount+1
                print InfoColor + MACCOLOR + str(ListInfo_STATION[x]) + InfoColor + "  " + str(CBSSID) + "\t" + str(ListInfo_CBestQuality[x]).ljust(5) + str(ListInfo_CQualityRange[x]) + InfoColor + "\t" + str(ListInfo_CLastSeen[x]).ljust(22) + str(ListInfo_CTimeGapFull[x]).ljust(10) + "" + fcolor.SPink + str(ListInfo_CESSID[x]).ljust(32) + InfoColor + str(ListInfo_COUI[x])+ str(SELFMAC)
                if ListInfo_PROBE[x]!="":
                    print fcolor.SWhite + "    Probe : " + fcolor.BBlue + str(ListInfo_PROBE[x])
            x = x + 1
        DrawLine("_",fcolor.CReset + fcolor.Black,"")
        print "" + fcolor.SYellow
        if DisplayClientFilter!="":
            print fcolor.BGreen + "Filter       : " + str(DisplayClientFilter)
        LblColor=fcolor.SYellow
        SummaryColor=fcolor.BGreen
        print LblColor + "Client Total : " + SummaryColor + str(len(ListInfo_STATION)).ljust(17) + LblColor + "Updated      : " + SummaryColor + str(__builtin__.ListInfo_CExist).ljust(17) + LblColor + "Added : " + SummaryColor + str(__builtin__.ListInfo_CAdd).ljust(21) + LblColor + "Listed : " + SummaryColor + str(DisplayClientCount).ljust(21) + LblColor + "Not Shown : " + SummaryColor + str(DislpayNotShownClient) 
        print LblColor + "Connected    : " + SummaryColor + str(__builtin__.ListInfo_AssociatedCount).ljust(17) + LblColor + "Unassociated : " + SummaryColor + str(__builtin__.ListInfo_UnassociatedCount).ljust(17) + LblColor + "Probe : " + SummaryColor + str(__builtin__.ListInfo_ProbeCount) 
        DrawLine("_",fcolor.CReset + fcolor.Black,"")

def GetFilterDetail():
    __builtin__.DisplayNetworkFilter= ""
    __builtin__.DisplayClientFilter=""
    __builtin__.DisplayUnassocFilter=""
    __builtin__.DisplayAllFilter=""
    if __builtin__.NETWORK_FILTER!="ALL":
        __builtin__.DisplayNetworkFilter=__builtin__.DisplayNetworkFilter + fcolor.BCyan + "Encryption - " + fcolor.Pink + str(__builtin__.NETWORK_FILTER) + "\t"
    if __builtin__.NETWORK_SIGNAL_FILTER!="ALL":
        __builtin__.DisplayNetworkFilter=__builtin__.DisplayNetworkFilter + fcolor.BCyan + "Signal - " + fcolor.Pink + str(__builtin__.NETWORK_SIGNAL_FILTER) + "\t"
    if __builtin__.NETWORK_CHANNEL_FILTER!="ALL":
        __builtin__.DisplayNetworkFilter=__builtin__.DisplayNetworkFilter + fcolor.BCyan + "Channel - " + fcolor.Pink + str(__builtin__.NETWORK_CHANNEL_FILTER) + "\t"
    if __builtin__.NETWORK_WPS_FILTER!="ALL":
        __builtin__.DisplayNetworkFilter=__builtin__.DisplayNetworkFilter + fcolor.BCyan + "WPS - " + fcolor.Pink + str(__builtin__.NETWORK_WPS_FILTER) + "\t"
    if __builtin__.NETWORK_CLIENT_FILTER!="ALL":
        __builtin__.DisplayNetworkFilter=__builtin__.DisplayNetworkFilter + fcolor.BCyan + "Client - " + fcolor.Pink + str(__builtin__.NETWORK_CLIENT_FILTER) + "\t"
    if __builtin__.NETWORK_PROBE_FILTER!="ALL":
        __builtin__.DisplayClientFilter=__builtin__.DisplayClientFilter + fcolor.BCyan + "Probe - " + fcolor.Pink + str(__builtin__.NETWORK_PROBE_FILTER) + "\t"
    if __builtin__.NETWORK_ASSOCIATED_FILTER!="ALL":
        __builtin__.DisplayClientFilter=__builtin__.DisplayClientFilter + fcolor.BCyan + "Associated - " + fcolor.Pink + str(__builtin__.NETWORK_ASSOCIATED_FILTER) + "\t"
    if __builtin__.NETWORK_UNASSOCIATED_FILTER!="ALL":
        __builtin__.DisplayClientFilter=__builtin__.DisplayClientFilter + fcolor.BCyan + "Unassociated - " + fcolor.Pink + str(__builtin__.NETWORK_UNASSOCIATED_FILTER) + "\t"
    if __builtin__.NETWORK_CSIGNAL_FILTER!="ALL":
        __builtin__.DisplayClientFilter=__builtin__.DisplayClientFilter + fcolor.BCyan + "Signal - " + fcolor.Pink + str(__builtin__.NETWORK_CSIGNAL_FILTER) + "\t"
    if __builtin__.NETWORK_UPROBE_FILTER!="ALL":
        __builtin__.DisplayUnassocFilter=__builtin__.DisplayUnassocFilter + fcolor.BCyan + "Probe - " + fcolor.Pink + str(__builtin__.NETWORK_UPROBE_FILTER) + "\t"
    if __builtin__.NETWORK_UCSIGNAL_FILTER!="ALL":
        __builtin__.DisplayUnassocFilter=__builtin__.DisplayUnassocFilter + fcolor.BCyan + "Signal - " + fcolor.Pink + str(__builtin__.NETWORK_UCSIGNAL_FILTER) + "\t"
    if __builtin__.DisplayNetworkFilter!="":
        __builtin__.DisplayAllFilter=__builtin__.DisplayAllFilter + str(tabspacefull) + fcolor.BWhite +         "Access Point Filter         : " + str(__builtin__.DisplayNetworkFilter) 
    if __builtin__.DisplayClientFilter!="":
        if __builtin__.DisplayAllFilter!="":
            __builtin__.DisplayAllFilter=__builtin__.DisplayAllFilter + "\n"
        __builtin__.DisplayAllFilter=__builtin__.DisplayAllFilter + str(tabspacefull) + fcolor.BWhite +         "Station Filter              : " + str(__builtin__.DisplayClientFilter) 
    if __builtin__.DisplayUnassocFilter!="":
        if __builtin__.DisplayAllFilter!="":
            __builtin__.DisplayAllFilter=__builtin__.DisplayAllFilter + "\n"
        __builtin__.DisplayAllFilter=__builtin__.DisplayAllFilter + str(tabspacefull) + fcolor.BWhite +         "Unassociated Station Filter : " + str(__builtin__.DisplayUnassocFilter) 
                    
def DisplayInfrastructure():
    WPACount=0;WEPCount=0;OPNCount=0;OTHCount=0;DisplayNotShownClient=0;DisplayNotShownSSID=0;DisplayClientCount=0;DisplayCount=0;DisplayEnriched=0;UNASSOC=0
    if __builtin__.NETWORK_VIEW=="1" or __builtin__.NETWORK_VIEW=="3" or __builtin__.NETWORK_VIEW=="4"  or __builtin__.NETWORK_VIEW=="5":
        x=0;Skip=""
        GetFilterDetail()
        if __builtin__.NETWORK_VIEW=="1" or __builtin__.NETWORK_VIEW=="3":
            CenterText(fcolor.BWhite + fcolor.BGGreen, "A C C E S S     P O I N T S    L I S T I N G")
        if __builtin__.NETWORK_VIEW=="4" or __builtin__.NETWORK_VIEW=="5":
            CenterText(fcolor.BWhite + fcolor.BGGreen, "A C C E S S     P O I N T S   /   W I R E L E S S      C L I E N T S    L I S T I N G")
        print fcolor.BWhite + "BSSID              STN  ENC   CIPHER      AUTH      CH   PWR    Range    CLK   WPS  Ver  LCK    ESSID                            OUI"
        DrawLine("^",fcolor.CReset + fcolor.Black,"")
        while x < len(ListInfo_BSSID):
            if ListInfo_Privacy[x].find("WPA")!=-1:
                CPrivacy=fcolor.SRed 
                WPACount += 1
            elif ListInfo_Privacy[x].find("WEP")!=-1:
                CPrivacy=fcolor.SYellow
                WEPCount += 1
            elif ListInfo_Privacy[x].find("OPN")!=-1:
                CPrivacy=fcolor.SGreen 
                OPNCount += 1
            else:
                CPrivacy=fcolor.SBlack
                OTHCount += 1
            ToDisplay=""
            if __builtin__.NETWORK_FILTER=="ALL":
                if __builtin__.NETWORK_SIGNAL_FILTER=="ALL":
                    ToDisplay="1"
                if ListInfo_QualityRange[x].find(__builtin__.NETWORK_SIGNAL_FILTER)!=-1:
                    ToDisplay="1"

            if ListInfo_Privacy[x].find(__builtin__.NETWORK_FILTER)!=-1:
                if __builtin__.NETWORK_SIGNAL_FILTER=="ALL":
                    ToDisplay="1"
                if ListInfo_QualityRange[x].find(__builtin__.NETWORK_SIGNAL_FILTER)!=-1:
                    ToDisplay="1"
            if ToDisplay=="1" and __builtin__.NETWORK_CHANNEL_FILTER!="ALL":
                ToDisplay=""
                if ListInfo_Channel[x]==__builtin__.NETWORK_CHANNEL_FILTER:
                    ToDisplay="1"
            if ToDisplay=="1" and __builtin__.NETWORK_WPS_FILTER!="ALL":
                ToDisplay==""
                if __builtin__.NETWORK_WPS_FILTER=="Yes":
                    if ListInfo_WPS[x]=="Yes":
                        ToDisplay="1"
                    else:
                        ToDisplay=""
                if __builtin__.NETWORK_WPS_FILTER=="No":
                    if ListInfo_WPS[x]=="-":
                        ToDisplay="1"
                    else:
                        ToDisplay=""
            if ToDisplay=="1" and __builtin__.NETWORK_CLIENT_FILTER!="ALL":
                ToDisplay==""
                if __builtin__.NETWORK_CLIENT_FILTER=="Yes":
                    if ListInfo_ConnectedClient[x]!="0":
                        ToDisplay="1"
                    else:
                        ToDisplay=""
                if __builtin__.NETWORK_CLIENT_FILTER=="No":
                    if ListInfo_ConnectedClient[x]=="0":
                        ToDisplay="1"
                    else:
                        ToDisplay=""
            EnrichData="  "
            if ListInfo_Enriched[x]=="Yes":
                EnrichData=fcolor.BIRed + " *"
                DisplayEnriched=DisplayEnriched+1
            if __builtin__.NETWORK_VIEW=="1" or __builtin__.NETWORK_VIEW=="3":
                if __builtin__.HIDE_INACTIVE_SSID=="No":
                    InfoColor=fcolor.SGreen
                else:
                    InfoColor=fcolor.SWhite
            else:
                if __builtin__.HIDE_INACTIVE_SSID=="No" or __builtin__.HIDE_INACTIVE_STN=="No":
                    InfoColor=fcolor.SGreen
                else:
                    InfoColor=fcolor.SWhite
            DisplayCount += 1
            DontShowClient=0
            BSSIDColor=InfoColor
            ClientColor=InfoColor
            ESSIDColor=fcolor.SPink
            OUIColor=fcolor.SCyan
            if int(ListInfo_ConnectedClient[x])>0:
                BSSIDColor=fcolor.BYellow
                ClientColor=fcolor.BGreen
                ESSIDColor=fcolor.BPink
                OUIColor=fcolor.BWhite
            DESSID=str(ListInfo_ESSID[x])
            if str(ListInfo_ESSID[x])=="":
                DESSID=fcolor.SBlack + "<<NO ESSID>>                     "
            else:
                DESSID=str(DESSID).ljust(33)
            if int(__builtin__.ListInfo_SSIDTimeGap[x]) <= int(__builtin__.REMOVE_AFTER_MIN):
                Cipher=ListInfo_Cipher[x]
                if Cipher=="CCMP WRAP TKIP":
                    __builtin__.ListInfo_Cipher[x]="C/T/WRAP"
                print  BSSIDColor + str(ListInfo_BSSID[x]).ljust(19) + ClientColor + str(ListInfo_ConnectedClient[x]).ljust(5) + InfoColor + str(CPrivacy) + str(ListInfo_Privacy[x]).ljust(6) + InfoColor + str(Cipher).ljust(12) + str(ListInfo_Auth[x]).ljust(10) + str(ListInfo_Channel[x]).ljust(5) + str(ListInfo_BestQuality[x]).ljust(7) + str(ListInfo_QualityRange[x]) + InfoColor + "\t " + str(ListInfo_Cloaked[x]).ljust(6) + str(ListInfo_WPS[x]).ljust(5)  + str(ListInfo_WPSVer[x]).ljust(5) + str(ListInfo_WPSLock[x]).ljust(5) + str(EnrichData) + ESSIDColor + str(DESSID) + OUIColor + str(ListInfo_BSSID_OUI[x]) 
            else:
                if __builtin__.HIDE_INACTIVE_SSID=="Yes":
                    DontShowClient=1
                    DisplayNotShownSSID=DisplayNotShownSSID+1
                else:
                    if ListInfo_Enriched[x]=="Yes":
                        EnrichData=fcolor.SBlack + " *"
                    print  fcolor.BIGray + str(ListInfo_BSSID[x]).ljust(19) + str(ListInfo_ConnectedClient[x]).ljust(5) + RemoveColor(str(CPrivacy)) + RemoveColor(str(ListInfo_Privacy[x])).ljust(6) + str(ListInfo_Cipher[x]).ljust(12) + str(ListInfo_Auth[x]).ljust(10) + str(ListInfo_Channel[x]).ljust(5) + str(ListInfo_BestQuality[x]).ljust(7) + RemoveColor(str(ListInfo_QualityRange[x])) + "\t " + str(ListInfo_Cloaked[x]).ljust(6) + str(ListInfo_WPS[x]).ljust(5)  + str(ListInfo_WPSVer[x]).ljust(5) + str(ListInfo_WPSLock[x]).ljust(5) +  str(EnrichData) + str(DESSID) + str(ListInfo_BSSID_OUI[x])
                    print  fcolor.BIGray + "\t\t\tFirst Seen : " + fcolor.SBlack + ListInfo_FirstSeen[x].ljust(24) + fcolor.BIGray + "\tLast Seen : " + fcolor.SBlack + ListInfo_LastSeen[x] + fcolor.BIGray + "\t[ " + str(ListInfo_SSIDTimeGap[x]) + " min ago ]"
            if __builtin__.NETWORK_VIEW=="4" or __builtin__.NETWORK_VIEW=="5":
                if DontShowClient!=1:
                    cln=0
                    ClientCt=0
                    DisplayClientCount=0
                    ToDisplayClient="1"
                    while cln < len(ListInfo_STATION):
                        if ListInfo_CBSSID[cln].find("Not Associated")!=-1:
                            UNASSOC=1
                        if ListInfo_BSSID[x]==ListInfo_CBSSID[cln]:
                            ToDisplayClient="1"
                            if ToDisplayClient=="1" and __builtin__.NETWORK_PROBE_FILTER!="ALL":
                                ToDisplayClient=""
                                if __builtin__.NETWORK_PROBE_FILTER=="Yes":
                                    if len(ListInfo_PROBE[cln])>0:
                                        ToDisplayClient="1"
                                elif __builtin__.NETWORK_PROBE_FILTER=="No":
                                    if len(ListInfo_PROBE[cln])==0:
                                        ToDisplayClient="1"
                            if ToDisplayClient=="1" and __builtin__.NETWORK_ASSOCIATED_FILTER!="ALL":
                                ToDisplayClient=""
                                if __builtin__.NETWORK_ASSOCIATED_FILTER=="Yes":
                                    if ListInfo_CBSSID[cln].find("not associated")==-1:
                                        ToDisplayClient="1"
                                if __builtin__.NETWORK_ASSOCIATED_FILTER=="No":
                                    if ListInfo_CBSSID[cln].find("Not Associated")!=-1:
                                        ToDisplayClient="1"
                            if ToDisplayClient=="1" and __builtin__.NETWORK_UNASSOCIATED_FILTER!="ALL":
                                ToDisplayClient=""
                                if __builtin__.NETWORK_UNASSOCIATED_FILTER=="Yes":
                                    if ListInfo_CBSSID[cln].find("Not Associated")!=-1:
                                        ToDisplayClient="1"
                                if __builtin__.NETWORK_UNASSOCIATED_FILTER=="No":
                                    if ListInfo_CBSSID[cln].find("Not Associated")==-1:
                                        ToDisplayClient="1"
                            if  ToDisplayClient=="1" and __builtin__.NETWORK_CSIGNAL_FILTER!="ALL":
                                ToDisplayClient=""    
                                if ListInfo_CQualityRange[cln].find(__builtin__.NETWORK_CSIGNAL_FILTER)!=-1:
                                    ToDisplayClient="1"
                            if ToDisplayClient=="1":
                                MACCOLOR=fcolor.SGreen
                                SELFMAC=""
                                if ListInfo_STATION[cln]==__builtin__.SELECTED_MANIFACE_MAC or ListInfo_STATION[cln]==__builtin__.SELECTED_MON_MAC:
                                    MACCOLOR=fcolor.BRed
                                    SELFMAC=fcolor.BWhite + " [ " + fcolor.BRed + "Your Interface MAC" + fcolor.BWhite + " ]"
                                if int(__builtin__.ListInfo_CTimeGap[cln]) <= int(__builtin__.REMOVE_AFTER_MIN):
                                    DisplayClientCount=DisplayClientCount+1
                                    ClientCt=ClientCt+1
                                    print fcolor.SWhite + "   [" + fcolor.SGreen + str(ClientCt) + fcolor.SWhite + "]" + fcolor.BWhite + "\t  Client   :  - " + MACCOLOR + str(ListInfo_STATION[cln]).ljust(33) + str(ListInfo_CBestQuality[cln]).ljust(7) + str(ListInfo_CQualityRange[cln]) + fcolor.CDim + fcolor.SGreen + "\t " + str(ListInfo_CLastSeen[cln]) + fcolor.CDim + fcolor.Cyan + "\t" + str(ListInfo_COUI[cln]) + str(SELFMAC)
                                else:
                                    if __builtin__.HIDE_INACTIVE_STN!="Yes":
                                        DisplayClientCount=DisplayClientCount+1
                                        ClientCt=ClientCt+1
                                        print fcolor.SBlack + "   [" + str(ClientCt) + "]" + "\t  Client   :  - " + str(ListInfo_STATION[cln]).ljust(33) + str(ListInfo_CBestQuality[cln]).ljust(7) + RemoveColor(str(ListInfo_CQualityRange[cln])) + "\t " + str(ListInfo_CLastSeen[cln]) + "\t" + str(ListInfo_COUI[cln]) + str(SELFMAC)
                                if ListInfo_PROBE[cln]!="" and __builtin__.NETWORK_VIEW!="5":
                                        if int(__builtin__.ListInfo_CTimeGap[cln]) <= int(__builtin__.REMOVE_AFTER_MIN):
                                                print fcolor.SWhite + "          Probe    :  - " + fcolor.SBlue + str(ListInfo_PROBE[cln])
                                        else:
                                            if __builtin__.HIDE_INACTIVE_STN!="Yes":
                                                print fcolor.SBlack + "          Probe    :  - " + fcolor.SBlack + str(ListInfo_PROBE[cln])
                        cln = cln + 1
            else:
                DisplayNotShownSSID += 1
            x=x+1
        DisplayUnassociated=0
        if __builtin__.NETWORK_VIEW=="4" or __builtin__.NETWORK_VIEW=="5":
            if UNASSOC==1 and ToDisplayClient=="1":
                if __builtin__.NETWORK_UNASSOCIATED_FILTER=="Yes" or __builtin__.NETWORK_UNASSOCIATED_FILTER=="ALL": 
                    cln=0
                    print ""
                    CenterText(fcolor.BBlack + fcolor.BGIGreen,"< < << UNASSOCIATED STATIONS [Last seen within " + str(REMOVE_AFTER_MIN) + " mins]   >> > >    ")
                    print fcolor.SYellow
                    while cln < len(ListInfo_STATION):
                        if ListInfo_CBSSID[cln].find("Not Associated")!=-1:
                            ToDisplay="1"
                            if __builtin__.NETWORK_UPROBE_FILTER!="ALL":
                                ToDisplay=""

                                if __builtin__.NETWORK_UPROBE_FILTER=="Yes" and ListInfo_PROBE[cln]!="":
                                    ToDisplay="1"
                                if __builtin__.NETWORK_UPROBE_FILTER=="No" and ListInfo_PROBE[cln]=="":
                                    ToDisplay="1"
                            if ToDisplay=="1" and __builtin__.NETWORK_UCSIGNAL_FILTER!="ALL":
                                ToDisplay=""
                                SRange=RemoveColor(str(ListInfo_CQualityRange[cln]))
                                if __builtin__.NETWORK_UCSIGNAL_FILTER==str(SRange):
                                    ToDisplay="1"
                            if ToDisplay=="1":
                                if int(__builtin__.ListInfo_CTimeGap[cln]) <= int(__builtin__.REMOVE_AFTER_MIN):
                                    MACCOLOR=fcolor.SGreen
                                    SELFMAC=""
                                    if ListInfo_STATION[cln]==__builtin__.SELECTED_MANIFACE_MAC or ListInfo_STATION[cln]==__builtin__.SELECTED_MON_MAC:
                                        MACCOLOR=fcolor.BRed
                                        SELFMAC=fcolor.BWhite + " [ " + fcolor.BRed + "Your Interface MAC" + fcolor.BWhite + " ]"
                                    DisplayUnassociated += 1
                                    print MACCOLOR + str(ListInfo_STATION[cln]).ljust(24) + fcolor.SGreen + str(ListInfo_CBestQuality[cln]).ljust(7) + str(ListInfo_CQualityRange[cln]) + fcolor.SGreen + "\t " + str(ListInfo_CFirstSeen[cln]) + "\t" + str(ListInfo_CLastSeen[cln]) + "   " + str(ListInfo_CTimeGapFull[cln]) + "\t" + str(ListInfo_COUI[cln]) + SELFMAC
                                    if ListInfo_PROBE[cln]!="" and __builtin__.NETWORK_VIEW=="4":
                                        print fcolor.SWhite + "Probe  : " + fcolor.BBlue + str(ListInfo_PROBE[cln])
                                else:
                                    DisplayNotShownClient=DisplayNotShownClient+1
                            else:
                                DisplayNotShownClient=DisplayNotShownClient+1
                        cln=cln+1 
                if DisplayUnassociated==0:
                    if __builtin__.DisplayUnassocFilter!="":
                        print fcolor.BWhite + "No matched unassociated station found !!"
                    else:
                        print fcolor.BRed + "No unassociated station found !!"
                if __builtin__.DisplayUnassocFilter!="":
                    print ""
                    print fcolor.BGreen + "Filter       : " + str(__builtin__.DisplayUnassocFilter)
            DrawLine("_",fcolor.CReset + fcolor.Black,"")
        if __builtin__.NETWORK_VIEW=="4" or __builtin__.NETWORK_VIEW=="5":
            CenterText(fcolor.BGBlue + fcolor.BWhite,"< < <<  SUMMARY  LISTING  >> > >      ")
            print fcolor.SYellow
        LblColor=fcolor.SYellow
        SummaryColor=fcolor.BGreen
        if __builtin__.NETWORK_VIEW=="1" or __builtin__.NETWORK_VIEW=="3":
             DrawLine("_",fcolor.CReset + fcolor.Black,"")
             print ""
        if __builtin__.DisplayNetworkFilter!="":
            print fcolor.BGreen + "Filter       : " + str(__builtin__.DisplayNetworkFilter)
        DTotalSSID=SummaryColor + str(len(ListInfo_BSSID)) + LblColor + " (" + SummaryColor + str(__builtin__.ListInfo_WPSCount) + " WPS" + LblColor + ")"
        DTotalSSID=str(DTotalSSID).ljust(53)
        DUpdated=SummaryColor + str(__builtin__.ListInfo_Exist) + LblColor + " (" + SummaryColor + str(__builtin__.ListInfo_WPSExist) + " WPS" + LblColor + ")"
        DUpdated=str(DUpdated).ljust(53)
        DAdded=SummaryColor + str(__builtin__.ListInfo_Add) + LblColor + " (" + SummaryColor + str(__builtin__.ListInfo_WPSAdd) + " WPS" + LblColor + ")"
        DAdded=str(DAdded).ljust(53)
        print LblColor + "SSID Total   : " + str(DTotalSSID) + "Updated      : " + str(DUpdated) + "Added : " + str(DAdded) + "Listed : " + SummaryColor + str(DisplayCount).ljust(11) + LblColor + "Not Shown : " + SummaryColor + str(DisplayNotShownSSID).ljust(11) + LblColor + "Enriched : " + SummaryColor + str(DisplayEnriched)
        print LblColor + "WPA/WPA2     : " + SummaryColor + str(WPACount).ljust(17) + LblColor + "WEP          : " + SummaryColor + str(WEPCount).ljust(17) + LblColor + "Open  : " + SummaryColor + str(OPNCount).ljust(17) + LblColor + "Others : " + SummaryColor + str(OTHCount)
        if __builtin__.NETWORK_VIEW=="4" or __builtin__.NETWORK_VIEW=="5":
            if __builtin__.DisplayClientFilter!="":
                print fcolor.BGreen + "Filter       : " + str(__builtin__.DisplayClientFilter)
            print LblColor + "Station Total: " + SummaryColor + str(len(ListInfo_STATION)).ljust(17) + LblColor + "Updated      : " + SummaryColor + str(__builtin__.ListInfo_CExist).ljust(17) + LblColor + "Added : " + SummaryColor + str(__builtin__.ListInfo_CAdd).ljust(17) + LblColor + "Listed : " + SummaryColor + str(DisplayClientCount).ljust(11) + LblColor + "Not Shown : " +  SummaryColor + str(DisplayNotShownClient)
            print LblColor + "Connected    : " + SummaryColor + str(__builtin__.ListInfo_AssociatedCount).ljust(17) + LblColor + "Unassociated : " + SummaryColor + str(__builtin__.ListInfo_UnassociatedCount).ljust(17) + LblColor + "Probe : " + SummaryColor + str(__builtin__.ListInfo_ProbeCount).ljust(17) + LblColor + "Matched: " + SummaryColor + str(DisplayUnassociated)  
        print ""
                 
def DisplayPanel():
    os.system('clear')
    os.system('clear')
    ShowBanner()
    ShowSYWorks()
    print fcolor.BWhite + "  - Version " + appver + " (Updated - " + appupdated + ")"
    DrawLine("_",fcolor.CReset + fcolor.Black,"");print ""
    return
    DisText=fcolor.SGreen + "Hide Inactive SSID\t : " + fcolor.BRed + str(__builtin__.HIDE_INACTIVE_SSID)
    DisText2=fcolor.SGreen + "Hide Inactive after\t : " + fcolor.BRed + str(__builtin__.REMOVE_AFTER_MIN) + " minutes"
    if __builtin__.NETWORK_VIEW=="1":
        print fcolor.SGreen + "Network View Type\t : " + fcolor.BRed + "(1) Access Point Only".ljust(60) + str(DisText)
    if __builtin__.NETWORK_VIEW=="2":
        print fcolor.SGreen + "Network View Type\t : " + fcolor.BRed + "(2) Client Only".ljust(60) + str(DisText)
    if __builtin__.NETWORK_VIEW=="3":
        print fcolor.SGreen + "Network View Type\t : " + fcolor.BRed + "(3) Access Point / Client".ljust(60) + str(DisText)
    if __builtin__.NETWORK_VIEW=="4":
        print fcolor.SGreen + "Network View Type\t : " + fcolor.BRed + "(4) Advanced (Access Point / Client)".ljust(60) + str(DisText)
    if __builtin__.NETWORK_VIEW=="5":
        print fcolor.SGreen + "Network View Type\t : " + fcolor.BRed + "(5) Advanced (Access Point / Client) - Without Probe Display".ljust(60) + str(DisText)
    print fcolor.SGreen + "Monitored Items  \t : " + fcolor.BRed + str(int(len(__builtin__.MonitoringMACList)) + int(len(__builtin__.MonitoringNameList))).ljust(60) + str(DisText2)
    print fcolor.SGreen + "Beep If Alert    \t : " + fcolor.BRed + str(__builtin__.ALERTSOUND).ljust(60) + ""
    MONINTOR_IFACE=fcolor.BRed + str(__builtin__.SELECTED_MON) + fcolor.SGreen + " [MAC : " + fcolor.BRed + str(__builtin__.SELECTED_MON_MAC) + fcolor.SGreen + "]"
    MONINTOR_IFACE=str(MONINTOR_IFACE) + "\t\t\t       "
    SELECTED_IFACE=fcolor.BRed + str(__builtin__.SELECTED_MANIFACE) + fcolor.SGreen + " [MAC : " + fcolor.BRed + str(__builtin__.SELECTED_MANIFACE_MAC) + fcolor.SGreen + "]"
    print fcolor.SGreen + "Monitor Interface\t : " +  str(MONINTOR_IFACE) + fcolor.SGreen + "Managed Interface\t : " +  str(SELECTED_IFACE)
    DrawLine("_",fcolor.CReset + fcolor.Black,""); print ""

def FindMACIndex(MACAddr,ListToFind):
    MACIndex=""
    MACLoc=str(ListToFind).find(str(MACAddr))
    if MACLoc!=-1:
        MACIndex=int(MACLoc) -2
        MACIndex=MACIndex/21
    return MACIndex

def RewriteIWList():
    if IsFileDirExist(__builtin__.TMP_IWList_DUMP)=="F":
        open(__builtin__.IWList_DUMP,"w").write("")
        with open(__builtin__.TMP_IWList_DUMP,"r") as f:
            for line in f:
                line=line.replace("      Cell ","\n      Cell ").replace("\n\n","\n").replace("\00","").lstrip().rstrip()
                open(__builtin__.IWList_DUMP,"a+b").write(line + "\n")

def EnrichSSID():
    RewriteIWList()
    if IsFileDirExist(__builtin__.TMP_IWList_DUMP)=="F":
        open(__builtin__.TMP_IWList_DUMP,"a+b").write("Cell XX - Address: XX:XX:XX:XX:XX:XX")
        BSSID="";ESSI="";Freq="";Channel="";Quality="";Signal="";PairwiseCipher="";GroupCipher="";AuthSuite="";WPAVer="";EncKey="";WMode="";BitRate="";
        with open(__builtin__.TMP_IWList_DUMP,"r") as f:
            FoundStage="0"
            for line in f:
                line=line.replace("\n","").replace("\00","").lstrip().rstrip()
                if len(line)>1:
                    if str(line).find("Cell ")!=-1 and str(line).find("Address:")!=-1:
                        if FoundStage=="0":
                            FoundStage="1"
                            FLoc=str(line).find("Address:")
                            BSSID=str(line)[FLoc:].replace("Address:","").lstrip().rstrip()
                        else:
                            if BitRate!="" and BitRate[-3:]==" | ":
                                BitRate=BitRate[:-3]
                            if str(ListInfo_BSSID).find(str(BSSID))!=-1:
                                y=FindMACIndex(BSSID,ListInfo_BSSID)
                                __builtin__.ListInfo_Enriched[y]="Yes"
                                if Freq!="":
                                    __builtin__.ListInfo_Freq[y]=str(Freq)
                                if ESSID!="" and IsAscii(ESSID)==True and str(ESSID).find("\\x")==-1:
                                    if __builtin__.ListInfo_ESSID[y]!=str(ESSID):
                                        __builtin__.ListInfo_ESSID[y]=str(ESSID)
                                if Channel!="":
                                    __builtin__.ListInfo_Channel[y]=str(Channel)
                                if Quality!="":
                                    __builtin__.ListInfo_Quality[y]=str(Quality)
                                if Signal!="":
                                    __builtin__.ListInfo_Signal[y]=str(Signal)
                                    __builtin__.ListInfo_BestQuality[y]=str(Signal)
                                if BitRate!="":
                                    __builtin__.ListInfo_BitRate[y]=str(BitRate)
                                if LastBeacon!="":
                                    __builtin__.ListInfo_LastBeacon[y]=str(LastBeacon)
                                if PairwiseCipher!="":
                                    __builtin__.ListInfo_PairwiseCipher[y]=str(PairwiseCipher)
                                if GroupCipher!="":
                                    __builtin__.ListInfo_GroupCipher[y]=str(GroupCipher)
                                if AuthSuite!="":
                                    __builtin__.ListInfo_AuthSuite[y]=str(AuthSuite)
                                    if __builtin__.ListInfo_Auth[y]=="-" and len(AuthSuite)<5:
                                        __builtin__.ListInfo_Auth[y]=str(AuthSuite)
                                if WMode!="":
                                    __builtin__.ListInfo_Mode[y]=str(WMode)
                                if WPAVer!="":
                                    __builtin__.ListInfo_WPAVer[y]=str(WPAVer)
                                if EncKey!="":
                                    __builtin__.ListInfo_EncKey[y]=str(EncKey)
                                if WPAVer!="":
                                    if __builtin__.ListInfo_Privacy[y]=="" or __builtin__.ListInfo_Privacy[y]=="None":
                                       if str(WPAVer).find("WPA2")!=-1:
                                           __builtin__.ListInfo_Privacy[y]="WPA2"
                                       elif str(WPAVer).find("WPA ")!=-1:
                                           __builtin__.ListInfo_Privacy[y]="WPA"
                                if PairwiseCipher!="" and __builtin__.ListInfo_Cipher[y]=="-":
                                    __builtin__.ListInfo_Cipher[y]=PairwiseCipher
                            BSSID="";ESSID="";Freq="";Channel="";Quality="";Signal="";PairwiseCipher="";GroupCipher="";AuthSuite="";WPAVer="";EncKey="";WMode="";BitRate="";
                            FoundStage="1"
                            FLoc=str(line).find("Address:")
                            BSSID=str(line)[FLoc:].replace("Address:","").lstrip().rstrip()
                    if str(line).find("Frequency:")!=-1 and str(line).find("GHz")!=-1:
                        FLoc=str(line).find("Frequency:")
                        FLoc2=str(line).find("GHz")
                        Freq=str(line)[FLoc:-FLoc2].replace("Frequency:","").lstrip().rstrip()
                    if str(line).find("Channel ")!=-1 and str(line).find(")")!=-1:
                        line=line.replace("(","").replace(")","")
                        FLoc=str(line).find("Channel ")
                        Channel=str(line)[FLoc:].replace("Channel","").lstrip().rstrip()
                    if str(line).find("ESSID:\x22")!=-1 and str(line).find("ESSID:\x22\x22")==-1:
                        line=line.replace("ESSID:\x22","")
                        ESSID=str(line)[:-1]
                    if str(line).find("Quality=")!=-1 and str(line).find(" ")!=-1:
                        FLoc=str(line).find("Quality=")
                        FLoc2=str(line).find(" ")
                        FLoc2=len(line)-int(FLoc2)
                        Quality=str(line)[FLoc:-FLoc2].replace("Quality=","").lstrip().rstrip()
                    if str(line).find("Signal level=")!=-1:
                        FLoc=str(line).find("Signal level=")
                        Signal=str(line)[FLoc:].replace("Signal level=","").replace("dBm","").lstrip().rstrip()
                    if str(line).find("Mb/s")!=-1:
                        line=line.replace(";", " |").replace("Bit Rates:","")
                        BitRate=BitRate + str(line).lstrip().rstrip() + " | "
                    if str(line).find("Extra:")!=-1 or str(line).find("IE: ")!=-1:
                        if FoundStage=="1":
                            FoundStage="2"
                    if str(line).find("Last beacon: ")!=-1:
                        FLoc=str(line).find("Last beacon: ")
                        FLoc2=str(line).find("ago")
                        FLoc2=len(line)-int(FLoc2)
                        LastBeacon=str(line)[FLoc:-FLoc2].replace("Last beacon: ","").lstrip().rstrip()
                    if str(line).find("Pairwise Ciphers ")!=-1:
                        FLoc=str(line).find("Pairwise Ciphers ")
                        line=line[FLoc:]
                        FLoc=str(line).find(" : ")
                        if FLoc!=-1:
                            FLoc=FLoc+3
                            line=line[FLoc:]
                            PairwiseCipher=line.replace(" ","/")
                    if str(line).find("Group Cipher : ")!=-1:
                        FLoc=str(line).find("Group Cipher : ")
                        line=line[FLoc:]
                        FLoc=str(line).find(" : ")
                        if FLoc!=-1:
                            FLoc=FLoc+3
                            line=line[FLoc:]
                            GroupCipher=line.replace(" ","/")
                    if str(line).find("Authentication Suites")!=-1:
                        FLoc=str(line).find("Authentication Suites")
                        line=line[FLoc:]
                        FLoc=str(line).find(" : ")
                        if FLoc!=-1:
                            FLoc=FLoc+3
                            line=line[FLoc:]
                            AuthSuite=line
                    if str(line).find("WPA Version")!=-1:
                        FLoc=str(line).find("WPA Version")
                        line=line[FLoc:]
                        WPAVer=line
                    if str(line).find("WPA2 Version")!=-1:
                        FLoc=str(line).find("WPA2 Version")
                        line=line[FLoc:]
                        WPAVer=line
                    if str(line).find("Encryption key:")!=-1:
                        FLoc=str(line).find("Encryption key:")
                        line=line[FLoc:]
                        EncKey=line.replace("Encryption key:","")
                    if str(line).find("Mode:")!=-1:
                        FLoc=str(line).find("Mode:")
                        line=line[FLoc:]
                        WMode=line.replace("Mode:","")

def GetFrequency(sChannel):
    Freq=""
    if sChannel!="":
        if sChannel=='1':
            Freq = '2.412'
        if sChannel=='2':
            Freq = '2.417'
        if sChannel=='3':
            Freq = '2.422'
        if sChannel=='4':
            Freq = '2.427'
        if sChannel=='5':
            Freq = '2.432'
        if sChannel=='6':
            Freq = '2.437'
        if sChannel=='7':
            Freq = '2.442'
        if sChannel=='8':
            Freq = '2.447'
        if sChannel=='9':
            Freq = '2.452'
        if sChannel=='10':
            Freq = '2.457'
        if sChannel=='11':
            Freq = '2.462'
        if sChannel=='12':
            Freq = '2.467'
        if sChannel=='13':
            Freq = '2.472'
        if sChannel=='14':
            Freq = '2.484'
        if sChannel=='131':
            Freq = '3.6575'
        if sChannel=='132':
            Freq = '3.6625'
        if sChannel=='132':
            Freq = '3.66'
        if sChannel=='133':
            Freq = '3.6675'
        if sChannel=='133':
            Freq = '3.665'
        if sChannel=='134':
            Freq = '3.6725'
        if sChannel=='134':
            Freq = '3.67'
        if sChannel=='135':
            Freq = '3.6775'
        if sChannel=='136':
            Freq = '3.6825'
        if sChannel=='136':
            Freq = '3.68'
        if sChannel=='137':
            Freq = '3.6875'
        if sChannel=='137':
            Freq = '3.685'
        if sChannel=='138':
            Freq = '3.6895'
        if sChannel=='138':
            Freq = '3.69'
        if sChannel=='183':
            Freq = '4.915'
        if sChannel=='184':
            Freq = '4.92'
        if sChannel=='185':
            Freq = '4.925'
        if sChannel=='187':
            Freq = '4.935'
        if sChannel=='188':
            Freq = '4.94'
        if sChannel=='189':
            Freq = '4.945'
        if sChannel=='192':
            Freq = '4.96'
        if sChannel=='196':
            Freq = '4.98'
        if sChannel=='16':
            Freq = '5.08'
        if sChannel=='34':
            Freq = '5.17'
        if sChannel=='36':
            Freq = '5.18'
        if sChannel=='38':
            Freq = '5.19'
        if sChannel=='40':
            Freq = '5.20'
        if sChannel=='42':
            Freq = '5.21'
        if sChannel=='44':
            Freq = '5.22'
        if sChannel=='46':
            Freq = '5.23'
        if sChannel=='48':
            Freq = '5.24'
        if sChannel=='52':
            Freq = '5.26'
        if sChannel=='56':
            Freq = '5.28'
        if sChannel=='60':
            Freq = '5.30'
        if sChannel=='64':
            Freq = '5.32'
        if sChannel=='100':
            Freq = '5.50'
        if sChannel=='104':
            Freq = '5.52'
        if sChannel=='108':
            Freq = '5.54'
        if sChannel=='112':
            Freq = '5.56'
        if sChannel=='116':
            Freq = '5.58'
        if sChannel=='120':
            Freq = '5.60'
        if sChannel=='124':
            Freq = '5.62'
        if sChannel=='128':
            Freq = '5.64'
        if sChannel=='132':
            Freq = '5.66'
        if sChannel=='136':
            Freq = '5.68'
        if sChannel=='140':
            Freq = '5.70'
        if sChannel=='149':
            Freq = '5.745'
        if sChannel=='153':
            Freq = '5.765'
        if sChannel=='154':
            Freq = '5.770'
        if sChannel=='155':
            Freq = '5.775'
        if sChannel=='156':
            Freq = '5.780'
        if sChannel=='157':
            Freq = '5.785'
        if sChannel=='158':
            Freq = '5.790'
        if sChannel=='159':
            Freq = '5.795'
        if sChannel=='160':
            Freq = '5.80'
        if sChannel=='161':
            Freq = '5.805'
        if sChannel=='162':
            Freq = '5.810'
        if sChannel=='163':
            Freq = '5.815'
        if sChannel=='164':
            Freq = '5.820'
        if sChannel=='165':
            Freq = '5.825'
    return Freq;
               

def GetIWList(cmdMode,SELECTED_IFACE,RETRY):
    if RETRY=="":
        __builtin__.AP_BSSIDList=[]
        __builtin__.AP_FREQList=[]
        __builtin__.AP_QUALITYList=[]
        __builtin__.AP_SIGNALList=[]
        __builtin__.AP_ENCKEYList=[]
        __builtin__.AP_ESSIDList=[]
        __builtin__.AP_MODEList=[]
        __builtin__.AP_CHANNELList=[]
        __builtin__.AP_ENCTYPEList=[]
    POPULATE=0
    if len(__builtin__.AP_BSSIDList)>0:
        Result=AskQuestion(fcolor.SGreen + "An existing list with [ " + fcolor.BRed + str(len(__builtin__.AP_BSSIDList)) + fcolor.SGreen + " ] records were found, " + fcolor.BGreen + "populate existing ?","Y/n","U","Y","1")
        if Result=="Y":
            POPULATE=1
        else:
            __builtin__.AP_BSSIDList=[]
            __builtin__.AP_FREQList=[]
            __builtin__.AP_QUALITYList=[]
            __builtin__.AP_SIGNALList=[]
            __builtin__.AP_ENCKEYList=[]
            __builtin__.AP_ESSIDList=[]
            __builtin__.AP_MODEList=[]
            __builtin__.AP_CHANNELList=[]
            __builtin__.AP_ENCTYPEList=[]
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
    __builtin__.AP_BSSID=""
    __builtin__.AP_FREQ=""
    __builtin__.AP_QUALITY=""
    __builtin__.AP_SIGNAL=""
    __builtin__.AP_ENCKEY=""
    __builtin__.AP_ESSID=""
    __builtin__.AP_MODE=""
    __builtin__.AP_CHANNEL=""
    __builtin__.AP_ENCTYPE=""
    if POPULATE=="1":
        printc (".","Populating current list...","")
    for line in f:
        line=line.replace("\n","").lstrip().rstrip()

        if line.find("Cell ")!=-1:
            if __builtin__.AP_BSSID!="" and __builtin__.AP_MODE!="":
                if __builtin__.AP_ENCTYPE=="" and __builtin__.AP_ENCKEY=="ON":
                    __builtin__.AP_ENCTYPE="WEP"
                if __builtin__.AP_ENCTYPE=="" and __builtin__.AP_ENCKEY=="OFF":
                    __builtin__.AP_ENCTYPE="OPEN"
                if __builtin__.AP_ENCTYPE=="WPA2/WPA":
                    __builtin__.AP_ENCTYPE=="WPA/WPA2"
                ADD=""
                if cmdMode=="ALL-S" and __builtin__.AP_ESSID.find("\\x")==-1 and __builtin__.AP_ESSID!="":
                    ADD="1"
                if cmdMode=="ALL":
                    ADD="1"
                if cmdMode=="WPA-S" and __builtin__.AP_ENCTYPE.find("WPA")!=-1 and __builtin__.AP_ESSID.find("\\x")==-1 and __builtin__.AP_ESSID!="" and len(__builtin__.AP_ESSID)>2:
                    ADD="1"
                if cmdMode=="WPA" and __builtin__.AP_ENCTYPE.find("WPA")!=-1:
                    ADD="1"
                if cmdMode=="WEP-S" and __builtin__.AP_ENCTYPE.find("WEP")!=-1 and __builtin__.AP_ESSID.find("\\x")==-1 and __builtin__.AP_ESSID!="" and len(__builtin__.AP_ESSID)>2:
                    ADD="1"
                if cmdMode=="WEP" and __builtin__.AP_ENCTYPE.find("WEP")!=-1:
                    ADD="1"
                if cmdMode=="OPN-S" and __builtin__.AP_ENCTYPE.find("OPEN")!=-1 and __builtin__.AP_ESSID.find("\\x")==-1 and __builtin__.AP_ESSID!="" and len(__builtin__.AP_ESSID)>2:
                    ADD="1"
                if cmdMode=="OPN" and __builtin__.AP_ENCTYPE.find("OPEN")!=-1:
                    ADD="1"
                if str(POPULATE)=="1":
                    if any(__builtin__.AP_BSSID in s for s in __builtin__.AP_BSSIDList):
                        ADD="0"
                if ADD=="1":
                    if int(__builtin__.AP_QUALITY[:2])<=35:
                        SNLColor=fcolor.IRed
                        BSNLColor=fcolor.BIRed
                    if int(__builtin__.AP_QUALITY[:2])>35 and int(__builtin__.AP_QUALITY[:2])<55:
                        SNLColor=fcolor.IYellow
                        BSNLColor=fcolor.BIYellow
                    if int(__builtin__.AP_QUALITY[:2])>=55:
                        SNLColor=fcolor.IGreen
                        BSNLColor=fcolor.BIGreen
                    if __builtin__.AP_ENCTYPE.find("WPA")!=-1:
                        __builtin__.AP_ENCTYPE=fcolor.IPink + __builtin__.AP_ENCTYPE
                        __builtin__.AP_BSSID=SNLColor + __builtin__.AP_BSSID
                    if __builtin__.AP_ENCTYPE.find("OPEN")!=-1:
                        __builtin__.AP_ENCTYPE=fcolor.IBlue + __builtin__.AP_ENCTYPE
                        __builtin__.AP_BSSID=SNLColor + __builtin__.AP_BSSID
                    if __builtin__.AP_ENCTYPE.find("WEP")!=-1:
                        __builtin__.AP_ENCTYPE=fcolor.ICyan + __builtin__.AP_ENCTYPE
                        __builtin__.AP_BSSID=SNLColor + __builtin__.AP_BSSID
                    __builtin__.AP_BSSIDList.append(str(__builtin__.AP_BSSID))
                    __builtin__.AP_FREQList.append(str(__builtin__.AP_FREQ))
                    __builtin__.AP_QUALITYList.append(SNLColor + str(__builtin__.AP_QUALITY))
                    __builtin__.AP_SIGNALList.append(SNLColor + str(__builtin__.AP_SIGNAL))
                    __builtin__.AP_ENCKEYList.append(str(__builtin__.AP_ENCKEY))
                    __builtin__.AP_ESSIDList.append(str(BSNLColor + __builtin__.AP_ESSID))
                    __builtin__.AP_MODEList.append(str(__builtin__.AP_MODE))
                    __builtin__.AP_CHANNELList.append(str(__builtin__.AP_CHANNEL))
                    __builtin__.AP_ENCTYPEList.append(str(__builtin__.AP_ENCTYPE))
                __builtin__.AP_BSSID=""
                __builtin__.AP_FREQ=""
                __builtin__.AP_QUALITY=""
                __builtin__.AP_CHANNEL=""
                __builtin__.AP_SIGNAL=""
                __builtin__.AP_ENCKEY=""
                __builtin__.AP_ESSID=""
                __builtin__.AP_MODE=""
                __builtin__.AP_ENCTYPE=""
            POS=line.index('Address:')
            if POS>-1:
                POS=POS+9
                __builtin__.AP_BSSID=str(line[POS:])
        if __builtin__.AP_BSSID!="" and line.find("Channel:")!=-1:
            POS=line.index('Channel:')
            if POS>-1:
                POS=POS+8
                __builtin__.AP_CHANNEL=str(line[POS:])
        if __builtin__.AP_BSSID!="" and line.find("Frequency:")!=-1:
            POS=line.index('Frequency:')
            if POS>-1:
                POS=POS+10
                __builtin__.AP_FREQ=str(line[POS:])
                POS=__builtin__.AP_FREQ.index(' (')
                if POS>-1:
                    __builtin__.AP_FREQ=str(__builtin__.AP_FREQ[:POS])
        if __builtin__.AP_BSSID!="" and line.find("Quality=")!=-1:
            POS=line.index('Quality=')
            if POS>-1:
                POS=POS+8
                __builtin__.AP_QUALITY=str(line[POS:])
                POS=__builtin__.AP_QUALITY.index(' ')
                if POS>-1:
                    __builtin__.AP_QUALITY=str(__builtin__.AP_QUALITY[:POS])
        if __builtin__.AP_BSSID!="" and line.find("Signal level=")!=-1:
            POS=line.index('Signal level=')
            if POS>-1:
                POS=POS+13
                __builtin__.AP_SIGNAL=str(line[POS:])
        if __builtin__.AP_BSSID!="" and line.find("Encryption key:")!=-1:
            POS=line.index('Encryption key:')
            if POS>-1:
                POS=POS+15
                __builtin__.AP_ENCKEY=str(line[POS:]).upper()
        if __builtin__.AP_BSSID!="" and line.find("ESSID:")!=-1:
            POS=line.index('ESSID:')
            if POS>-1:
                POS=POS+6
                __builtin__.AP_ESSID=str(line[POS:])
        if __builtin__.AP_BSSID!="" and line.find("Mode:")!=-1:
            POS=line.index('Mode:')
            if POS>-1:
                POS=POS+5
                __builtin__.AP_MODE=str(line[POS:])
        if __builtin__.AP_BSSID!="" and line.find("WPA2 Version")!=-1:
            if __builtin__.AP_ENCTYPE!="": 
                if __builtin__.AP_ENCTYPE.find("WPA2")==-1:
                    __builtin__.AP_ENCTYPE=__builtin__.AP_ENCTYPE + "/WPA2"
            else:
                __builtin__.AP_ENCTYPE=__builtin__.AP_ENCTYPE + "WPA2"

        if __builtin__.AP_BSSID!="" and line.find("WPA Version")!=-1:
            if __builtin__.AP_ENCTYPE!="": 
                __builtin__.AP_ENCTYPE=__builtin__.AP_ENCTYPE + "/WPA"
            else:
                __builtin__.AP_ENCTYPE=__builtin__.AP_ENCTYPE + "WPA"
        __builtin__.AP_ENCTYPE=__builtin__.AP_ENCTYPE.replace("\n","")
        if __builtin__.AP_ENCTYPE=="WPA2/WPA":
            __builtin__.AP_ENCTYPE="WPA/WPA2"
    f.close()
    if __builtin__.AP_BSSID!="" and __builtin__.AP_MODE!="":
        if __builtin__.AP_ENCTYPE=="" and __builtin__.AP_ENCKEY=="ON":
            __builtin__.AP_ENCTYPE="WEP"
        if __builtin__.AP_ENCTYPE=="" and __builtin__.AP_ENCKEY=="OFF":
            __builtin__.AP_ENCTYPE="OPEN"
        if __builtin__.AP_ENCTYPE=="WPA2/WPA":
            __builtin__.AP_ENCTYPE=="WPA/WPA2"

        ADD=""
        if cmdMode=="ALL-S" and __builtin__.AP_ESSID.find("\\x")==-1 and __builtin__.AP_ESSID!="":
            ADD="1"
        if cmdMode=="ALL":
            ADD="1"
        if cmdMode=="WPA-S" and __builtin__.AP_ENCTYPE.find("WPA")!=-1 and __builtin__.AP_ESSID.find("\\x")==-1 and __builtin__.AP_ESSID!="" and len(__builtin__.AP_ESSID)>2:
            ADD="1"
        if cmdMode=="WPA" and __builtin__.AP_ENCTYPE.find("WPA")!=-1:
            ADD="1"
        if cmdMode=="WEP-S" and __builtin__.AP_ENCTYPE.find("WEP")!=-1 and __builtin__.AP_ESSID.find("\\x")==-1 and __builtin__.AP_ESSID!="" and len(__builtin__.AP_ESSID)>2:
            ADD="1"
        if cmdMode=="WEP" and __builtin__.AP_ENCTYPE.find("WEP")!=-1:
            ADD="1"
        if cmdMode=="OPN-S" and __builtin__.AP_ENCTYPE.find("OPEN")!=-1 and __builtin__.AP_ESSID.find("\\x")==-1 and __builtin__.AP_ESSID!="" and len(__builtin__.AP_ESSID)>2:
            ADD="1"
        if cmdMode=="OPN" and __builtin__.AP_ENCTYPE.find("OPEN")!=-1:
            ADD="1"
        if ADD=="1":
            if int(__builtin__.AP_QUALITY[:2])<=35:
                SNLColor=fcolor.IRed
                BSNLColor=fcolor.BIRed
            if int(__builtin__.AP_QUALITY[:2])>35 and int(__builtin__.AP_QUALITY[:2])<55:
                SNLColor=fcolor.IYellow
                BSNLColor=fcolor.BIYellow
            if int(__builtin__.AP_QUALITY[:2])>=55:
                SNLColor=fcolor.IGreen
                BSNLColor=fcolor.BIGreen
            if __builtin__.AP_ENCTYPE.find("WPA")!=-1:
                __builtin__.AP_ENCTYPE=fcolor.IPink + __builtin__.AP_ENCTYPE
                __builtin__.AP_BSSID=SNLColor + __builtin__.AP_BSSID
            if __builtin__.AP_ENCTYPE.find("OPEN")!=-1:
                __builtin__.AP_ENCTYPE=fcolor.IBlue + __builtin__.AP_ENCTYPE
                __builtin__.AP_BSSID=SNLColor + __builtin__.AP_BSSID
            if __builtin__.AP_ENCTYPE.find("WEP")!=-1:
                __builtin__.AP_ENCTYPE=fcolor.ICyan + __builtin__.AP_ENCTYPE
                __builtin__.AP_BSSID=SNLColor + __builtin__.AP_BSSID
            __builtin__.AP_BSSIDList.append(str(__builtin__.AP_BSSID))
            __builtin__.AP_FREQList.append(str(__builtin__.AP_FREQ))
            __builtin__.AP_QUALITYList.append(SNLColor + str(__builtin__.AP_QUALITY))
            __builtin__.AP_SIGNALList.append(SNLColor + str(__builtin__.AP_SIGNAL))
            __builtin__.AP_ENCKEYList.append(str(__builtin__.AP_ENCKEY))
            __builtin__.AP_ESSIDList.append(str(BSNLColor + __builtin__.AP_ESSID))
            __builtin__.AP_MODEList.append(str(__builtin__.AP_MODE))
            __builtin__.AP_CHANNELList.append(str(__builtin__.AP_CHANNEL))
            __builtin__.AP_ENCTYPEList.append(str(__builtin__.AP_ENCTYPE))
        __builtin__.AP_BSSID=""
        __builtin__.AP_FREQ=""
        __builtin__.AP_QUALITY=""
        __builtin__.AP_CHANNEL=""
        __builtin__.AP_SIGNAL=""
        __builtin__.AP_ENCKEY=""
        __builtin__.AP_ESSID=""
        __builtin__.AP_MODE=""
        __builtin__.AP_ENCTYPE=""

def RunAirodump():
    DelFile (tmpdir + "Collect-Dump-*",1)
    ps=subprocess.Popen("ifconfig " + str(__builtin__.SELECTED_MON) + " up > /dev/null 2>&1", shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'))
    ps.wait()
    cmdLine="xterm -geometry 100x20-0-0 -iconic -bg black -fg white -fn 5x8 -title 'WIDS - Monitoring SSID/Clients' -hold -e 'airodump-ng -w " + appdir + "/tmp/Collect-Dump " + __builtin__.SELECTED_MON + "'"
    ps=subprocess.Popen(cmdLine , shell=True, stdout=subprocess.PIPE, preexec_fn=os.setsid)	
    __builtin__.DumpProc=ps.pid

def RunWash():
    DelFile (tmpdir + "WPS*",1)
    ps=subprocess.Popen("ifconfig " + str(__builtin__.SELECTED_MON) + " up > /dev/null 2>&1", shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'))
    ps.wait()

    cmdLine="xterm -geometry 100x3-0-200 -iconic -bg black -fg white -fn 5x8 -title 'WIDS - Monitoring WPS' -hold -e 'wash -o " + __builtin__.WPS_DUMP + " -C -i " + __builtin__.SELECTED_MON + "'"
    ps=subprocess.Popen(cmdLine , shell=True, stdout=subprocess.PIPE, preexec_fn=os.setsid)	
    __builtin__.WashProc=ps.pid

def RunIWList():
    ps=subprocess.Popen("ifconfig " + str(__builtin__.SELECTED_MANIFACE) + " up > /dev/null 2>&1", shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'))
    ps.wait()
    cmdLine="ps -eo pid | grep '" + str(__builtin__.IWListProc) + "'"
    ps=subprocess.Popen(cmdLine , shell=True, stdout=subprocess.PIPE)	
    readout=str(ps.stdout.read().replace("\n",""))
    readout=str(readout).lstrip().rstrip()
    __builtin__.IWListProc=str(__builtin__.IWListProc)
    if str(readout)==str(__builtin__.IWListProc):
        os.killpg(int(__builtin__.IWListProc), signal.SIGTERM)

    if __builtin__.SELECTED_MANIFACE!="":
        cmdLine="xterm -geometry 100x3-0-200 -iconic -bg black -fg white -fn 5x8 -title 'WIDS - Monitoring AP' -hold -e 'iwlist " + __builtin__.SELECTED_MANIFACE + " scanning > " + str(__builtin__.TMP_IWList_DUMP) + "'"
        ps=subprocess.Popen(cmdLine , shell=True, stdout=subprocess.PIPE, preexec_fn=os.setsid)	
        __builtin__.IWListProc=ps.pid

def KillProc(ProcName):
    cmdLine="ps aux | grep xterm | grep -v '" + ProcName + "' | awk '{print $2}' | xargs kill -9 > /dev/null 2>&1"
    ps=subprocess.Popen(cmdLine , shell=True, stdout=subprocess.PIPE)	
    ps.wait()

def KillAllMonitor():
    Search="WIDS - Monitoring SSID/Clients"
    KillProc(Search)
    Search="WIDS - Monitoring WPS"
    KillProc(Search)
    Search="WIDS - Monitoring AP"
    KillProc(Search)

def GetMyMAC(IFACE):
    MACADDR=""
    ps=subprocess.Popen("ifconfig " + str(IFACE) + " | grep 'HWaddr' | tr -s ' ' | cut -d ' ' -f5" , shell=True, stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'))
    MACADDR=ps.stdout.read().replace("\n","").upper().replace("-",":")
    MACADDR=MACADDR[:17]
    return MACADDR
    

def Main():

    KillAllMonitor()
    MonCt = GetInterfaceList("MON")
    __builtin__.MONList=__builtin__.IFaceList
    Ct=GetInterfaceList("MAN")
    __builtin__.SELECTED_MANIFACE=""
    if Ct!=0:
        __builtin__.SELECTED_MANIFACE=__builtin__.IFaceList[0]

    GetAppName()
    CheckLinux()
    CheckPyVersion("2.6")
    os.system('clear')
    DisplayAppDetail()
    DisplayDescription()
    CheckAdmin()
    CheckAppLocation()
    CheckRequiredFiles()
    GetParameter("1")
    DelFile (tmpdir + "Collect-Dump-*",1)
    DelFile (tmpdir + "WPS*",1)
    DelFile (tmpdir + "Dumps*",1)

    RETRY=0
    __builtin__.PrintToFile=__builtin__.PRINTTOFILE
    if __builtin__.ReadPacketOnly=="1":
        if IsFileDirExist(captured_pcap)=="F" and IsFileDirExist(captured_csv)=="F":
            print "     Reading captured packet only..."
            ConvertPackets()
            AnalyseCaptured()
        else:
            printc ("!!!","[-ro] Function is use to read existing captured packet only...","")
            printc (" ","Make sure all neccessary captured files is present in order to use this function...","")
        exit()
    ps=subprocess.Popen("ps -A | grep 'airodump-ng'" , shell=True, stdout=subprocess.PIPE)	
    Process=ps.stdout.read()
    if Process!="":
        ps=subprocess.Popen("killall 'airodump-ng'" , shell=True, stdout=subprocess.PIPE)	
        Process=ps.stdout.read()
    ps=subprocess.Popen("ps -A | grep 'aireplay-ng'" , shell=True, stdout=subprocess.PIPE)	
    Process=ps.stdout.read()
    if Process!="":
        ps=subprocess.Popen("killall 'aireplay-ng'" , shell=True, stdout=subprocess.PIPE)	
        Process=ps.stdout.read()

    printc ("i","Monitor Selection","")
    MonCt = GetInterfaceList("MON")
    WLANCt = GetInterfaceList("WLAN")
    if MonCt==0 and WLANCt==0:
        printc (".",fcolor.SRed + "No wireless interface detected !","")
        __builtin__.ERRORFOUND=1
        exit_gracefully(1)

    if MonCt==0 and WLANCt!=0:
        if __builtin__.SELECTED_IFACE=="":
            __builtin__.SELECTED_IFACE=SelectInterfaceToUse()
        else:
            Rund="airmon-ng  check kill  > /dev/null 2>&1"
            result=os.system(Rund)
            Rund="airmon-ng start " + str(__builtin__.SELECTED_IFACE) + " > /dev/null 2>&1"
            result=os.system(Rund)
            __builtin__.SELECTED_MANIFACE=__builtin__.SELECTED_IFACE
            Rund="iwconfig " + __builtin__.SELECTED_IFACE + " > /dev/null 2>&1"
            result=os.system(Rund)
            if result==0:
                printc(">",fcolor.BIGray + "Interface Selection Bypassed....","")
            else:
                printc ("!!!", fcolor.BRed + "The interface specified [ " + fcolor.BWhite + __builtin__.SELECTED_IFACE + fcolor.BRed + " ] is not available." ,"")
                print ""
                __builtin__.SELECTED_IFACE=SelectInterfaceToUse()
        printc (" ", fcolor.SWhite + "Selected Interface ==> " + fcolor.BRed + str(__builtin__.SELECTED_IFACE),"")
        print ""
        ps=subprocess.Popen("ifconfig " + str(__builtin__.SELECTED_IFACE) + " up  > /dev/null 2>&1" , shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'))
    MonCt = GetInterfaceList("MON")
    if MonCt==0:
        printc (".",fcolor.SGreen + "Enabling monitoring for [ " + fcolor.BRed + __builtin__.SELECTED_IFACE + fcolor.SGreen + " ]...","")
        ps=subprocess.Popen("airmon-ng  check kill  > /dev/null 2>&1", shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'))
        ps.wait()
        ps=subprocess.Popen("airmon-ng start " + str(__builtin__.SELECTED_IFACE) + " > /dev/null 2>&1", shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'))
        ps.wait()
        __builtin__.SELECTED_MANIFACE=__builtin__.SELECTED_IFACE
        time.sleep (0.1)
        MonCt = GetInterfaceList("MON")
        if MonCt>=1:
            if __builtin__.SELECTED_MON=="":
                __builtin__.SELECTED_MON=SelectMonitorToUse()
            else:
                Rund="iwconfig " + __builtin__.SELECTED_MON + " > /dev/null 2>&1"
                result=os.system(Rund)
                if result==0:
                    printc(">",fcolor.BIGray + "Monitor Selection Bypassed....","")
                else:
                    printc ("!!!", fcolor.BRed + "The monitoring interface specified [ " + fcolor.BWhite + __builtin__.SELECTED_MON + fcolor.BRed + " ] is not available." ,"")
                    print ""
                    __builtin__.SELECTED_MON=SelectMonitorToUse()
    else:
        __builtin__.SELECTED_MON=SelectMonitorToUse()

    printc (" ", fcolor.SWhite + "Selected Monitoring Interface ==> " + fcolor.BRed + str(__builtin__.SELECTED_MON),"")
    print ""
    ps=subprocess.Popen("ifconfig " + str(__builtin__.SELECTED_MON) + " up  > /dev/null 2>&1" , shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'))

    LoadConfig()
    RunAirodump()
    RunWash()

    cmdLine="ps -eo pid,args | grep 'WIDS - Monitoring SSID/Clients' | grep 'xterm' | cut -c 1-6"
    ps=subprocess.Popen(cmdLine , shell=True, stdout=subprocess.PIPE)	
    __builtin__.DumpProcPID=ps.stdout.read()
    cmdLine="ps -eo pid,args | grep 'WIDS - Monitoring WPS' | grep 'xterm' | cut -c 1-6"    
    ps=subprocess.Popen(cmdLine , shell=True, stdout=subprocess.PIPE)	
    __builtin__.WashProcPID=ps.stdout.read()
    __builtin__.SELECTED_MON_MAC=GetMyMAC(__builtin__.SELECTED_MON)
    __builtin__.SELECTED_MANIFACE_MAC=GetMyMAC(__builtin__.SELECTED_MANIFACE)

    GetMonitoringMAC()

    DisplayPanel()    
    x=0
    while x<int(__builtin__.LoopCount):
        captured_pcap=tmpdir + "captured"
        retkey=WaitingCommands(__builtin__.TIMEOUT,1)
        DisplayPanel()
        RewriteCSV()
        ExtractDump()
        EnrichDump()
        EnrichSSID()
        ExtractWPS()
        ExtractClient()
        DisplayInfrastructure()
        DisplayClientList()
        CheckMonitoringMAC()
        CheckDiffBSSIDConnection()
        WriteDBFile()
        if retkey==None or retkey=="":
            x=x+1
            if int(__builtin__.LoopCount)-x<3 and int(__builtin__.LoopCount)!=x:
                printc (" ", "Remaining loop count : " + str(int(__builtin__.LoopCount)-x),"")
        else:
            print ""
            x=__builtin__.LoopCount + 1
    printc ("i", fcolor.BWhite + "Completed !! ","")
    exit_gracefully(0)

def WriteDBFile():
    WriteAccessPointDB()
    __builtin__.UPDATE_STN_COUNT=int(__builtin__.UPDATE_STN_COUNT)+1
    if int(__builtin__.UPDATE_STN_COUNT)>=int(__builtin__.TIMES_BEFORE_UPDATE_STN_DB):
        __builtin__.UPDATE_STN_COUNT=0
        WriteAllStationDB()

def WriteAccessPointDB():
    SkipWrite=0
    x=0
    AddData=0
    while x<len(ListInfo_BSSID):
        WriteFile=0
        if int(__builtin__.ListInfo_BSSIDTimes[x])>=int(__builtin__.TIMES_BEFORE_UPDATE_AP_DB):
            WriteFile=1
        if __builtin__.ListInfo_Enriched[x]=="Yes":
            WriteFile=1
        if WriteFile==1 and len(ListInfo_BSSID[x])==17 and __builtin__.SELECTED_MANIFACE_MAC!=ListInfo_BSSID[x] and __builtin__.SELECTED_MON_MAC!=ListInfo_BSSID[x]:
            SkipWrite=0
            with open(DBFile2,"r") as f:
                for line in f:
                    line=line.replace("\n","").replace("\r","")
                    sl=len(line)
                    if SkipWrite==0 and sl>34:
                        tmplist=[]
                        tmplist=str(line).split(";")
                        if len(tmplist)>10:
                            if tmplist[0]==str(ListInfo_BSSID[x]) and tmplist[5]==str(ListInfo_Channel[x]) and tmplist[6]==str(ListInfo_Privacy[x]) and tmplist[7]==str(ListInfo_Cipher[x]) and tmplist[8]==str(ListInfo_Auth[x]) and tmplist[10]==str(ListInfo_BitRate[x]) and tmplist[15]==str(ListInfo_WPS[x]) and tmplist[16]==str(ListInfo_WPSVer[x]) and tmplist[18]==str(ListInfo_ESSID[x]):
                                SkipWrite=1
                                break
                if SkipWrite==0 and RemoveUnwantMAC(ListInfo_BSSID[x])!="":
                    AddData=AddData+1
                    WriteData=str(ListInfo_BSSID[x]) + str(col)
                    WriteData=WriteData + str(ListInfo_Enriched[x]) + str(col)  
                    WriteData=WriteData + str(ListInfo_Mode[x]) + str(col) 
                    WriteData=WriteData + str(ListInfo_FirstSeen[x]) + str(col) 
                    WriteData=WriteData + str(ListInfo_LastSeen[x]) + str(col) 
                    WriteData=WriteData + str(ListInfo_Channel[x]) + str(col) 
                    WriteData=WriteData + str(ListInfo_Privacy[x]) + str(col) 
                    WriteData=WriteData + str(ListInfo_Cipher[x]) + str(col) 
                    WriteData=WriteData + str(ListInfo_Auth[x]) + str(col) 
                    WriteData=WriteData + str(ListInfo_MaxRate[x]) + str(col) 
                    WriteData=WriteData + str(ListInfo_BitRate[x]) + str(col) 
                    WriteData=WriteData + str(ListInfo_BestQuality[x]) + str(col) 
                    WriteData=WriteData + str(ListInfo_GPSBestLat[x]) + str(col) 
                    WriteData=WriteData + str(ListInfo_GPSBestLon[x]) + str(col) 
                    WriteData=WriteData + str(ListInfo_GPSBestAlt[x]) + str(col) 
                    WriteData=WriteData + str(ListInfo_WPS[x]) + str(col) 
                    WriteData=WriteData + str(ListInfo_WPSVer[x]) + str(col) 
                    WriteData=WriteData + str(Now()) + str(col)
                    WriteData=WriteData + str(ListInfo_ESSID[x]) + str(col) + "\n"
                    open(DBFile2,"a+b").write(WriteData)
        x += 1

def WriteAllStationDB():
    AddData=0
    AddData3=0
    AddData4=0
    x=0
    SkipWrite=0
    while x<len(ListInfo_STATION):
        ESSID=FindESSID(ListInfo_CBSSID[x])
        SkipWrite=0
        if len(ListInfo_STATION[x])==17 and __builtin__.SELECTED_MANIFACE_MAC!=ListInfo_STATION[x] and __builtin__.SELECTED_MON_MAC!=ListInfo_STATION[x]:
            if ListInfo_CBSSID[x].find("Not Associated")==-1:
                with open(DBFile5,"r") as f:
                    next(f)
                    for line in f:
                        line=line.replace("\n","").replace("\r","")
                        sl=len(line)
                        if SkipWrite==0 and sl>34:
                            tmplist=[]
                            tmplist=str(line).split(";")
                            if len(tmplist)>2:

                                if tmplist[0]==str(ListInfo_STATION[x]) and tmplist[1]==str(ListInfo_CBSSID[x]):
                                    if IsAscii(tmplist[2])==True and IsAscii(ListInfo_CESSID[x])==False:
                                        SkipWrite=1

                                    if tmplist[2]==str(ListInfo_CESSID[x]):
                                        SkipWrite=1
                                        break
                    if SkipWrite==0 and RemoveUnwantMAC(ListInfo_STATION[x])!="":
                        AddData=AddData+1
                        WriteData=str(ListInfo_STATION[x]) + str(col)
                        WriteData=WriteData + str(ListInfo_CBSSID[x]) + str(col) 
                        WriteData=WriteData + str(ESSID) + str(col) + "\n"
                        open(DBFile5,"a+b").write(WriteData)
                f.close()
            if ListInfo_STATION[x]!="":
                SkipWrite=0

                with open(DBFile3,"r") as f:
                    next(f)
                    for line in f:
                        line=line.replace("\n","").replace("\r","")
                        sl=len(line)
                        if SkipWrite==0 and sl>34:
                            tmplist=[]
                            tmplist=str(line).split(";")
                            if len(tmplist)>2:
                                if tmplist[0]==str(ListInfo_STATION[x]) and tmplist[1]==str(ListInfo_CBSSID[x]) :
                                    if tmplist[6]==str(ListInfo_CESSID[x]):
                                        SkipWrite=1
                                        break
                    if SkipWrite==0 and RemoveUnwantMAC(ListInfo_STATION[x])!="":
                        AddData3=AddData3+1
                        WriteData=str(ListInfo_STATION[x]) + str(col)
                        WriteData=WriteData + str(ListInfo_CBSSID[x]) + str(col)  
                        WriteData=WriteData + str(ListInfo_CFirstSeen[x]) + str(col) 
                        WriteData=WriteData + str(ListInfo_CLastSeen[x]) + str(col) 
                        WriteData=WriteData + str(ListInfo_CBestQuality[x]) + str(col) 
                        WriteData=WriteData + str(Now()) + str(col)
                        WriteData=WriteData + str(ESSID) + str(col) + "\n"
                        open(DBFile3,"a+b").write(WriteData)
                f.close()

            if ListInfo_PROBE[x]!="":
                tmpProbeList=[]
                tmpProbeList=str(ListInfo_PROBE[x]).split(" / ")
                y=0
                while y<len(tmpProbeList):
                    ProbeName=str(tmpProbeList[y])
                    if ProbeName!="":
                        SkipWrite=0
                        with open(DBFile4,"r") as f:
                            next(f)
                            for line in f:
                                line=line.replace("\n","").replace("\r","")
                                sl=len(line)
                                if SkipWrite==0 and sl>17:
                                    tmplist=[]
                                    tmplist=str(line).split(";")
                                    if len(tmplist)>2:
                                        if tmplist[0]==str(ListInfo_STATION[x]) and tmplist[2]==str(ProbeName) :
                                            SkipWrite=1
                                            break
                            if SkipWrite==0 and RemoveUnwantMAC(ListInfo_STATION[x])!="":
                                AddData4=AddData4+1
                                WriteData=str(ListInfo_STATION[x]) + str(col)
                                WriteData=WriteData + str(Now()) + str(col)
                                WriteData=WriteData + str(ProbeName) + str(col) + "\n"
                                open(DBFile4,"a+b").write(WriteData)
                        f.close()
                    y += 1
        x += 1
    return

def Check_OUI(MACAddr):
    Result=""
    OUI=""
    if len(MACAddr)==17:
        MACAddr=MACAddr.replace(":","")
        MACAddr9=MACAddr[:9]
        MACAddr6=MACAddr[:6]
        MACAddr12=MACAddr[:12]
        if IsFileDirExist(__builtin__.MACOUI)=="F":

            cmdLine="grep -w " + str(MACAddr12) + " " + str(__builtin__.MACOUI)
            ps=Popen(str(cmdLine), shell=True, stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'),preexec_fn=os.setsid)
            readout=str(ps.stdout.read().replace("\n","").replace(MACAddr6,"").lstrip().rstrip())
            if readout!="":
                OUI=str(readout)
                return OUI
            else:
                cmdLine="grep -w " + str(MACAddr9) + " " + str(__builtin__.MACOUI)
                ps=Popen(str(cmdLine), shell=True, stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'),preexec_fn=os.setsid)
                readout=str(ps.stdout.read().replace("\n","").replace(MACAddr6,"").lstrip().rstrip())
                if readout!="":
                    OUI=str(readout)
                    return OUI
                else:
                    cmdLine="grep -w " + str(MACAddr6) + " " + str(__builtin__.MACOUI)
                    ps=Popen(str(cmdLine), shell=True, stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'),preexec_fn=os.setsid)
                    readout=str(ps.stdout.read().replace("\n","").replace(MACAddr6,"").lstrip().rstrip())
                    if readout!="":
                        OUI=str(readout)
                        return OUI
                    else:
                        return "Unknown"
    return "Unknown"

def GetScreenWidth():
    curses.setupterm()
    TWidth=curses.tigetnum('cols')
    TWidth=TWidth
    return TWidth

def CheckMaxCount(StrVal,MaxRec):
    if int(StrVal)>int(MaxRec):
        MaxRec=int(StrVal)
    return MaxRec

def DisplayNetworkChart():
    x=0
    CH_MaxCt=0;EN_MaxCt=0;CL_MaxCt=0;SN_MaxCt=0
    CH0=0;DCH0=0;CH1=0;DCH1=0;CH2=0;DCH2=0;CH3=0;DCH3=0;CH4=0;DCH4=0;CH5=0;DCH5=0;CH6=0;DCH6=0;CH7=0;DCH7=0;CH8=0;DCH8=0;CH9=0;DCH9=0;CH10=0;DCH10=0;CH11=0;DCH11=0;CH12=0;DCH12=0;CH13=0;DCH13=0;CH14=0;DCH14=0;CH100=0;DCH100=0;WPA2=0;DWPA2=0;WPA=0;DWPA=0;WEP=0;DWEP=0;OPN=0;DOPN=0;UNK=0;DUNK=0
    WPA2_WPS=0;WPA_WPS=0;WEP_WPS=0;OPN_WPS=0;UNK_WPS=0
    SN_VG=0;DSN_VG=SN_VG;SN_GD=0;DSN_GD=SN_GD;SN_AV=0;DSN_AV=SN_AV;SN_PR=0;DSN_PR=SN_PR;SN_UK=0;DSN_UK=SN_UK
    WPA2_CLN=0;DWPA2_CLN=0;WPA_CLN=0;DWPA_CLN=0;WEP_CLN=0;DWEP_CLN=0;OPN_CLN=0;DOPN_CLN=0;UNK_CLN=0;DUNK_CLN=0
    WPA2_CLNCT=0;DWPA2_CLNCT=0;WPA_CLNCT=0;DWPA_CLNCT=0;WEP_CLNCT=0;DWEP_CLNCT=0;OPN_CLNCT=0;DOPN_CLNCT=0;UNK_CLNCT=0;DUNK_CLNCT=0
    while x < len(ListInfo_BSSID):
        CH=__builtin__.ListInfo_Channel[x]
        ENC=__builtin__.ListInfo_Privacy[x]
        WPS=__builtin__.ListInfo_WPS[x]
        CLN=int(__builtin__.ListInfo_ConnectedClient[x])
        SNL=RemoveColor(str(__builtin__.ListInfo_QualityRange[x]))
        if ENC=="WPA2":
          WPA2 += 1;EN_MaxCt=CheckMaxCount(WPA2,EN_MaxCt);DWPA2=WPA2
          if WPS=="Yes":
              WPA2_WPS += 1
          if CLN!=0:
              print CLN
              WPA2_CLN += 1;DWPA2_CLN=WPA2_CLN
              WPA2_CLNCT = WPA2_CLNCT + int(CLN);DWPA2_CLNCT=WPA2_CLNCT
              CL_MaxCt=CheckMaxCount(WPA2_CLN,CL_MaxCt)
        if ENC=="WPA":
          WPA += 1;EN_MaxCt=CheckMaxCount(WPA,EN_MaxCt);DWPA=WPA
          if WPS=="Yes":
              WPA_WPS += 1
          if CLN!=0:
              WPA_CLN += 1;DWPA_CLN=WPA_CLN
              WPA_CLNCT = WPA_CLNCT + int(CLN);DWPA_CLNCT=WPA_CLNCT
              CL_MaxCt=CheckMaxCount(WPA_CLN,CL_MaxCt)
        if ENC=="WEP":
          WEP += 1;EN_MaxCt=CheckMaxCount(WEP,EN_MaxCt);DWEP=WEP
          if WPS=="Yes":
              WEP_WPS += 1
          if CLN!=0:
              WEP_CLN += 1;DWEP_CLN=WEP_CLN
              WEP_CLNCT = WEP_CLNCT + int(CLN);DWEP_CLNCT=WEP_CLNCT
              CL_MaxCt=CheckMaxCount(WEP_CLN,CL_MaxCt)
        if ENC=="OPN":
          OPN += 1;EN_MaxCt=CheckMaxCount(OPN,EN_MaxCt);DOPN=OPN
          if WPS=="Yes":
              OPN_WPS += 1
          if CLN!=0:
              OPN_CLN += 1;DOPN_CLN=OPN_CLN
              OPN_CLNCT = OPN_CLNCT + int(CLN);DOPN_CLNCT=OPN_CLNCT
              CL_MaxCt=CheckMaxCount(OPN_CLN,CL_MaxCt)
        if ENC!="WPA2" and ENC!="WPA" and ENC!="WEP" and ENC!="OPN":
          UNK += 1;EN_MaxCt=CheckMaxCount(UNK,EN_MaxCt);DUNK=UNK
          if WPS=="Yes":
              UNK_WPS += 1
          if CLN!=0:
              UNK_CLN += 1;UNK_CLN=UNK_CLN
              UNK_CLNCT = UNK_CLNCT + int(CLN);DUNK_CLNCT=UNK_CLNCT
              CL_MaxCt=CheckMaxCount(UNK_CLN,CL_MaxCt)
        if CH=="1":
          CH1 += 1;CH_MaxCt=CheckMaxCount(CH1,CH_MaxCt);DCH1=CH1
        if CH=="2":
          CH2 += 1;CH_MaxCt=CheckMaxCount(CH2,CH_MaxCt);DCH2=CH2
        if CH=="3":
          CH3 += 1;CH_MaxCt=CheckMaxCount(CH3,CH_MaxCt);DCH3=CH3
        if CH=="4":
          CH4 += 1;CH_MaxCt=CheckMaxCount(CH4,CH_MaxCt);DCH4=CH4
        if CH=="5":
          CH5 += 1;CH_MaxCt=CheckMaxCount(CH5,CH_MaxCt);DCH5=CH5
        if CH=="6":
          CH6 += 1;CH_MaxCt=CheckMaxCount(CH6,CH_MaxCt);DCH6=CH6
        if CH=="7":
          CH7 += 1;CH_MaxCt=CheckMaxCount(CH7,CH_MaxCt);DCH7=CH7
        if CH=="8":
          CH8 += 1;CH_MaxCt=CheckMaxCount(CH8,CH_MaxCt);DCH8=CH8
        if CH=="9":
          CH9 += 1;CH_MaxCt=CheckMaxCount(CH9,CH_MaxCt);DCH9=CH9
        if CH=="10":
          CH10 += 1;CH_MaxCt=CheckMaxCount(CH10,CH_MaxCt);DCH10=CH10
        if CH=="11":
          CH11 += 1;CH_MaxCt=CheckMaxCount(CH11,CH_MaxCt);DCH11=CH11
        if CH=="12":
          CH12 += 1;CH_MaxCt=CheckMaxCount(CH12,CH_MaxCt);DCH12=CH12
        if CH=="13":
          CH13 += 1;CH_MaxCt=CheckMaxCount(CH13,CH_MaxCt);DCH13=CH13
        if CH=="14":
          CH14 += 1;CH_MaxCt=CheckMaxCount(CH14,CH_MaxCt);DCH14=CH14
        if int(CH)>14:
          CH100 += 1;CH_MaxCt=CheckMaxCount(CH100,CH_MaxCt);DCH100=CH100
        if int(CH)<1:
          CH0 += 1;CH_MaxCt=CheckMaxCount(CH0,CH_MaxCt);DCH0=CH0
        if SNL=="V.Good" or SNL=="V.Good":
            SN_VG += 1;DSN_VG=SN_VG;SN_MaxCt=CheckMaxCount(SN_VG,SN_MaxCt)
        if SNL=="Good" or SNL=="Good":
            SN_GD += 1;DSN_GD=SN_GD;SN_MaxCt=CheckMaxCount(SN_GD,SN_MaxCt)
        if SNL=="Average":
            SN_AV += 1;DSN_AV=SN_AV;SN_MaxCt=CheckMaxCount(SN_AV,SN_MaxCt)
        if SNL=="Poor":
            SN_PR += 1;DSN_PR=SN_PR;SN_MaxCt=CheckMaxCount(SN_PR,SN_MaxCt)
        if SNL=="Unknown":
            SN_UK += 1;DSN_UK=SN_UK;SN_MaxCt=CheckMaxCount(SN_UK,SN_MaxCt)
        x += 1

    os.system('clear')
    CenterText(fcolor.BWhite + fcolor.BGBlue, "Access Point Information Barchart View")
    print ""
    MaxWidth=GetScreenWidth()
    HalfWidth=MaxWidth/2
    CH_TIMES="";EN_TIMES=""; CL_TIMES=""; SN_TIMES=""

    CalCH=int(CH_MaxCt * 2) + 25
    if int(CalCH)<int(HalfWidth):
       CH_TIMES="x2"
    else:
        CalCH=int(CH_MaxCt) + 25
        if int(CalCH)<int(HalfWidth):
           CH_TIMES="x1"
        else:
            CalCH=int(CH_MaxCt / 2) + 25
            if int(CalCH)<int(HalfWidth):
               CH_TIMES="/2"
            else:
                CalCH=int(CH_MaxCt / 3) + 25
                if int(CalCH)<int(HalfWidth):
                   CH_TIMES="/3"
                else:
                    CalCH=int(CH_MaxCt / 4) + 25
                    if int(CalCH)<int(HalfWidth):
                       CH_TIMES="/4"
    CalEN=int(EN_MaxCt * 2) + 20
    if int(CalEN)<int(HalfWidth):
       EN_TIMES="x2"
    else:
        CalEN=int(EN_MaxCt) + 20
        if int(CalEN)<int(HalfWidth):
           EN_TIMES="x1"
        else:
            CalEN=int(EN_MaxCt / 2) + 20
            if int(CalEN)<int(HalfWidth):
               EN_TIMES="/2"
            else:
                CalEN=int(EN_MaxCt / 3) + 20
                if int(CalEN)<int(HalfWidth):
                   EN_TIMES="/3"
                else:
                    CalEN=int(EN_MaxCt / 4) + 20
                    if int(CalEN)<int(HalfWidth):
                       EN_TIMES="/4"
    CalCL=int(CL_MaxCt * 4) + 20
    if int(CalCL)<int(HalfWidth):
        CL_TIMES="x4"
    else:
        CalCL=int(CL_MaxCt * 3) + 20
        if int(CalCL)<int(HalfWidth):
            CL_TIMES="x3"
        else:
            CalCL=int(CL_MaxCt * 2) + 20
            if int(CalCL)<int(HalfWidth):
                CL_TIMES="x2"
            else:
                CalCL=int(CL_MaxCt) + 20
                if int(CalCL)<int(HalfWidth):
                    CL_TIMES="x1"
                else:
                    CalCL=int(CL_MaxCt / 2) + 20
                    if int(CalCL)<int(HalfWidth):
                        CL_TIMES="/2"
                    else:
                        CalCL=int(CL_MaxCt / 3) + 20
                        if int(CalCL)<int(HalfWidth):
                            CL_TIMES="/3"
                        else:
                            CalCL=int(CL_MaxCt / 4) + 20
                            if int(CalCL)<int(HalfWidth):
                                CL_TIMES="/4"
    CalSN=int(SN_MaxCt * 4) + 15
    if int(CalSN)<int(HalfWidth):
        SN_TIMES="x4"
    else:
        CalSN=int(SN_MaxCt * 3) + 15
        if int(CalSN)<int(HalfWidth):
            SN_TIMES="x3"
        else:
            CalSN=int(SN_MaxCt * 2) + 15
            if int(CalSN)<int(HalfWidth):
                SN_TIMES="x2"
            else:
                CalSN=int(SN_MaxCt) + 15
                if int(CalSN)<int(HalfWidth):
                    SN_TIMES="x1"
                else:
                    CalSN=int(SN_MaxCt / 2) + 15
                    if int(CalSN)<int(HalfWidth):
                        SN_TIMES="/2"
                    else:
                        CalSN=int(SN_MaxCt / 3) + 15
                        if int(CalSN)<int(HalfWidth):
                            SN_TIMES="/3"
                        else:
                            CalSN=int(SN_MaxCt / 4) + 15
                            if int(CalSN)<int(HalfWidth):
                                SN_TIMES="/4"
    CH_CHG=0
    if CH_TIMES=="x2":
        CH0=int(CH0) * 2;CH1=int(CH1) * 2; CH2=int(CH2) * 2; CH3=int(CH3) * 2; CH4=int(CH4) * 2;CH5=int(CH5) * 2; CH6=int(CH6) * 2; CH7=int(CH7) * 2;CH8=int(CH8) * 2;CH9=int(CH9) * 2;CH10=int(CH10) * 2;CH11=int(CH11) * 2;CH12=int(CH12) * 2;CH13=int(CH13) * 2;CH14=int(CH14) * 2;CH100=int(CH100) * 2
    if CH_TIMES=="/2" or CH_TIMES=="/3" or CH_TIMES=="/4":
        CH_CHG=1
        DivVal=int(CH_TIMES[-1:])
        CH0=int(CH0/DivVal);CH1=int(CH1/DivVal);CH2=int(CH2/DivVal);CH3=int(CH3/DivVal);CH4=int(CH4/DivVal);CH5=int(CH5/DivVal);CH6=int(CH6/DivVal);CH7=int(CH7/DivVal);CH8=int(CH8/DivVal);CH9=int(CH9/DivVal);CH10=int(CH10/DivVal);CH11=int(CH11/DivVal);CH12=int(CH12/DivVal);CH13=int(CH13/DivVal);CH14=int(CH14/DivVal);CH100=int(CH100/DivVal)
    if CH_CHG==1:
        if CH0==0 and DCH0!=0:
            CH0=1
        if CH1==1 and DCH1!=0:
            CH1=1
        if CH2==0 and DCH2!=0:
            CH2=1
        if CH3==0 and DCH3!=0:
            CH3=1
        if CH4==0 and DCH4!=0:
            CH4=1
        if CH5==0 and DCH5!=0:
            CH5=1
        if CH6==0 and DCH6!=0:
            CH6=1
        if CH7==0 and DCH7!=0:
            CH7=1
        if CH8==0 and DCH8!=0:
            CH8=1
        if CH9==0 and DCH9!=0:
            CH9=1
        if CH10==0 and DCH10!=0:
            CH10=1
        if CH11==0 and DCH11!=0:
            CH11=1
        if CH12==0 and DCH12!=0:
            CH12=1
        if CH13==0 and DCH13!=0:
            CH13=1
        if CH14==0 and DCH14!=0:
            CH14=1
        if CH100==0 and DCH100!=0:
            CH100=1
    EN_CHG=0
    if EN_TIMES=="x2":
        WPA2=int(WPA2*2);WPA=int(WPA*2);WEP=int(WEP*2);OPN=int(OPN*2);UNK=int(UNK*2)
    if EN_TIMES=="/2" or EN_TIMES=="/3" or EN_TIMES=="/4":
        EN_CHG=1
        DivVal=int(EN_TIMES[-1:]);WPA2=int(WPA2/DivVal);WPA=int(WPA/DivVal);WEP=int(WEP/DivVal);OPN=int(OPN/DivVal);UNK=int(UNK/DivVal)
    if EN_CHG==1:
        if WPA2==0 and DWPA2!=0:
            WPA2=1
        if WPA==0 and DWPA!=0:
            WPA=1
        if WEP==0 and DWEP!=0:
            WEP=1
        if OPN==0 and DOPN!=0:
            OPN=1
        if UNK==0 and DUNK!=0:
            UNK=1
    CL_CHG=0
    if CL_TIMES=="x2" or CL_TIMES=="x3" or CL_TIMES=="x4":
        DivVal=int(CL_TIMES[-1:])
        WPA2_CLN=int(WPA2_CLN*DivVal);WPA_CLN=int(WPA_CLN*DivVal);WEP_CLN=int(WEP_CLN*DivVal);OPN_CLN=int(OPN_CLN*DivVal);UNK_CLN=int(UNK_CLN*DivVal)
    if CL_TIMES=="/2" or CL_TIMES=="/3" or CL_TIMES=="/4":
        CL_CHG=1
        DivVal=int(CL_TIMES[-1:]);WPA2_CLN=int(WPA2_CLN/DivVal);WPA_CLN=int(WPA_CLN/DivVal);WEP_CLN=int(WEP_CLN/DivVal);OPN_CLN=int(OPN_CLN/DivVal);UNK_CLN=int(UNK_CLN/DivVal)
    if CL_CHG==1:
        if WPA2_CLN==0 and DWPA2_CLN!=0:
            WPA2_CLN=1
        if WPA_CLN==0 and DWPA_CLN!=0:
            WPA_CLN=1
        if WEP_CLN==0 and DWEP_CLN!=0:
            WEP_CLN=1
        if OPN_CLN==0 and DOPN_CLN!=0:
            OPN_CLN=1
        if UNK_CLN==0 and DUNK_CLN!=0:
            UNK_CLN=1
    SN_CHG=0
    if SN_TIMES=="x2" or SN_TIMES=="x3" or SN_TIMES=="x4":
        DivVal=int(SN_TIMES[-1:])
        SN_VG=int(SN_VG*DivVal);SN_GD=int(SN_GD*DivVal);SN_AV=int(SN_AV*DivVal);SN_PR=int(SN_PR*DivVal);SN_UK=int(SN_UK*DivVal)
    if SN_TIMES=="/2" or SN_TIMES=="/3" or SN_TIMES=="/4":
        SN_CHG=1
        DivVal=int(SN_TIMES[-1:]);SN_VG=int(SN_VG/DivVal);SN_GD=int(SN_GD/DivVal);SN_AV=int(SN_AV/DivVal);SN_PR=int(SN_PR/DivVal);SN_UK=int(SN_UK/DivVal)
    if SN_CHG==1:
        if SN_VG==0 and DSN_VG!=0:
            SN_VG=1
        if SN_GD==0 and DSN_GD!=0:
            SN_GD=1
        if SN_AV==0 and DSN_AV!=0:
            SN_AV=1
        if SN_PR==0 and DSN_PR!=0:
            SN_PR=1
        if SN_UK==0 and DSN_UK!=0:
            SN_UK=1
    Title1 = "Channel [ " + str(x) + " ] Access Points"; Title1 = Title1.ljust(80)
    Title2 = "Encryption (Access Point / Total WPS)";Title2 = Title2.ljust(50)
    MainTitle = fcolor.BGreen + str(Title1) + str(Title2)
    print MainTitle
    print ""
    DText=DisplayBar("Channel 01  : ", " ", CH1, DCH1, 80, fcolor.BWhite, fcolor.BGRed, fcolor.SWhite)
    DText2=DisplayBar("WPA2    : ", " ", WPA2, str(DWPA2) + " / " + str(WPA2_WPS) + " WPS", 50, fcolor.BWhite, fcolor.BGRed, fcolor.SWhite)
    print DText + DText2;print ""
    DText=DisplayBar("Channel 02  : ", " ", CH2, DCH2, 80, fcolor.BWhite, fcolor.BGGreen, fcolor.SWhite)
    DText2=DisplayBar("WPA     : ", " ", WPA, str(DWPA) + " / " + str(WPA_WPS) + " WPS", 50, fcolor.BWhite, fcolor.BGPink, fcolor.SWhite)
    print DText + DText2;print ""
    DText=DisplayBar("Channel 03  : ", " ", CH3, DCH3, 80, fcolor.BWhite, fcolor.BGYellow, fcolor.SWhite)
    DText2=DisplayBar("WEP     : ", " ", WEP, str(DWEP) + " / " + str(WEP_WPS) + " WPS", 50, fcolor.BWhite, fcolor.BGYellow, fcolor.SWhite)
    print DText + DText2;print ""
    DText=DisplayBar("Channel 04  : ", " ", CH4, DCH4, 80, fcolor.BWhite, fcolor.BGBlue, fcolor.SWhite)
    DText2=DisplayBar("OPN     : ", " ", OPN, str(DOPN) + " / " + str(OPN_WPS) + " WPS", 50, fcolor.BWhite, fcolor.BGGreen, fcolor.SWhite)
    print DText + DText2;print ""
    DText=DisplayBar("Channel 05  : ", " ", CH5, DCH5, 80, fcolor.BWhite, fcolor.BGPink, fcolor.SWhite)
    DText2=DisplayBar("Unknown : ", " ", UNK, str(DUNK) + " / " + str(UNK_WPS) + " WPS", 50, fcolor.BWhite, fcolor.BGWhite, fcolor.SWhite)
    print DText + DText2;print ""
    DText=DisplayBar("Channel 06  : ", " ", CH6, DCH6, 80, fcolor.BWhite, fcolor.BGCyan, fcolor.SWhite)
    print DText + fcolor.BGreen + "Connected Client (Access Point / Total Clients)";print ""
    DText=DisplayBar("Channel 07  : ", " ", CH7, DCH7, 80, fcolor.BWhite, fcolor.BGWhite, fcolor.SWhite)
    DText2=DisplayBar("WPA2    : ", " ", WPA2_CLN, str(DWPA2_CLN) + " / " + str(WPA2_CLNCT) + " Clients", 50, fcolor.BWhite, fcolor.BGBlue, fcolor.SWhite)
    print DText + DText2 ;print ""
    DText=DisplayBar("Channel 08  : ", " ", CH8, DCH8, 80, fcolor.BWhite, fcolor.BGIRed, fcolor.SWhite)
    DText2=DisplayBar("WPA     : ", " ", WPA_CLN, str(DWPA_CLN) + " / " + str(WPA_CLNCT) + " Clients", 50, fcolor.BWhite, fcolor.BGBlue, fcolor.SWhite)
    print DText + DText2 ;print ""
    DText=DisplayBar("Channel 09  : ", " ", CH9, DCH9, 80, fcolor.BWhite, fcolor.BGIGreen, fcolor.SWhite)
    DText2=DisplayBar("WEP     : ", " ", WEP_CLN, str(DWEP_CLN) + " / " + str(WEP_CLNCT) + " Clients", 50, fcolor.BWhite, fcolor.BGBlue, fcolor.SWhite)
    print DText + DText2 ;print ""
    DText=DisplayBar("Channel 10  : ", " ", CH10, DCH10, 80, fcolor.BWhite, fcolor.BGIYellow, fcolor.SWhite)
    DText2=DisplayBar("OPN     : ", " ", OPN_CLN, str(DOPN_CLN) + " / " + str(OPN_CLNCT) + " Clients", 50, fcolor.BWhite, fcolor.BGBlue, fcolor.SWhite)
    print DText + DText2 ;print ""
    DText=DisplayBar("Channel 11  : ", " ", CH11, DCH11, 80, fcolor.BWhite, fcolor.BGIBlue, fcolor.SWhite)
    DText2=DisplayBar("Unknown : ", " ", UNK_CLN, str(DUNK_CLN) + " / " + str(UNK_CLNCT) + " Clients", 50, fcolor.BWhite, fcolor.BGWhite, fcolor.SWhite)
    print DText + DText2 ;print ""
    DText=DisplayBar("Channel 12  : ", " ", CH12, DCH12, 80, fcolor.BWhite, fcolor.BGIPink, fcolor.SWhite)
    print DText + fcolor.BGreen + "Signal Range";print ""
    DText=DisplayBar("Channel 13  : ", " ", CH13, DCH13, 80, fcolor.BWhite, fcolor.BGICyan, fcolor.SWhite)
    DText2=DisplayBar("Good    : ", " ", SN_GD, str(DSN_GD) , 50, fcolor.BWhite, fcolor.BGGreen, fcolor.SWhite)
    print DText + DText2 ;print ""
    DText=DisplayBar("Channel 14  : ", " ", CH14, DCH14, 80, fcolor.BWhite, fcolor.BGGreen, fcolor.SWhite)
    DText2=DisplayBar("Average : ", " ", SN_AV, str(DSN_AV) , 50, fcolor.BWhite, fcolor.BGYellow, fcolor.SWhite)
    print DText + DText2 ;print ""
    DText=DisplayBar("Channel >14 : ", " ", CH100, DCH100, 80, fcolor.BWhite, fcolor.BGYellow, fcolor.SWhite)
    DText2=DisplayBar("Poor    : ", " ", SN_PR, str(DSN_PR) , 50, fcolor.BWhite, fcolor.BGRed, fcolor.SWhite)
    print DText + DText2 ;print ""
    DText=DisplayBar("Error Chn   : ", " ", CH0, DCH0, 80, fcolor.BWhite, fcolor.BGRed, fcolor.SWhite)
    DText2=DisplayBar("Unknown : ", " ", SN_UK, str(DSN_UK) , 50, fcolor.BWhite, fcolor.BGWhite, fcolor.SWhite)
    print DText + DText2 ;print ""

def DisplayBar(Label, Fill, BarTimes, BarCount, Justify, LblColor, BarColor, CountColor):
    DText="C1" + str(Label) + "C2" + Fill * int(BarTimes) + "C3" + " " + str(BarCount)
    DText=DText.ljust(Justify + 6)
    DText=DText.replace("C1",LblColor).replace("C2",BarColor).replace("C3", fcolor.CReset + CountColor)
    return DText

def ExtractWPS():
    LineList = []
    __builtin__.ListInfo_WPSExist = 0
    __builtin__.ListInfo_WPSAdd = 0
    __builtin__.ListInfo_WPSCount = 0
    if IsFileDirExist(__builtin__.WPS_DUMP)=="F":
        with open(__builtin__.WPS_DUMP,"r") as f:
            for line in f:
                line=line.replace("\n","")
                line=line.replace("\00","")
                if line.find("BSSID                  Channel       RSSI       WPS Version       WPS Locked")==-1 and line.find("--------------------")==-1 and len(line)>82:
                    st = list(line)
                    st[18]=";"
                    st[30]=";"
                    st[45]=";"
                    st[60]=";"
                    st[80]=";"
                    lp="".join(st)
                    LineList=lp.split(";")
                    BSSID=LineList[0].lstrip().rstrip()
                    if len(BSSID)==17:
                        __builtin__.ListInfo_WPSCount += 1
                        WPSVer=LineList[3].lstrip().rstrip()
                        WPSLock=LineList[4].lstrip().rstrip()
                    x=0
                    foundloc=0
                    Skip=""
                    while x < len(ListInfo_BSSID):
                        if BSSID==ListInfo_BSSID[x]:
                            Skip="1"
                            foundloc=x
                            x = len(ListInfo_BSSID)
                            if ListInfo_WPS[foundloc]!="Yes":
                                __builtin__.ListInfo_WPSAdd += 1
                            else:
                                __builtin__.ListInfo_WPSExist += 1
                        x=x+1
                    if Skip=="1":
                        ListInfo_WPS[foundloc] = "Yes"
                        ListInfo_WPSVer[foundloc] = WPSVer
                        ListInfo_WPSLock[foundloc] = WPSLock

def DisplayESSIDDetail(MACAddr,MACColor):
    Result=""
    ESSID=FindESSID(MACAddr)
    if ESSID=="":
        ESSID=fcolor.BIGray + "<<NO NAME>>"
    Result=ColorStd2 + "  BSSID    [ " + MACColor + str(MACAddr) + ColorStd2 + " ]'s Name is [ " + fcolor.BYellow + str(ESSID) + ColorStd2 + " ].\n"
    return Result

def DisplaySSIDDetail(MACAddr):
    i=0
    Result=""
    while i < len(ListInfo_BSSID):
        if str(ListInfo_BSSID[i])==str(MACAddr):
            PrivacyDetail=str(ListInfo_Privacy[i]) + " / " + str(ListInfo_Cipher[i]) + " / " + str(ListInfo_Auth[i])
            Result= ColorStd2  + "  Details  : " + fcolor.BGreen + str(PrivacyDetail).ljust(36) + ColorStd2 + "Channel : " + fcolor.BGreen + str(ListInfo_Channel[i]).ljust(9) + ColorStd2 + "Client : " + fcolor.BGreen + str(ListInfo_ConnectedClient[i]).ljust(9)  + ColorStd2 + "WPS : " + fcolor.BGreen + str(ListInfo_WPS[i]).ljust(5)  + "\n"
            return str(Result);
        i += 1
    return Result;

def GetSSIDSignal(MACAddr):
    i=0;Signal=""
    while i < len(ListInfo_BSSID):
        if str(ListInfo_BSSID[i])==str(MACAddr):
            Signal=ListInfo_BestQuality[i]
            Signal=Signal + " / " + ListInfo_QualityRange[i]
            return str(Signal);
        i += 1
    return Signal;

def GetClientSignal(MACAddr):
    i=0;Signal=""
    while i < len(ListInfo_STATION):
        if str(ListInfo_STATION[i])==str(MACAddr):
            Signal=ListInfo_CBestQuality[i]
            Signal=Signal + " / " + ListInfo_CQualityRange[i]
            return str(Signal);
        i += 1
    return Signal;

def RemoveAdditionalLF(strValue):
    ax=0
    while ax<3:
        strValue=str(strValue).replace("\n\n\n","\n\n")
        ax += 1
    return strValue

def DisplayOUIDetail(MACAddr,MACColor):
    Result=""
    OUI=Check_OUI(MACAddr)
    Result=ColorStd2 + "  MAC Addr [ " + MACColor + str(MACAddr) + ColorStd2 + " ]'s MAC OUI belongs to [ " + fcolor.SCyan + str(OUI) + ColorStd2 + " ].\n"
    return Result


def CheckDiffBSSIDConnection():
    x=0
    __builtin__.MSG_DiffBSSIDConnection=""
    __builtin__.MSG_NoAssocConnection=""
    __builtin__.MSG_APnClient=""
    ColorSeen=fcolor.SBlue
    CautiousCount=0
    while x < len(ListInfo_STATION):
        y=0
	if str(ListInfo_BSSID).find(str(ListInfo_STATION[x]))!=-1:
            y=int(str(ListInfo_BSSID).find(ListInfo_STATION[x]))-2
            y=y/21
            while y < len(ListInfo_BSSID):
                if ListInfo_STATION[x]==ListInfo_BSSID[y]:
                    ConnectedBSSID=""
                    if int(ListInfo_SSIDTimeGap[y])<=int(__builtin__.REMOVE_AFTER_MIN) and int(ListInfo_CTimeGap[x])<=int(__builtin__.REMOVE_AFTER_MIN):
                        CautiousCount += 1
                        OUITxt=DisplayOUIDetail(ListInfo_STATION[x],ColorDev)
                        __builtin__.MSG_APnClient = __builtin__.MSG_APnClient + ColorStd + "Device MAC [ " + ColorDev + str(ListInfo_STATION[x]) + ColorStd + " ] is found to be both an " + fcolor.BRed + "Access Point " + ColorStd + "&" + fcolor.BRed + " Wireless Client\n" 
                        __builtin__.MSG_APnClient = __builtin__.MSG_APnClient + str(DisplayESSIDDetail(ListInfo_STATION[x],ColorDev))
                        __builtin__.MSG_APnClient = __builtin__.MSG_APnClient + str(OUITxt) 
                        __builtin__.MSG_APnClient = __builtin__.MSG_APnClient + str(DisplaySSIDDetail(ListInfo_STATION[x])) 
                        __builtin__.MSG_APnClient = __builtin__.MSG_APnClient + ColorStd2 + "  Ac. Pt.  : First Seen on [ " + ColorSeen + str(ListInfo_FirstSeen[y]) + ColorStd2 + " ] and Last Seen on [ " + ColorSeen + str(ListInfo_LastSeen[y]) + ColorStd2 + " ] ( Last seen " + str(ListInfo_SSIDTimeGap[y]) + " mins ago)\n"
                        __builtin__.MSG_APnClient = __builtin__.MSG_APnClient + ColorStd2 + "  Station  : First Seen on [ " + ColorSeen + str(ListInfo_CFirstSeen[x]) + ColorStd2 + " ] and Last Seen on [ " + ColorSeen + str(ListInfo_CLastSeen[x]) + ColorStd2 + " ] ( Last seen " + str(ListInfo_CTimeGap[x]) + " mins ago)\n" 
                        if str(ListInfo_CBSSIDPrev[x]).find("Not Associated")==-1:
                            OUITxt2=DisplayOUIDetail(ListInfo_CBSSIDPrev[x],Color1st)
                            __builtin__.MSG_APnClient = __builtin__.MSG_APnClient + ColorStd + "  Signal   [ " + ColorDev + str(ListInfo_STATION[x]) + ColorStd + " ] = " + ColorDev + str(GetClientSignal(str(ListInfo_STATION[x]))) + ColorStd + " ==>  [ " + Color1st + str(ListInfo_CBSSIDPrev[x]) + ColorStd + " ] = " + Color1st  + str(GetSSIDSignal(str(ListInfo_CBSSIDPrev[x]))) + "\n"
                            __builtin__.MSG_APnClient = __builtin__.MSG_APnClient + str(DisplayESSIDDetail(ListInfo_CBSSIDPrev[x],Color1st))
                            __builtin__.MSG_APnClient = __builtin__.MSG_APnClient + OUITxt2
                            __builtin__.MSG_APnClient = __builtin__.MSG_APnClient + str(DisplaySSIDDetail(ListInfo_CBSSIDPrev[x]))
                            ConnectedBSSID=ListInfo_CBSSIDPrev[x]
                        if str(ListInfo_CBSSID[x]).find("Not Associated")==-1 and ListInfo_CBSSIDPrev[x]!=ListInfo_CBSSID[x]:
                            OUITxt2=DisplayOUIDetail(ListInfo_CBSSID[x],Color2nd)
                            __builtin__.MSG_APnClient = __builtin__.MSG_APnClient + ColorStd + "  Signal   [ " + ColorDev + str(ListInfo_STATION[x]) + ColorStd + " ] = " + ColorDev + str(GetClientSignal(str(ListInfo_STATION[x]))) + ColorStd + " ==>  [ " + Color1st + str(ListInfo_CBSSID[x]) + ColorStd + " ] = " + Color2nd  + str(GetSSIDSignal(str(ListInfo_CBSSID[x]))) + "\n"
                            __builtin__.MSG_APnClient = __builtin__.MSG_APnClient + str(DisplayESSIDDetail(ListInfo_CBSSID[x],Color2nd))
                            __builtin__.MSG_APnClient = __builtin__.MSG_APnClient + OUITxt2
                            __builtin__.MSG_APnClient = __builtin__.MSG_APnClient + str(DisplaySSIDDetail(ListInfo_CBSSID[x]))
                            ConnectedBSSID=ListInfo_CBSSID[x]
                            
                        __builtin__.MSG_APnClient = __builtin__.MSG_APnClient + str(ReportNow()) + "\n"
                        SkipWrite=0
                        if IsFileDirExist(DBFile1)=="F":
                            with open(DBFile1,"r") as f:
                                for line in f:
                                    line=line.replace("\n","")
                                    line=line.replace("\r","")
                                    if SkipWrite==0:
                                        sl=len(line.replace("\n",""))
                                        if sl>34:
                                            tmplist=[]

                                            tmplist=str(line).split(";")
                                            if len(tmplist)>4:
                                                if tmplist[0]==str(ListInfo_STATION[x]) and tmplist[1]==str(ConnectedBSSID) and tmplist[5]==str(ListInfo_ESSID[y]):
                                                    SkipWrite=1
                                                    break
                        if SkipWrite==0:
                            col=";"
                            WriteData=str(ListInfo_STATION[x]) + str(col) + str(ConnectedBSSID) + str(col) + str(ListInfo_FirstSeen[y]) + str(col) + str(ListInfo_CFirstSeen[x]) + str(col) + str(Now())  + str(col) + str(ListInfo_ESSID[y]) + str(col) + "\n"
                            open(DBFile1,"a+b").write(WriteData)
                    y=len(ListInfo_BSSID)
                y += 1
        if ListInfo_CBSSIDPrev[x]!=ListInfo_CBSSID[x]:
            if ListInfo_CBSSIDPrev[x].find("Not Associated")==-1:
               OUITxt=DisplayOUIDetail(ListInfo_STATION[x],ColorDev)
               OUITxt2=DisplayOUIDetail(ListInfo_CBSSIDPrev[x],Color1st)
               ESSIDTxt2=DisplayESSIDDetail(ListInfo_CBSSIDPrev[x],Color1st)
               OUITxt3=DisplayOUIDetail(ListInfo_CBSSID[x],Color2nd)
               ESSIDTxt3=DisplayESSIDDetail(ListInfo_CBSSID[x],Color2nd)
               CautiousCount += 1
               __builtin__.MSG_DiffBSSIDConnection = __builtin__.MSG_DiffBSSIDConnection + ColorStd + "Device MAC [ " + ColorDev + str(ListInfo_STATION[x]) + ColorStd + " ] initially associated with [ " + Color1st + str(ListInfo_CBSSIDPrev[x]) + ColorStd + " ] is now associated to [ " + Color2nd + str(ListInfo_CBSSID[x]) + ColorStd + " ].\n" 
               __builtin__.MSG_DiffBSSIDConnection = __builtin__.MSG_DiffBSSIDConnection + str(DisplayOUIDetail(ListInfo_STATION[x],ColorDev)) 
               __builtin__.MSG_DiffBSSIDConnection = __builtin__.MSG_DiffBSSIDConnection + ColorStd + "  Signal   [ " + ColorDev + str(ListInfo_STATION[x]) + ColorStd + " ] = " + ColorDev + str(GetClientSignal(str(ListInfo_STATION[x]))) + ColorStd + " ==>  [ " + Color1st + str(ListInfo_CBSSIDPrev[x]) + ColorStd + " ] = " + Color1st  + str(GetSSIDSignal(str(ListInfo_CBSSIDPrev[x]))) + "\n"
               __builtin__.MSG_DiffBSSIDConnection = __builtin__.MSG_DiffBSSIDConnection + ColorStd + "  Signal   [ " + ColorDev + str(ListInfo_STATION[x]) + ColorStd + " ] = " + ColorDev + str(GetClientSignal(str(ListInfo_STATION[x]))) + ColorStd + " ==>  [ " + Color2nd + str(ListInfo_CBSSID[x]) + ColorStd + " ] = " + Color2nd + str(GetSSIDSignal(str(ListInfo_CBSSID[x]))) + "\n"
               __builtin__.MSG_DiffBSSIDConnection = __builtin__.MSG_DiffBSSIDConnection + str(DisplayESSIDDetail(ListInfo_CBSSIDPrev[x],Color1st))  
               __builtin__.MSG_DiffBSSIDConnection = __builtin__.MSG_DiffBSSIDConnection + str(DisplayOUIDetail(ListInfo_CBSSIDPrev[x],Color1st)) 
               __builtin__.MSG_DiffBSSIDConnection = __builtin__.MSG_DiffBSSIDConnection + str(DisplaySSIDDetail(ListInfo_CBSSIDPrev[x]))
               if str(ListInfo_CBSSID[x]).find("Not Associated")==-1:
                   __builtin__.MSG_DiffBSSIDConnection = __builtin__.MSG_DiffBSSIDConnection + str(DisplayESSIDDetail(ListInfo_CBSSID[x],Color2nd))
                   __builtin__.MSG_DiffBSSIDConnection = __builtin__.MSG_DiffBSSIDConnection + str(DisplayOUIDetail(ListInfo_CBSSID[x],Color2nd))
                   __builtin__.MSG_DiffBSSIDConnection = __builtin__.MSG_DiffBSSIDConnection + str(DisplaySSIDDetail(ListInfo_CBSSID[x]))
                   __builtin__.MSG_DiffBSSIDConnection = __builtin__.MSG_DiffBSSIDConnection + str(ReportNow()) + "\n"
                   WriteSwitchedAP(ListInfo_STATION[x],ListInfo_CBSSIDPrev[x],ListInfo_CBSSID[x],FindESSID(ListInfo_CBSSIDPrev[x]), FindESSID(ListInfo_CBSSID[x]))
            else:
               CautiousCount += 1
               OUITxt=DisplayOUIDetail(ListInfo_STATION[x],ColorDev)
               OUITxt3=DisplayOUIDetail(ListInfo_CBSSID[x],Color2nd)
               ESSIDTxt3=DisplayESSIDDetail(ListInfo_CBSSID[x],Color2nd)
               __builtin__.MSG_NoAssocConnection = __builtin__.MSG_NoAssocConnection + ColorStd + "Device MAC [ " + ColorDev + str(ListInfo_STATION[x]) + ColorStd + " ] initially not associated is now associated with [ " + Color2nd + str(ListInfo_CBSSID[x]) + ColorStd + " ].\n" 
               __builtin__.MSG_NoAssocConnection = __builtin__.MSG_NoAssocConnection + ColorStd + "  Signal   [ " + ColorDev + str(ListInfo_STATION[x]) + ColorStd + " ] = " + ColorDev + str(GetClientSignal(str(ListInfo_STATION[x]))) + ColorStd + " ==> [ " + Color2nd + str(ListInfo_CBSSID[x]) + ColorStd + " ] = " + Color2nd  + str(GetSSIDSignal(str(ListInfo_CBSSID[x]))) + "\n"
               __builtin__.MSG_NoAssocConnection = __builtin__.MSG_NoAssocConnection + str(OUITxt) + str(ESSIDTxt3) + str(OUITxt3) 
               __builtin__.MSG_NoAssocConnection = __builtin__.MSG_NoAssocConnection + str(DisplaySSIDDetail(ListInfo_CBSSID[x]))
               __builtin__.MSG_NoAssocConnection = __builtin__.MSG_NoAssocConnection + str(ReportNow())+ "\n"
            ListInfo_CBSSIDPrev[x]=ListInfo_CBSSID[x]
            if str(ListInfo_CBSSIDPrevList[x]).find(str(ListInfo_CBSSID[x]))==-1:
                ListInfo_CBSSIDPrevList[x]=ListInfo_CBSSIDPrevList[x] + str(ListInfo_CBSSID[x]) + " | " 
        x += 1
    if __builtin__.MSG_DiffBSSIDConnection!="" or __builtin__.MSG_NoAssocConnection!="" or __builtin__.MSG_APnClient!="":
        CenterText(fcolor.BGIYellow + fcolor.BRed,"=====  CONNECTION  ALERT  [ " + str(CautiousCount) + " ] ===== ")
        print ""
        BeepSound()
        if __builtin__.MSG_DiffBSSIDConnection!="":
            __builtin__.MSG_DiffBSSIDConnection=str(__builtin__.MSG_DiffBSSIDConnection).replace("\n\n\n","\n\n")
            WriteCautiousLog(__builtin__.MSG_DiffBSSIDConnection)
            print str(__builtin__.MSG_DiffBSSIDConnection)
            __builtin__.MSG_HistoryConnection=__builtin__.MSG_HistoryConnection + __builtin__.MSG_DiffBSSIDConnection + ""
            __builtin__.MSG_HistoryConnection=RemoveAdditionalLF(__builtin__.MSG_HistoryConnection)

        if __builtin__.MSG_NoAssocConnection!="":
            __builtin__.MSG_NoAssocConnection=str(__builtin__.MSG_NoAssocConnection).replace("\n\n\n","\n\n")
            print str(__builtin__.MSG_NoAssocConnection)
            WriteCautiousLog(__builtin__.MSG_NoAssocConnection)
            __builtin__.MSG_HistoryConnection=__builtin__.MSG_HistoryConnection + __builtin__.MSG_NoAssocConnection + "\n"
            __builtin__.MSG_HistoryConnection=RemoveAdditionalLF(__builtin__.MSG_HistoryConnection)

        if __builtin__.MSG_APnClient!="":
            __builtin__.MSG_APnClient=str(__builtin__.MSG_APnClient).replace("\n\n\n","\n\n")
            print str(__builtin__.MSG_APnClient)
            WriteCautiousLog(__builtin__.MSG_APnClient)
            if str(__builtin__.MSG_HistoryConnection).find(__builtin__.MSG_APnClient)==-1:
                __builtin__.MSG_HistoryConnection=__builtin__.MSG_HistoryConnection + __builtin__.MSG_APnClient + "\n"
                __builtin__.MSG_HistoryConnection=RemoveAdditionalLF(__builtin__.MSG_HistoryConnection)
        DrawLine("_",fcolor.CReset + fcolor.Black,"")
        print ""

def WriteSwitchedAP(StnMAC,PrevBSSID,NewBSSID,PrevESSID,NewESSID):
    SkipWrite=0
    with open(DBFile6,"r") as f:
        next(f)
        for line in f:
            line=line.replace("\n","").replace("\r","")
            sl=len(line)
            if SkipWrite==0 and sl>17:
                tmplist=[]
                tmplist=str(line).split(";")
                if len(tmplist)>=6:
                    if tmplist[0]==str(StnMAC) and tmplist[1]==str(PrevBSSID) and tmplist[2]==str(NewBSSID) and tmplist[4]==str(PrevESSID)  and tmplist[5]==str(NewESSID):
                        SkipWrite=1
        if SkipWrite==0 and RemoveUnwantMAC(StnMAC)!="":
            WriteData=str(StnMAC) + str(col)
            WriteData=WriteData + str(PrevBSSID) + str(col)  
            WriteData=WriteData + str(NewBSSID) + str(col) 
            WriteData=WriteData + str(Now()) + str(col)
            WriteData=WriteData + str(PrevESSID) + str(col) 
            WriteData=WriteData + str(NewESSID) + str(col) + "\n"
            open(DBFile6,"a+b").write(WriteData)

def WriteCautiousLog(StrVal):
    StrVal=RemoveColor(StrVal)
    if IsFileDirExist(CautiousLog)!="F":
        open(CautiousLog,"w").write("")
    if IsFileDirExist(CautiousLog)=="F":
        open(CautiousLog,"a+b").write(StrVal)

def ExtractClient():
    LineList = []
    if IsFileDirExist(__builtin__.Client_CSV)=="F":
        with open(__builtin__.Client_CSV,"r") as f:
            __builtin__.ListInfo_CExist = 0
            __builtin__.ListInfo_CAdd = 0
            __builtin__.ListInfo_UnassociatedCount = 0
            __builtin__.ListInfo_AssociatedCount = 0
            __builtin__.ListInfo_ProbeCount = 0
            for line in f:
                line=line.replace("\n","").replace("\00","").replace("\r","")
                if len(line)>=94:
                    line=line + ";;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;"
                    st = list(line)
                    st[18]=";"
                    st[39]=";"
                    st[60]=";"
                    st[65]=";"
                    st[75]=";"
                    st[94]=";"
                    lp="".join(st)
                    lp=lp.replace(",;","; ")
                    LineList=lp.split(";")
                    STATION=LineList[0]
                    if len(STATION)==17:
                        x=0
                        foundloc=0
                        Skip=""
                        if str(ListInfo_STATION).find(STATION)!=-1:
                            foundloc=FindMACIndex(STATION,ListInfo_STATION)
                            Skip="1"
                            if __builtin__.ListInfo_STATION[foundloc]!=STATION:
                                print "STATION : " + str(STATION)
                                print "ListInfo_STATION[foundloc] : " + str(ListInfo_STATION[foundloc])
                                printc ("x","","")

                        CQualityPercent=0
                        CQRange=fcolor.SBlack + "Unknown"
                        CSignal=str(LineList[3]).lstrip().rstrip()
                        if len(CSignal)>1 and len(CSignal)<4:
                            CSignal=CSignal.replace("-","")
                            if CSignal.isdigit()==True:
                                CSignal="-" + str(CSignal)
                                CQualityPercent=int(100 + int(CSignal))
                                if CQualityPercent>=99 or CQualityPercent==0:  
                                    CQRange=fcolor.SBlack + "Unknown"
                                if CQualityPercent>=70 and CQualityPercent<=98:
                                    CQRange=fcolor.SGreen + "V.Good"
                                if CQualityPercent>=50 and CQualityPercent<=69:
                                    CQRange=fcolor.SGreen + "Good"
                                if CQualityPercent>=26 and CQualityPercent<=49:
                                    CQRange=fcolor.SYellow + "Average"
                                if CQualityPercent>=1 and CQualityPercent<=25:
                                    CQRange=fcolor.SRed + "Poor"
                        ProbesData=LineList[6]
                        ProbesData=ProbesData.replace(","," / ").lstrip().rstrip()
                        Assoc=LineList[5]
                        if ProbesData!="":
                            __builtin__.ListInfo_ProbeCount += 1

                        if Assoc!="":
                            Assoc=str(Assoc).lstrip().rstrip()
                            Assoc=str(Assoc).replace("(not associated)","Not Associated")
                        if Assoc.find("Not Associated")==-1:
                            __builtin__.ListInfo_AssociatedCount += 1
                        else:
                            Assoc="Not Associated"
                            __builtin__.ListInfo_UnassociatedCount += 1

                        if Assoc!="Not Associated":
                            ESSID=FindESSID(Assoc)

                        else:
                            ESSID=""
                        CLIENT_OUI=Check_OUI(STATION)
                        if Skip=="":
                            __builtin__.ListInfo_CAdd += 1
                            __builtin__.ListInfo_STATION.append (str(STATION).lstrip().rstrip())
                            __builtin__.ListInfo_CFirstSeen.append ((LineList[1]).lstrip().rstrip())
                            __builtin__.ListInfo_CLastSeen.append ((LineList[2]).lstrip().rstrip())
                            __builtin__.ListInfo_CBestQuality.append (str(LineList[3]).lstrip().rstrip())
                            __builtin__.ListInfo_CQualityRange.append (CQRange)
                            __builtin__.ListInfo_CQualityPercent.append (CQualityPercent)
                            __builtin__.ListInfo_CPackets.append (str(LineList[4]).lstrip().rstrip())
                            __builtin__.ListInfo_CBSSID.append (str(Assoc).lstrip().rstrip())
                            __builtin__.ListInfo_CBSSIDPrev.append (str(Assoc).lstrip().rstrip())
                            __builtin__.ListInfo_CBSSIDPrevList.append (str(Assoc).lstrip().rstrip() + " | ")
                            __builtin__.ListInfo_PROBE.append (str(ProbesData).lstrip().rstrip())
                            __builtin__.ListInfo_CESSID.append (str(ESSID).lstrip().rstrip())
                            __builtin__.ListInfo_COUI.append (str(CLIENT_OUI).lstrip().rstrip())
                            StartTime=LineList[1].lstrip().rstrip()
                            EndTime=LineList[2].lstrip().rstrip()
                            Elapse=CalculateTime (StartTime,EndTime)
                            __builtin__.ListInfo_CElapse.append (Elapse)
                            __builtin__.ListInfo_CTimeGap.append (__builtin__.TimeGap)
                            __builtin__.ListInfo_CTimeGapFull.append (__builtin__.TimeGapFull)
                        else:
                            __builtin__.ListInfo_CExist += 1
                            __builtin__.ListInfo_STATION[foundloc] = str(STATION).lstrip().rstrip()
                            __builtin__.ListInfo_CFirstSeen[foundloc] = str(LineList[1]).lstrip().rstrip()
                            __builtin__.ListInfo_CLastSeen[foundloc] = str(LineList[2]).lstrip().rstrip()
                            __builtin__.ListInfo_CBestQuality[foundloc] = str(LineList[3]).lstrip().rstrip()
                            __builtin__.ListInfo_CQualityRange[foundloc] = str(CQRange)
                            __builtin__.ListInfo_CQualityPercent[foundloc] = str(CQualityPercent)
                            __builtin__.ListInfo_CPackets[foundloc] = str(LineList[4]).lstrip().rstrip()
                            __builtin__.ListInfo_CBSSID[foundloc] = str(Assoc).lstrip().rstrip()
                            __builtin__.ListInfo_CESSID[foundloc] = str(ESSID).lstrip().rstrip()
                            __builtin__.ListInfo_PROBE[foundloc] = str(ProbesData).lstrip().rstrip()
                            __builtin__.ListInfo_COUI[foundloc] = str(CLIENT_OUI).lstrip().rstrip()
                            StartTime=LineList[1].lstrip().rstrip()
                            EndTime=LineList[2].lstrip().rstrip()
                            Elapse=CalculateTime (StartTime,EndTime)
                            __builtin__.ListInfo_CElapse[foundloc]= str(Elapse)
                            __builtin__.ListInfo_CTimeGap[foundloc]= str(__builtin__.TimeGap)
                            __builtin__.ListInfo_CTimeGapFull[foundloc]= str(__builtin__.TimeGapFull)
    x=0
    while x < len(ListInfo_BSSID):
        y=0
        while y < len(ListInfo_CBSSID):
            if ListInfo_CBSSID[y]==ListInfo_BSSID[x]:
                Client=0
                Client=int(ListInfo_ConnectedClient[x])
                Client=int(Client) + 1
                ListInfo_ConnectedClient[x]=Client
            y=y+1
        x=x+1

def FindESSID(MACAddr):
    BSSIDLoc=str(ListInfo_BSSID).find(str(MACAddr))
    if BSSIDLoc!=-1:
        ax=int(BSSIDLoc) -2
        ax=ax/21
        if ListInfo_BSSID[ax]==MACAddr:
            Result=ListInfo_ESSID[ax]
            return Result
        else:
            print "ax = " + str(ax)
            print "MACAddr = " + str(MACAddr)
            print "ListInfo_BSSID[ax] = " + str(ListInfo_BSSID[ax])
            printc ("x","","")
    return ""

def EnrichDump():
    if IsFileDirExist(__builtin__.SSID_CSV)=="F":
        with open(__builtin__.SSID_CSV,"r") as f:
            for line in f:
                line=line.replace("\n","")
                line=line.replace("\00","")
                if len(line)>20:
                    line=line + ";;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;"
                    line=line.replace(",",";")
                    LineList=line.split(";")
                    BSSID=LineList[0]
                    FIRSTSEEN=LineList[1]
                    LASTSEEN=LineList[2]
                    CHANNEL=LineList[3]
                    FREQ=LineList[4]
                    ENCRYPTION=LineList[5].lstrip().rstrip()
                    CIPHER=LineList[6].lstrip().rstrip()
                    AUTH=LineList[7].lstrip().rstrip()
                    SIGNAL=LineList[8].lstrip().rstrip()
                    if CIPHER=="CCMP TKIP":
                        CIPHER="CCMP/TKIP"
                    x=0
                    while x < len(ListInfo_BSSID):
                        if BSSID==ListInfo_BSSID[x]:
                            if CIPHER!="":
                                ListInfo_Cipher[x] = CIPHER
                            if AUTH!="":
                                ListInfo_Auth[x] = AUTH
                            x=len(ListInfo_BSSID)
                        x=x+1

def ExtractDump():
    cmdLine="ps -eo pid | grep '" + str(__builtin__.DumpProc) + "'"
    ps=subprocess.Popen(cmdLine , shell=True, stdout=subprocess.PIPE)	
    readout=str(ps.stdout.read().replace("\n",""))
    readout=str(readout).lstrip().rstrip()
    __builtin__.DumpProc=str(__builtin__.DumpProc)
    if str(readout)!=str(__builtin__.DumpProc):
        printc ("!", "[Network Monitor stopped - Restarting]","")
        RunAirodump()
        time.sleep(1)
    cmdLine="ps -eo pid | grep '" + str(__builtin__.WashProc) + "'"
    __builtin__.WashProc=str(__builtin__.WashProc)
    ps=subprocess.Popen(cmdLine , shell=True, stdout=subprocess.PIPE)	
    readout=str(ps.stdout.read().replace("\n",""))
    readout=str(readout).lstrip().rstrip()
    if str(readout)=="" or readout!=str(__builtin__.WashProc):
        printc ("!", "[WPS Monitor stopped - Restarting]","")
        RunWash()
        time.sleep(1)
    LineList = []
    Encryption = []
    __builtin__.ListInfo_Exist = 0
    __builtin__.ListInfo_Add = 0
    if IsFileDirExist(__builtin__.NewCaptured_Kismet)=="F":
        with open(__builtin__.NewCaptured_Kismet,"r") as f:
            for line in f:
                line=line.replace("\n","")
                line=line.replace("\00","")
                if line.find("Network;NetType;ESSID;BSSID;Info;Channel")==-1 and len(line)>10:
                    line=line + "0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;"
                    LineList=line.split(";")
                    BSSID=LineList[3]
                    if len(BSSID)==17:
                        ESSID=LineList[2]
                        if len(ESSID)==0:
                            ESSID=""
                        if len(ESSID)>=32:
                            ESSID=ESSID[:-32]
                        x=0

                        foundloc=0
                        Skip=""
                        mi=FindMACIndex(BSSID,ListInfo_BSSID)
                        if mi!="":
                            foundloc=mi
                            Skip="1"
                            if IsAscii(ESSID)==True and ESSID.find("\\x")==-1:
                                if ListInfo_BSSID[foundloc]==BSSID:
                                    if ListInfo_ESSID[foundloc]!="" and IsAscii(ESSID)==True and ESSID.find("\\x")==-1:
                                        ESSID=ListInfo_ESSID[foundloc]
                        QualityPercent=0
                        QRange=fcolor.SBlack + "Unknown"
                        if len(LineList[21])>1 and len(LineList[21])<4:
                            if str(LineList[21])=="No" or str(LineList[21])=="Yes":
                                LineList[21]=-1
                            QualityPercent=int(100 + int(LineList[21]))
                            if QualityPercent>=99 or QualityPercent==0:  
                                QRange=fcolor.SBlack + "Unknown"
                            if QualityPercent>=70 and QualityPercent<=98:
                                QRange=fcolor.SGreen + "V.Good"
                            if QualityPercent>=50 and QualityPercent<=69:
                                QRange=fcolor.SGreen + "Good"
                            if QualityPercent>=26 and QualityPercent<=49:
                                QRange=fcolor.SYellow + "Average"
                            if QualityPercent>=1 and QualityPercent<=25:
                                QRange=fcolor.SRed + "Poor"
                        Encryption=LineList[7].split(",")
                        Encryption.append ("-");Encryption.append ("-");Encryption.append ("-")
                        Privacy="";Ciper="";Auth=""
                        Privacy=Encryption[0];Ciper=Encryption[1];Auth=Encryption[2];
                        HiddenSSID="No"
                        if len(LineList[2])==0:
                            HiddenSSID="Yes"
                        BSSID_OUI=Check_OUI(BSSID)

                        StartTime=LineList[19].lstrip().rstrip()
                        StartTime2=str(LineList[19]).lstrip().rstrip()
                        EndTime=LineList[20].lstrip().rstrip()
                        StartTime=ConvertDateFormat(StartTime,"%c")
                        EndTime=ConvertDateFormat(EndTime,"%c")
                        if Skip=="":
                            __builtin__.ListInfo_Add += 1
                            ListInfo_ESSID.append (ESSID)
                            ListInfo_HiddenSSID.append (HiddenSSID)
                            ListInfo_BSSIDTimes.append ("1")
                            ListInfo_BSSID.append (LineList[3])
                            ListInfo_Channel.append (LineList[5])
                            ListInfo_Cloaked.append (LineList[6])
                            ListInfo_Privacy.append (Privacy)
                            ListInfo_Cipher.append (Ciper)
                            ListInfo_Auth.append (Auth)
                            ListInfo_MaxRate.append (LineList[9])
                            ListInfo_Beacon.append (LineList[11])
                            ListInfo_Data.append (LineList[13])
                            ListInfo_Total.append (LineList[16])
                            ListInfo_FirstSeen.append (StartTime)
                            ListInfo_LastSeen.append (EndTime)
                            ListInfo_BestQuality.append (LineList[21])
                            ListInfo_BestSignal.append (LineList[22])
                            ListInfo_BestNoise.append (LineList[23])
                            ListInfo_GPSBestLat.append (LineList[32])
                            ListInfo_GPSBestLon.append (LineList[33])
                            ListInfo_GPSBestAlt.append (LineList[34])
                            ListInfo_QualityRange.append(QRange)
                            ListInfo_QualityPercent.append (str(QualityPercent))
                            ListInfo_BSSID_OUI.append(BSSID_OUI)
                            ListInfo_WPS.append (str("-"))
                            ListInfo_WPSVer.append (str("-"))
                            ListInfo_WPSLock.append (str("-"))
                            ListInfo_ConnectedClient.append ("0")
                            __builtin__.ListInfo_Freq.append (str(GetFrequency(LineList[5])))
                            __builtin__.ListInfo_Signal.append (str("-"))
                            __builtin__.ListInfo_Enriched.append (str(""))
                            __builtin__.ListInfo_Quality.append (str("-"))
                            __builtin__.ListInfo_BitRate.append (str("-"))
                            __builtin__.ListInfo_WPAVer.append (str("-"))
                            __builtin__.ListInfo_PairwiseCipher.append (str("-"))
                            __builtin__.ListInfo_GroupCipher.append (str("-"))
                            __builtin__.ListInfo_AuthSuite.append (str("-"))
                            __builtin__.ListInfo_LastBeacon.append (str("-"))
                            __builtin__.ListInfo_Mode.append (str("-"))
                            __builtin__.ListInfo_EncKey.append (str("-"))
                            Elapse=CalculateTime (StartTime,EndTime)
                            __builtin__.ListInfo_SSIDElapse.append (Elapse)
                            __builtin__.ListInfo_SSIDTimeGap.append (__builtin__.TimeGap)
                            __builtin__.ListInfo_SSIDTimeGapFull.append (__builtin__.TimeGapFull)
                        else:
                            __builtin__.ListInfo_Exist += 1
                            Times=ListInfo_BSSIDTimes[foundloc]
                            Times=int(Times)+1
                            ListInfo_BSSIDTimes[foundloc]=Times
                            ListInfo_HiddenSSID[foundloc]= HiddenSSID
                            ListInfo_BSSID[foundloc] = LineList[3]
                            if LineList[5]>0:
                                ListInfo_Channel[foundloc] =  LineList[5]
                            ListInfo_Cloaked[foundloc] = LineList[6]
                            if __builtin__.ListInfo_Enriched[foundloc]!="Yes":
                                ListInfo_Privacy[foundloc] = Privacy
                                ListInfo_Cipher[foundloc] = Ciper
                                ListInfo_Auth[foundloc] = Auth
                            if ESSID!="":
                                if str(ESSID).find("...")==-1 and str(ESSID).find("\\x")==-1:
                                    ListInfo_ESSID[foundloc] = ESSID
                                else:
                                    if str(ListInfo_ESSID[foundloc])== "":
                                        ListInfo_ESSID[foundloc] = ESSID
                            ListInfo_MaxRate[foundloc] = LineList[9]
                            ListInfo_Beacon[foundloc] = LineList[11]
                            ListInfo_Data[foundloc] = LineList[13]
                            ListInfo_Total[foundloc] = LineList[16]
                            ListInfo_FirstSeen[foundloc] = StartTime
                            ListInfo_LastSeen[foundloc] = EndTime
                            ListInfo_BestQuality[foundloc] = LineList[21]
                            ListInfo_BestSignal[foundloc] = LineList[22]
                            ListInfo_BestNoise[foundloc] = LineList[23]
                            ListInfo_GPSBestLat[foundloc] = LineList[32]
                            ListInfo_GPSBestLon[foundloc] = LineList[33]
                            ListInfo_GPSBestAlt[foundloc] = LineList[34]
                            ListInfo_QualityRange[foundloc] = QRange
                            ListInfo_QualityPercent[foundloc] = str(QualityPercent)
                            ListInfo_BSSID_OUI[foundloc] = str(BSSID_OUI)
                            ListInfo_ConnectedClient[foundloc]="0"
                            Elapse=CalculateTime (StartTime,EndTime)
                            __builtin__.ListInfo_SSIDElapse[foundloc]= str(Elapse)
                            __builtin__.ListInfo_SSIDTimeGap[foundloc]= __builtin__.TimeGap
                            __builtin__.ListInfo_SSIDTimeGapFull[foundloc]= __builtin__.TimeGapFull


def GetMonitoringMAC():
    MonitoringMACStr=""
    __builtin__.MonitoringMACList=[]
    __builtin__.MonitoringNameList=[]
    if IsFileDirExist(MonitorMACfile)=="F":
        with open(MonitorMACfile,"r") as f:
            for line in f:
                line=line.replace("\n","")
                line=line.replace("\00","")
                if len(line) > 10:
                    if line[:8]=="MACID : ":
                        line=line[8:]
                        if len(line)==17:
                            __builtin__.MonitoringMACList.append(line)
                    if line[:8]=="ESSID : ":
                        line=line[8:]
                        __builtin__.MonitoringNameList.append(line)
    else:
        open(MonitorMACfile,"a+b").write("")

def DisplayMonitoringMAC():
    if len(__builtin__.MonitoringMACList)==0 and len(__builtin__.MonitoringNameList)==0:
        printc ("i","No items was specified in current setting..","")
    else:
        printc (".", fcolor.BPink + "List of Monitoring Items","")
        x=0
        while x < len(__builtin__.MonitoringMACList):
            printc (" ",fcolor.SWhite + "MAC  : " + fcolor.BGreen + str(__builtin__.MonitoringMACList[x]),"")
            x=x+1
        x=0
        while x < len(__builtin__.MonitoringNameList):
            printc (" ",fcolor.SWhite + "Name : " + fcolor.BGreen + str(__builtin__.MonitoringNameList[x]),"")
            x=x+1

        DrawLine("_",fcolor.CReset + fcolor.Black,"")
        print ""

def SaveMonitoringMAC():
    if len(__builtin__.MonitoringMACList)>0 or len(__builtin__.MonitoringNameList)>0:
        open(MonitorMACfile,"w").write("")
        x=0
        while x < len(__builtin__.MonitoringMACList):
            open(MonitorMACfile,"a+b").write("MACID : " + str(__builtin__.MonitoringMACList[x]) + "\n")
            x=x+1
        x=0
        while x < len(__builtin__.MonitoringNameList):
            open(MonitorMACfile,"a+b").write("ESSID : " + str(__builtin__.MonitoringNameList[x]) + "\n")
            x=x+1

def CheckMonitoringMAC():
    if len(__builtin__.MonitoringMACList)>0 or len(__builtin__.MonitoringNameList)>0:
        FoundCount=0
        InactiveCount=0
        InActiveMAC=""
        __builtin__.FoundMonitoringMAC=""
        x=0
        while x < len(__builtin__.MonitoringMACList):
            y=0
            while y < len(ListInfo_BSSID):
                if __builtin__.MonitoringMACList[x].upper()==ListInfo_BSSID[y].upper():
                    if int(__builtin__.ListInfo_SSIDTimeGap[y]) <= int(__builtin__.REMOVE_AFTER_MIN):
                        FoundCount += 1
                        __builtin__.FoundMonitoringMAC = __builtin__.FoundMonitoringMAC + fcolor.SWhite + "[" + fcolor.BGreen + str(FoundCount) + fcolor.SWhite + "]".ljust(4) + fcolor.SGreen + "L.Seen  : " + fcolor.BWhite + str(ListInfo_LastSeen[y]).ljust(24) +   fcolor.SGreen + "BSSID   : " + fcolor.BYellow + str(ListInfo_BSSID[y]) + "\t" + fcolor.SGreen + "Power : " + fcolor.BWhite + str(ListInfo_BestQuality[y]).ljust(8) + fcolor.SGreen + "ESSID : " + fcolor.BWhite + str(ListInfo_ESSID[y]) + "\n"
                    else:
                        InactiveCount += 1
                        InActiveMAC= InActiveMAC + fcolor.SWhite + "[" + fcolor.BGreen + str(InactiveCount) + fcolor.SWhite + "]".ljust(4) + fcolor.SGreen + "L.Seen  : " + fcolor.SWhite +  str(ListInfo_LastSeen[y]).ljust(24) + fcolor.SGreen + "BSSID   : " + fcolor.SYellow + str(ListInfo_BSSID[y]) + "\t" + fcolor.SGreen + "Power : " + fcolor.BWhite + str(ListInfo_BestQuality[y]).ljust(8) + fcolor.SGreen + "ESSID : " + fcolor.SWhite + str(ListInfo_ESSID[y]) + "\n"
                y=y+1
            y=0
            while y < len(ListInfo_STATION):
                if __builtin__.MonitoringMACList[x].upper()==ListInfo_STATION[y].upper():
                    if int(__builtin__.ListInfo_CTimeGap[y]) <= int(__builtin__.REMOVE_AFTER_MIN):
                        FoundCount += 1
                        __builtin__.FoundMonitoringMAC= __builtin__.FoundMonitoringMAC + fcolor.SWhite + "[" + fcolor.BGreen + str(FoundCount) + fcolor.SWhite + "]".ljust(4) + fcolor.SGreen + "L.Seen  : " + fcolor.BWhite + str(ListInfo_CLastSeen[y]).ljust(24)  + fcolor.SGreen + "Station : " + fcolor.BYellow + ListInfo_STATION[y] + "\t" + fcolor.SGreen + "Power : " + fcolor.BWhite + str(ListInfo_CBestQuality[y]).ljust(8) + fcolor.SGreen 
                        if ListInfo_CBSSID[y]!="":
                            ESSID=FindESSID(ListInfo_CBSSID[y])
                            if ListInfo_CBSSID[y].find("Not Associated")==-1:
                                __builtin__.FoundMonitoringMAC= __builtin__.FoundMonitoringMAC + fcolor.SGreen + "BSSID : " + fcolor.BWhite + str(ListInfo_CBSSID[y]) + fcolor.SGreen + "  [ " + fcolor.BWhite + str(ESSID) + fcolor.SGreen + " ]\n"
                            else:
                                __builtin__.FoundMonitoringMAC= __builtin__.FoundMonitoringMAC + fcolor.SGreen + "BSSID : " + fcolor.BIGray + "Not Associated\n"
                        if ListInfo_PROBE[y]!="":
                            if ListInfo_CBSSID[y]!="":
                                __builtin__.FoundMonitoringMAC= __builtin__.FoundMonitoringMAC + fcolor.SGreen + "      Probe   : " + fcolor.BBlue  + str(ListInfo_PROBE[y]) + "\n"
                    else:
                        InactiveCount += 1
                        InActiveMAC = InActiveMAC  + fcolor.SWhite + "[" + fcolor.BGreen + str(InactiveCount) + fcolor.SWhite + "]".ljust(4) + fcolor.SGreen + "L.Seen  : " + fcolor.SWhite + str(ListInfo_CLastSeen[y]).ljust(24) + fcolor.SGreen + "Station : " + fcolor.SYellow + ListInfo_STATION[y] + "\t" + fcolor.SGreen + "Power : " + fcolor.SWhite + str(ListInfo_CBestQuality[y]).ljust(8) + fcolor.SGreen 
                        if ListInfo_CBSSID[y]!="":
                            ESSID=FindESSID(ListInfo_CBSSID[y])
                            if ListInfo_CBSSID[y].find("Not Associated")==-1:
                                InActiveMAC = InActiveMAC + fcolor.SGreen + "BSSID : " + fcolor.SWhite + str(ListInfo_CBSSID[y]) + fcolor.SWhite + "  [ " + fcolor.SWhite + str(ESSID) + fcolor.SGreen + " ]\n"
                            else:
                                InActiveMAC = InActiveMAC + fcolor.SGreen + "BSSID : " + fcolor.SBlack + "Not Associated\n"

                        if ListInfo_PROBE[y]!="":
                            InActiveMAC = InActiveMAC + fcolor.SGreen + "      Probe   : " + fcolor.SBlue + str(ListInfo_PROBE[y]) + "\n"
                y=y+1
            x=x+1
        x=0
        while x < len(__builtin__.MonitoringNameList):
            y=0
            while y < len(ListInfo_BSSID):
                if __builtin__.MonitoringNameList[x].upper()==ListInfo_ESSID[y].upper():
                    if int(__builtin__.ListInfo_SSIDTimeGap[y]) <= int(__builtin__.REMOVE_AFTER_MIN):
                        FoundCount += 1
                        __builtin__.FoundMonitoringMAC = __builtin__.FoundMonitoringMAC + fcolor.SWhite + "[" + fcolor.BGreen + str(FoundCount) + fcolor.SWhite + "]".ljust(4) + fcolor.SGreen + "L.Seen  : " + fcolor.BWhite + str(ListInfo_LastSeen[y]).ljust(24) +   fcolor.SGreen + "BSSID   : " + fcolor.BWhite + str(ListInfo_BSSID[y]) + "\t" + fcolor.SGreen + "Power : " + fcolor.BWhite + str(ListInfo_BestQuality[y]).ljust(8) + fcolor.SGreen + "ESSID : " + fcolor.BYellow + str(ListInfo_ESSID[y]) + "\n"
                    else:
                        InactiveCount += 1
                        InActiveMAC= InActiveMAC + fcolor.SWhite + "[" + fcolor.BGreen + str(InactiveCount) + fcolor.SWhite + "]".ljust(4) + fcolor.SGreen + "L.Seen  : " + fcolor.SWhite +  str(ListInfo_LastSeen[y]).ljust(24) + fcolor.SGreen + "BSSID   : " + fcolor.SWhite + str(ListInfo_BSSID[y]) + "\t" + fcolor.SGreen + "Power : " + fcolor.SWhite + str(ListInfo_BestQuality[y]).ljust(8) + fcolor.SGreen + "ESSID : " + fcolor.SYellow + str(ListInfo_ESSID[y]) + "\n"
                y=y+1
            y=0
            while y < len(ListInfo_STATION):
                if ListInfo_PROBE[y].upper().find(__builtin__.MonitoringNameList[x].upper())!=-1:
                    ProbeName=ListInfo_PROBE[y]
                    if int(__builtin__.ListInfo_CTimeGap[y]) <= int(__builtin__.REMOVE_AFTER_MIN):
                        FoundCount += 1
                        __builtin__.FoundMonitoringMAC= __builtin__.FoundMonitoringMAC + fcolor.SWhite + "[" + fcolor.BGreen + str(FoundCount) + fcolor.SWhite + "]".ljust(4) + fcolor.SGreen + "L.Seen  : " + fcolor.BWhite + str(ListInfo_CLastSeen[y]).ljust(24)  + fcolor.SGreen + "Station : " + fcolor.BWhite + ListInfo_STATION[y] + "\t" + fcolor.SGreen + "Power : " + fcolor.BWhite + str(ListInfo_CBestQuality[y]).ljust(8) + fcolor.SGreen 
                        if ListInfo_CBSSID[y]!="":
                            ESSID=FindESSID(ListInfo_CBSSID[y])
                            if ListInfo_CBSSID[y].find("Not Associated")==-1:
                                __builtin__.FoundMonitoringMAC= __builtin__.FoundMonitoringMAC + fcolor.SGreen + "BSSID : " + fcolor.BWhite + str(ListInfo_CBSSID[y]) + fcolor.SGreen + "  [ " + fcolor.BWhite + str(ESSID) + fcolor.SGreen + " ]\n"
                            else:
                                __builtin__.FoundMonitoringMAC= __builtin__.FoundMonitoringMAC + fcolor.SGreen + "BSSID : " + fcolor.BIGray + "Not Associated\n"
                        if ListInfo_PROBE[y]!="":
                            ProbeName=ProbeName.replace(__builtin__.MonitoringNameList[x],fcolor.BYellow + __builtin__.MonitoringNameList[x] + fcolor.BBlue)
                            __builtin__.FoundMonitoringMAC= __builtin__.FoundMonitoringMAC + fcolor.SGreen + "      Probe   : " + fcolor.BBlue  + str(ProbeName) + "\n"
                    else:
                        InactiveCount += 1
                        InActiveMAC = InActiveMAC  + fcolor.SWhite + "[" + fcolor.BGreen + str(InactiveCount) + fcolor.SWhite + "]".ljust(4) + fcolor.SGreen + "L.Seen  : " + fcolor.SWhite + str(ListInfo_CLastSeen[y]).ljust(24) + fcolor.SGreen + "Station : " + fcolor.SWhite + ListInfo_STATION[y] + "\t" + fcolor.SGreen + "Power : " + fcolor.SWhite + str(ListInfo_CBestQuality[y]).ljust(8) + fcolor.SGreen 
                        if ListInfo_CBSSID[y]!="":
                            ESSID=FindESSID(ListInfo_CBSSID[y])
                            if ListInfo_CBSSID[y].find("Not Associated")==-1:
                                InActiveMAC = InActiveMAC + fcolor.SGreen + "BSSID : " + fcolor.SWhite + str(ListInfo_CBSSID[y]) + fcolor.SWhite + "  [ " + fcolor.SWhite + str(ESSID) + fcolor.SGreen + " ]\n"
                            else:
                                InActiveMAC = InActiveMAC + fcolor.SGreen + "BSSID : " + fcolor.SBlack + "Not Associated\n"

                        if ListInfo_PROBE[y]!="":
                            ProbeName=ProbeName.replace(__builtin__.MonitoringNameList[x],fcolor.SYellow + __builtin__.MonitoringNameList[x] + fcolor.SBlue)
                            InActiveMAC = InActiveMAC + fcolor.SGreen + "      Probe   : " + fcolor.SBlue + str(ProbeName) + "\n"
                y=y+1
            x=x+1
        if __builtin__.FoundMonitoringMAC!="" or InActiveMAC!="":
            CenterText(fcolor.BGIRed + fcolor.BWhite,"=====  MONITORING   PANEL  ===== ")
            print ""
            BeepSound()
            if __builtin__.FoundMonitoringMAC!="":
                print fcolor.BRed + "FOUND " + str(FoundCount) + " LIVE MONITORED ITEMS !!!"
                print __builtin__.FoundMonitoringMAC
            if InActiveMAC!="":
                print fcolor.BRed + "FOUND " + str(InactiveCount) + " INACTIVE MONITORED ITEMS !!!"
                print InActiveMAC
            DrawLine("_",fcolor.CReset + fcolor.Black,"")
            print ""

def SaveConfig():
    open(ConfigFile,"w").write("WAIDPS Configuration"+ "\n")
    open(ConfigFile,"a+b").write("HIDE_INACTIVE_SSID=" + str(HIDE_INACTIVE_SSID) + "\n")
    open(ConfigFile,"a+b").write("HIDE_INACTIVE_STN=" + str(HIDE_INACTIVE_STN) + "\n")
    open(ConfigFile,"a+b").write("REMOVE_AFTER_MIN=" + str(REMOVE_AFTER_MIN)+ "\n")
    open(ConfigFile,"a+b").write("NETWORK_VIEW=" + str(NETWORK_VIEW)+ "\n")
    open(ConfigFile,"a+b").write("ALERTSOUND=" + str(ALERTSOUND)+ "\n")
    open(ConfigFile,"a+b").write("TIMEOUT=" + str(TIMEOUT)+ "\n")
    open(ConfigFile,"a+b").write("TIMES_BEFORE_UPDATE_AP_DB=" + str(TIMES_BEFORE_UPDATE_AP_DB) + "\n")
    open(ConfigFile,"a+b").write("TIMES_BEFORE_UPDATE_STN_DB=" + str(TIMES_BEFORE_UPDATE_STN_DB)+ "\n")
    printc ("i",fcolor.BRed + "Application Setting Saved...","")


def LoadConfig():
    tmpList=[]
    if IsFileDirExist(ConfigFile)=="F":
	with open(ConfigFile,"r") as f:
	    for line in f:
                line=line.replace("\n","")
                tmpList=str(line).split("=")
                if len(tmpList)==2:
                    if tmpList[0]=="HIDE_INACTIVE_SSID" and tmpList[1]!="":
                        __builtin__.HIDE_INACTIVE_SSID=tmpList[1]
                    if tmpList[0]=="REMOVE_AFTER_MIN" and tmpList[1]!="":
                        __builtin__.REMOVE_AFTER_MIN=tmpList[1]
                    if tmpList[0]=="NETWORK_VIEW" and tmpList[1]!="":
                        __builtin__.NETWORK_VIEW=tmpList[1]
                    if tmpList[0]=="ALERTSOUND" and tmpList[1]!="":
                        __builtin__.ALERTSOUND=tmpList[1]
                    if tmpList[0]=="TIMEOUT" and tmpList[1]!="":
                        __builtin__.TIMEOUT=tmpList[1]
                    if tmpList[0]=="TIMES_BEFORE_UPDATE_AP_DB" and tmpList[1]!="":
                        __builtin__.TIMES_BEFORE_UPDATE_AP_DB=tmpList[1]
                    if tmpList[0]=="TIMES_BEFORE_UPDATE_STN_DB" and tmpList[1]!="":
                        __builtin__.TIMES_BEFORE_UPDATE_STN_DB=tmpList[1]
                    if tmpList[0]=="HIDE_INACTIVE_STN" and tmpList[1]!="":
                        __builtin__.HIDE_INACTIVE_STN=tmpList[1]
                    if tmpList[0]=="A" and tmpList[1]!="":
                        A=tmpList[1]
    else:
        open(ConfigFile,"w").write("WAIDPS Configuration"+ "\n")
        open(ConfigFile,"a+b").write("HIDE_INACTIVE_SSID=" + str(HIDE_INACTIVE_SSID) + "\n")
        open(ConfigFile,"a+b").write("HIDE_INACTIVE_STN=" + str(HIDE_INACTIVE_STN) + "\n")
        open(ConfigFile,"a+b").write("REMOVE_AFTER_MIN=" + str(REMOVE_AFTER_MIN)+ "\n")
        open(ConfigFile,"a+b").write("NETWORK_VIEW=" + str(NETWORK_VIEW)+ "\n")
        open(ConfigFile,"a+b").write("ALERTSOUND=" + str(ALERTSOUND)+ "\n")
        open(ConfigFile,"a+b").write("TIMEOUT=" + str(TIMEOUT)+ "\n")
        open(ConfigFile,"a+b").write("TIMES_BEFORE_UPDATE_AP_DB=" + str(TIMES_BEFORE_UPDATE_AP_DB) + "\n")
        open(ConfigFile,"a+b").write("TIMES_BEFORE_UPDATE_STN_DB=" + str(TIMES_BEFORE_UPDATE_STN_DB)+ "\n")

def InsNum(StrVal):
    Rtn="[" + str(StrVal) + "]"
    Rtn=Rtn.ljust(6)
    Rtn=fcolor.SWhite + str(Rtn).replace(str(StrVal),fcolor.BWhite + str(StrVal) + fcolor.SWhite)
    return Rtn;

def SearchDBFiles(cmdType,SearchVal,SearchLen,SearchType,SearchTypelbl):
    DbMatchBSSIDCt=0
    DbMatchStationCt=0
    __builtin__.DbShowBSSIDList = []
    __builtin__.DbShowStationList = []
    tmpList= []
    print ""
    if cmdType=="MAC":
        SELECTTYPE="MAC"
        printc (".",fcolor.BWhite + "Search MAC Criteria (Database) : " + fcolor.BRed + str(SearchVal) + fcolor.SWhite + " (" + str(__builtin__.SearchTypelbl) + ")" ,"")
        if IsFileDirExist(DBFile2)=="F":
	    with open(DBFile2,"r") as f:
                next(f)
    	        for line in f:
                    line=line.replace("\n","")
                    tmpList=str(line).split(";")
                    if len(tmpList)>=18:
                        ToDisplay = 0
                        if __builtin__.SearchType=="0" and str(tmpList[0])==SearchVal:
                            if str(__builtin__.ShowBSSIDList2).find(tmpList[0])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[0])==-1:
                                __builtin__.DbShowBSSIDList.append (tmpList[0])
                                DbMatchBSSIDCt += 1
                                ToDisplay=1
                        if __builtin__.SearchType=="1" and str(tmpList[0]).find(SearchVal)!=-1:
                            if str(__builtin__.ShowBSSIDList2).find(tmpList[0])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[0])==-1:
                                __builtin__.DbShowBSSIDList.append (tmpList[0])
                                DbMatchBSSIDCt += 1
                                ToDisplay=1
                        if __builtin__.SearchType=="2" and str(tmpList[0])[:SearchLen]==SearchVal:
                            if str(__builtin__.ShowBSSIDList2).find(tmpList[0])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[0])==-1:
                                __builtin__.DbShowBSSIDList.append (tmpList[0])
                                DbMatchBSSIDCt += 1
                                ToDisplay=1
                        if __builtin__.SearchType=="3" and str(tmpList[0])[-SearchLen:]==SearchVal:
                            if str(__builtin__.ShowBSSIDList2).find(tmpList[0])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[0])==-1:
                                __builtin__.DbShowBSSIDList.append (tmpList[0])
                                DbMatchBSSIDCt += 1
                                ToDisplay=1
                        if ToDisplay==1:
                            print tabspacefull + fcolor.SGreen + "Found Match in DB : " + fcolor.SWhite + str(tmpList[0]) + fcolor.SGreen + " (BSSID)"
        if IsFileDirExist(DBFile3)=="F":
	    with open(DBFile3,"r") as f:
                next(f)
    	        for line in f:
                    line=line.replace("\n","")
                    tmpList=str(line).split(";")
                    if len(tmpList)>=7:
                        if len(tmpList[1])==17:
                            ToDisplay = 0
                            if __builtin__.SearchType=="0" and str(tmpList[1])==SearchVal:
                                if str(__builtin__.ShowBSSIDList2).find(tmpList[1])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[1])==-1:
                                    __builtin__.DbShowBSSIDList.append (tmpList[1])
                                    DbMatchBSSIDCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="1" and str(tmpList[1]).find(SearchVal)!=-1:
                                if str(__builtin__.ShowBSSIDList2).find(tmpList[1])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[1])==-1:
                                    __builtin__.DbShowBSSIDList.append (tmpList[1])
                                    DbMatchBSSIDCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="2" and str(tmpList[1])[:SearchLen]==SearchVal:
                                if str(__builtin__.ShowBSSIDList2).find(tmpList[1])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[1])==-1:
                                    __builtin__.DbShowBSSIDList.append (tmpList[1])
                                    DbMatchBSSIDCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="3" and str(tmpList[1])[-SearchLen:]==SearchVal:
                                if str(__builtin__.ShowBSSIDList2).find(tmpList[1])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[1])==-1:
                                    __builtin__.DbShowBSSIDList.append (tmpList[1])
                                    DbMatchBSSIDCt += 1
                                    ToDisplay=1
                            if ToDisplay==1:
                                print tabspacefull + fcolor.SGreen + "Found Match in DB : " + fcolor.SWhite + str(tmpList[1]) + fcolor.SGreen + " (BSSID)"
                        if len(tmpList[0])==17:
                            ToDisplay = 0
                            if __builtin__.SearchType=="0" and str(tmpList[0])==SearchVal:
                                if str(__builtin__.ShowStationList2).find(tmpList[0])==-1  and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                    __builtin__.DbShowStationList.append (tmpList[0])
                                    DbMatchStationCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="1" and str(tmpList[0]).find(SearchVal)!=-1:
                                if str(__builtin__.ShowStationList2).find(tmpList[0])==-1 and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                    __builtin__.DbShowStationList.append (tmpList[0])
                                    DbMatchStationCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="2" and str(tmpList[0])[:SearchLen]==SearchVal:
                                if str(__builtin__.ShowStationList2).find(tmpList[0])==-1 and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                    __builtin__.DbShowStationList.append (tmpList[0])
                                    DbMatchStationCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="3" and str(tmpList[1])[-SearchLen:]==SearchVal:
                                if str(__builtin__.ShowStationList2).find(tmpList[0])==-1 and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                    __builtin__.DbShowStationList.append (tmpList[0])
                                    DbMatchStationCt += 1
                                    ToDisplay=1
                            if ToDisplay==1:
                                print tabspacefull + fcolor.SGreen + "Found Match in DB : " + fcolor.SWhite + str(tmpList[0]) + fcolor.SGreen + " (STATION)"
        if IsFileDirExist(DBFile4)=="F":
	    with open(DBFile4,"r") as f:
                next(f)
    	        for line in f:
                    line=line.replace("\n","")
                    tmpList=str(line).split(";")
                    if len(tmpList)>=3:
                        ToDisplay = 0
                        if __builtin__.SearchType=="0" and str(tmpList[0])==SearchVal:
                            if str(__builtin__.ShowStationList2).find(tmpList[0])==-1 and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                __builtin__.DbShowStationList.append (tmpList[0])
                                DbMatchStationCt += 1
                                ToDisplay=1
                        if __builtin__.SearchType=="1" and str(tmpList[0]).find(SearchVal)!=-1:
                            if str(__builtin__.ShowStationList2).find(tmpList[0])==-1  and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                __builtin__.DbShowStationList.append (tmpList[0])
                                DbMatchStationCt += 1
                                ToDisplay=1
                        if __builtin__.SearchType=="2" and str(tmpList[0])[:SearchLen]==SearchVal:
                            if str(__builtin__.ShowStationList2).find(tmpList[0])==-1 and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                __builtin__.DbShowStationList.append (tmpList[0])
                                DbMatchStationCt += 1
                                ToDisplay=1
                        if __builtin__.SearchType=="3" and str(tmpList[0])[-SearchLen:]==SearchVal:
                            if str(__builtin__.ShowStationList2).find(tmpList[0])==-1 and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                __builtin__.DbShowStationList.append (tmpList[0])
                                DbMatchStationCt += 1
                                ToDisplay=1
                        if ToDisplay==1:
                            print tabspacefull + fcolor.SGreen + "Found Match in DB : " + fcolor.SWhite + str(tmpList[0]) + fcolor.SGreen + " (STATION)"
        if IsFileDirExist(DBFile1)=="F":
	    with open(DBFile1,"r") as f:
                next(f)
    	        for line in f:
                    line=line.replace("\n","")
                    tmpList=str(line).split(";")
                    if len(tmpList)>=6:
                        if len(tmpList[1])==17:
                            ToDisplay = 0
                            if __builtin__.SearchType=="0" and str(tmpList[1])==SearchVal:
                                if str(__builtin__.ShowBSSIDList2).find(tmpList[1])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[1])==-1:
                                    __builtin__.DbShowBSSIDList.append (tmpList[1])
                                    DbMatchBSSIDCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="1" and str(tmpList[1]).find(SearchVal)!=-1:
                                if str(__builtin__.ShowBSSIDList2).find(tmpList[1])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[1])==-1:
                                    __builtin__.DbShowBSSIDList.append (tmpList[1])
                                    DbMatchBSSIDCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="2" and str(tmpList[1])[:SearchLen]==SearchVal:
                                if str(__builtin__.ShowBSSIDList2).find(tmpList[1])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[1])==-1:
                                    __builtin__.DbShowBSSIDList.append (tmpList[1])
                                    DbMatchBSSIDCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="3" and str(tmpList[1])[-SearchLen:]==SearchVal:
                                if str(__builtin__.ShowBSSIDList2).find(tmpList[1])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[1])==-1:
                                    __builtin__.DbShowBSSIDList.append (tmpList[1])
                                    DbMatchBSSIDCt += 1
                                    ToDisplay=1
                            if ToDisplay==1:
                                print tabspacefull + fcolor.SGreen + "Found Match in DB : " + fcolor.SWhite + str(tmpList[1]) + fcolor.SGreen + " (BSSID)"
                        if len(tmpList[0])==17:
                            ToDisplay = 0
                            if __builtin__.SearchType=="0" and str(tmpList[0])==SearchVal:
                                if str(__builtin__.ShowStationList2).find(tmpList[0])==-1  and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                    __builtin__.DbShowStationList.append (tmpList[0])
                                    DbMatchStationCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="1" and str(tmpList[0]).find(SearchVal)!=-1:
                                if str(__builtin__.ShowStationList2).find(tmpList[0])==-1 and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                    __builtin__.DbShowStationList.append (tmpList[0])
                                    DbMatchStationCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="2" and str(tmpList[0])[:SearchLen]==SearchVal:
                                if str(__builtin__.ShowStationList2).find(tmpList[0])==-1 and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                    __builtin__.DbShowStationList.append (tmpList[0])
                                    DbMatchStationCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="3" and str(tmpList[1])[-SearchLen:]==SearchVal:
                                if str(__builtin__.ShowStationList2).find(tmpList[0])==-1 and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                    __builtin__.DbShowStationList.append (tmpList[0])
                                    DbMatchStationCt += 1
                                    ToDisplay=1
                            if ToDisplay==1:
                                print tabspacefull + fcolor.SGreen + "Found Match in DB : " + fcolor.SWhite + str(tmpList[0]) + fcolor.SGreen + " (STATION)"
    if cmdType=="NAME":
        SELECTTYPE="NAME"
        printc (".",fcolor.BWhite + "Search Name Criteria (Database) : " + fcolor.BRed + str(SearchVal) + fcolor.SWhite + " (" + str(__builtin__.SearchTypelbl) + ")" ,"")
        if IsFileDirExist(DBFile2)=="F":
	    with open(DBFile2,"r") as f:
                next(f)
    	        for line in f:
                    line=line.replace("\n","")
                    tmpList=str(line).split(";")
                    if len(tmpList)>=18:
                        ToDisplay = 0
                        if __builtin__.SearchType=="0" and str(tmpList[18]).upper()==SearchVal.upper():
                            if str(__builtin__.ShowBSSIDList2).find(tmpList[0])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[0])==-1:
                                __builtin__.DbShowBSSIDList.append (tmpList[0])
                                DbMatchBSSIDCt += 1
                                ToDisplay=1
                        if __builtin__.SearchType=="1" and str(tmpList[18]).upper().find(SearchVal.upper())!=-1:
                            if str(__builtin__.ShowBSSIDList2).find(tmpList[0])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[0])==-1:
                                __builtin__.DbShowBSSIDList.append (tmpList[0])
                                DbMatchBSSIDCt += 1
                                ToDisplay=1
                        if __builtin__.SearchType=="2" and str(tmpList[18]).upper()[:SearchLen]==SearchVal.upper():
                            if str(__builtin__.ShowBSSIDList2).find(tmpList[0])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[0])==-1:
                                __builtin__.DbShowBSSIDList.append (tmpList[0])
                                DbMatchBSSIDCt += 1
                                ToDisplay=1
                        if __builtin__.SearchType=="3" and str(tmpList[18]).upper()[-SearchLen:]==SearchVal.upper():
                            if str(__builtin__.ShowBSSIDList2).find(tmpList[0])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[0])==-1:
                                __builtin__.DbShowBSSIDList.append (tmpList[0])
                                DbMatchBSSIDCt += 1
                                ToDisplay=1
                        if ToDisplay==1:
                            print tabspacefull + fcolor.SGreen + "Found Match in DB : " + fcolor.SWhite + str(tmpList[0]) + fcolor.SGreen + " (BSSID)"
        if IsFileDirExist(DBFile3)=="F":
	    with open(DBFile3,"r") as f:
                next(f)
    	        for line in f:
                    line=line.replace("\n","")
                    tmpList=str(line).split(";")
                    if len(tmpList)>=7:
                        if len(tmpList[1])==17:
                            ToDisplay = 0
                            if __builtin__.SearchType=="0" and str(tmpList[6]).upper()==SearchVal.upper():
                                if str(__builtin__.ShowBSSIDList2).find(tmpList[1])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[1])==-1:
                                    __builtin__.DbShowBSSIDList.append (tmpList[1])
                                    DbMatchBSSIDCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="1" and str(tmpList[6]).upper().find(SearchVal.upper())!=-1:
                                if str(__builtin__.ShowBSSIDList2).find(tmpList[1])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[1])==-1:
                                    __builtin__.DbShowBSSIDList.append (tmpList[1])
                                    DbMatchBSSIDCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="2" and str(tmpList[6]).upper()[:SearchLen]==SearchVal.upper():
                                if str(__builtin__.ShowBSSIDList2).find(tmpList[1])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[1])==-1:
                                    __builtin__.DbShowBSSIDList.append (tmpList[1])
                                    DbMatchBSSIDCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="3" and str(tmpList[6]).upper()[-SearchLen:]==SearchVal.upper():
                                if str(__builtin__.ShowBSSIDList2).find(tmpList[1])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[1])==-1:
                                    __builtin__.DbShowBSSIDList.append (tmpList[1])
                                    DbMatchBSSIDCt += 1
                                    ToDisplay=1
                            if ToDisplay==1:
                                print tabspacefull + fcolor.SGreen + "Found Match in DB : " + fcolor.SWhite + str(tmpList[1]) + fcolor.SGreen + " (BSSID)"
                        if len(tmpList[0])==17:
                            ToDisplay = 0
                            if __builtin__.SearchType=="0" and str(tmpList[6]).upper()==SearchVal.upper():
                                if str(__builtin__.ShowStationList2).find(tmpList[0])==-1  and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                    __builtin__.DbShowStationList.append (tmpList[0])
                                    DbMatchStationCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="1" and str(tmpList[6]).upper().find(SearchVal.upper())!=-1:
                                if str(__builtin__.ShowStationList2).find(tmpList[0])==-1 and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                    __builtin__.DbShowStationList.append (tmpList[0])
                                    DbMatchStationCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="2" and str(tmpList[6]).upper()[:SearchLen]==SearchVal.upper():
                                if str(__builtin__.ShowStationList2).find(tmpList[0])==-1 and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                    __builtin__.DbShowStationList.append (tmpList[0])
                                    DbMatchStationCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="3" and str(tmpList[6]).upper()[-SearchLen:]==SearchVal.upper():
                                if str(__builtin__.ShowStationList2).find(tmpList[0])==-1 and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                    __builtin__.DbShowStationList.append (tmpList[0])
                                    DbMatchStationCt += 1
                                    ToDisplay=1
                            if ToDisplay==1:
                                print tabspacefull + fcolor.SGreen + "Found Match in DB : " + fcolor.SWhite + str(tmpList[0]) + fcolor.SGreen + " (STATION)"
        if IsFileDirExist(DBFile4)=="F":
	    with open(DBFile4,"r") as f:
                next(f)
    	        for line in f:
                    line=line.replace("\n","")
                    tmpList=str(line).split(";")
                    if len(tmpList)>=3:
                        ToDisplay = 0
                        if __builtin__.SearchType=="0" and str(tmpList[2]).upper()==SearchVal.upper():
                            if str(__builtin__.ShowStationList2).find(tmpList[0])==-1 and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                __builtin__.DbShowStationList.append (tmpList[0])
                                DbMatchStationCt += 1
                                ToDisplay=1
                        if __builtin__.SearchType=="1" and str(tmpList[2]).upper().find(SearchVal.upper())!=-1:
                            if str(__builtin__.ShowStationList2).find(tmpList[0])==-1  and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                __builtin__.DbShowStationList.append (tmpList[0])
                                DbMatchStationCt += 1
                                ToDisplay=1
                        if __builtin__.SearchType=="2" and str(tmpList[2]).upper()[:SearchLen]==SearchVal.upper():
                            if str(__builtin__.ShowStationList2).find(tmpList[0])==-1 and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                __builtin__.DbShowStationList.append (tmpList[0])
                                DbMatchStationCt += 1
                                ToDisplay=1
                        if __builtin__.SearchType=="3" and str(tmpList[2]).upper()[-SearchLen:]==SearchVal.upper():
                            if str(__builtin__.ShowStationList2).find(tmpList[0])==-1 and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                __builtin__.DbShowStationList.append (tmpList[0])
                                DbMatchStationCt += 1
                                ToDisplay=1
                        if ToDisplay==1:
                            print tabspacefull + fcolor.SGreen + "Found Match in DB : " + fcolor.SWhite + str(tmpList[0]) + fcolor.SGreen + " (STATION)"
        if IsFileDirExist(DBFile1)=="F":
	    with open(DBFile1,"r") as f:
                next(f)
    	        for line in f:
                    line=line.replace("\n","")
                    tmpList=str(line).split(";")
                    if len(tmpList)>=6:
                        if len(tmpList[1])==17:
                            ToDisplay = 0
                            if __builtin__.SearchType=="0" and str(tmpList[5]).upper()==SearchVal.upper():
                                if str(__builtin__.ShowBSSIDList2).find(tmpList[1])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[1])==-1:
                                    __builtin__.DbShowBSSIDList.append (tmpList[1])
                                    DbMatchBSSIDCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="1" and str(tmpList[5]).upper().find(SearchVal.upper())!=-1:
                                if str(__builtin__.ShowBSSIDList2).find(tmpList[1])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[1])==-1:
                                    __builtin__.DbShowBSSIDList.append (tmpList[1])
                                    DbMatchBSSIDCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="2" and str(tmpList[5]).upper()[:SearchLen]==SearchVal.upper():
                                if str(__builtin__.ShowBSSIDList2).find(tmpList[1])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[1])==-1:
                                    __builtin__.DbShowBSSIDList.append (tmpList[1])
                                    DbMatchBSSIDCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="3" and str(tmpList[5]).upper()[-SearchLen:]==SearchVal.upper():
                                if str(__builtin__.ShowBSSIDList2).find(tmpList[1])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[1])==-1:
                                    __builtin__.DbShowBSSIDList.append (tmpList[1])
                                    DbMatchBSSIDCt += 1
                                    ToDisplay=1
                            if ToDisplay==1:
                                print tabspacefull + fcolor.SGreen + "Found Match in DB : " + fcolor.SWhite + str(tmpList[1]) + fcolor.SGreen + " (BSSID)"
                        if len(tmpList[0])==17:
                            ToDisplay = 0
                            if __builtin__.SearchType=="0" and str(tmpList[5]).upper().upper()==SearchVal.upper():
                                if str(__builtin__.ShowStationList2).find(tmpList[0])==-1  and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                    __builtin__.DbShowStationList.append (tmpList[0])
                                    DbMatchStationCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="1" and str(tmpList[5]).upper().find(SearchVal.upper())!=-1:
                                if str(__builtin__.ShowStationList2).find(tmpList[0])==-1 and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                    __builtin__.DbShowStationList.append (tmpList[0])
                                    DbMatchStationCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="2" and str(tmpList[5]).upper()[:SearchLen]==SearchVal.upper():
                                if str(__builtin__.ShowStationList2).find(tmpList[0])==-1 and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                    __builtin__.DbShowStationList.append (tmpList[0])
                                    DbMatchStationCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="3" and str(tmpList[5]).upper()[-SearchLen:]==SearchVal.upper():
                                if str(__builtin__.ShowStationList2).find(tmpList[0])==-1 and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                    __builtin__.DbShowStationList.append (tmpList[0])
                                    DbMatchStationCt += 1
                                    ToDisplay=1
                            if ToDisplay==1:
                                print tabspacefull + fcolor.SGreen + "Found Match in DB : " + fcolor.SWhite + str(tmpList[0]) + fcolor.SGreen + " (STATION)"
    if DbMatchBSSIDCt>0 or DbMatchStationCt>0:
        printc ("+",fcolor.SWhite + "Duplication from active listing will be ignored.","")
        if DbMatchBSSIDCt>0:
            printc ("i","Total BSSID Matched in Database   : " + fcolor.BRed + str(DbMatchBSSIDCt),"")
        if DbMatchStationCt>0:
            printc ("i","Total Station Matched in Database : " + fcolor.BRed + str(DbMatchStationCt),"")
        print ""
        printc ("x","Press any key to display the listing detail...","")
    else:
        printc ("+",fcolor.SWhite + "Duplication from active listing will be ignored.","")
        if SELECTTYPE=="MAC":
            printc ("!!","The specified MAC address was not found in database files !!!","")
        if SELECTTYPE=="NAME":
            printc ("!!","The specified Name was not found in database files !!!","")
        DrawLine("_",fcolor.CReset + fcolor.Black,""); print ""
        return;
    if DbMatchBSSIDCt>0:
        x=0
        CenterText(fcolor.BWhite + fcolor.BGBlue, "MATCHED ACCESS POINT LISTING [ " + str(len(__builtin__.DbShowBSSIDList)) + " ] FROM DATABASE")
        while x<len(DbShowBSSIDList):
            CenterText(fcolor.BBlack + fcolor.BGWhite, "ACCESS POINT MAC ADDRESS [ " + str(DbShowBSSIDList[x]) + "] DETAILED INFORMATION FROM DATABASE - RECORD " + str(x + 1) + "/" + str(len(__builtin__.DbShowBSSIDList)))
            print ""
            DisplayMACDetailFromFiles(DbShowBSSIDList[x])
            x += 1
    if DbMatchStationCt>0:
        x=0
        CenterText(fcolor.BWhite + fcolor.BGBlue, "MATCHED STATION LISTING [ " + str(len(__builtin__.DbShowStationList)) + " ] FROM DATABASE")
        while x<len(DbShowStationList):
            CenterText(fcolor.BBlack + fcolor.BGWhite, "STATION MAC ADDRESS [ " + str(DbShowStationList[x]) + "] DETAILED INFORMATION FROM DATABASE - RECORD " + str(x+1) + "/" + str(len(__builtin__.DbShowStationList)))
            print ""
            DisplayMACDetailFromFiles(DbShowStationList[x])
            x += 1

def DisplayMACDetailFromFiles (MACAddr):
    MAC_OUI=Check_OUI(MACAddr)
    tmpList=[]
    AsClientText=""
    AsAPText=""
    TimeColor=fcolor.SGreen
    ESSIDColor=fcolor.BPink
    BSSIDColor=fcolor.BRed
    RptColor=fcolor.SCyan
    OthColor=fcolor.BGreen
    LF = "\n"
    if IsFileDirExist(DBFile1)=="F":
        RecCt=0;DisplayText=""
	with open(DBFile1,"r") as f:
            next(f)
	    for line in f:
                line=line.replace("\n","")
                tmpList=str(line).split(";")
                if len(tmpList)>=6:
                    if tmpList[0]==MACAddr:
                        RecCt += 1
                        ESSID=tmpList[5]
                        if ESSID=="":
                            ESSID=fcolor.IGray + "<<NO ESSID>>"
                        DText=InsNum(RecCt) + StdColor + "MAC ID [ " + SelColor + str(tmpList[0]) + StdColor + " ] is both a Station & Access Point [ " + ESSIDColor + str(ESSID) + StdColor + " ] on " + TimeColor + str(tmpList[2]) + StdColor + " as Access Point."
                        RecDetail="Recorded " + str(tmpList[4])
                        RC=int(RightEnd(DText))
                        DisplayText=DisplayText + DText + RptColor +  str(RecDetail).rjust(RC) + LF
                        if len(tmpList[1])==17:
                            DisplayText=DisplayText + tabspacefull + StdColor + "The MAC is also found to be associated to Access Point [ " + BSSIDColor + str(tmpList[1]) + StdColor + " ] as a wireless client on " + TimeColor + str(tmpList[3]) + LF
                        else:
                            DisplayText=DisplayText + tabspacefull + StdColor + "The MAC was not found to be associated with any Access Point as on " + TimeColor + str(tmpList[3]) + LF
        if DisplayText!="":
            DisplayText = fcolor.BBlue + "Access Point & Station (History)\n" + fcolor.CReset + DisplayText
            print DisplayText 
    if IsFileDirExist(DBFile6)=="F":
        RecCt=0;RecCt2=0;DisplayText="";DisplayText2=""
	with open(DBFile6,"r") as f:
            next(f)
	    for line in f:
                line=line.replace("\n","")
                tmpList=str(line).split(";")
                if len(tmpList)>=5:
                    if tmpList[0]==MACAddr:
                        RecCt += 1
                        RecDetail="Recorded " + str(tmpList[3])
                        DText=InsNum(RecCt) + StdColor +   "MAC ID [ " + SelColor + str(tmpList[0]) + StdColor + "] ==> Initally connected to MAC [ " + fcolor.BBlue + str(tmpList[1]) + StdColor + " ] ESSID [ " + fcolor.BBlue + str(tmpList[4]) + StdColor +  " ]"
                        RC=int(RightEnd(DText))
                        DisplayText=DisplayText + DText + RptColor +  str(RecDetail).rjust(RC) + LF
                        DText=StdColor + "\t\t\t\t  ==> Subsequently to MAC       [ " + fcolor.BRed + str(tmpList[2]) + StdColor + " ] ESSID [ " + fcolor.BRed + str(tmpList[5]) + StdColor +  " ]"
                        DisplayText=DisplayText + DText  + LF
        if DisplayText!="":
            AsClientText = AsClientText + DisplayText + LF
    if IsFileDirExist(DBFile2)=="F":
        RecCt=0;DisplayText=""
	with open(DBFile2,"r") as f:
            next(f)
	    for line in f:
                line=line.replace("\n","")
                tmpList=str(line).split(";")
                if len(tmpList)>=18:
                    if tmpList[0]==MACAddr:
                        RecCt += 1
                        RecDetail="Recorded " + str(tmpList[17])
                        ENRICHED=str(tmpList[1])
                        if ENRICHED=="Yes":
                            ENRICHED=fcolor.BRed + " *"
                        else:
                            ENRICHED=fcolor.BRed + "  "
                        BSSID=SelColor + str(tmpList[0]) + ENRICHED
                        ESSID=ESSIDColor + str(tmpList[18])
                        MODE=OthColor + str(tmpList[2])
                        FIRSTSEEN=RptColor +str(tmpList[3])
                        LASTSEEN=RptColor +str(tmpList[4])
                        CHANNEL=OthColor +str(tmpList[5])
                        PRIVACY=OthColor + str(tmpList[6]) + " / " + str(tmpList[7]) + " / " + str(tmpList[8])
                        RATES=str(OthColor + "Max : " + OthColor + str(tmpList[9]) + " Mb/s" + StdColor + " [" + fcolor.SGreen + str(tmpList[10]) + StdColor + "]").replace(" | ", StdColor + " | " + fcolor.SGreen)
                        SIGNAL=OthColor + str(tmpList[11])
                        GPS=OthColor + str(tmpList[12]) + StdColor + " / " + OthColor + str(tmpList[13]) + StdColor + " / " + OthColor + str(tmpList[14])
                        WPS=OthColor + str(tmpList[15]) + StdColor + " / " + OthColor + str(tmpList[16]) 
                        DText=InsNum(RecCt) + StdColor +  "BSSID      : " + str(BSSID) + "    " + StdColor +   "ESSID      : " + str(ESSID).ljust(35) + StdColor +    "MODE  : " + str(MODE).ljust(25) + StdColor +  "WPS : " + str(WPS)
                        RC=int(RightEnd(DText))
                        DisplayText=DisplayText + DText + RptColor +  str(RecDetail).rjust(RC) + LF
                        DText=tabspacefull + StdColor +   "Channel    : " + str(CHANNEL).ljust(30) + StdColor + "Privacy    : " + str(PRIVACY).ljust(35) + StdColor +  "Power : " + str(SIGNAL) + " dBm" + LF
                        DisplayText=DisplayText + DText 
                        DText=tabspacefull + StdColor +   "Bit Rates  : " + str(RATES) + LF
                        DisplayText=DisplayText + DText 
                        DText=tabspacefull + StdColor +   "First Seen : " + str(FIRSTSEEN).ljust(75) + StdColor + "Last Seen : " + str(LASTSEEN) + LF
                        DisplayText=DisplayText + DText 
                        DText=tabspacefull + StdColor +   "Lon/Lat/Alt: " + str(GPS) + LF
                        DisplayText=DisplayText + DText + LF
        if DisplayText!="":
            AsAPText = AsAPText + DisplayText 
#    if IsFileDirExist(DBFile5)=="F":
#        RecCt=0;RecCt2=0;DisplayText="";DisplayText2=""
#	with open(DBFile5,"r") as f:
#            next(f)
#	    for line in f:
#                line=line.replace("\n","")
#                tmpList=str(line).split(";")
#                if len(tmpList)>=3:
#                    ESSID=tmpList[2]
#                    if ESSID=="":
#                        ESSID=fcolor.IGray + "<<NO ESSID>>"
#
#                    if tmpList[0]==MACAddr:
#                        RecCt += 1
#                        DisplayText=DisplayText + InsNum(RecCt) + StdColor +    "MAC ID [ " + SelColor + str(tmpList[0]) + StdColor + " ] has connected to BSSID [ " + BSSIDColor + str(tmpList[1]) + StdColor + "] ESSID [ " + ESSIDColor + str(ESSID) + StdColor + " ] before." + LF
#                    if tmpList[1]==MACAddr:
#                        RecCt2 += 1
#                        DisplayText2=DisplayText2 + InsNum(RecCt2) + StdColor + "MAC ID [ " + SelColor + str(tmpList[1]) + StdColor + " ] ESSID [ " + ESSIDColor +  str(ESSID) + StdColor + "] was connected by Client MAC [ " + BSSIDColor + str(tmpList[0]) + StdColor + " ] before." + LF
#        if DisplayText!="":
#            AsClientText = AsClientText + DisplayText + LF
#        if DisplayText2!="":
#            AsAPText = AsAPText + DisplayText2 + LF
    if IsFileDirExist(DBFile3)=="F":
        RecCt=0;RecCt2=0;DisplayText="";DisplayText2=""
	with open(DBFile3,"r") as f:
            next(f)
	    for line in f:
                line=line.replace("\n","")
                tmpList=str(line).split(";")
                if len(tmpList)>=7:
                    Signal=StdColor + " - Signal : " + OthColor + str(tmpList[4]) + " dBm"
                    ESSID=tmpList[6]
                    if ESSID=="":
                        ESSID=fcolor.IGray + "<<NO ESSID>>"

                    if tmpList[0]==MACAddr:
                        RecCt += 1
                        if tmpList[1]=="Not Associated":
                            DText=InsNum(RecCt) + StdColor + "MAC ID [ " + SelColor + str(tmpList[0]) + StdColor +  " ] was not associated to any Access Point." + str(Signal) 
                            RecDetail="Recorded " + str(tmpList[5])
                            RC=int(RightEnd(DText))
                            DisplayText=DisplayText + DText + RptColor +  str(RecDetail).rjust(RC) + LF
                            DisplayText=DisplayText
                        else:
                            DText=InsNum(RecCt) + StdColor +   "MAC ID [ " + SelColor + str(tmpList[0]) + StdColor +  " ] has associated to Access Point [ " + BSSIDColor + tmpList[1] + StdColor + " ] ESSID [ " + ESSIDColor + str(ESSID) + StdColor + " ]" + str(Signal) + StdColor + " before."
                            RecDetail="Recorded " + str(tmpList[5])
                            RC=int(RightEnd(DText))
                            DisplayText=DisplayText + DText + RptColor +  str(RecDetail).rjust(RC) + LF

                    if tmpList[1]==MACAddr:
                        RecCt2 += 1
                        DText=InsNum(RecCt2) + StdColor + "Client MAC [ " + BSSIDColor + tmpList[0] + StdColor + " ] was connected to MAC [ " + SelColor + str(tmpList[1]) + StdColor + " ] ESSID [ " + ESSIDColor + str(ESSID) + StdColor + " ]" + str(Signal) 
                        RecDetail="Recorded " + str(tmpList[5])
                        RC=int(RightEnd(DText))
                        DisplayText2=DisplayText2 + DText + RptColor +  str(RecDetail).rjust(RC) + LF

        if DisplayText!="":
            AsClientText = AsClientText + DisplayText + LF
        if DisplayText2!="":
            AsAPText = AsAPText + DisplayText2 + LF
    if IsFileDirExist(DBFile4)=="F":
        RecCt=0;RecCt2=0;DisplayText="";DisplayText2=""
	with open(DBFile4,"r") as f:
            next(f)
	    for line in f:
                line=line.replace("\n","")
                tmpList=str(line).split(";")
                if len(tmpList)>=3:
                    if tmpList[0]==MACAddr:
                        RecCt += 1
                        RecDetail="Recorded " + str(tmpList[1])
                        DText=InsNum(RecCt) + StdColor +   "MAC ID [ " + SelColor + str(tmpList[0]) + StdColor + "] ==> " + fcolor.BBlue + "Probe " + StdColor + "[ " + fcolor.BPink + str(tmpList[2]) + StdColor +  " ]" 
                        RC=int(RightEnd(DText))
                        DisplayText=DisplayText + DText + RptColor +  str(RecDetail).rjust(RC) + LF
        if DisplayText!="":
            AsClientText = AsClientText + DisplayText + LF
    if AsAPText!="":
        CenterText(fcolor.BIGray, "As Access Point (History Logs)     ")
        DrawLine("v",fcolor.CReset + fcolor.Black,""); print ""
        AsAPText=AsAPText[:-2]
        print AsAPText
        DrawLine("_",fcolor.CReset + fcolor.Black,""); print ""
    if AsClientText!="":
        CenterText(fcolor.BIGray, "As Wireless Station (History Logs)     ")
        DrawLine("v",fcolor.CReset + fcolor.Black,""); print ""
        AsClientText=AsClientText[:-2]
        print AsClientText
        DrawLine("_",fcolor.CReset + fcolor.Black,""); print ""

def RightEnd(StrVal):
    curses.setupterm()
    TWidth=curses.tigetnum('cols')
    TWidth=TWidth-1
    SL = len(RemoveColor(StrVal))
    RL = int(TWidth) - SL 
    return int(RL)



################################
#          Configuration       #
################################
__builtin__.STxt=fcolor.BRed
__builtin__.NTxt=fcolor.BYellow
__builtin__.col=";"
ColorStd=fcolor.SGreen
ColorStd2=fcolor.SWhite
ColorDev=fcolor.BBlue
Color1st=fcolor.BCyan
Color2nd=fcolor.BRed
SelColor=fcolor.BYellow
SelBColor=fcolor.BRed
StdColor=fcolor.SWhite
InfoColor=fcolor.SWhite
lblColor=fcolor.BGreen
txtColor=fcolor.SGreen
VendorColor=fcolor.Cyan
__builtin__.REMOVE_AFTER_MIN = 1
__builtin__.RemoveAfterSec = 60
__builtin__.HIDE_INACTIVE_SSID="Yes"
__builtin__.HIDE_INACTIVE_STN="Yes"
__builtin__.NETWORK_VIEW="4"   
__builtin__.ALERTSOUND="No"
__builtin__.TIMEOUT=20
__builtin__.TIMES_BEFORE_UPDATE_AP_DB=10
__builtin__.TIMES_BEFORE_UPDATE_STN_DB=5
__builtin__.UPDATE_STN_COUNT=0
__builtin__.TimeStart=""
__builtin__.TimeEnd=""
appdir="/SYWorks/WiFi-Harvester/"
dbdir="/SYWorks/Database/"
tmpdir=appdir + "tmp/"
PathList = ['tmp/']

__builtin__.FilenameHeader="NH-"
__builtin__.ConfigFile=appdir + "config.ini"
__builtin__.MonitorMACfile=dbdir + "MonitorMAC.ini"
__builtin__.MACOUI=dbdir + "mac-oui.db"
CautiousLog=dbdir + FilenameHeader + "Cautious.log"

DBFile1=dbdir + FilenameHeader + "APnStation.db"
DBFile2=dbdir + FilenameHeader + "AccessPoint.db"
DBFile3=dbdir + FilenameHeader + "Station.db"
DBFile4=dbdir + FilenameHeader + "Probes.db"
DBFile5=dbdir + FilenameHeader + "ConnectHistory.db"
DBFile6=dbdir + FilenameHeader + "SwitchedAP.db"

__builtin__.SELECTED_MANIFACE_MAC=[]
__builtin__.SELECTED_MON_MAC=[]
__builtin__.MonitoringMACList=[]
__builtin__.ScriptName=os.path.basename(__file__)
__builtin__.RequiredFiles=['tshark', 'airodump-ng', 'aireplay-ng','aircrack-ng','iwconfig', 'ifconfig', 'xterm']
__builtin__.Captured_CSV=tmpdir + "Collect-Dump-01.csv"
__builtin__.NewCaptured_CSV=tmpdir + "Dumps.csv"
__builtin__.SSID_CSV=tmpdir + "Dumps-SSID.csv"
__builtin__.Client_CSV=tmpdir + "Dumps-Client.csv"
__builtin__.Captured_Kismet=tmpdir + "Collect-Dump-01.kismet.csv"
__builtin__.NewCaptured_Kismet=tmpdir + "Dumps-kismet.csv"
__builtin__.WPS_DUMP=tmpdir + "WPS-Dump"
__builtin__.TMP_IWList_DUMP=tmpdir + "SSID.tmp"
__builtin__.IWList_DUMP=tmpdir + "SSID"
__builtin__.ERRORFOUND=0
__builtin__.Infrastructure_DumpList = []
__builtin__.Client_DumpList = []
__builtin__.ListInfo_BSSIDTimes = []
__builtin__.ListInfo_ESSID = []
__builtin__.ListInfo_BSSID = []
__builtin__.ListInfo_Channel = []
__builtin__.ListInfo_Cloaked = []
__builtin__.ListInfo_Privacy = []
__builtin__.ListInfo_Cipher = []
__builtin__.ListInfo_Auth = []
__builtin__.ListInfo_MaxRate = []
__builtin__.ListInfo_Beacon = []
__builtin__.ListInfo_Data = []
__builtin__.ListInfo_Total = []
__builtin__.ListInfo_FirstSeen = []
__builtin__.ListInfo_LastSeen = []
__builtin__.ListInfo_BestQuality = []
__builtin__.ListInfo_QualityRange = []
__builtin__.ListInfo_QualityPercent = []
__builtin__.ListInfo_BestSignal = []
__builtin__.ListInfo_BestNoise = []
__builtin__.ListInfo_GPSBestLat = []
__builtin__.ListInfo_GPSBestLon = []
__builtin__.ListInfo_GPSBestAlt = []
__builtin__.ListInfo_HiddenSSID = []
__builtin__.ListInfo_BSSID_OUI = []
__builtin__.ListInfo_ConnectedClient = []
__builtin__.ListInfo_Enriched = []
__builtin__.ListInfo_Freq = []
__builtin__.ListInfo_Quality = []
__builtin__.ListInfo_Signal = []
__builtin__.ListInfo_BitRate = []
__builtin__.ListInfo_WPAVer = []
__builtin__.ListInfo_PairwiseCipher = []
__builtin__.ListInfo_GroupCipher = []
__builtin__.ListInfo_AuthSuite = []
__builtin__.ListInfo_LastBeacon = []
__builtin__.ListInfo_Mode = []
__builtin__.ListInfo_EncKey = []
__builtin__.ListInfo_CESSID = []
__builtin__.ListInfo_COUI = []
__builtin__.ListInfo_CElapse = []
__builtin__.ListInfo_SSIDElapse = []
__builtin__.ListInfo_SSIDTimeGap = []
__builtin__.ListInfo_SSIDTimeGapFull = []
__builtin__.ListInfo_CFirstSeen = []
__builtin__.ListInfo_CLastSeen = []
__builtin__.ListInfo_STATION = []
__builtin__.ListInfo_CBSSID = []
__builtin__.ListInfo_CBSSIDPrev = []
__builtin__.ListInfo_CBSSIDPrevList = []
__builtin__.ListInfo_CBestQuality = []
__builtin__.ListInfo_CQualityRange = []
__builtin__.ListInfo_CQualityPercent = []
__builtin__.ListInfo_CPackets = []
__builtin__.ListInfo_PROBE = []
__builtin__.ListInfo_CTimeGap = []
__builtin__.ListInfo_CTimeGapFull = []
__builtin__.ListInfo_WPS = []
__builtin__.ListInfo_WPSVer = []
__builtin__.ListInfo_WPSLock = []
__builtin__.ListInfo_Exist = 0
__builtin__.ListInfo_Add = 0
__builtin__.ListInfo_CExist = 0
__builtin__.ListInfo_CAdd = 0
__builtin__.ListInfo_UnassociatedCount = 0
__builtin__.ListInfo_AssociatedCount = 0
__builtin__.ListInfo_ProbeCount = 0
__builtin__.ListInfo_WPSExist = 0
__builtin__.ListInfo_WPSAdd = 0
__builtin__.ListInfo_WPSCount = 0
__builtin__.MONList = []
__builtin__.MONListC = []
__builtin__.DumpProc=""
__builtin__.DumpProcPID=""
__builtin__.WashProc=""
__builtin__.IWListProc=""
__builtin__.WashProcPID=""
__builtin__.NETWORK_FILTER="ALL"
__builtin__.NETWORK_SIGNAL_FILTER="ALL"
__builtin__.NETWORK_CHANNEL_FILTER="ALL"
__builtin__.NETWORK_WPS_FILTER="ALL"
__builtin__.NETWORK_CLIENT_FILTER="ALL"
__builtin__.NETWORK_PROBE_FILTER="ALL"
__builtin__.NETWORK_UPROBE_FILTER="ALL"
__builtin__.NETWORK_ASSOCIATED_FILTER="ALL"
__builtin__.NETWORK_UNASSOCIATED_FILTER="ALL"
__builtin__.NETWORK_CSIGNAL_FILTER="ALL"
__builtin__.NETWORK_UCSIGNAL_FILTER="ALL"
__builtin__.MSG_HistoryConnection=""
__builtin__.ShowBSSIDList = []
__builtin__.ShowStationList = []
__builtin__.SearchLen=""
__builtin__.DisplayNetworkFilter=""
__builtin__.DisplayClientFilter=""
__builtin__.DisplayUnassocFilter=""
__builtin__.DisplayAllFilter=""
__builtin__.AP_BSSIDList=[]
__builtin__.AP_FREQList=[]
__builtin__.AP_QUALITYList=[]
__builtin__.AP_SIGNALList=[]
__builtin__.AP_ENCKEYList=[]
__builtin__.AP_ESSIDList=[]
__builtin__.AP_MODEList=[]
__builtin__.AP_CHANNELList=[]
__builtin__.AP_ENCTYPEList=[]



if __name__ == '__main__':
    try:
        __builtin__.PrintToFile=""
        __builtin__.tabspace="   "
        __builtin__.tabspacefull="      "
        __builtin__.DEBUG=0
        Main()

    except KeyboardInterrupt: print '\n (^C) interrupted\n'
    except EOFError:          print '\n (^D) interrupted\n'
    exit_gracefully(0)

