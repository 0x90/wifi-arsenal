#! /usr/bin/python
#
# This was written for educational purpose only. Use it at your own risk.
# Author will be not responsible for any damage!
# Written By SY Chua, syworks@gmail.com
#

appver="1.0, R.9"
apptitle="WIDS"
appDesc="- The Wireless Intrusion Detection System"
appcreated="07 Jan 2014"
appupdated="26 Feb 2014"
appnote="by SY Chua, " + appcreated + ", Updated " + appupdated



import sys,os
import subprocess
import random
import curses
from subprocess import call
import termios
import tty
import time
import signal
import select 
import datetime
import ssl
import os.path
import binascii, re
import commands
from subprocess import Popen, PIPE
import threading

##################################
#  Global Variables Declaration  #
##################################
global RTY
RTY=""

def CheckAdmin():
    is_admin = os.getuid() == 0
    if is_admin==False:
        printc ("!!!","Application required admin rights in-order to work properly !","")
        exit(1)

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
    pcolor=fcolor.BGreen
    tcolor=fcolor.SGreen
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

    firstsixa=""
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
            firstsixa=firstsix
            if firstsix=="<$rs$>":
                ReturnOut="1"
                lptext=lptext-6
                ptext=ptext[-lptext:]
    if PrintToFile=="1" and ptype!="@" and ptype!="x" and ptype!="@^" and firstsixa!="<$rs$>":
        ptypep=ptype
        if ptypep=="  " or ptypep==" ":
            ptypep="     "
        else:
            ptypep="[" + ptype + "]  "
        open(LogFile,"a+b").write(RemoveColor(ptypep) + RemoveColor(str(ptext.lstrip().rstrip())) + "\n")
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

    github="https://github.com/SYWorks/wireless-ids.git"
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
    printc ("!!!","Legal  Disclaimer :- " + fcolor.Red + "FOR EDUCATIONAL PURPOSES ONLY !!","")
    print fcolor.SWhite + " Usage of this application for attacking target without prior mutual consent is illegal. It is the"
    print fcolor.SWhite + " end user's responsibility to obey all applicable local, state and  federal laws. Author assume no"
    print fcolor.SWhite + " liability and are not responsible for any misuse or damage caused by this application."
    print ""

def DisplayFullDescription():
    print fcolor.BRed + " Description : "
    print fcolor.SGreen + " This a a beta release and reliablity of the information might not be totally accurate.."
    print fcolor.SWhite + " This application sniff the surrounding wireless network for any suspicious packets detected such as high amount of"
    print fcolor.SWhite + " association/authentication packets, suspicious data sent via broadcast address, unreasonable high amount of deauth"
    print fcolor.SWhite + " packets or EAP association  packets  which  in the other way indicated possible way indicated possible WEP/WPA/WPS"
    print fcolor.SWhite + " attacks found.."
    print fcolor.BWhite + " New !! " + fcolor.SWhite + "Detecting connected client for possible Rogue AP"
    print ""

def DisplayDescription():
    print fcolor.BRed + "Description : "
    print fcolor.SWhite + " This application sniff your surrounding wireless traffic and analyse for suspicious packets such as"
    print fcolor.SWhite + " WEP/WPA/WPS attacks, wireless client switched to another access point, detection of possible Rogue AP,"
    print fcolor.SWhite + " displaying AP with the same name and much more.. "
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
    print fcolor.BWhite + "    -l  --loop" + fcolor.BBlue + " <arg>\t" + fcolor.CReset + fcolor.White + "- Run the number of loop before exiting"
    print fcolor.BWhite + "    -i  --iface" + fcolor.BBlue + " <arg>\t" + fcolor.CReset + fcolor.White + "- Set Interface to use"
    print fcolor.BWhite + "    -t  --timeout" + fcolor.BBlue + " <arg>\t" + fcolor.CReset + fcolor.White + "- Duration to capture before analysing the captured data"
    print fcolor.BWhite + "    -hp --hidepropbe" + fcolor.BBlue + "\t" + fcolor.CReset + fcolor.White + "- Hide displaying of Probing devices."
    print fcolor.BWhite + "    -la --log-a" + fcolor.BBlue + " \t" + fcolor.CReset + fcolor.White + "- Append to current scanning log detail"
    print fcolor.BWhite + "    -lo --log-o" + fcolor.BBlue + " \t" + fcolor.CReset + fcolor.White + "- Overwrite existing scanning logs"
    print fcolor.BWhite + "        --log" + fcolor.BBlue + "\t\t" + fcolor.CReset + fcolor.White + "- Similar to --log-o"

    print ""
    print fcolor.BGreen + "Examples: " + fcolor.BYellow + "" + DScriptName + fcolor.BWhite + " --update"
    print fcolor.BGreen + "          " + fcolor.BYellow + "" + DScriptName + fcolor.BWhite + " -i " + fcolor.BBlue + "wlan0" + fcolor.BWhite + " -t " + fcolor.BBlue + "120"+ fcolor.BWhite
    print fcolor.BGreen + "          " + fcolor.BYellow + "" + DScriptName + fcolor.BWhite + " --loop " + fcolor.BBlue + "10" + fcolor.BWhite + " --timeout " + fcolor.BBlue + "30"+ fcolor.BWhite
    print fcolor.BGreen + "          " + fcolor.BYellow + "" + DScriptName + fcolor.BWhite + " --iface " + fcolor.BBlue + "wlan1" + fcolor.BWhite + " --timeout " + fcolor.BBlue + "20"+ fcolor.BWhite

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
    print fcolor.BWhite + "    -hp --hidepropbe" + fcolor.BBlue + "\t" + fcolor.CReset + fcolor.White + "- Hide displaying of Probing devices."

    print ""
    print fcolor.BGreen + "Examples: " + fcolor.BYellow + "" + DScriptName + fcolor.BWhite + " --update"
    print fcolor.BGreen + "          " + fcolor.BYellow + "" + DScriptName + fcolor.BWhite + " -i " + fcolor.BBlue + "wlan0" + fcolor.BWhite + " -t " + fcolor.BBlue + "120"+ fcolor.BWhite
    print fcolor.BGreen + "          " + fcolor.BYellow + "" + DScriptName + fcolor.BWhite + " --iface " + fcolor.BBlue + "wlan1" + fcolor.BWhite + " --timeout " + fcolor.BBlue + "20"+ fcolor.BWhite
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
    global PRINTTOFILE
    global ReadPacketOnly
    global LoopCount
    global TEMP_HIDEPROBE
    TEMP_HIDEPROBE="0"
    ReadPacketOnly=""
    LoopCount=99999999
    SELECTED_IFACE=""
    global SELECTED_MON
    SELECTED_MON=""
    PRINTTOFILE=""
    global TIMEOUT
    TIMEOUT=20
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
                elif arg=="-ro":
                    Err=0
                    ReadPacketOnly="1"
                elif arg=="--update":
                    Err=0
                    GetUpdate("1")
                    exit()
                elif arg=="--remove":
                    Err=0
                    UninstallApplication()
                    exit()
                elif arg=="--spoof":
                    AllArguments=AllArguments + fcolor.BWhite + "Spoof MAC\t\t:  " + fcolor.BRed + "Enabled\n"
                    SPOOF_MAC="1"
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
                                AllArguments=AllArguments + fcolor.BWhite + "Timeout (Seconds)\t:  " + fcolor.BRed + str(TIMEOUT) + "\n"
                                if float(TIMEOUT)<20:
				    AllArguments=AllArguments + fcolor.SWhite + "\t\t\t:  Timeout second set may be to low for detection.\n"
                            else:
                                printc("!!!","Invalid timeout variable set [ " + fcolor.BWhite + i2str + fcolor.BRed + " ] !","")  
                                Err=1
                        else:
                            printc("!!!","Invalid timeout variable set [ " + fcolor.BWhite + i2str + fcolor.BRed + " ] !","")  
                            Err=1
                elif arg=="-l" or arg=="--loop":
                    i=i2
                    if i2str=="":
                        printc("!!!","Invalid loopcount variable set !","")  
                        Err=1
                    else:
                        Err=0
                        if i2str[:1]!="-":
                            if i2str.isdigit():
                                LoopCount=i2str
                                if float(LoopCount)<1:
				    AllArguments=AllArguments + fcolor.SWhite + "\t\t\t:  Minimum loop count is 1.\n"
                                    LoopCount=1
                                AllArguments=AllArguments + fcolor.BWhite + "Loop Count\t\t:  " + fcolor.BRed + str(LoopCount) + "\n"

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
                            SELECTED_IFACE=i2str
                            AllArguments=AllArguments + fcolor.BWhite + "Selected interface\t:  " + fcolor.BRed + i2str + "\n"
                        else:
                            printc("!!!","Invalid Interface variable set [ " + fcolor.BWhite + i2str + fcolor.BRed + " ] !","")  
                            Err=1
                elif arg=="--hideprobe" or arg=="-hp":
                    TEMP_HIDEPROBE="1"
                    AllArguments=AllArguments + fcolor.BWhite + "Probing Devices\t\t:  " + fcolor.BRed + "Hide\n"
                    Err=0
                elif arg=="--log-a" or arg=="-la":
                    PRINTTOFILE="1"
                    AllArguments=AllArguments + fcolor.BWhite + "Result Logging\t\t:  " + fcolor.BRed + "Append\n"

                    Err=0
                elif arg=="--log-o" or arg=="-lo" or arg=="--log":
                    PRINTTOFILE="1"
                    AllArguments=AllArguments + fcolor.BWhite + "Result Logging\t\t:  " + fcolor.BRed + "Overwrite\n"
                    open(LogFile,"wb").write("")
                    Err=0
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
            if MODE=="MONITOR":
                if cmdMode=="MON":
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
            if MODE=="MASTER":
                if cmdMode=="MAS":
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
            if MODE=="AD-HOC":
                if cmdMode=="ADH":
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
            if cmdMode=="IP" and BCAST!="":
                if IPV6ADDR!="" or IPADDR!="":
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
            if cmdMode=="CON" and IPADDR!="" and GATEWAY!="" and BCAST!="":
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

            if cmdMode=="LAN" and LANMODE=="LAN":
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

            if cmdMode=="LOOP" and LANMODE=="LO":
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
    global ListingIndex
    ListingIndex=""
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

    Result = CombineListing(IFaceList, MACList,UpDownList,IEEEList,StatusList,ModeList,"","")
    if int(Result)>1:
        TitleList=['Sel','Iface','MAC Address','Up ?', 'IEEE','Status','Mode','','']
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


    Result = CombineListing(IFaceList, MACList,UpDownList,IEEEList,StatusList,"","","")
    if int(Result)>1:
        TitleList=['Sel','Iface','MAC Address','Up ?', 'IEEE','Status','','','']
        Result=QuestionFromList(TitleList, MergedSpaceList,MergedList,"Select the monitoring interface from the list","0")
        if Result=="0":
                 Result=AskQuestion(fcolor.SGreen + "You need to select a monitoring interface to use," + fcolor.BGreen + " retry ?","Y/n","U","Y","1")
                 if Result=="Y":
                     Result=SelectMonitorToUse()
                     return Result
                 else:
                     exit(0)
        Result=int(Result)-1
        SELECTED_MON=IFaceList[int(Result)]
    else:
        SELECTED_MON=IFaceList[0]
    return SELECTED_MON;

def CheckRequiredFiles():
    FCheck=Run("locate -n 3 aircrack-ng | sed -n '1p'","0")
    if FCheck=="":
        printc ("!!!","Aircrack-NG suite must be installed inorder to use the Wireless IDS !","")
	exit (0)
    FCheck=Run("locate -n 3 tshark | sed -n '1p'","0")
    if FCheck=="":
        printc ("!!!","Aircrack-NG suite must be installed inorder to use the Wireless IDS !","")
        exit (0)
    if IsFileDirExist(macoui)!="F":
        printc ("!!!","MAC OUI Database not found !","")
        printc ("  ",fcolor.SGreen + "You can download it @ " + fcolor.SBlue + "https//raw2.github.com/SYWorks/wireless-ids/master/mac-oui.db\n","")



 
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


def CaptureTraffic():
    global pid1
    pid1=""
    captured_pcap=tmpdir + "captured"
    tcpdump_log=tmpdir + "tcpdump.log"
    tcpdump_cap=tmpdir + "tcpdump.cap"
    Result=DelFile(captured_pcap + "*","0")
    Result=DelFile(tcpdump_cap + "*","0")
    TimeOut=TIMEOUT
    TimeOut=float(TIMEOUT)


    mcmd1="airodump-ng " + SELECTED_MON + " -w " + str(captured_pcap) + " > /dev/null 2>&1"
    mcmd2="tshark -i " + str(SELECTED_MON) + " -w " + str(tcpdump_cap) + " -n -t ad -a duration:" + str(TIMEOUT) +  " > /dev/null 2>&1"
    ps2=subprocess.Popen(mcmd2 , shell=True, stdout=subprocess.PIPE, preexec_fn=os.setsid)	
    ps1=subprocess.Popen(mcmd1 , shell=True, stdout=subprocess.PIPE, preexec_fn=os.setsid)	


    printc ("@",fcolor.SGreen + "Refreshing after " + fcolor.BYellow + str(TimeOut) + fcolor.SGreen + " seconds... please wait..",TimeOut)
    pid1=ps1.pid
    pid2=ps2.pid
    os.killpg(pid1, signal.SIGTERM)
    os.killpg(pid2, signal.SIGTERM)
    time.sleep(0.1)

    ts = time.time()
    DateTimeStamp=datetime.datetime.fromtimestamp(ts).strftime('%d/%m/%Y %H:%M:%S')

    if IsFileDirExist(tcpdump_cap)=="F":
        statinfo = os.stat(tcpdump_cap)
        filesize=statinfo.st_size
        if filesize<300:
            printc ("i","" + "" + fcolor.BYellow + DateTimeStamp + " - " + fcolor.SRed +  "Captured packets size is too small... please make sure the monitoring interfaceing is working ...","")
    else:
        printc ("!!!", "Couldn't find captured file.. retrying again..","")
        CaptureTraffic()


def GetMACOUI(MACAddr,Display):
    if Display=="":
        Display="1"
    Result=""
    OUI=""
    if len(MACAddr)==17:
        MACAddrO=MACAddr
        MACAddr=MACAddr.replace(":","")
        if IsFileDirExist(macoui)=="F":
            with open(macoui,'r') as rf:
                elines = rf.readlines()
                for eline in elines:
                    eline=eline.replace("\n","")
                    OUI_MAC =eline.split(' ')[0]
                    lOUI_MAC=len(OUI_MAC)
                    if len(OUI_MAC)>0:
                        if MACAddr[:lOUI_MAC] in eline:
                            lOUI_MAC=lOUI_MAC+1
                            OUI=eline[lOUI_MAC:]
                            if Display=="1":
                                printc (" ",fcolor.SWhite + "[ " +  fcolor.SGreen + str(MACAddrO) + fcolor.SWhite + " ]'s MAC OUI belongs to [ " + fcolor.SYellow + str(OUI) + fcolor.BWhite + " ].","")
                            else:
                                Result="     " + fcolor.SWhite + "[ " +  fcolor.SGreen + str(MACAddrO) + fcolor.SWhite + " ]'s MAC OUI belongs to [ " + fcolor.SYellow + str(OUI) + fcolor.BWhite + " ]."
                            return Result
        if Display=="1":
            printc (" ",fcolor.BIGray + "[ " +  fcolor.BBlue + str(MACAddrO) + fcolor.BIGray + " ]'s MAC OUI is not found in MAC OUI Database.","")     
        else:
            Result="     " + fcolor.SWhite + "[ " +  fcolor.SGreen + str(MACAddrO) + fcolor.SWhite + " ]'s MAC OUI belongs to [ " + fcolor.SYellow + str(OUI) + fcolor.BWhite + " ]."
        return Result



def GetEncryptType(AFMAC):
    Privacy=""
    captured_csv=tmpdir + "CapturedListing.csv"
    if IsFileDirExist(captured_csv)=="F" and AFMAC!="":
        ModiESSID=""
        CLIENTS=""
        with open(captured_csv,"r") as f:
            for line in f:
                line=line.replace("\n","")
                line=line.replace("\00","")
                if len(line)>10 and line.find(str(AFMAC))!=-1 and CLIENTS!=1:
                    line=line + " ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., "
                    line=line.replace("\r","")
                    CList=line.split(",")
                    FMAC=line.split()[0].replace(',','')
                    FS1=line.split()[0].replace(',','')
                    FS2=line.split()[1].replace(',','')
                    FS=str(FS1) + " " + str(FS2)
                    Privacy=CList[5].lstrip().rstrip()
                    Cipher=CList[6].lstrip().rstrip()
                    Authentication=CList[7].lstrip().rstrip()
                    Power=CList[8].lstrip().rstrip()
                    ESSID=CList[13].lstrip().rstrip().replace("\n","")
                    SMAC=CList[5].lstrip().rstrip()
                    Privacy=Privacy.replace('WPA2WPA OPN','WPA2WPA (OPN)')
                    Privacy=Privacy.replace('WPA2 OPN','WPA2 (OPN)')
                    Privacy=Privacy.replace('WPA OPN','WPA (OPN)')
                    Privacy=Privacy.replace('WPA2WPA','WPA2/WPA')
                    Privacy=Privacy.replace('WEP OPN','WEP (OPN)')
                    Cipher=Cipher.replace('CCMP TKIP','CCMP/TKIP')
                    CLIENTS=1
    return Privacy


def GetMACDetail(FrMAC,ToMAC,AType,PDisplay):
    global CList
    CList=[]
    global Privacy
    global Cipher
    Privacy=""
    PrivacyBK=""
    Cipher=""
    CipherBK=""
    AuthenticationBK=""
    global MACDetail
    MACResult=""
    MACDetail=""
    CLIENTS=0
    captured_csv=tmpdir + "CapturedListing.csv"
    ESSID_log=tmpdir + "ESSID.log"
    essidfile=tmpdir + "essidcount.log"
    ESSIDCt=[]



    if IsFileDirExist(captured_csv)=="F":
        ModiESSID=""
        with open(captured_csv,"r") as f:
            for line in f:
                line=line.replace("\n","")
                line=line.replace("\00","")
                if len(line)>10:
                    line=line + " ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., "
                    line=line.replace("\r","")
                    CList=line.split(",")
                    FMAC=line.split()[0].replace(',','')
                    FS1=line.split()[0].replace(',','')
                    FS2=line.split()[1].replace(',','')
                    FS=str(FS1) + " " + str(FS2)
                    Privacy=CList[5].lstrip().rstrip()
                    Cipher=CList[6].lstrip().rstrip()
                    Authentication=CList[7].lstrip().rstrip()
                    Power=CList[8].lstrip().rstrip()
                    ESSID=CList[13].lstrip().rstrip().replace("\n","")
                    SMAC=CList[5].lstrip().rstrip()
                    Privacy=Privacy.replace('WPA2WPA OPN','WPA2WPA (OPN)')
                    Privacy=Privacy.replace('WPA2 OPN','WPA2 (OPN)')
                    Privacy=Privacy.replace('WPA OPN','WPA (OPN)')
                    Privacy=Privacy.replace('WPA2WPA','WPA2/WPA')
                    Privacy=Privacy.replace('WEP OPN','WEP (OPN)')
                    Cipher=Cipher.replace('CCMP TKIP','CCMP/TKIP')

                    if FS=="Station MAC":
                        CLIENTS=1
 
                     




                    if len(FMAC)==17:
                        if AType=="RAP":
                            MAXCt=0
                            MAXName=""
                            with open(essidfile,'r+') as rf:
                                elines =  rf.readlines()
                                rf.seek(0)
                                rf.truncate()
                                for eline in elines:
                                    eline=eline.replace("\n","")
                                    if FrMAC in eline:
                                        ED_MAC =eline.split(', ')[0]
                                        ED_NAME=eline.split(', ')[1]
                                        ED_CT = eline.split(', ')[2]
                                        if int(ED_CT)>MAXCt:
                                            MAXCt=ED_CT
                                            MAXName=ED_NAME
                                    rf.write(eline + "\n")
                            if MAXName!="":
                                ESSID=MAXName

                        if FrMAC.find(str(FMAC))!=-1:
                            CMAC=""
                            if ToMAC=="FF:FF:FF:FF:FF:FF":
                                ToMAC="Broadcast"
                            if CLIENTS!=1 and Privacy!="":
                                if ESSID=="":
                                    ESSID=fcolor.IGray + "<<No ESSID>>"
                                CMAC="1"
                                if FMAC!="FF:FF:FF:FF:FF:FF" and FMAC!="Broadcast" and FMAC!="(not associated)" and ESSID!=fcolor.IGray + "<<No ESSID>>":
                                    if PDisplay=="":
                                        printc (" ",fcolor.BWhite + "[ " + fcolor.BBlue + str(FMAC) + fcolor.BWhite + " ]'s SSID Name is [ " + fcolor.BBlue + str(ESSID) + fcolor.BWhite + " ] and Privicy=" + fcolor.BRed + str(Privacy) + fcolor.BWhite + " Cipher=" + fcolor.BRed + str(Cipher) + fcolor.BWhite + " Authentication=" + fcolor.BRed + str(Authentication) + fcolor.BWhite + " Power=" + fcolor.BRed + str(Power) + fcolor.BWhite + "","")
                                    else:
                                        MACDetail=MACDetail + printc (" ","<$rs$>" + fcolor.BWhite + "[ " + fcolor.BBlue + str(FMAC) + fcolor.BWhite + " ]'s SSID Name is [ " + fcolor.BBlue + str(ESSID) + fcolor.BWhite + " ] and Privicy=" + fcolor.BRed + str(Privacy) + fcolor.BWhite + " Cipher=" + fcolor.BRed + str(Cipher) + fcolor.BWhite + " Authentication=" + fcolor.BRed + str(Authentication) + fcolor.BWhite + " Power=" + fcolor.BRed + str(Power) + fcolor.BWhite + "","")  + "\n"

                                PrivacyBK=Privacy
                                CipherBK=Cipher
                                AuthenticationBK=Authentication

                            if SMAC!="" and CLIENTS==1:
                                if SMAC=="(not associated)":
                                    if PDisplay=="":
                                        printc (" ",fcolor.SGreen + "[ " + fcolor.SWhite + str(FMAC) + fcolor.SGreen + " ] is not associated access point.","")
                                    else:
                                        MACDetail=MACDetail + printc (" ","<$rs$>" + fcolor.SGreen + "[ " + fcolor.SWhite + str(FMAC) + fcolor.SGreen + " ] is not associated access point.","") + "\n"
                                    CMAC="1"
                                else:
                                    if PDisplay=="":
                                        printc (" ",fcolor.BWhite + "[ " + fcolor.BCyan + str(FMAC) + fcolor.BWhite + " ] is associated with access point [ " + fcolor.BCyan + str(SMAC) + fcolor.BWhite + " ]","")
                                        GetMACOUI(SMAC,"")
                                    else:
                                        MACDetail=MACDetail + printc (" ","<$rs$>" + fcolor.BWhite + "[ " + fcolor.BCyan + str(FMAC) + fcolor.BWhite + " ] is associated with access point [ " + fcolor.BCyan + str(SMAC) + fcolor.BWhite + " ]","") + "\n"
                                        MACDetail=MACDetail + GetMACOUI(SMAC,"0") + "\n"


                                    if PDisplay=="":
                                        RESSID=GetESSID(SMAC)
                                    else:
                                        RESSID=GetESSIDOnlyText(SMAC)
                                        if RESSID!="":
                                            MACDetail=MACDetail + str(RESSID) + "\n"
                                             
                                     
                                    CMAC="1"
                            if CMAC=="1":
                                if PDisplay=="":
                                    GetMACOUI(FMAC,"")
                                else:
                                    MACDetail=MACDetail + GetMACOUI(FMAC,"0") + "\n"

                        if FrMAC.find(str(SMAC))!=-1:
                            if FMAC!="" and CLIENTS==1 and SMAC!="(not associated)":
                                if PDisplay=="":
                                    printc (" ",fcolor.BWhite + "[ " + fcolor.BCyan + str(FMAC) + fcolor.BWhite + " ] is associated with client [ " + fcolor.BCyan + str(SMAC) + fcolor.BWhite + " ]","")
                                    GetMACOUI(FMAC,"")
                                else:
                                    MACDetail=MACDetail + printc (" ","<$rs$>" + fcolor.BWhite + "[ " + fcolor.BCyan + str(FMAC) + fcolor.BWhite + " ] is associated with client [ " + fcolor.BCyan + str(SMAC) + fcolor.BWhite + " ]","") + "\n"
                                    MACDetail=MACDetail + GetMACOUI(FMAC,"0") + "\n"


                    if ToMAC.find(str(FMAC))!=-1:
                        if CLIENTS!=1:
                            if ESSID=="":
                                ESSID=fcolor.IGray + "<<No ESSID>>"
                            if FMAC!="FF:FF:FF:FF:FF:FF" and FMAC!="Broadcast" and FMAC!="(not associated)" and ESSID!=fcolor.IGray + "<<No ESSID>>":
                                if PDisplay=="":
                                    printc (" ",fcolor.BWhite + "[ " + fcolor.BBlue + str(FMAC) + fcolor.BWhite + " ]'s SSID Name is [ " + fcolor.BBlue + str(ESSID) + fcolor.BWhite + " ] and Privicy=" + fcolor.BRed + str(Privacy) + fcolor.BWhite + " Cipher=" + fcolor.BRed + str(Cipher) + fcolor.BWhite + " Authentication=" + fcolor.BRed + str(Authentication) + fcolor.BWhite + " Power=" + fcolor.BRed + str(Power) + fcolor.BWhite + "","")
                                    GetMACOUI(FMAC,"")
                                else:
                                    MACDetail=MACDetail + printc (" ","<$rs$>" + fcolor.BWhite + "[ " + fcolor.BBlue + str(FMAC) + fcolor.BWhite + " ]'s SSID Name is [ " + fcolor.BBlue + str(ESSID) + fcolor.BWhite + " ] and Privicy=" + fcolor.BRed + str(Privacy) + fcolor.BWhite + " Cipher=" + fcolor.BRed + str(Cipher) + fcolor.BWhite + " Authentication=" + fcolor.BRed + str(Authentication) + fcolor.BWhite + " Power=" + fcolor.BRed + str(Power) + fcolor.BWhite + "","") + "\n"
                                    MACDetail=MACDetail + GetMACOUI(FMAC,"0") + "\n" 


                            PrivacyBK=Privacy
                            CipherBK=Cipher
                            AuthenticationBK=Authentication

                        else:
                            if SMAC!="":
                                if SMAC=="(not associated)":
                                    if PDisplay=="":
                                        printc (" ",fcolor.SGreen + "[ " + fcolor.SWhite + str(FMAC) + fcolor.SGreen + " ] is not associated access point.","")
                                    else:
                                        MACDetail=MACDetail + printc (" ","<$rs$>" + fcolor.SGreen + "[ " + fcolor.SWhite + str(FMAC) + fcolor.SGreen + " ] is not associated access point.","")  + "\n"

                                    if FMAC!="FF:FF:FF:FF:FF:FF" and FMAC!="Broadcast" and FMAC!="(not associated)":
                                        if PDisplay=="":
                                            GetMACOUI(FMAC,"")
                                            RESSID=GetESSID(FMAC)
                                        else:
                                            MACDetail=MACDetail + GetMACOUI(FMAC,"0") + "\n"
                                            RESSID=GetESSIDOnlyText(FMAC)
                                            if RESSID!="":
                                                MACDetail=MACDetail + str(RESSID) + "\n"


                                  


                                else:
                                    if PDisplay=="":
                                        printc (" ",fcolor.BWhite + "[ " + fcolor.BCyan + str(FMAC) + fcolor.BWhite + " ] is associated with access point [ " + fcolor.BCyan + str(SMAC) + fcolor.BWhite + " ]","")
                                        GetMACOUI(SMAC,"")
                                    else:
                                        MACDetail=MACDetail + printc (" ","<$rs$>" + fcolor.BWhite + "[ " + fcolor.BCyan + str(FMAC) + fcolor.BWhite + " ] is associated with access point [ " + fcolor.BCyan + str(SMAC) + fcolor.BWhite + " ]","") + "\n"
                                        MACDetail=MACDetail + GetMACOUI(SMAC,"0") + "\n"

                                    if SMAC!="FF:FF:FF:FF:FF:FF" and SMAC!="Broadcast" and SMAC!="(not associated)":
                                        if PDisplay=="":
                                            RESSID=GetESSID(SMAC)
                                        else:
                                            RESSID=GetESSIDOnlyText(FMAC)
                                            if RESSID!="":
                                                MACDetail=MACDetail + str(RESSID) + "\n"



                    ESSID=ESSID.lstrip().rstrip().replace("\r","").replace("\n","")
                    if CLIENTS!=1:
                        SkipESSID=0
                        if IsFileDirExist(ESSID_log)!="F":
                            open(ESSID_log,"wb").write("" )
                        else:
                            with open(ESSID_log,"r") as f:
                                for line in f:                         
                                    line=line.replace("\n","")
                                    if len(line)>=18:
                                        if line.find(FMAC)!=-1:
                                            SkipESSID=1
                                            FileESSID=line.replace(FMAC,"").replace("\t","")
                                            FileESSID=FileESSID.lstrip().rstrip().replace("\r","").replace("\n","")
                        if SkipESSID==0 and ESSID!="":
                            if FMAC!="BSSID":
                                open(ESSID_log,"a+b").write("" + str(FMAC) + "\t" + str(ESSID) + "\n")
                        if SkipESSID==1 and ESSID!="":
                            if FileESSID!=ESSID:
                                ModiESSID=ModiESSID + fcolor.BGreen + "ESSID of [ " + fcolor.BBlue + str(FMAC) + fcolor.BGreen + " ] changed from [ " + fcolor.BRed + str(FileESSID) + fcolor.BGreen + " ] to [ " + fcolor.BRed + str(ESSID) + fcolor.BGreen + " ].\n"


    if len(Privacy)==17:
        Privacy=GetEncryptType(Privacy)
        PrivacyBK=Privacy
    else:
        if Privacy=="" or Privacy=="(not associated)":
            Privacy=GetEncryptType(FMAC)
            PrivacyBK=Privacy


    PrivacyBK=PrivacyBK.lstrip().rstrip()
    CipherBK=CipherBK.lstrip().rstrip()
    AuthenticationBK=AuthenticationBK.lstrip().rstrip()

    if PrivacyBK!="" and PrivacyBK.find("WPA")!=-1:
        if PrivacyBK.find("WEP")!=-1:
            if CipherBK.find("WEP")!=-1:
                PrivacyGeneral="WEP"
            else:
                PrivacyGeneral="WPA"
        else:
            PrivacyGeneral="WPA"
    else:
        PrivacyGeneral=PrivacyBK


    PrivacyGeneral=PrivacyGeneral.lstrip().rstrip()


    return PrivacyGeneral + ", " + str(PrivacyBK) + ", " + str(CipherBK) + ", " + str(AuthenticationBK)
    

def RemoveUnwantMAC(MACAddr):
    sMAC=[]
    sMAC=MACAddr.split("/")
    x=0
    lsMAC=len(sMAC)
    while x<lsMAC:
        MAC_ADR=sMAC[x]
        MAC_ADR=MAC_ADR.lstrip().rstrip()
        sMAC[x]=MAC_ADR
        if MAC_ADR[:12]=="FF:FF:FF:FF:":
            sMAC[x]=""
        if MAC_ADR[:6]=="33:33:":
            sMAC[x]=""
        if MAC_ADR[:9]=="01:80:C2:":
            sMAC[x]=""
        if MAC_ADR[:9]=="01:00:5E:":
            sMAC[x]=""
        if MAC_ADR[:3]=="FF:":
            sMAC[x]=""
        if MAC_ADR==MyMAC:
            sMAC[x]=""

        x=x+1
    x=0
    NewMAC=""
    while x<len(sMAC):
        if sMAC[x]!="":
            NewMAC=NewMAC + str(sMAC[x]) + " / "
        x=x+1
    if NewMAC[-3:]==" / ":
        NewMAC=NewMAC[:-3]
    return NewMAC

def GetAPDetail(MAC_Addr,ESSIDName):
    ReturnTxt=""
    newcaptured=tmpdir + "CapturedListing.csv"
    CLIENTS=""
    ClientCt=0
    with open(newcaptured,"r") as f:
        for line in f:
            line=line.replace("\n","")
            line=line.replace("\00","")
            if len(line)>5:
                line=line + " ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., "
                line=line.replace("\r","")
                CList=line.split(",")
                FMAC=line.split()[0].replace(',','')
                FS1=line.split()[0].replace(',','')
                FS2=line.split()[1].replace(',','')
                FS=str(FS1) + " " + str(FS2)
                Channel=CList[3].lstrip().rstrip()
                Speed=CList[4].lstrip().rstrip()
                Power=CList[8].lstrip().rstrip()
                Privacy=CList[5].lstrip().rstrip()
                Cipher=CList[6].lstrip().rstrip()
                Authentication=CList[7].lstrip().rstrip()
                Power=CList[8].lstrip().rstrip()
                ESSID=CList[13].lstrip().rstrip().replace("\n","")
                SMAC=CList[5].lstrip().rstrip()
                Privacy=Privacy.replace('WPA2WPA OPN','WPA2/WPA (OPN)')
                Privacy=Privacy.replace('WPA2 OPN','WPA2 (OPN)')
                Privacy=Privacy.replace('WPA OPN','WPA (OPN)')
                Privacy=Privacy.replace('WPA2WPA','WPA2/WPA')
                Privacy=Privacy.replace('WEP OPN','WEP (OPN)')
                Cipher=Cipher.replace('CCMP TKIP','CCMP/TKIP')
                ESSID=CheckSSIDChr(ESSID)

                if FS=="Station MAC":
                    CLIENTS="1"
                if MAC_Addr==FMAC and CLIENTS=="":
                    lblcolor=fcolor.BGreen
                    txtcolor=fcolor.BWhite
                    lblcolor2=fcolor.BIBlue
                    txtcolor2=fcolor.BIYellow
                    ltxtcolor=fcolor.SWhite
                    ltxtcolor2=fcolor.SYellow
                    if Power!="" and Power!="-1":
                        Power=Power.replace("-","").lstrip().rstrip()
                        Power=100-int(Power)

                    ReturnTxt1=lblcolor + "    Privacy : " + txtcolor + str(Privacy).ljust(15) + lblcolor + "Cipher : " + txtcolor + str(Cipher).ljust(12) + lblcolor + "Auth  : " + txtcolor + str(Authentication).ljust(8) + lblcolor + "ESSID : " + txtcolor + str(ESSIDName) + "\n"
                    ReturnTxt2=lblcolor2 + "Channel : " + txtcolor2 + str(Channel).ljust(15) + lblcolor2 + "Speed  : " + txtcolor2 + str(Speed) + ltxtcolor2 + " MB".ljust(10) + lblcolor2 + "Power : " + txtcolor2 + str(Power).ljust(8)  + "\n"
                if CLIENTS=="1":
                    if SMAC==MAC_Addr:
                        ClientCt=ClientCt+1


    ReturnTxt=ReturnTxt1 + lblcolor2 + "     Client : " + txtcolor2 + str(ClientCt) + ltxtcolor2 + " client".ljust(20) + ReturnTxt2
    return ReturnTxt;
    


def CheckSimilarESSID():
    x=0
    global BSSIDListA
    global ESSIDListA
    SimilarName=""
    BSSIDListA=[]
    ESSIDListA=[]
    tl=len(ESSIDList)
    while x<tl:
        FoundName="1"
        sl=len(ESSIDList)
        y=x+1
        FoundName=""
        while y<sl:

            if ESSIDList[y]==ESSIDList[x] and ESSIDList[x]!="" and ESSIDList[x]!="." and BSSIDList[x]!=BSSIDList[y] and SimilarName.find(BSSIDList[y])==-1:
                lblcolor=fcolor.BGreen
                txtcolor=fcolor.BWhite
                lblcolor2=fcolor.BIBlue
                txtcolor2=fcolor.BIYellow

                if FoundName=="":
                    APResult=GetAPDetail(BSSIDList[x],ESSIDList[x])
                    Text1=lblcolor + "BSSID  : " + txtcolor + str(BSSIDList[x]) + str(APResult) # + lblcolor + "ESSID : " + txtcolor + str(ESSIDList[x]) + "\n"
                    FoundName="1"
                    SimilarName = SimilarName + "     " + Text1

                APResult=GetAPDetail(BSSIDList[y],ESSIDList[y])
                Text2=lblcolor + "BSSID  : " + txtcolor + str(BSSIDList[y]) + str(APResult) + "" + fcolor.Black + ""

                SimilarName = SimilarName + "     " + Text2
                FoundName="1"
            y=y+1
        if FoundName=="1":
            SimilarName = SimilarName + "     " + fcolor.Black + "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"
        FoundName=""

        x=x+1
    if SimilarName!="":
        printc (" ","","")
        printc ("i",fcolor.BUCyan + "Access Point Using The Same Name" + fcolor.CReset,"")
        print SimilarName 
        if PrintToFile=="1":
            open(LogFile,"a+b").write(RemoveColor(str(SimilarName)) + "\n")

                
        



def AnalyseCaptured():
    global List_FrMAC
    global List_ToMAC
    global List_Data
    global List_Auth
    global List_Deauth
    global List_Assoc
    global List_Reassoc
    global List_Disassoc
    global List_RTS
    global List_CTS
    global List_ACK
    global List_EAPOL
    global List_WPS
    global List_Beacon
    global List_SSID
    global List_SSIDCT
    global List_IsAP
    global List_PResp
    global List_PReq
    global List_ProbeName
    global List_NULL
    global List_QOS
    global List_Data86
    global List_Data98
    global List_Data94
    global MACDetail
    MACDetail=""
    List_FrMAC=[]
    List_ToMAC=[]
    List_Data=[]
    List_Data86=[]
    List_Data98=[]
    List_Data94=[]
    List_Auth=[]
    List_Deauth=[]
    List_Assoc=[]
    List_Reassoc=[]
    List_Disassoc=[]
    List_RTS=[]
    List_CTS=[]
    List_ACK=[]
    List_EAPOL=[]
    List_WPS=[]
    List_Beacon=[]
    List_SSID=[]
    List_SSIDCT=[]
    List_IsAP=[]
    List_PResp=[]
    List_PReq=[]
    List_ProbeName=[]
    List_NULL=[]
    List_QOS=[]
    BAK_FR_MAC=""
    essidfile=tmpdir + "essidcount.log"
    macfile=tmpdir + "macadrcount.log"
    tcpdump_log=tmpdir + "tcpdump.log"
    resultlog=tmpdir + "Result.log"
    resultlist=tmpdir + "ResultList.log"


    open(essidfile,"wb").write("")
    open(macfile,"wb").write("")
    linecount=0
    if IsFileDirExist(tcpdump_log)!="F":
        printc ("!!!","Converted file not found ..","")
        retrun 

    open(resultlog,"wb").write(tcpdump_log + "\n")

    TotalLine=GetFileLine(tcpdump_log,"0")
    BRes=0
    DisplayCt=0
    with open(tcpdump_log,"r") as f:
        for line in f:
            linecount=linecount+1
            DisplayCt=DisplayCt+1
            if DisplayCt>50:
                completed=Percent(linecount / float(TotalLine),2)
                BRes=printl(fcolor.SGreen + "Analysing Packets : " + str(completed) + ".." ,"2",BRes)
                DisplayCt=0
            line=line.replace("\n","")
            line=line.replace("(TA)","")
            line=line.replace("(RA)","")
            line=line.replace("(BSSID)","")
            sl=len(line)
            if sl>=15:
                line=line.replace("[Malformed Packet]", "")
                line=line + ", ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., .,"
                line=line.replace("\r","")
                FoundType=""

                STYPE=""
                DTYPE=""
                DTYPE2=""
                DTYPE3=""
                SSID=""
                PSSID=""
                AESSID=""
                FR_MAC=line.split()[3].replace(',','').upper()
                TO_MAC=line.split()[5].replace(',','').upper()
                TO_MAC2=line.split()[4].replace(',','').upper()
                DTYPE=line.split()[8].replace(',','').replace(')','').upper()
                DTYPE2=line.split()[7].replace(',','').replace('(','').upper()
                DTYPE3=line.split()[9].replace(',','').replace('(','').upper()
                WPS1=line.split()[6].replace(',','').replace('(','').upper()
                WPS2=line.split()[11].replace(',','').replace('(','').upper()
                WPS3=line.split()[12].replace(',','').replace('(','').upper()
                SSID=line.split(', ')[5].replace(',','').replace('(','')
                PSSID=line.split(', ')[4].replace(',','').replace('(','')
                ATO_MAC=""

                if len(TO_MAC)==17:
                    ATO_MAC=TO_MAC
                if len(TO_MAC2)==17:
                    ATO_MAC=TO_MAC2

                WPS2=WPS2.replace("FLAGS=","")
                WPS3=WPS3.replace("FLAGS=","")

                if SSID==".":
                    SSID=""

                if PSSID!="" and PSSID[:5]=="SSID=":
                    if PSSID[-18:]=="[Malformed Packet]":
                        PSSID=PSSID[:-18]
                    PSSID=PSSID[5:]
                else:
                    PSSID=""


                if SSID!="" and SSID[:5]=="SSID=":
                    if SSID[-18:]=="[Malformed Packet]":
                        print "Found [Malformed Packet]"
                        SSID=SSID[:-18]
                    SSID=SSID[5:]
                    AESSID=SSID
                    SSID=CheckSSIDChr(SSID)


                if line.find(str('EAPOL'))!=-1:
                    DTYPE=line.split()[6].replace(',','').replace(')','').upper()

                if len(FR_MAC)==17 and len(TO_MAC)==17:
                    FoundType=1
                    STYPE=DTYPE
                if len(TO_MAC2)==17:
                    FoundType=2
                    STYPE=DTYPE2
                if len(FR_MAC)!=17 and len(TO_MAC)!=17 and len(TO_MAC2)!=17:
                    FoundType=3
                    STYPE=DTYPE2
                    DTYPEA=str(DTYPE2) + " " + str(DTYPE)
                    if DTYPEA=="RESERVED FRAME":
                        STYPE=DTYPEA

                if DTYPE=="NULL" and DTYPE3=="FUNCTION":
                    DTYPEA=str(DTYPE) + " " + str(DTYPE3)
                    STYPE=DTYPEA + ""

                if DTYPE=="BEACON" and DTYPE3=="FRAME":
                    DTYPEA=str(DTYPE) + " " + str(DTYPE3)
                    STYPE=DTYPEA
                    FOUND_REC=""
                    if SSID!="" and len(FR_MAC)==17:
                        with open(essidfile,'r+') as essidf:
                            elines =  essidf.readlines()
                            essidf.seek(0)
                            essidf.truncate()
                            for eline in elines:
                                eline=eline.replace("\n","")
                                if FR_MAC in eline:
                                    ED_MAC =eline.split(', ')[0]   #.replace(',','')
                                    ED_NAME=eline.split(', ')[1]   #.replace(',','')
                                    ED_CT = eline.split(', ')[2]   #.replace(',','')
                                    if ED_NAME==SSID:
                                        ED_CT=int(ED_CT)+1
                                        eline=str(FR_MAC) + ", " + str(SSID) + ", " + str(ED_CT)
                                        FOUND_REC=1
                                essidf.write(eline + "\n")
                            if FOUND_REC=="":
                                essidf.write(FR_MAC + ", " + SSID + ", 1")
                FOUND_REC=""
                if len(FR_MAC)==17 and len(ATO_MAC)==17:
                    with open(macfile,'r+') as rf:
                        elines =  rf.readlines()
                        rf.seek(0)
                        rf.truncate()
                        for eline in elines:
                            eline=eline.replace("\n","")
                            if FR_MAC in eline:
                                ED_FRMAC =eline.split(', ')[0].replace(',','')
                                ED_TOMAC=eline.split(', ')[1].replace(',','')
                                ED_CT = eline.split(', ')[2].replace(',','')
                                if ED_TOMAC==ATO_MAC:
                                    ED_CT=int(ED_CT)+1
                                    eline=str(FR_MAC) + ", " + str(ATO_MAC) + ", " + str(ED_CT)
                                    FOUND_REC=1
                            rf.write(eline + "\n")
                        if FOUND_REC=="":
                            rf.write(FR_MAC + ", " + ATO_MAC + ", 1")


                DTYPEA=str(DTYPE) + " " + str(DTYPE3)
                if DTYPEA=="PROBE RESPONSE":
                    STYPE=DTYPEA
                if DTYPEA=="PROBE REQUEST":
                    STYPE=DTYPEA

                if WPS1=="EAP" and WPS2=="WPS":
                    STYPE="WPS"



                if str(TO_MAC)=="FF:FF:FF:FF:FF:FF":
                    BCast=1
                else:
                    BCast=0

                if len(FR_MAC)!=17:
                    FR_MAC=""
                if len(TO_MAC)!=17 and len(TO_MAC2)==17:
                    TO_MAC=TO_MAC2
                if len(TO_MAC2)!=17:
                    TO_MAC2=""
                if len(TO_MAC)!=17:
                    TO_MAC=""
                if FR_MAC!="":
                    BAK_FR_MAC=FR_MAC

                open(resultlog,"a+b").write("Line : " + str(line) + "\n")
                open(resultlog,"a+b").write("FoundType : " + str(FoundType) + "\n")
                open(resultlog,"a+b").write("STYPE : " + str(STYPE) + "\n")
                open(resultlog,"a+b").write("BCast  : " + str(BCast) + "\n")
                open(resultlog,"a+b").write("FR_MAC : " + str(FR_MAC) + " = " + str(len(FR_MAC))+ "\n")
                open(resultlog,"a+b").write("TO_MAC : " + str(TO_MAC) + " = " + str(len(TO_MAC)) +  "\n")
                open(resultlog,"a+b").write("TO_MAC2 : " + str(TO_MAC2) + str(len(TO_MAC2)) +"\n")
                open(resultlog,"a+b").write("DTYPE  : " + str(DTYPE) + "\n")
                open(resultlog,"a+b").write("DTYPE2  : " + str(DTYPE2) + "\n")
                open(resultlog,"a+b").write("DTYPE3  : " + str(DTYPE3) + "\n")
                open(resultlog,"a+b").write("WPS1  : " + str(WPS1) + "\n")
                open(resultlog,"a+b").write("WPS2  : " + str(WPS2) + "\n")
                open(resultlog,"a+b").write("WPS3  : " + str(WPS3) + "\n")
                open(resultlog,"a+b").write("SSID  : " + str(SSID) + "\n")
                open(resultlog,"a+b").write("PSSID : " + str(PSSID) + "\n")
                open(resultlog,"a+b").write("AESSID: " + str(AESSID) + "\n")
                open(resultlog,"a+b").write("-----------------------------------------------------" + "\n")

                GET_DATA="0"
                GET_AUTH="0"
                GET_DEAUTH="0"
                GET_DISASSOC="0"
                GET_REASSOC="0"
                GET_ASSOC="0"
                GET_RTS="0"
                GET_CTS="0"
                GET_ACK="0"
                GET_EAPOL="0"
                GET_WPS="0"
                GET_BEACON="0"
                GET_PRESP="0"
                GET_PRQX="0"
                GET_NULL="0"
                GET_QOS="0"
                GET_DATA86="0"
                GET_DATA98="0"
                GET_DATA94="0"

                if STYPE=="DATA" or STYPE=="QOS":
                    if TO_MAC=="FF:FF:FF:FF:FF:FF":
                        GET_DATA="1"

                if STYPE=="DATA":                            
                    if DTYPE2=="71" or DTYPE2=="73":
                        if TO_MAC[:9]=="01:00:5E:":
                            GET_DATA="1"

                if STYPE=="DATA":                             
                    if DTYPE2=="98" and WPS2==".P....F.C":
                        GET_DATA98="1"


                if STYPE=="DATA":                              
                    if DTYPE2=="94" and WPS2==".P...M.TC":
                        GET_DATA94="1"

                if STYPE=="DATA" and WPS2==".P.....TC":                             
                    if FR_MAC[9:]==":00:00:00":
                        GET_DATA86="1"



                if STYPE=="DATA":                            
                    if TO_MAC[:9]=="FF:F3:18:":
#                        print "DTYPE2 : " + str(DTYPE2)
                        GET_DATA="1"

                if STYPE=="QOS":         # DTYPE2=="103":
                    if WPS3==".P....F.C" or WPS2==".P....F.C":
                        GET_QOS="1"

                if STYPE=="AUTHENTICATION":
                    GET_AUTH="1"
                if STYPE=="DEAUTHENTICATION":
                    GET_DEAUTH="1"
                if STYPE=="DISASSOCIATE":
                    GET_DISASSOC="1"
                if STYPE=="ASSOCIATION":
                    GET_ASSOC="1"
                if STYPE=="REASSOCIATION":
                    GET_REASSOC="1"
                if STYPE=="REQUEST-TO-SEND":
                    GET_RTS="1"
                if STYPE=="CLEAR-TO-SEND":
                    GET_CTS="1"
                if STYPE=="ACKNOWLEDGEMENT":
                    GET_ACK="1"
                if STYPE=="BEACON FRAME":
                    GET_BEACON="1"
                    open(essidfile,"a+b").write("")
                if STYPE=="EAPOL":
                    GET_EAPOL="1"
                if STYPE=="WPS":
                    GET_WPS="1"
                if STYPE=="PROBE RESPONSE":
                    GET_PRESP="1"
                if STYPE=="PROBE REQUEST":
                    GET_PRQX="1"
                if STYPE=="NULL FUNCTION":
                    GET_NULL="1"
            
                     
                if STYPE=="DATA" or STYPE=="QOS" or STYPE=="AUTHENTICATION" or STYPE=="DEAUTHENTICATION" or STYPE=="ASSOCIATION" or STYPE=="DISASSOCIATE" or STYPE=="REASSOCIATION" or STYPE=="REQUEST-TO-SEND" or STYPE=="CLEAR-TO-SEND" or STYPE=="ACKNOWLEDGEMENT" or STYPE=="EAPOL" or STYPE=="WPS" or STYPE=="BEACON FRAME" or STYPE=="PROBE RESPONSE" or STYPE=="PROBE REQUEST" or STYPE=="NULL FUNCTION":
                    ListSR=0
                    ExistList=-1
                    ListLen=len(List_FrMAC)
                    if ListLen!=0:
                        while ListSR<ListLen:
                            if len(FR_MAC)==17 and len(TO_MAC)==17:
                               if List_FrMAC[ListSR]==FR_MAC and List_ToMAC[ListSR].find(TO_MAC)!=-1:
                                   ExistList=ListSR

                               if List_FrMAC[ListSR]==FR_MAC and List_ToMAC[ListSR].find(TO_MAC)==-1 and ExistList==-1:
                                   List_ToMAC[ListSR]=List_ToMAC[ListSR] + " / " + str(TO_MAC)
                                   ExistList=ListSR

                            if len(FR_MAC)==0 and len(TO_MAC)==17 and ExistList==-1:
                                if List_FrMAC[ListSR]==TO_MAC:
                                   ExistList=ListSR

                            if ExistList!=-1:
                                ListSR=ListLen
                            ListSR=ListSR+1

		         
                    if ExistList==-1 and len(FR_MAC)==17:   # and len(TO_MAC)==17:		# NOT FOUND ON LIST
                        List_FrMAC.append(str(FR_MAC))
                        List_ToMAC.append(str(TO_MAC))
                        List_Data.append(str(GET_DATA))
                        List_Data86.append(str(GET_DATA86))
                        List_Data98.append(str(GET_DATA98))
                        List_Data94.append(str(GET_DATA94))
                        List_Auth.append(str(GET_AUTH))
                        List_Deauth.append(str(GET_DEAUTH))
                        List_Assoc.append(str(GET_ASSOC))
                        List_Reassoc.append(str(GET_REASSOC))
                        List_Disassoc.append(str(GET_DISASSOC))
                        List_RTS.append(str(GET_RTS))
                        List_CTS.append(str(GET_CTS))
                        List_ACK.append(str(GET_ACK))
                        List_EAPOL.append(str(GET_EAPOL))
                        List_WPS.append(str(GET_WPS))
                        List_NULL.append(str(GET_NULL))
                        List_QOS.append(str(GET_QOS))
                        List_Beacon.append(str(GET_BEACON))
                        List_PResp.append(str(GET_PRESP))
                        List_PReq.append(str(GET_PRQX))
                        List_SSID.append(str(SSID) + ", ")
                        List_ProbeName.append(str(PSSID) + ", ")

                        if AESSID!="":
                            List_IsAP.append("Yes")
                        else:
                            List_IsAP.append("No")

                    if ExistList!=-1:		# FOUND ON LIST
                        GET_DATA=List_Data[ExistList]
                        GET_DATA86=List_Data86[ExistList]
                        GET_DATA98=List_Data98[ExistList]
                        GET_DATA94=List_Data94[ExistList]
                        GET_AUTH=List_Auth[ExistList]
                        GET_DEAUTH=List_Deauth[ExistList]
                        GET_ASSOC=List_Assoc[ExistList]
                        GET_REASSOC=List_Reassoc[ExistList]
                        GET_DISASSOC=List_Disassoc[ExistList]
                        GET_RTS=List_RTS[ExistList]
                        GET_CTS=List_CTS[ExistList]
                        GET_ACK=List_ACK[ExistList]
                        GET_EAPOL=List_EAPOL[ExistList]
                        GET_WPS=List_WPS[ExistList]
                        GET_BEACON=List_Beacon[ExistList]
                        GET_PRESP=List_PResp[ExistList]
                        GET_PRQX=List_PReq[ExistList]
                        GET_NULL=List_NULL[ExistList]
                        GET_QOS=List_QOS[ExistList]


                        SSID_List=[]
                        if List_SSID[ExistList]!="":
                            List_SSIDS=str(List_SSID[ExistList])
                            SSID_List=List_SSIDS.split(", ")

                        ProbeName_List=[]
                        if List_ProbeName[ExistList]!="":
                            List_ProbeNameS=str(List_ProbeName[ExistList])
                            ProbeName_List=List_ProbeNameS.split(", ")




                        if SSID!="":
                            List_IsAP[ExistList]="Yes"
                               



                        
                        lSSID=len(SSID_List)
                        lsid=0
                        FoundSSID="0"
                        if lSSID!=0 and SSID!="":
                            while lsid<lSSID:
                                if SSID_List[lsid]!="" and SSID_List[lsid]==str(SSID):
                                    FoundSSID="1"
                                    lsid=lSSID
                                lsid=lsid+1
                            if FoundSSID=="0":
                                if List_SSID[ExistList]==", ":
                                    List_SSID[ExistList]=""
                                if SSID!="Broadcast":
                                    List_SSID[ExistList]=List_SSID[ExistList] + str(SSID) + ", "


                        lSSID=len(ProbeName_List)
                        lsid=0
                        FoundProbeName="0"
                        if lSSID!=0 and PSSID!="":
                            while lsid<lSSID:
                                if ProbeName_List[lsid]!="" and ProbeName_List[lsid]==str(PSSID):
                                    FoundProbeName="1"
                                    lsid=lSSID
                                lsid=lsid+1
                            if FoundProbeName=="0":
                                if List_ProbeName[ExistList]==", ":
                                    List_ProbeName[ExistList]=""
                                List_ProbeName[ExistList]=List_ProbeName[ExistList] + str(PSSID) + ", "
                        if STYPE=="DATA" and DTYPE2=="98" and WPS2==".P....F.C":               # chopchop ??
                            GET_DATA98=str(int(GET_DATA98) + 1)


                        if STYPE=="DATA" and DTYPE2=="98" and WPS2==".P.....TC":               # Interactive Replay ??
                            GET_DATA98=str(int(GET_DATA98) + 1)



                        if STYPE=="DATA" and DTYPE2=="94" and WPS2==".P...M.TC":               # fragment PRGA
                            GET_DATA94=str(int(GET_DATA94) + 1)
 
                        if STYPE=="DATA" or STYPE=="QOS":
                            if TO_MAC=="FF:FF:FF:FF:FF:FF":
                                GET_DATA=str(int(GET_DATA) + 1)
                        if STYPE=="DATA":
                            if DTYPE2=="71" or DTYPE2=="73":
                                if TO_MAC[:9]=="01:00:5E:":
                                    GET_DATA=str(int(GET_DATA) + 1)
                        if STYPE=="DATA":
                            if TO_MAC[:9]!="FF:FF:FF:" and TO_MAC[:3]=="FF:":
                                GET_DATA=str(int(GET_DATA) + 1)

                        if STYPE=="DATA" and WPS2==".P.....TC":                               # MDK mICHAEL SHUTDOWN EXPLOIT (TKIP)
                             if FR_MAC[9:]=="00:00:00":
                               GET_DATA86=str(int(GET_DATA86) + 1)

                        if STYPE=="AUTHENTICATION":
                            GET_AUTH=str(int( GET_AUTH) + 1)
                        if STYPE=="DEAUTHENTICATION":
                            GET_DEAUTH=str(int(GET_DEAUTH) + 1)
                        if STYPE=="DISASSOCIATE":
                            GET_DISASSOC=str(int(GET_DISASSOC) + 1)
                        if STYPE=="ASSOCIATION":
                            GET_ASSOC=str(int(GET_ASSOC) + 1)
                        if STYPE=="REASSOCIATION":
                            GET_REASSOC=str(int(GET_REASSOC) + 1)
                        if STYPE=="REQUEST-TO-SEND":
                            GET_RTS=str(int(GET_RTS) + 1)
                        if STYPE=="CLEAR-TO-SEND":
                            GET_CTS=str(int(GET_CTS) + 1)
                        if STYPE=="ACKNOWLEDGEMENT":
                            GET_ACK=str(int(GET_ACK) + 1)
                        if STYPE=="EAPOL":
                            GET_EAPOL=str(int(GET_EAPOL) + 1)
                        if STYPE=="WPS":
                            GET_WPS=str(int(GET_WPS) + 1)
                        if STYPE=="BEACON FRAME":
                            GET_BEACON=str(int(GET_BEACON) + 1)
                        if STYPE=="PROBE RESPONSE":
                            GET_PRESP=str(int(GET_PRESP) + 1)
                        if STYPE=="PROBE REQUEST":
                            GET_PRQX=str(int(GET_PRQX) + 1)
                        if STYPE=="NULL FUNCTION":
                            GET_NULL=str(int(GET_NULL) + 1)

                        if STYPE=="QOS" and TO_MAC[:9]!="FF:FF:FF:":         # DTYPE2=="103":
                            if WPS3==".P....F.C" or WPS2==".P....F.C":
                                GET_QOS=str(int(GET_QOS) + 1)


                        List_Data[ExistList]=GET_DATA
                        List_Data86[ExistList]=GET_DATA86
                        List_Data98[ExistList]=GET_DATA98
                        List_Data94[ExistList]=GET_DATA94
                        List_Auth[ExistList]=GET_AUTH
                        List_Deauth[ExistList]=GET_DEAUTH
                        List_Assoc[ExistList]=GET_ASSOC
                        List_Reassoc[ExistList]=GET_REASSOC
                        List_Disassoc[ExistList]=GET_DISASSOC
                        List_RTS[ExistList]=GET_RTS
                        List_CTS[ExistList]=GET_CTS
                        List_ACK[ExistList]=GET_ACK
                        List_EAPOL[ExistList]=GET_EAPOL
                        List_WPS[ExistList]=GET_WPS
                        List_Beacon[ExistList]=GET_BEACON
                        List_PResp[ExistList]=GET_PRESP
                        List_PReq[ExistList]=GET_PRQX
                        List_NULL[ExistList]=GET_NULL
                        List_QOS[ExistList]=GET_QOS

                        if SSID!="" and List_SSID[ExistList]=="":
                            List_SSID[ExistList]=SSID + ", "
                            List_IsAP[ExistList]="Yes"

                        if PSSID!="" and List_ProbeName[ExistList]=="":
                            List_ProbeName[ExistList]=PSSID + ", "

                        if AESSID!="":
                            List_IsAP[ExistList]="Yes"
                    ExistList=-1

    x=0
    while x<len(List_FrMAC):
        SSID_CT="0"
        if List_SSID[x]!="":
            if List_SSID[x][-2:]==", ":
                List_SSID[x]=List_SSID[x][:-2]
                List_SSID[x]=List_SSID[x].replace("Broadcast, ","").replace("Broadcast","")
                SSID_List=List_SSID[x].split(", ")
                SSID_CT=str(len(SSID_List))
        if List_ProbeName[x]!="":
            if List_ProbeName[x][-2:]==", ":
                List_ProbeName[x]=List_ProbeName[x][:-2]
                if List_ProbeName[x]!="" and List_SSID[x]!="":
                    if List_Beacon==0:
                        List_SSID[x]=""
                        List_IsAP[x]="No"

        if List_SSID[x]=="":
            SSID_CT="0"

 
        
        List_SSIDCT.append(str(SSID_CT))
        x=x+1


    printl(fcolor.BRed + "                                           ","","")
    printl(fcolor.BRed + "     Analysing Completed..\r","","")


    if IsFileDirExist(resultlist)!="F":
        open(resultlist,"wb").write("" + "\n")
    ts = time.time()
    DateTimeStamp=datetime.datetime.fromtimestamp(ts).strftime('%d/%m/%Y %H:%M:%S')
    open(resultlist,"wb").write(tcpdump_log + "\n")
    open(resultlist,"a+b").write("Date/Time\t:" + str(DateTimeStamp) + "\n")
    x=0
    l=len(List_FrMAC)
    while x<l:
        open(resultlist,"a+b").write("SN\tFR MAC \t\t\tBF   \tIsAP? \tECT  \tData \tData86 \tDat94  \tDat98 \tQOS\tAuth \tDeauth \tAssoc \tR.Asc \tD.Asc \tRTS \tCTS \tACK \tEAPOL \tWPS \tRQX \tResp \tNULL" + "\n")
        open(resultlist,"a+b").write(str(x) + "\t" + List_FrMAC[x] + "\t" + List_Beacon[x] + "\t" + List_IsAP[x] + "\t" + List_SSIDCT[x] + "\t" + List_Data[x] + "\t" + List_Data86[x] + "\t" + List_Data94[x]  + "\t" + List_Data98[x] + "\t" + List_QOS[x] + "\t"  + List_Auth[x] + "\t"  + List_Deauth[x] + "\t"  + List_Assoc[x] + "\t"  + List_Reassoc[x] + "\t"  + List_Disassoc[x] + "\t"  + List_RTS[x] + "\t"  + List_CTS[x] + "\t"  + List_ACK[x] + "\t"   + List_EAPOL[x] + "\t"   + List_WPS[x] + "\t" + List_PReq[x] + "\t" + List_PResp[x] + "\t" + List_NULL[x] + "\n")
        open(resultlist,"a+b").write("ESSID\t" + List_SSID[x] + "\n")
        open(resultlist,"a+b").write("Probe\t" + List_ProbeName[x] + "\n")
        open(resultlist,"a+b").write("DEST\t" + List_ToMAC[x] + "\n\n")
        x=x+1
    open(resultlist,"a+b").write("" + "\n\n")

    listlen=len(List_FrMAC)
    listsr=0
    Concern=0
    AWPA=0
    AWEP=0
    AWPS=0
    ATUN=0
    AWNG=0
    ACCP=0
    ATFL=0
    ABCF=0
    MDKM=0
    ASFL=0
    PRGA=0
    IARP=0
    WPAD=0
    WPSDetected=0
    AType=""
    if listlen!=0:
        printl(fcolor.BRed + "\r","","")
        while listsr<listlen:

            ToMAC=List_ToMAC[listsr]
            ToMACList=ToMAC.split(" / ")
            tml=0
            Multicast=0
            Chopchop=0
            while tml<len(ToMACList):
                ChkMAC=ToMACList[tml]
                if ChkMAC[:9]=="01:00:5E:":
                    Multicast=Multicast+1
                if ChkMAC[:9]!="FF:FF:FF:" and ChkMAC[:3]=="FF:":
                    Chopchop=Chopchop+1
                tml=tml+1

            if int(List_Deauth[listsr])>=10:
                FrMAC=str(List_FrMAC[listsr])
                ToMAC=RemoveUnwantMAC(str(List_ToMAC[listsr]))
                if ToMAC=="":
                    ToMAC = fcolor.BRed + "Broadcast"

                if int(List_Disassoc[listsr])>=10:
                    Concern=Concern+1
                    printc (" ","","")
                    printc (".",fcolor.BGreen + "Deauth Flood detected calling from [ " + fcolor.BBlue + str(FrMAC) + fcolor.BGreen + " ] to [ " + fcolor.BBlue + str(ToMAC) + fcolor.BGreen + " ]  with " + fcolor.BYellow + str(List_Deauth[listsr]) + fcolor.BGreen + " deauth packets","")
                    printc (".",fcolor.BGreen + "Dissassociation Flood detected calling from [ " + fcolor.BBlue + str(FrMAC) + fcolor.BGreen + " ] to [ " + fcolor.BBlue + str(ToMAC) + fcolor.BGreen + " ]  with " + fcolor.BYellow + str(List_Disassoc[listsr]) + fcolor.BGreen + " disassociation packets","")
                    AType="DISASSOC"
                    WPAD="1"
                    ReturnResult=GetMACDetail(FrMAC,ToMAC,AType,"")
                    GenPrivacy=ReturnResult.split(",")[0].lstrip().rstrip()
                    printc (" ",fcolor.SWhite + "Possible MDK3 WPA Downgrade..","")
                else:
                    Concern=Concern+1
                    printc (" ","","")
                    printc (".",fcolor.BGreen + "Deauth Flood detected calling from [ " + fcolor.BBlue + str(FrMAC) + fcolor.BGreen + " ] to [ " + fcolor.BBlue + str(ToMAC) + fcolor.BGreen + " ]  with " + fcolor.BYellow + str(List_Deauth[listsr]) + fcolor.BGreen + " deauth packets","")
                    AType="DEAUTH"
                    ReturnResult=GetMACDetail(FrMAC,ToMAC,AType,"")
                    GenPrivacy=ReturnResult.split(",")[0].lstrip().rstrip()
  
                    if FrMAC=="00:00:00:00:00:00" or ToMAC=="00:00:00:00:00:00":
                        ATUN="1"
                        printc (" ",fcolor.SWhite + "Possible TKIPTUN-NG Signature..","")
                    else:
                        if str(GenPrivacy)=="WPA" or int(List_EAPOL[listsr])>0:
                            AWPA="1"
                            printc (" ",fcolor.BGreen + "Handshake Found [ " + fcolor.BBlue + str(List_EAPOL[listsr]) + fcolor.BGreen + " ] ","")
            else:
                if int(List_Deauth[listsr])>0:
                    FrMAC=str(List_FrMAC[listsr])
                    ToMAC=RemoveUnwantMAC(str(List_ToMAC[listsr]))
                    if List_FrMAC[listsr].find("00:00:00:00:00:00")!=-1 or List_ToMAC[listsr].find("00:00:00:00:00:00")!=-1:
                        Concern=Concern+1
                        printc (" ","","")
                        printc (".",fcolor.BGreen + "Deauth Flood detected calling from [ " + fcolor.BBlue + str(FrMAC) + fcolor.BGreen + " ] to [ " + fcolor.BBlue + str(ToMAC) + fcolor.BGreen + " ]  with " + fcolor.BYellow + str(List_Deauth[listsr]) + fcolor.BGreen + " deauth packets","")
                        AType="DEAUTH"
                        ReturnResult=GetMACDetail(FrMAC,ToMAC,AType,"")
                        GenPrivacy=ReturnResult.split(",")[0]
                        ATUN="1"
                        printc (" ",fcolor.SWhite + "Possible TKIPTUN-NG Signature..","")
                        printc (" ",fcolor.BGreen + "Handshake Found [ " + fcolor.BBlue + str(List_EAPOL[listsr]) + fcolor.BGreen + " ] ","")



            if int(List_Data[listsr])>=25:
                FrMAC=RemoveUnwantMAC(str(List_FrMAC[listsr]))
                ToMAC=RemoveUnwantMAC(str(List_ToMAC[listsr]))
                if ToMAC=="":
                    ToMAC="Broadcast"
                if int(List_Data[listsr])>30 and Multicast<=1 and Chopchop<=1:
                    Concern=Concern+1
                    printc (" ","","")
                    printc (".",fcolor.BGreen + "Unusual Data sending from [ " + fcolor.BBlue + str(FrMAC) + fcolor.BGreen + " ] to [ " + fcolor.BBlue + str(ToMAC) + fcolor.BGreen + " ] with " + fcolor.BYellow + str(List_Data[listsr]) + fcolor.BGreen +  " Broadcast data packets","")
                    AType="BCDATA"
                    ReturnResult=GetMACDetail(FrMAC,ToMAC,AType,"")
                    GenPrivacy=ReturnResult.split(",")[0].lstrip().rstrip()
                    if str(GenPrivacy)=="WEP":
                        AWEP="1"
                if Multicast>5:
                    Concern=Concern+1
                    printc (" ","","")
                    printc (".",fcolor.BGreen + "Possible attack using Wesside-NG from [ " + fcolor.BBlue + str(FrMAC) + fcolor.BGreen + " ] to [ " + fcolor.BBlue + str(ToMAC) + fcolor.BGreen + " ] with " + fcolor.BYellow + str(Multicast) + fcolor.BGreen +  " Multicast data packets","")
                    AType="BCDATA"
                    ReturnResult=GetMACDetail(FrMAC,ToMAC,AType,"")
                    GenPrivacy=ReturnResult.split(",")[0].lstrip().rstrip()
                    AWNG="1"
                    if str(GenPrivacy)=="WEP":
                        AWEP="1"
                if Chopchop>5:
                    Concern=Concern+1
                    printc (" ","","")
                    printc (".",fcolor.BGreen + "Possible attack using with Korek Chopchop method from [ " + fcolor.BBlue + str(FrMAC) + fcolor.BGreen + " ] to [ " + fcolor.BBlue + str(ToMAC) + fcolor.BGreen + " ] with " + fcolor.BYellow + str(Chopchop) + fcolor.BGreen +  " data packets","")
                    AType="BCDATA"
                    ReturnResult=GetMACDetail(FrMAC,ToMAC,AType,"")
                    GenPrivacy=ReturnResult.split(",")[0].lstrip().rstrip()
                    ACCP="1"
                    if str(GenPrivacy)=="WEP":
                        AWEP="1"



            if int(List_Data94[listsr])>=5:
                Concern=Concern+1
                FrMAC=RemoveUnwantMAC(str(List_FrMAC[listsr]))
                ToMAC=RemoveUnwantMAC(str(List_ToMAC[listsr]))
                if ToMAC=="":
                    ToMAC="Broadcast"
                printc (" ","","")
                printc (".",fcolor.BGreen + "Possible Fragmentation PRGA Attack from [ " + fcolor.BBlue + str(FrMAC) + fcolor.BGreen + " ] to [ " + fcolor.BBlue + str(ToMAC) + fcolor.BGreen + " ] with " + fcolor.BYellow + str(List_Data94[listsr]) + fcolor.BGreen +  " data packets","")
                AType="PRGA"
                PRGA="1"
                ReturnResult=GetMACDetail(FrMAC,ToMAC,AType,"")
                GenPrivacy=ReturnResult.split(",")[0]
                Privacy=ReturnResult.split(",")[1].lstrip().rstrip()
                Cipher=ReturnResult.split(",")[2].lstrip().rstrip()
                Authentication=ReturnResult.split(",")[3]
                if str(GenPrivacy)=="WEP":
                    AWEP="1"




            if int(List_Data86[listsr])>=5:
                Concern=Concern+1
                FrMAC=RemoveUnwantMAC(str(List_FrMAC[listsr]))
                ToMAC=RemoveUnwantMAC(str(List_ToMAC[listsr]))
                if ToMAC=="":
                    ToMAC="Broadcast"
                printc (" ","","")
                printc (".",fcolor.BGreen + "Possible MDK Michael shutdown exploitation (TKIP) from [ " + fcolor.BBlue + str(FrMAC) + fcolor.BGreen + " ] to [ " + fcolor.BBlue + str(ToMAC) + fcolor.BGreen + " ] with " + fcolor.BYellow + str(List_Data86[listsr]) + fcolor.BGreen +  " data packets","")
                AType="MDKM"
                MDKM="1"
                ReturnResult=GetMACDetail(FrMAC,ToMAC,AType,"")
                GenPrivacy=ReturnResult.split(",")[0]
                Privacy=ReturnResult.split(",")[1].lstrip().rstrip()
                Cipher=ReturnResult.split(",")[2].lstrip().rstrip()
                Authentication=ReturnResult.split(",")[3]

            if int(List_QOS[listsr])>=1:
                FrMAC=RemoveUnwantMAC(str(List_FrMAC[listsr]))
                ToMAC=RemoveUnwantMAC(str(List_ToMAC[listsr]))

                if ToMAC=="":
                    ToMAC="Broadcast"
                PResult=printc (".","<$rs$>" + fcolor.BGreen + "High amount of QOS recieved from [ " + fcolor.BBlue + str(FrMAC) + fcolor.BGreen + " ] to [ " + fcolor.BBlue + str(ToMAC) + fcolor.BGreen + " ] with " + fcolor.BYellow + str(List_QOS[listsr]) + fcolor.BGreen +  " QOS data packets","")
                ReturnResult=GetMACDetail(FrMAC,ToMAC,AType,1)
                GenPrivacy=ReturnResult.split(",")[0]
                Privacy=ReturnResult.split(",")[1].lstrip().rstrip()
                Cipher=ReturnResult.split(",")[2].lstrip().rstrip()
                Authentication=ReturnResult.split(",")[3]
                if Cipher=="TKIP":
                    AType="TUN"
                    ATUN="1"
                    Concern=Concern+1
                    printc (" ","","")
                    print PResult
                    print MACDetail + "\r"
                    print "     " + fcolor.SWhite + "Note: Basing on signature, it could be attack by TKIPTUN-NG."

            if int(List_Auth[listsr])>=5:
                Concern=Concern+1
                FrMAC=RemoveUnwantMAC(str(List_FrMAC[listsr]))
                ToMAC=RemoveUnwantMAC(str(List_ToMAC[listsr]))
                if int(List_Auth[listsr])<=80:
                    printc (" ","","")
                    printc (".",fcolor.BGreen + "Detected authentication sent from [ " + fcolor.BBlue + str(FrMAC) + fcolor.BGreen + " ] to [ " + fcolor.BBlue + str(ToMAC) + fcolor.BGreen + " ] with " + fcolor.BYellow + str(List_Auth[listsr]) + fcolor.BGreen + " authentication request detected","")
                    AType="AUTH"
                    RtnESSID=GetMACDetail(FrMAC,ToMAC,AType,"") 

                else:
                    printc (" ","","")
                    if len(List_ToMAC[listsr])>100:
                        ATFL="1"
                        printc (".",fcolor.BGreen + "Detected possible Authentication DOS on [ " + fcolor.BBlue + str(FrMAC) + fcolor.BGreen + " ] to [ " + fcolor.BBlue + "Many Clients" + fcolor.BGreen + " ] with " + fcolor.BRed + str(List_Auth[listsr])  + fcolor.BGreen + " authentication request detected","")
                        printc (" ",fcolor.SWhite + "Note: This situation usually seen on Aireplay-NG WPA Migration Mode.","")
                        Ask=AskQuestion ("There are a total of [ " + fcolor.BRed + str(len(List_ToMAC[listsr])) + fcolor.BGreen +  " ] client's MAC captured, display them ?","y/N","","N","")
                        if Ask=="Y" or Ask=="y":
                            printc (".",fcolor.BGreen + "Client MAC [ " +  fcolor.BBlue + str(ToMAC) + fcolor.BGreen + " ]","")
                            AType="AUTH"
                            RtnESSID=GetMACDetail(FrMAC,ToMAC,AType,"") 
                    else:
                        ATFL="1"
                        printc (".",fcolor.BGreen + "Unusual high amount of authentication sent from [ " + fcolor.BBlue + str(FrMAC) + fcolor.BGreen + " ] to [ " + fcolor.BBlue + str(ToMAC) + fcolor.BGreen + " ] with " + fcolor.BRed + str(List_Auth[listsr]) + fcolor.BGreen + " authentication request detected","")
                        printc (" ",fcolor.SWhite + "Note: If amount is too high, likely to be Authentication DOS.","")
                        AType="AUTH"
                        RtnESSID=GetMACDetail(FrMAC,ToMAC,AType,"")
            if int(List_Assoc[listsr])>=8:
                Concern=Concern+1
                FrMAC=RemoveUnwantMAC(str(List_FrMAC[listsr]))
                ToMAC=RemoveUnwantMAC(str(List_ToMAC[listsr]))
                printc (" ","","")
                if len(List_ToMAC[listsr])>100:
                    ASFL="1"
                    printc (".",fcolor.BGreen + "Detected possible association flood on [ " + fcolor.BBlue + str(FrMAC) + fcolor.BGreen + " ] to [ " + fcolor.BBlue + "Many Clients" + fcolor.BGreen + " ] with " + fcolor.BRed + str(List_Assoc[listsr]) + fcolor.BGreen + " association request detected","")
                    Ask=AskQuestion ("There are a total of [ " + fcolor.BRed + str(len(List_ToMAC[listsr])) + fcolor.BGreen + " ] client's MAC captured, display them ?","y/N","","N","")
                    if Ask=="Y":
                        printc (".",fcolor.BGreen + "Client MAC [ " +  fcolor.BBlue + str(ToMAC) + fcolor.BGreen + " ]","")
                        AType="ASSOC"
                        RtnESSID=GetMACDetail(FrMAC,ToMAC,AType,"") 
                else:
                    printc (".",fcolor.BGreen + "Unusual high amount of association sent from [ " + fcolor.BBlue + str(FrMAC) + fcolor.BGreen + " ] to [ " + fcolor.BBlue + str(ToMAC) + fcolor.BGreen + " ] with " + fcolor.BRed + str(List_Assoc[listsr]) + fcolor.BGreen + " association request detected","")
                    printc (" ",fcolor.SWhite + "Note: If amount is too high, likely to be Association flood.","")
                    AType="ASSOC"
                    RtnESSID=GetMACDetail(FrMAC,ToMAC,AType,"")
                if Multicast>5:
                    printc (" ",fcolor.SWhite + "Note: Basing on signature, possible Wesside-NG attack with [ " + fcolor.SRed + str(Multicast) + fcolor.SWhite + " ] multicast detected." ,"")




            if int(List_WPS[listsr])>=2:
                Concern=Concern+1
                WPSDetected=1
                AWPS="1"
                FrMAC=RemoveUnwantMAC(str(List_FrMAC[listsr]))
                ToMAC=RemoveUnwantMAC(str(List_ToMAC[listsr]))
                printc (" ","","")
                printc (".",fcolor.BGreen + "EAP communication between AP and client sending from [ " + fcolor.BBlue + str(FrMAC) + fcolor.BGreen + " ] to [ " + fcolor.BBlue + str(ToMAC) + fcolor.BGreen + " ] with " + fcolor.BYellow + str(List_WPS[listsr]) + fcolor.BGreen + " EAP packets detected","")
                AType="EAP"
                RtnESSID=GetMACDetail(FrMAC,ToMAC,AType,"")
                printc (" ",fcolor.SWhite + "Note: If constantly seeing EAP communication between this two devices, it is likely that a WPS bruteforce is in progress..","")

            if int(List_SSIDCT[listsr])>=2:
                FrMAC=str(List_FrMAC[listsr])
                ToMAC=str(List_ToMAC[listsr])

                if ToMAC!="FF:FF:FF:FF:FF:FF" or len(ToMAC)>17:
                    TMC=[]
                    AList=List_SSID[listsr] + ", "
                    TMC=AList.split(",")
                    FM="0"
                    if List_SSIDCT[listsr]=="2" or List_SSIDCT[listsr]=="3":
                       if List_SSIDCT[listsr]=="3":

                           if len(TMC[0].lstrip().rstrip())==len(TMC[1].lstrip().rstrip()) and len(TMC[1].lstrip().rstrip())==len(TMC[2].lstrip().rstrip()):
                               FM="1"
                       else:
                           if len(TMC[0].lstrip().rstrip())==len(TMC[1].lstrip().rstrip()):
                               FM="1"
                    if FM=="0":
                        AToMAC=ToMAC
                        if AToMAC=="FF:FF:FF:FF:FF:FF":
                            AToMAC=fcolor.BRed + "Broadcast"
                        else:
                            FrMAC=RemoveUnwantMAC(str(List_FrMAC[listsr]))
                            AToMAC=RemoveUnwantMAC(str(List_ToMAC[listsr]))
                        printc (" ","","")

                        SSIDCount=List_SSIDCT[listsr]
                        if List_SSID[listsr].find("Broadcast")!=-1 and AToMAC!="":
                            SSIDCount=int(SSIDCount)-1

                        FrMAC=RemoveUnwantMAC(str(List_FrMAC[listsr]))
                        AToMAC=RemoveUnwantMAC(str(List_ToMAC[listsr]))

                        Concern=Concern+1
                        RAPDetected=1
                        ARAP="1"
                        printc (".",fcolor.BGreen + "Suspect Rogue AP using [ " + fcolor.BBlue + str(FrMAC) + fcolor.BGreen + " ] and responsed to [ " + fcolor.BBlue + str(AToMAC) + fcolor.BGreen + " ] using " + fcolor.BYellow + str(SSIDCount) + fcolor.BGreen + " different SSID Name.","")
                        printc (".",fcolor.BGreen + "Broadcasted SSID Name  [ " + fcolor.BBlue + str(List_SSID[listsr]) + fcolor.BGreen + " ]...","")
                        AType="RAP"
                        RtnESSID=GetMACDetail(FrMAC,ToMAC,AType,"")
                        printc (" ",fcolor.SWhite + "Note: If names look quite similar, it is unlikely to be Rogue AP as due to lost/malfunction packets.","")

                if ToMAC=="FF:FF:FF:FF:FF:FF" and int(List_SSIDCT[listsr])>15 :
                    Concern=Concern+1
                    print ""
                    printc (".",fcolor.BGreen + "Detected possible 'Beacon Flood' using MAC Address [ " + fcolor.BBlue + str(FrMAC) + fcolor.BGreen + " ] with " + fcolor.BYellow + str(List_SSIDCT[listsr]) + fcolor.BGreen + " different SSID Name.","")
                    printc (".",fcolor.BGreen + "Broadcasted SSID Name  [ " + fcolor.BBlue + str(List_SSID[listsr]) + fcolor.BGreen + " ]...","")
                    AType="BCF"
                    ABCF="1"
            listsr = listsr +1
    CheckSimilarESSID()
    tcpdump_cap=tmpdir + "tcpdump.cap"
    Result=""
    if Concern==0:
        if IsFileDirExist(tcpdump_cap)=="F":
            statinfo = os.stat(tcpdump_cap)
            filesize=statinfo.st_size
            if filesize>=300:
                Result=printc ("i","<$rs$>" + "" + fcolor.BYellow + DateTimeStamp + " - " + fcolor.SGreen +  "Did not detect any suspicious activity ...\n","")
    else:
        Result=printc ("i","<$rs$>" + "" + fcolor.BBlue + DateTimeStamp + " - " + fcolor.BRed + str(Concern) + fcolor.BWhite + " concerns found...","")
        WText=""
        if AWEP=="1":
	    WText=str(WText) + "WEP , "
        if AWNG=="1":
            WText=str(WText) + "WESSIDE-NG , "
        if ACCP=="1":
            WText=str(WText) + "KoreK Chopchop , "
        if AWPA=="1":
	    WText=str(WText) + "WPA , "
        if ATUN=="1":
            WText=str(WText) + "TKIPTUN-NG , "
        if AWPS=="1":
            WText=str(WText) + "WPS , "
        if ATFL=="1":
            WText=str(WText) + "Authentication DOS , "
        if ASFL=="1":
            WText=str(WText) + "Association DOS , "
        if ABCF=="1":
            WText=str(WText) + "Beacon Flood , "
        if PRGA=="1":
            WText=str(WText) + "Fragmentation PRGA , "
        if IARP=="1":
            WText=str(WText) + "ARP/Interactive Replay , "
        if MDKM=="1":
            WText=str(WText) + "MDK3 - Michael Shutdown Exploitation , "
        if WPAD=="1":
            WText=str(WText) + "MDK3 - WPA Downgrade Test , "
        if WText!="":
	    WText=WText[:-3]
	    Result=Result + "\n" + fcolor.BGreen + "     Possibility : " + fcolor.BRed + WText + " attacks."
    if Concern!=0:
        printc (" ","","")

    printl(fcolor.BRed + "                                                             ","","")
    printl(fcolor.BRed + "" + Result,"","")
    if PrintToFile=="1" and Result!="":
        open(LogFile,"a+b").write(RemoveColor(str(Result)) + "\n")
        if Concern!=0:
             open(LogFile,"a+b").write("\n")
    

    if Concern!=0:
        printc (" ","","")
        DrawLine("_",fcolor.CReset + fcolor.Black,"")
        printc (" ","","")

def GetESSID(MAC_ADDR):
    ESSID_log=tmpdir + "ESSID.log"
    ESSID=""
    if IsFileDirExist(ESSID_log)=="F":
        if len(MAC_ADDR)==17:
            with open(ESSID_log,"r") as rf:
                for eline in rf: 
                    eline=eline.replace("\n","")
                    if len(eline)>=18:
                        if eline.find(MAC_ADDR)!=-1:
                          ESSID=eline.replace(MAC_ADDR + "\t","")
                          if ESSID!="(not associated)":
                              printc (" ",fcolor.BWhite + "[ " + fcolor.BBlue + str(MAC_ADDR) + fcolor.BWhite + " ]'s SSID Name is [ " + fcolor.BBlue + str(ESSID) + fcolor.BWhite + " ].","")
                              return ESSID


def GetESSIDOnly(MAC_ADDR):
    ESSID_log=tmpdir + "ESSID.log"
    ESSID=""
    if IsFileDirExist(ESSID_log)=="F":
        if len(MAC_ADDR)==17:
            with open(ESSID_log,"r") as rf:
                for eline in rf: 
                    eline=eline.replace("\n","")
                    if len(eline)>=18:
                        if eline.find(MAC_ADDR)!=-1:
                          ESSID=eline.replace(MAC_ADDR + "\t","")
                          if ESSID!="(not associated)":
                              return ESSID


def GetESSIDOnlyText(MAC_ADDR):
    ESSID_log=tmpdir + "ESSID.log"
    TOText=""
    if IsFileDirExist(ESSID_log)=="F":
        if len(MAC_ADDR)==17:
            with open(ESSID_log,"r") as rf:
                for eline in rf: 
                    eline=eline.replace("\n","")
                    if len(eline)>=18:
                        if eline.find(MAC_ADDR)!=-1:
                          ESSID=eline.replace(MAC_ADDR + "\t","")
                          if ESSID!="(not associated)":
                              TOText="     " + fcolor.BWhite + "[ " + fcolor.BBlue + str(MAC_ADDR) + fcolor.BWhite + " ]'s SSID Name is [ " + fcolor.BBlue + str(ESSID) + fcolor.BWhite + " ]."
    return TOText





def UpdateClients():
    global ClientList
    global ESSIDList
    global BSSIDList
    global CL_ESSIDList
    global CL_BSSIDList
    global CL_MACList
    global CL_CountList
    ClientList=[]
    ESSIDList=[]
    BSSIDList=[]
    ClientList=[]

    CL_ESSIDList=[]
    CL_BSSIDList=[]
    CL_MACList=[]
    CL_CountList=[]
    NonAssociatedClient=""
    ESSIDChangedName=""
    ChangedAssociation=""
    ESSID_log=tmpdir + "ESSID.log"
    clientfile=tmpdir + "clients.log"
    newcaptured=tmpdir + "CapturedListing.csv"
    if IsFileDirExist(clientfile)!="F":
        open(clientfile,"wb").write("" )
    if IsFileDirExist(newcaptured)=="F":
        ModiESSID=""
        CLIENTS=""
        linecount=0

        TotalLine=GetFileLine(newcaptured,"0")
        BRes=0
        DisplayCt=0

        printl(fcolor.SGreen + "     Updating clients database....","","")
        with open(newcaptured,"r") as f:
            for line in f:
                line=line.replace("\n","")
                line=line.replace("\00","")
                linecount=linecount+1
                DisplayCt=DisplayCt+1
                if DisplayCt>10:
                    completed=Percent(linecount / float(TotalLine),2)
                    BRes=printl(fcolor.SGreen + "Updating clients database... : " + str(completed) + ".." ,"2",BRes)
                    DisplayCt=0

                if len(line)>5:
                    line=line + " ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., .,"
                    line=line.replace("\r","")
                    CList=line.split(",")
                    FMAC=line.split()[0].replace(',','')
                    FS1=line.split()[0].replace(',','')
                    FS2=line.split()[1].replace(',','')
                    FS=str(FS1) + " " + str(FS2)
                    Privacy=CList[5].lstrip().rstrip()
                    Cipher=CList[6].lstrip().rstrip()
                    Authentication=CList[7].lstrip().rstrip()
                    Power=CList[8].lstrip().rstrip()
                    ESSID=CList[13].lstrip().rstrip().replace("\n","")
                    SMAC=CList[5].lstrip().rstrip()
                    ProbeNetwork=CList[6].rstrip() + " / " + CList[7] + " / " +  CList[8] + " / " +  CList[9] + " / " + CList[10] + " / " +  CList[11] + " / " +  CList[12] + " / " +  CList[13] + " / " +  CList[14]
                    ProbeNetwork=ProbeNetwork.replace("/  .","").lstrip().rstrip()
                    ProbeNetwork=ProbeNetwork.rstrip().lstrip()
                    if len(ProbeNetwork)>3:
                        if ProbeNetwork[-2:]==" .":
                            ProbeNetwork=ProbeNetwork[:-2].rstrip()
                    if ProbeNetwork==".":
                        ProbeNetwork=""

                    Privacy=Privacy.replace('WPA2WPA OPN','WPA2WPA (OPN)')
                    Privacy=Privacy.replace('WPA2 OPN','WPA2 (OPN)')
                    Privacy=Privacy.replace('WPA OPN','WPA (OPN)')
                    Privacy=Privacy.replace('WPA2WPA','WPA2/WPA')
                    Privacy=Privacy.replace('WEP OPN','WEP (OPN)')
                    Cipher=Cipher.replace('CCMP TKIP','CCMP/TKIP')
                    ESSID=CheckSSIDChr(ESSID)
                    

                    if FS=="Station MAC":
                        CLIENTS=1
                    else:
                        if FMAC!="":
                            ESSIDList.append(str(ESSID))
                            BSSIDList.append(str(FMAC))
                    if CLIENTS==1 and len(FMAC)==17:
                        Result=""
                        if SMAC=="(not associated)":
                            if ProbeNetwork!="":
                                NonAssociatedClient=NonAssociatedClient + fcolor.BWhite + "\n     Wireless Device [ " + fcolor.BBlue + str(FMAC) + fcolor.BWhite + " ] is not associated to any network and is probing for [ " +  fcolor.BYellow + str(ProbeNetwork) + fcolor.BWhite + " ] .."
                                Result=GetMACOUI(FMAC,"0")
                                NonAssociatedClient=NonAssociatedClient + "\n" + Result
                            else:
                                NonAssociatedClient=NonAssociatedClient + fcolor.BWhite + "\n     Wireless Device [ " + fcolor.BBlue + str(FMAC) + fcolor.BWhite + " ] is not associated to any network and did not probe for any SSID .."
                                Result=GetMACOUI(FMAC,"0")
                                NonAssociatedClient=NonAssociatedClient + "\n" + Result
                        clientfile=tmpdir + "clients.log"
                        tmpfile=tmpdir + "clients.tmp"
                        if IsFileDirExist(clientfile)=="F":
                            FOUNDBSSID=""
                            open(tmpfile,"a+b").write("")
                            with open(clientfile,"r") as f:
                                for line in f:
                                    ESTN=""
                                    EXAP=""
                                    ESID=""
                                    line=line.replace("\n","")
                                    line=line.replace("\00","")
                                    if len(line)>24:
                                        line=line + ","
                                        ClientList=line.split(",")
                                        ESTN=ClientList[0]
                                        EXAP=ClientList[1]
                                        ESID=ClientList[2]
                                    ESTN=ESTN.replace(",","").lstrip().rstrip()
                                    EXAP=EXAP.replace(",","").lstrip().rstrip()
                                    ESID=ESID.lstrip().rstrip()

                                    xlbs=0
                                    lBSSID=len(BSSIDList)
                                    ESSID1=""
                                    ESSID2=""
                                    while xlbs<lBSSID:
                                        if BSSIDList[xlbs]==str(EXAP) and len(EXAP)==17:
                                            ESSID1=ESSIDList[xlbs]

                                        if BSSIDList[xlbs]==str(SMAC) and len(SMAC)==17:
                                            ESSID2=ESSIDList[xlbs]
                                            ESSID=ESSIDList[xlbs]
                                        xlbs=xlbs+1

                                    xlbs=0
                                    CLIENTMAC_FOUND=""
                                    lBSSID=len(CL_BSSIDList)

                                    while xlbs<lBSSID:
                                        if CL_BSSIDList[xlbs]==str(EXAP):
                                            CLIENTMAC_FOUND="1"
                                            if len(EXAP)==17 and ESTN!="" and CL_MACList[xlbs].find(ESTN)==-1:
                                                CL_MACList[xlbs]=CL_MACList[xlbs] + str(ESTN) + ", "
                                                CLIENTMAC_COUNT=CL_CountList[xlbs]
                                                if CLIENTMAC_COUNT=="":
                                                    CLIENTMAC_COUNT="0"
                                                CLIENTMAC_COUNT=int(CLIENTMAC_COUNT)+1
                                                CL_CountList[xlbs]=CLIENTMAC_COUNT
                                        xlbs=xlbs+1
                                    if CLIENTMAC_FOUND!="1" and len(ESTN)==17:
                                        CL_ESSIDList.append(str(GetESSIDOnly(EXAP)))
                                        CL_BSSIDList.append(str(EXAP))
                                        CL_MACList.append(str(ESTN) + ", ")
                                        CL_CountList.append("1")
                                        CLIENTMAC_FOUND=""
                                      


                              
                                    if len(FMAC)==17 and ESTN==FMAC and ESSID!="" and ESSID!=".":
                                        FOUNDBSSID="1"
                                        if ESID!=ESSID and ESSID!="" and ESID!="" and  len(SMAC)==17 and EXAP==SMAC:
                                            TOText=fcolor.BWhite + "\n     ESSID for [ " + fcolor.BBlue + str(EXAP) + fcolor.BWhite + " ] changed from [ " +  fcolor.BYellow + str(ESID) + fcolor.BWhite + " ] to  [ " + fcolor.BYellow + str(ESSID) + fcolor.BWhite + " ].."
                                            ESSIDChangedName=ESSIDChangedName + str(TOText)
                                            printl (TOText,"","")
                                            ESID=ESSID
                                         
                                        if len(SMAC)==17 and EXAP!=SMAC and ChangedAssociation.find(str(ESTN))==-1:
                                            TOText=fcolor.BRed + "\nAlert : " + fcolor.SGreen + "Client [ " + fcolor.BBlue + str(ESTN) + fcolor.SGreen + " ] initally associated to [ " +  fcolor.BCyan + str(EXAP) + fcolor.SGreen + " ] is now associated to [ " + fcolor.BRed + str(SMAC) + fcolor.SGreen + " ].."
                                            ChangedAssociation=ChangedAssociation + str(TOText)
                                            if ESSID1=="":
                                                ESSID1=GetESSIDOnly(EXAP)
                                                ChangedAssociation=ChangedAssociation + str(ESSID1)
                                            else:
                                                TOText=fcolor.BRed + "\n        " + fcolor.SGreen + "BSSID  [ " + fcolor.BCyan + str(EXAP) + fcolor.SGreen + " ]'s Name is [ " +  fcolor.BWhite + str(ESSID1) + fcolor.SGreen + " ]."
                                                ChangedAssociation=ChangedAssociation + str(TOText)
                                            if ESSID2=="":
                                                ESSID2=GetESSIDOnly(SMAC)
                                                ChangedAssociation=ChangedAssociation + str(ESSID2)
                                            else:
                                                TOText=fcolor.BRed + "\n        " + fcolor.SGreen + "BSSID  [ " + fcolor.BRed + str(SMAC) + fcolor.SGreen + " ]'s Name is [ " +  fcolor.BWhite + str(ESSID2) + fcolor.SGreen + " ]."
                                                ChangedAssociation=ChangedAssociation + str(TOText)
                                            EXAP=SMAC
                                            ESID=ESSID
                                            ChangedAssociation=ChangedAssociation + "\n"
                                    ESTN=ESTN.replace(",","").lstrip().rstrip()
                                    EXAP=EXAP.replace(",","").lstrip().rstrip()
                                    ESID=ESID.lstrip().rstrip()
                                    if ESTN!="" and EXAP!="" and ESID!="":
                                        open(tmpfile,"a+b").write(str(ESTN) + ", " + str(EXAP) + ", " + str(ESID)  + "\n")                               

                                if FOUNDBSSID=="":
                                    lBSSID=len(BSSIDList)
                                    xlbs=0
                                    EXAP=""
                                    ESID=""
                                    while xlbs<lBSSID:
                                        if BSSIDList[xlbs]==str(SMAC) and len(SMAC)==17:
                                            ESTN=str(FMAC)
                                            EXAP=BSSIDList[xlbs]
                                            ESID=ESSIDList[xlbs]
                                        xlbs=xlbs+1
                                    if EXAP!="" and ESID!="":
                                        open(clientfile,"a+b").write(str(ESTN) + ", " + str(EXAP) + ", " + str(ESID)  + "\n")
                                        open(tmpfile,"a+b").write(str(ESTN) + ", " + str(EXAP) + ", " + str(ESID)  + "\n")                               
                        os.remove(clientfile)
                        os.rename(tmpfile,clientfile)
        BRes=printl(fcolor.SGreen + "     Clients database updated...." ,"","")

    lBSSID=len(CL_BSSIDList)
    xlbs=0
    ClientFound=""
    while xlbs<lBSSID:
        if int(CL_CountList[xlbs])>100:
            printc (" ","","")
            ClientFound=CL_CountList[xlbs]
            CL_MACList[xlbs]=CL_MACList[xlbs].replace(", "," / ")
            CL_MACList[xlbs]=CL_MACList[xlbs][:-3]
            printc ("!!!",fcolor.BRed + "Alert: " + fcolor.BGreen + "Too much association was found associated to [ " + fcolor.BBlue + str(CL_BSSIDList[xlbs]) + fcolor.BGreen + " ] basing on association listing..","")
            ESSID=GetESSID(str(CL_BSSIDList[xlbs]))
            if PrintToFile=="":
                Ask=AskQuestion ("There are a total of [ " + fcolor.BRed + str(CL_CountList[xlbs]) + fcolor.BGreen +  " ] client's MAC captured, display them ?","y/N","","N","")
            else:
                printc(" ",fcolor.BGreen + "There are a total of [ " + fcolor.BRed + str(CL_CountList[xlbs]) + fcolor.BGreen +  " ] client's MAC captured.","")
                Ask="Y"
            if Ask=="Y" or Ask=="y":
                printc (".",fcolor.BGreen + "Client MAC [ " +  fcolor.BBlue + str(CL_MACList[xlbs]) + fcolor.BGreen + " ]","")
            print ""
        xlbs=xlbs+1
        if ClientFound!="":
            if IsFileDirExist(clientfile)=="F":
                os.remove(clientfile)

    if HIDEPROBE=="0":
        if NonAssociatedClient!="":
            BRes=printl(fcolor.SGreen + str(NonAssociatedClient) + "\n" ,"1","")
            if PrintToFile=="1":
                open(LogFile,"a+b").write(RemoveColor(str(NonAssociatedClient)) + "\n")

    if ChangedAssociation!="":
        BRes=printl(fcolor.SGreen + str(ChangedAssociation) + "\n" ,"1","")
        if PrintToFile=="1":
            open(LogFile,"a+b").write(RemoveColor(str(ChangedAssociation)) + "\n")

    if ESSIDChangedName!="":
        BRes=printl(fcolor.SGreen + str(ESSIDChangedName) + "\n" ,"1","")
        if PrintToFile=="1":
            open(LogFile,"a+b").write(RemoveColor(str(ESSIDChangedName)) + "\n")





def ConvertPackets():
    captured_pcap=tmpdir + "tcpdump.cap"
    tcpdump_log=tmpdir + "tcpdump.log"
    Result=DelFile(tcpdump_log,"0")
    RewriteCSV()
    UpdateClients()
    printl(fcolor.SGreen + "     Converting captured packets... Please wait...","","")
    ps=subprocess.Popen("tshark -r " + str(captured_pcap) + " -n -t ad > " + str(tcpdump_log), shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'))
    ps.wait()
    if PrintToFile=="1" and IsFileDirExist(captured_pcap)=="F":
        statinfo = os.stat(captured_pcap)
        open(LogFile,"a+b").write(">>>> Pkt Size : " + str(statinfo.st_size) + "\n")

    if ps.returncode==0:
        printl(fcolor.SGreen + "     Conversion completed......","","")
        return;
            
def RewriteCSV():
    captured_csv=tmpdir + "captured-01.csv"
    newcaptured_csv=tmpdir + "CapturedListing.csv"
    open(newcaptured_csv,"wb").write("" )
    if IsFileDirExist(captured_csv)=="F":
        with open(captured_csv,"r") as f:
            for line in f:
                line=line.replace("\n","")
                line=line.replace("\00","")
                open(newcaptured_csv,"a+b").write(line + "\n")



def IsAscii(inputStr):
    return all(ord(c) < 127 and ord(c) > 31 for c in inputStr)

def CheckSSIDChr(ESSID_Name):
    if IsAscii(ESSID_Name)==False:
        ESSID_Name=""
    return ESSID_Name
    

from random import randrange
from math import floor
global NullOut
global MyMAC
DN = open(os.devnull, 'w')
DebugMode="0"
printd("Main Start Here -->")
cmdline=len(sys.argv)
TWidth=103
ProxyType="0"
tmpfile='/tmp/ipinfo'
global InfoIP
InfoIP=""
global HIDEPROBE
global TEMP_HIDEPROBE
TEMP_HIDEPROBE=""
HIDEPROBE="0"
InfoIPVia=""
InfoIPFwd=""
TimeStart=""
MyMAC=""
appdir="/SYWorks/WIDS/"
macoui="/SYWorks/WIDS/mac-oui.db"
PathList = ['tmp/']
tmpdir=appdir + "tmp/"
#global PrevIconCount
PrevIconCount=0
NullOut=" > /dev/null 2>&1"
global LogFile
global PrintToFile
PrintToFile="0"
LogFile=appdir + "log.txt"

 

try:
    global MONList
    captured_pcap=tmpdir + "tcpdump.cap"
    captured_csv=tmpdir + "captured-01.csv"
    MONList = []
    global MONListC
    MONListC = []
    MonCt = GetInterfaceList("MON")
    MONList=IFaceList
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

    RETRY=0
    HIDEPROBE=TEMP_HIDEPROBE
    PrintToFile=PRINTTOFILE
    if ReadPacketOnly=="1":
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
        exit(1)

    if MonCt==0 and WLANCt!=0:
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

    if MonCt==0:
        printc (".",fcolor.SGreen + "Enabling monitoring for [ " + fcolor.BRed + SELECTED_IFACE + fcolor.SGreen + " ]...","")

        ps=subprocess.Popen("ifconfig " + str(SELECTED_IFACE) + " down > /dev/null 2>&1", shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'))
        ps.wait()
        ps=subprocess.Popen("iwconfig " +  str(SELECTED_IFACE) + " mode monitor > /dev/null 2>&1", shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'))
        ps.wait()
        ps=subprocess.Popen("ifconfig " + str(SELECTED_IFACE) + " up > /dev/null 2>&1", shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'))
        ps.wait()

        time.sleep (0.5)
        MonCt = GetInterfaceList("MON")

        if MonCt>=1:
            if SELECTED_MON=="":
                SELECTED_MON=SelectMonitorToUse()
            else:
                Rund="iwconfig " + SELECTED_MON + " > /dev/null 2>&1"
                result=os.system(Rund)
                if result==0:
                    printc(">",fcolor.BIGray + "Monitor Selection Bypassed....","")
                else:
                    printc ("!!!", fcolor.BRed + "The monitoring interface specified [ " + fcolor.BWhite + SELECTED_MON + fcolor.BRed + " ] is not available." ,"")
                    print ""
                    SELECTED_MON=SelectMonitorToUse()
    else:
        SELECTED_MON=SelectMonitorToUse()

    printc (" ", fcolor.SWhite + "Selected Monitoring Interface ==> " + fcolor.BRed + str(SELECTED_MON),"")
    print ""
    ps=subprocess.Popen("ifconfig " + str(SELECTED_MON) + " up  > /dev/null 2>&1" , shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'))

    x=0

    while x<int(LoopCount):
        captured_pcap=tmpdir + "captured"

        CaptureTraffic()
        ConvertPackets()
        AnalyseCaptured()
        x=x+1
        if int(LoopCount)-x<3 and int(LoopCount)!=x:
            printc (" ", "Remaining loop count : " + str(int(LoopCount)-x),"")
    printc ("i", fcolor.BWhite + "Completed !! ","")
    exit()



except (KeyboardInterrupt, SystemExit):
    printd("KeyboardInterrupt - " + str(KeyboardInterrupt) + "\n        SystemExit - " + str(SystemExit))
    printc (" ","","")
    printc ("*", fcolor.BRed + "Application shutdown !!","")
    if TimeStart!="":
        result=DisplayTimeStamp("summary-a","")
    if PrintToFile=="1":
        print fcolor.BGreen + "     Result Log\t: " + fcolor.SGreen + LogFile
        open(LogFile,"a+b").write("\n\n")
    PrintToFile="0"
    print ""
    MonCt = GetInterfaceList("MON")
    X=0
    while X<MonCt:
        PM=len(MONList)
        Y=0
        while Y<PM:
            if MONList[Y]==IFaceList[X]:
                IFaceList[Y]=""
            Y=Y+1
        X=X+1
    PM=len(IFaceList)
    Y=0
    while Y<PM:
        if IFaceList[Y]!="":
            printc (".", "Stopping " + str(IFaceList[Y]) + "....","")
            ps=subprocess.Popen("ifconfig " + str(IFaceList[Y]) + " down > /dev/null 2>&1", shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'))
            ps.wait()
            ps=subprocess.Popen("iwconfig " +  str(IFaceList[Y]) + " mode managed > /dev/null 2>&1", shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'))
            ps.wait()
            ps=subprocess.Popen("ifconfig " + str(IFaceList[Y]) + " up > /dev/null 2>&1", shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'))
            ps.wait()

            time.sleep(0.1)
        Y=Y+1
    ps=subprocess.Popen("killall 'airodump-ng' > /dev/null 2>&1" , shell=True, stdout=subprocess.PIPE)	
    time.sleep(0.1)
    ps=subprocess.Popen("killall 'tshark' > /dev/null 2>&1" , shell=True, stdout=subprocess.PIPE)	
    time.sleep(0.1)
    print fcolor.BWhite + "Please support by liking my page at " + fcolor.BBlue + "https://www.facebook.com/syworks" +fcolor.BWhite + " (SYWorks-Programming)"

    print ""
   
