#!/usr/bin/env python
# -*- coding: utf-8 -*-
# glenn@sensepost.com
import subprocess
from threading import Thread
import time
import sys
import os
import logging
from run_prog import run_program

if os.geteuid() != 0:
    exit("Please run me with root privilages")

DN = open(os.devnull, 'w')
logging.basicConfig(format='%(message)s', level=logging.DEBUG)

scriptPath=os.path.dirname(os.path.realpath(__file__))
#os.chdir(scriptPath)
sakis_exec=scriptPath + "/sakis3g"

class Sakis(Thread):
    """Uses the sakis3g binary to maintain a 3G connection. Supply APN"""
    def __init__(self,apn,bg = False):
        self.apn=apn
        self.dorun = True
        if not os.path.isfile(sakis_exec):
            logging.error("Error: 'sakis3g' binary is not in '%s' directory" % scriptPath)
            sys.exit(-1)
        Thread.__init__(self)
        self.start()

        if bg:
            logging.debug("[+] Starting backround 3G connection maintainer.")
        else:
            logging.debug("[+] Starting foreground 3G connection maintainer.")
            self.join()

    def run(self):
        self.maintain_connection()

    def maintain_connection(self):
        sawMessage, sawMessage2 = False, False
        while self.dorun:
            detected = self.is_plugged()
            while not detected and self.dorun:
                if not sawMessage2:
                    logging.info("No modem detected. Will check every 5 seconds until one apears, but won't show this message again.")
                    sawMessage2 = True
                time.sleep(5)
                detected = self.is_plugged()
            sawMessage2 = False
            if self.status() != "Connected" and detected and self.dorun:
                logging.info("Modem detected, but not currently online. Attempting to connect to 3G network '%s'" % self.apn)
                self.connect(self.apn)
                time.sleep(2)
                if self.status() == "Connected":
                    logging.info("Successfully connected to '%s'" % self.apn)
                    run_program("ntpdate ntp.ubuntu.com")
                else:
                    logging.info("Could not connect to '%s'. Will try again in 5 seconds" % self.apn)
            else:
                if not sawMessage:
                    logging.info("Modem is online.")
                    run_program("ntpdate ntp.ubuntu.com")
                    sawMessage = True
            time.sleep(5)
    
    def stop(self):
        logging.info("Stopping 3G connector. Will leave connection in its current state.")
        self.dorun = False

    @staticmethod
    def is_plugged():
        """Check if modem is plugged in"""
        try:
            r=subprocess.call([sakis_exec, "plugged"], stdout=DN, stderr=DN)
            if r == 0:
                return True
            else:
                return False
        except Exception,e:
            logging.error(e)
            return False
        

    @staticmethod
    def status():
        try:
            r=subprocess.call([sakis_exec, "status"], stdout=DN, stderr=DN)
            if r == 0:
                return "Connected"
            elif r == 6:
                return "Disconnected"
            else:
                return "Unknown"
        except Exception,e:
             logging.error(e)
             return "Error"

    @staticmethod
    def disconnect():
        r=subprocess.call([sakis_exec, "disconnect"], stdout=DN, stderr=DN)

    @staticmethod
    def get_apns():
        return "ToDo"

    @staticmethod
    def connect(apn):
        try:
            r=subprocess.call([sakis_exec, "connect", "APN='%s'"%apn], stdout=DN, stderr=DN)
            return r
        except Exception,e:
            logging.error(e)
            return -1

def usage():
    print "Usage:"
    print "\t%s <APN>"%__file__
    print "\te.g. %s orange.fr"%__file__

if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage()
        sys.exit(-1)
    f=None
    try: 
        f=Sakis(sys.argv[1], False)
    except KeyboardInterrupt:
        logging.info("Caught Ctrl+C. Shutting down")
        f.stop()
