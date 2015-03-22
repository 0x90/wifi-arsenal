#-------------------------------------------------------------------------------
# Name:        Mozilla Cookies Engine
# Purpose:     Mozilla Firefox Cookie Engine
#
# Author:      Saviour Emmanuel Ekiko
#
# Created:     20/07/2012
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


import os
import time
import sqlite3
import subprocess


# CREATE TABLE moz_cookies (id INTEGER PRIMARY KEY, baseDomain TEXT, name TEXT, value TEXT, host TEXT, path TEXT, expiry INTEGER, lastAccessed INTEGER, creationTime INTEGER, isSecure INTEGER, isHttpOnly INTEGER, CONSTRAINT moz_uniqueid UNIQUE (name, host, path))

class Mozilla_Cookie_Core(object):
    def __init__(self):
        self.isdeleted = False
        self.cookie_database = str()             # /root/.mozilla/firefox/nq474mcm.default/cookies.sqlite (Use self.get_Cookie_Path() to file path)

    def _create_moz_cookies(self):
        sql_code = "CREATE TABLE moz_cookies (id INTEGER PRIMARY KEY, baseDomain TEXT, name TEXT, value TEXT, host TEXT, path TEXT, expiry INTEGER, lastAccessed INTEGER, creationTime INTEGER, isSecure INTEGER, isHttpOnly INTEGER)"
        mozilla_cookie_db = sqlite3.connect(self.cookie_database)
        mozilla_cursor = mozilla_cookie_db.cursor()
        mozilla_cursor.execute(sql_code)
        mozilla_cookie_db.commit()
        mozilla_cookie_db.close()


    def _check_database_compatibility(self):
        if(self.isdeleted == False):
            self.kill_Process("firefox-bin")
            os.remove(self.cookie_database)
            self._create_moz_cookies()
            self.isdeleted = True



    def execute_query(self,sql_statement):
        '''Executes raw query into database and returns entry
            list() if any'''
        self._check_database_compatibility()
        mozilla_cookie_db = sqlite3.connect(self.cookie_database)
        mozilla_cursor = mozilla_cookie_db.cursor()
        try:
            mozilla_cursor.execute(str(sql_statement))
        except Exception,e:
            mozilla_cursor.close()
            os.remove(self.cookie_database)
            self._create_moz_cookies()
            mozilla_cookie_db = sqlite3.connect(self.cookie_database)
            mozilla_cursor = mozilla_cookie_db.cursor()
            mozilla_cursor.execute(str(sql_statement))

        return_objects = mozilla_cursor.fetchall()
        if(return_objects):
            return(return_objects)
        mozilla_cookie_db.commit()
        mozilla_cookie_db.close()

    # Mozilla Cookie entry format
    #
    # ('14', 'scorecardresearch.com', 'UID', '2baec64d-23.63.99.90-1342553308', '.scorecardresearch.com', '/', '1404761306', '1342815702910000', '1342553306190000', '0', '0')
    # (id_number,baseDomain,name,value,host,path,expiry,lastAccessed,creationTime,isSecure,isHttpOnly)
    #


    def calculate_mozilla_creationTime(self):
        crude_index = "0123456789"
        creation_time = str(int(time.time()))
        for add in xrange(16 - (len(creation_time) + 3)):
            creation_time += crude_index[add]
        creation_time += "000"
        return(creation_time)



    def insert_Cookie_Values(self,baseDomain,name,value,host,path,isSecure,isHttpOnly):
        '''Stores cookies into the moz_cookies table
        e.g "foobar.com","UID","1235423HYFFDTWB=YTER",".foobar.com","/","0","0"
        '''
        sql_code_a = "select max(id) from moz_cookies"

        response = self.execute_query(sql_code_a)[0][0]
        if(response):
            id_number = str(int(response) + 1)                           # calculates the next id number
        else:
            id_number = str(1)

        creationTime = self.calculate_mozilla_creationTime()    # 1342948082 + 023 + 0000 = (length == 16)
        lastAccessed = creationTime

        expiry = str(int(time.time()) + 1065600)                # Example : (Sun Jul 22 09:08:42 2012) -> (Fri Aug 3 17:45:51 2012) 12 days

        sql_code_b = "insert into moz_cookies values ('%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s')"
        sql_code_b = sql_code_b % (id_number,baseDomain,name,value,host,path,expiry,lastAccessed,creationTime,isSecure,isHttpOnly)
        self.execute_query(sql_code_b)



    def kill_Process(self,process_name):
        import commands
        pids = commands.getstatusoutput("pidof " + process_name)[1]
        for pid in pids.split():
            commands.getstatusoutput("kill " + pid)


    def get_Cookie_Path(self,cookie_name):
        '''Finds the cookie path from user's profile
           sets cookie_database variable to cookie path'''
        cookie_path = str()
        file_object = open(os.devnull,"w")
        userprofile = os.path.expanduser("~")
        for root,direc,files in os.walk(userprofile,True):
            if((cookie_name in files) and ("firefox" in root.lower())):
                cookie_path = root + os.sep + cookie_name
                self.cookie_database = cookie_path
                return(cookie_path)


# USAGE:

# cookie = Mozilla_Cookie_Core()
# cookie.get_Cookie_Path("cookies.sqlite")  | cookie.cookie_database = "D:\\cookies.sqlite"

# retrun_list = cookie.execute_query("select * from moz_cookies")
# for entries in retrun_list:
#    print(entries)



