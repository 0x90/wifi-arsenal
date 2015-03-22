#-------------------------------------------------------------------------------
# Name:        Bruteforce Core
# Purpose:     Bruteforcing network services
#
# Author:      Saviour Emmanuel Ekiko
#
# Created:     27/11/2012
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
import time
import base64
import ftplib
import socket
import urllib2

from PyQt4 import QtCore


class HTTP_Authentication(object):
    def __init__(self):
        self.target_url = str()

    def login_http(self,username,password):
        request = urllib2.Request(self.target_url)
        base64string = base64.encodestring('%s:%s' % (username, password)).replace('\n', '')
        request.add_header("Authorization", "Basic %s" % base64string)
        result = urllib2.urlopen(request)



class TELNET_Authentication(object):
    def __init__(self):
        self.target_address = str()
        self.target_port = int()

    def login_telnet(self,username,password):
        check_points = 0
        return_code = False
        self.telnet_sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.telnet_sock.connect((self.target_address,int(self.target_port)))

        if(username == str()):
            username = "root"

        communication_code = 0
        while(True):
            response = self.telnet_sock.recv(1024)
            if(re.findall("logon failure:",response,re.IGNORECASE)):
                return_code = False
                return(False)

            elif(re.findall("login",response,re.IGNORECASE)):
                check_points += 1
                for  username_char in list(username):
                    self.telnet_sock.send(username_char)
                    self.telnet_sock.recv(1204)
                self.telnet_sock.send("\x0d")

            elif(re.findall("password",response,re.IGNORECASE)):
                check_points += 1
                for password_char in list(password):
                    self.telnet_sock.send(password_char)
                self.telnet_sock.send("\x0d")

            elif(check_points == 2):
                return_code = True
                return(True)
            else:
                self.telnet_sock.send(response)

            if(communication_code > 11):
                break

            communication_code += 1
        self.telnet_sock.close()
        return(return_code)


class FTP_Authentication(object):
    def __init__(self):
        self.ftp = ftplib.FTP()
        self.target_address = str()
        self.target_port = int()

    def login_ftp(self,username,password):
        self.ftp.connect(self.target_address,int(self.target_port))
        self.ftp.login(username,password)
        self.ftp.close()




class Bruteforce_Attack(QtCore.QThread):
    def __init__(self):
        QtCore.QThread.__init__(self)
        self._timer = 0

        self._target_address = str()                         # Remote address
        self._target_port = int()                            # Remote address service port

        self.empty_username = True                          # Asssert if empty username is to be used
        self.empty_password = True                          # Assert if empty password is to be used

        self.user_wordlist = str()                          # Path to wordlist e.g /usr/local/login.txt
        self.password_wordlist = str()                      # Path to password wordlists e..g /usr/local/password.txt

        self._progress = float()
        self._total_combination = float()                   # possible user and password tries
        self._attack_type = str()                           # (FTP || TELNET || HTTP)
        self._error_message = str()                         # Holds Error messages

        self.next_try_details = ()                          # [23%,"username","password"]
        self.control = True                                 # WIll stop all attacks and exit threads when == False


    def setTimer(self,time):
        '''Set time to sleep in seconds'''
        self._timer = time

    def set_target_address(self,address,port):
        self._target_address = address
        self._target_port = port


    def set_attack_type(self,attack_type):
        '''Set Attack Type'''
        option_types = ["HTTP","FTP","TELNET"]
        if(attack_type not in option_types):
            raise Exception("Invalid Attack Type Selected Supported Types are (FTP,HTTP,TELNET)")
        self._attack_type = attack_type

    def get_exception(self):
        return(str(self._error_message))


    def _line_count(self,filename,wordlist_type):
        '''Returns line count'''
        lines = open(filename).readlines()
        if(wordlist_type == "userlist"):
            if(self.empty_username):
                lines.append(str())
        if(wordlist_type == "wordlist"):
            if(self.empty_password):
                lines.append(str())

        return(len(lines))


    def _wordlist_iterator(self):
        user_list = open(self.user_wordlist).readlines()
        password_list = open(self.password_wordlist).readlines()

        if(self.empty_username):
            user_list.append(str())
        if(self.empty_password):
            password_list.append(str())

        for username in user_list:
            for password in password_list:
                self._progress += 1.0
                yield(username.strip(),password.strip())


    def _calculate_percentage(self):
        percentage = (self._progress/self._total_combination) * 100
        percentage_format = "%1.2f"%(percentage)
        return(str(percentage_format) + "%")


    def _run_bruteforce(self):
        if(self._attack_type == "HTTP"):                                                # Switch Case Attack_Type

            self.bruteforce_http_method = HTTP_Authentication()
            self.bruteforce_http_method.target_url = self._target_address

            for username,password in self._wordlist_iterator():
                self.next_try_details = (self._calculate_percentage(),username,password)
                try:
                    self.bruteforce_http_method.login_http(username,password)                                  # TELNET HERE
                    self.emit(QtCore.SIGNAL("successful_login(QString,QString)"),username,password)
                except Exception,message:
                    if("connection timed out" in str(message).lower()):
                        self._error_message = "Unable to connect to the remote address, Connection timed out"
                        self.emit(QtCore.SIGNAL("We Got Error"))
                        return
                    if("no route to host" in str(message).lower()):
                        self._error_message = "Unable to connect to the remote address, Connection timed out"
                        self.emit(QtCore.SIGNAL("We Got Error"))
                        return

                    if("error 404" in str(message).lower()):
                        self._error_message = "The remote target returned an HTTP 404 error code, meaning that the requested page does not exist"
                        self.emit(QtCore.SIGNAL("We Got Error"))
                        return

                    if("name or service not known" in str(message).lower()):
                        self._error_message = "Unable to connect to the remote address, Connection timed out"
                        self.emit(QtCore.SIGNAL("We Got Error"))
                        return

                    if("unreachable" in str(message).lower()):
                        self._error_message = "Unable to connect to the remote address, Connection timed out"
                        self.emit(QtCore.SIGNAL("We Got Error"))
                        return

                    if("connection refused" in str(message).lower()):
                        self._error_message = "The connection was refused by the remote service, Please try again"
                        self.emit(QtCore.SIGNAL("We Got Error"))
                        return

                    if("no address associated" in str(message).lower()):
                        self._error_message = "No address is associated with the target hostname"
                        self.emit(QtCore.SIGNAL("We Got Error"))
                        return

                if(self.control == False):
                    return

                self.emit(QtCore.SIGNAL("Next Try"))
                time.sleep(self._timer)

            self.emit(QtCore.SIGNAL("Finished bruteforce"))
            self.control = False


        if(self._attack_type == "TELNET"):
            self.bruteforce_http_method = TELNET_Authentication()

            self.bruteforce_http_method.target_address = self._target_address
            self.bruteforce_http_method.target_port = self._target_port

            for username,password in self._wordlist_iterator():
                self.next_try_details = (self._calculate_percentage(),username,password)
                try:
                    if(self.bruteforce_http_method.login_telnet(username,password)):                                   # FTP HERE
                        self.emit(QtCore.SIGNAL("successful_login(QString,QString)"),username,password)
                except Exception,message:
                    if("name or service not known" in str(message).lower()):
                        self._error_message = "Unable to resolve target hostname"
                        self.emit(QtCore.SIGNAL("We Got Error"))
                        return

                    if("connection timed out" in str(message).lower()):
                        self._error_message = "Unable to connect to the remote address, Connection timed out"
                        self.emit(QtCore.SIGNAL("We Got Error"))
                        return
                    if("no route to host" in str(message).lower()):
                        self._error_message = "Unable to connect to the remote address, Connection timed out"
                        self.emit(QtCore.SIGNAL("We Got Error"))
                        return

                    if("unreachable" in str(message).lower()):
                        self._error_message = "Unable to connect to the remote address, Connection timed out"
                        self.emit(QtCore.SIGNAL("We Got Error"))
                        return

                    if("connection refused" in str(message).lower()):
                        self._error_message = "The connection was refused by the remote service, Please try again"
                        self.emit(QtCore.SIGNAL("We Got Error"))
                        return

                    if("no address associated" in str(message).lower()):
                        self._error_message = "No address is associated with the target hostname"
                        self.emit(QtCore.SIGNAL("We Got Error"))
                        return

                if(self.control == False):
                    return

                self.emit(QtCore.SIGNAL("Next Try"))
                time.sleep(self._timer)

            self.emit(QtCore.SIGNAL("Finished bruteforce"))
            self.control = False


        if(self._attack_type == "FTP"):
            self.bruteforce_http_method = FTP_Authentication()

            self.bruteforce_http_method.target_address = self._target_address
            self.bruteforce_http_method.target_port = self._target_port

            for username,password in self._wordlist_iterator():
                self.next_try_details = (self._calculate_percentage(),username,password)
                try:
                    self.bruteforce_http_method.login_ftp(username,password)                                   # FTP HERE
                    self.emit(QtCore.SIGNAL("successful_login(QString,QString)"),username,password)
                except Exception,message:
                    if("name or service not known" in str(message).lower()):
                        self._error_message = "Unable to resolve target hostname"
                        self.emit(QtCore.SIGNAL("We Got Error"))
                        return

                    if("connection timed out" in str(message).lower()):
                        self._error_message = "Unable to connect to the remote address, Connection timed out"
                        self.emit(QtCore.SIGNAL("We Got Error"))
                        return
                    if("no route to host" in str(message).lower()):
                        self._error_message = "Unable to connect to the remote address, Connection timed out"
                        self.emit(QtCore.SIGNAL("We Got Error"))
                        return

                    if("unreachable" in str(message).lower()):
                        self._error_message = "Unable to connect to the remote address, Connection timed out"
                        self.emit(QtCore.SIGNAL("We Got Error"))
                        return

                    if("connection refused" in str(message).lower()):
                        self._error_message = "The connection was refused by the remote service, Please try again"
                        self.emit(QtCore.SIGNAL("We Got Error"))
                        return


                    if("no address associated" in str(message).lower()):
                        self._error_message = "No address is associated with the target hostname"
                        self.emit(QtCore.SIGNAL("We Got Error"))
                        return

                if(self.control == False):
                    return

                self.emit(QtCore.SIGNAL("Next Try"))
                time.sleep(self._timer)

            self.emit(QtCore.SIGNAL("Finished bruteforce"))
            self.control = False


    def stop_Attack(self):
        self.control = False


    def start_Attack(self):
        self.control = True
        self._progress = 0.0
        user_count = self._line_count(self.user_wordlist,"userlist")
        password_count = self._line_count(self.password_wordlist,"wordlist")

        self._total_combination = float(user_count * password_count)
        self._run_bruteforce()


    def run(self):
        self.start_Attack()









