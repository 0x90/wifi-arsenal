#!/usr/bin/env python

from random import choice
from urllib import urlencode
from httplib import HTTPConnection


settings = {
    "ip": "172.16.42.1",
    "port": 1471,
    "root_password": "toor",
    "ap_ssid": "AccessPoint",
    "ap_password": "password"
}

parameters = ('amber', 'blue', 'red',)
values = ('on', 'off', 'blink',)

connection = HTTPConnection(settings["ip"], settings["port"])
php_session = ""

while True:
    post_data = "{}&verify_pineapple=true".format(urlencode(dict((parameter, choice(values),) for parameter in 
parameters)))
    connection.request("POST", "/?action=verify_pineapple", post_data, {"Content-type": 
"application/x-www-form-urlencoded", "Connection": "keep-alive", "Cookie" : php_session})
    response = connection.getresponse()
    php_session = php_session or response.getheader("set-cookie").split(";")[0]
    if "action=set_password" in response.read():
      connection.request("POST", "/?action=set_password", 
"password={0}&password2={0}&set_password=true&eula=true&sw_license=true".format(settings["root_password"]), 
{"Content-type": "application/x-www-form-urlencoded", "Cookie": php_session})
      connection.getresponse().read()
      connection.request("POST", "/?action=set_ssid", 
"ssid={0}&password={1}&password2={1}&set_ssid=true".format(settings["ap_ssid"], settings["ap_password"]), 
{"Content-type": "application/x-www-form-urlencoded", "Cookie": php_session})
      connection.getresponse().read()
      connection.request("GET", "/?action=finish")
      print "Setup finished"
      break

