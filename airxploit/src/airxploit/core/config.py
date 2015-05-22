'''
Created on 05.09.2010

@author: basti
'''

from pyxml2obj import XMLin
import logging
import os

class Config(object):
    '''
    Parse airxploit xml config
    '''
    
    def __init__(self):
        logging.debug(str(self.__class__) + " Parse config conf/airxploit.conf")
        if os.path.exists("conf/airxploit.conf"):
            self._cfg = XMLin( open("conf/airxploit.conf","r").read() )
        else:
            self._cfg = XMLin( open("../conf/airxploit.conf","r").read() )

    def get(self, name):
        '''
        get a config setting
        '''
        if name in self._cfg["config"]:
            return str(self._cfg["config"][name])
    
    def cmd(self, name):
        '''
        get a tool command
        '''
        if name in self._cfg["tools"]:
            return str(self._cfg["tools"][name])
