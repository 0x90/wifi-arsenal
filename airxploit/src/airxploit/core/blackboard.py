'''
Created on 31.07.2010

@author: basti
'''

import logging
import airxploit.core.target
from airxploit.fuckup.not_a_target import NotATarget

class Blackboard(object):
    '''
    A blackboard for centralized information gathering
    Every plugin can add targets and read or add information about it
    '''

    def __init__(self):
        self._targets = {}
               
    def add(self, target):
        """
        add a target to the blackboard
        """
        if issubclass(target.__class__, airxploit.core.target.Target):
            if target.addr not in self._targets:
                logging.debug(str(self.__class__) + " Adding target " + target.addr)
                self._targets[target.addr] = target
        else:
            raise NotATarget(target)

    def add_info(self, target, section, info):
        """
        add an info to section of target
        """
        if type(target).__bases__[0] == airxploit.core.target.Target and target.addr in self._targets:
            logging.debug(str(self.__class__) + " Adding info " + section + " to target " + target.addr)
            self._targets[target.addr].write_info(section, info)
        else:
            raise NotATarget(target)
    
    def read_all(self):
        """
        read all information on blackboard
        """
        return self._targets
         
    def read_all_without_info(self, section):
        """
        get all targets without a special info section
        """
        interesting_targets = []
        
        for target in self._targets.values():
            if not target.has_info(section):
                interesting_targets.append(target)
        
        return interesting_targets
