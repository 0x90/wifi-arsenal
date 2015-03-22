'''
Created on 31.07.2010

@author: basti
'''

class Target(object):
    '''
    AirXploit target
    '''

    def __init__(self):
        self.name = "unknown"
        self.addr = None
        self.encryption = None
        self.quality = None
        self._additional_information = {}

    def write_info(self, section, info):
        """
        write an info to a section
        """
        self._additional_information[section] = info

    def read_info(self, section):
        """
        read all information of section
        """
        if section in self._additional_information:
            return self._additional_information[section]
        else:
            return None
    
    def has_info(self, section):
        """
        check if target has information in the given section
        """
        if section in self._additional_information:
            return True
        else:
            return False
    
class Bluetooth(Target):
    '''
    Bluetooth target
    '''

    def __init__(self):
        Target.__init__(self)

class Wlan(Target):
    '''
    Wlan target
    '''

    def __init__(self):
        Target.__init__(self)
        self.channel = None
