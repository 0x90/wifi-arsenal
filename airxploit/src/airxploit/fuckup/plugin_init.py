'''
Created on 04.09.2010

@author: basti
'''

class PluginInit(Exception):
    """
    plugin initialization error
    """
    def __init__(self, what):
        super(PluginInit, self).__init__()
        self.__msg = "Initialization failed for plugin " + what
    
    def __str__(self):
        return self.__msg
