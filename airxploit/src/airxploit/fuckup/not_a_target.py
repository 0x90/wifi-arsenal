'''
Created on 08.08.2010

@author: basti
'''

class NotATarget(Exception):
    """
    the given object was not a target
    """
    def __init__(self, what):
        super(NotATarget, self).__init__()
        self.__msg = "Not an airxploit.core.target.Target object: " + str(what)
        
    def __str__(self):
        return self.__msg
