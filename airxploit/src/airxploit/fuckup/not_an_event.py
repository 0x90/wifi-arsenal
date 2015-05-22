'''
Created on 05.09.2010

@author: basti
'''

class NotAnEvent(Exception):
    """
    unknown event exception
    """
    def __init__(self, what):
        super(NotAnEvent, self).__init__()
        self.__msg = "Unknown event: " + str(what)
        
    def __str__(self):
        return self.__msg
