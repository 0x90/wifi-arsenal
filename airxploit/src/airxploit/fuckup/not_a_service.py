'''
Created on 05.09.2010

@author: basti
'''

class NotAService(Exception):
    """
    service unknown exception
    """
    def __init__(self, what):
        super(NotAService, self).__init__()
        self.__msg = "Unknown service: " + str(what)
        
    def __str__(self):
        return self.__msg
