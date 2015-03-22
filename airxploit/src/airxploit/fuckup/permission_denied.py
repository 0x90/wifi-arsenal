'''
Created on 08.08.2010

@author: basti
'''

class PermissionDenied(Exception):
    """
    guess what permission denied dude ;)
    """
    def __init__(self, what):
        super(PermissionDenied, self).__init__()
        self.__msg = "Permission denied: " + what
    
    def __str__(self):
        return self.__msg
