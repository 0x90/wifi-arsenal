'''
Created on 13.08.2010

@author: basti
'''
class NotACommand(Exception):
    """
    the given object was not an airxploit command
    """
    def __init__(self, what):
        super(NotACommand, self).__init__()
        self.__msg = "Not an airxploit.command.Command object: " + str(what)
        
    def __str__(self):
        return self.__msg
