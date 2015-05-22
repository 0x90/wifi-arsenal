'''
Created on 08.08.2010

@author: basti
'''

class BigShit(Exception):
    '''
    Some big shit happened and if you catch this you should kill yourself
    or at least your running code fragment ;)
    '''


    def __init__(self, what):
        super(BigShit, self).__init__()
        self.__msg = "Big shit happened: " + what
        
    def __str__(self):
        return self.__msg
