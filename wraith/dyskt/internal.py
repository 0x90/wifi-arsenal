#!/usr/bin/env python

""" internal.py: defines a report for internal communication betw/ dyskt children
"""
__name__ = 'internal'
__license__ = 'GPL v3.0'
__version__ = '0.0.1'
__date__ = 'December 2014'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Development'

class Report(object):
    """ report class passed thru Comms object """
    def __init__(self,cs,ts,ev,d,ps=None):
        """ initialize report """
        self.cs = cs        # report callsign of sender
        self.ts = ts        # timestamp event being report occurred
        self.event = ev     # event description
        self.msg = d        # the message
        self.params = ps    # any additional parameters
    @property
    def report(self): return self.cs,self.ts,self.event,self.msg,self.params