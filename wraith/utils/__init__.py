#!/usr/bin/env python

""" utils: utility functions

this also includes singular functions that currently do not have another
place to go
"""
__name__ = 'utils'
__license__ = 'GPL v3.0'
__version__ = '0.0.1'
__date__ = 'February 2015'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Production'

# intersection of two lists
def intersection(l1,l2): return filter(lambda x:x in l1,l2)