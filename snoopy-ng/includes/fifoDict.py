#!/usr/bin/env python
# -*- coding: utf-8 -*-
# glenn@sensepost.com

from collections import OrderedDict

class fifoDict:
    """OrderedDict with FIFO size constraint"""
    def __init__(self, size=1000, reducePc=0.2, names=None):
        """
            'names' paramter should be a n tuple the same same size as a tuple passed to the add method
            For example, names = ('mac', 'ssid')
        """
        self.od = OrderedDict()
        self.sz = size
        self.reducePc=0.5
        self.names = names

    def add(self, item):
        if item not in self.od:
            self.od[item] = 0

    def getNew(self):    
        newData = []
        markAsFetched = []
        for key, val in self.od.iteritems():
            if val == 0:
                newData.append( key )
        for key in newData:
            self.od[key] = 1
        #Reduce size of dict by reducePc % :
        if len(self.od) > self.sz:
            for i in range(int(self.reducePc * self.sz)):
                try:
                    self.od.popitem(last = False)
                except KeyError:
                    pass
        #If keys were supplied, combine with values and return 
        if self.names:
            toReturn = []
            for ident in newData:
                row = dict(zip(self.names,ident))
                toReturn.append(row)
            return toReturn
        else:
            return newData
