#!/usr/bin/python

__author__ = 'Bryan "Crypt0s" Halfpap'
__email__ = 'Bryan.Half@gmail.com'
__website__= ''
__date__ = '02/19/13'
__version__ = '2.1'
__file__ = 'liboui2.py'
__data__ = 'A class for (quickly) dealing with large oui txt'

import marshal
import urllib2
import re
import sys
import os
import pdb


class typeCheck:
    """
    Class for parsing and querying oui's to type lookup file
    """
    def __init__(self, filename):
        """
        filename = name of whatmac lookup file to parse
        """
        self.filename = filename
        # may cause an issue with parsed files in other directories
        self.pyobj = "%s.pyobj" %(self.filename)
        self.typeSearch4 = {}
        self.typeSearch3 = {}
        if self.loadobj() is False:
                self.parse(self.readin())
                self.dumpobj()
                

    def readin(self):
        """
        check for db file then read it in
        """
        if os.path.exists(self.filename):
            with open(self.filename, 'r') as type_file:
                return type_file.readlines()
        
    def parse(self, lines):
        """
        parse the read in lines to a dict
        """
        for line in lines:
            data = line.strip().split(',')
            self.typeSearch4[data[0]] = data[1]
            # create a 3byte lookup
            self.typeSearch3[data[0][:-3]] = data[1]

    def search(self, search):
        """
        do a 3byte or 4 byte lookup
        expects format in xx:xx:xx:xx:xx:xx
        """
        typeSearch = self.typeSearch4
        if search[:11] in typeSearch.keys():
            return (typeSearch[search[:11]], 4)
        else:
           typeSearch = self.typeSearch3
           if search[:8] in typeSearch.keys():
                return (typeSearch[search[:8]], 3)
    
    def dumpobj(self):
        """
        Make a marshal object dump for superfast loading
        """
        data = (self.typeSearch4, self.typeSearch3)
        with open(self.pyobj, 'w') as dumpfile:
            dumpfile.write(marshal.dumps(data))
    
    def loadobj(self):
        """ 
        Loads the object file in and makes a hash straightaway
        if it exists
        """
        if os.path.exists(self.pyobj) is False:
            return False
        with open(self.pyobj, 'r') as dumpfile:
            data = marshal.loads(dumpfile.read())
        self.typeSearch4 = data[0]
        self.typeSearch3 = data[1]
    
            
class Oui:
    """
    Class for parsing and querying oui.txt
    """
    def __init__(self, filename, parser='ieee'):
        """
        filename = filename of oui.txt to parse
        parser = parser to use, current options are ieee
        """
        OUI_FILE = None
        # support loading oui.txt from multiple locations 
        # where it might be pre installed
        self.OUI_PATH = ["/etc/aircrack-ng/airodump-ng-oui.txt",
            "/usr/local/etc/aircrack-ng/airodump-ng-oui.txt",
            "/usr/share/aircrack-ng/airodump-ng-oui.txt",
            "/var/lib/misc/oui.txt",
            "/etc/manuf/oui.txt",
            "/usr/share/wireshark/wireshark/manuf/oui.txt",
            "/usr/share/wireshark/manuf/oui.txt",
            "/etc/oui.txt"]
        # append any oui paths provided by program using lib to list
        if filename != None:
            self.OUI_PATH.append(filename)
        for PATH in self.OUI_PATH:
            if os.path.isfile(PATH):
                OUI_FILE = PATH
        if OUI_FILE == None:
            # default option
            OUI_FILE = "/etc/oui.txt"
        
        self.filename = OUI_FILE
        # may cause an issue with parsed files in other directories
        self.pyobj = "%s.pyobj" %(self.filename)
        self.the_hash = {}
        self.style = parser
        if self.loadobj() is False:
            if self.download():
                self.parse()
                self.dumpobj()
                
    def download(self):
        """
        download the oui.txt file
        """
        print "downloading list"
        oui_url = 'http://standards.ieee.org/regauth/oui/oui.txt'
        # file exists, use it, we should check in more then one location though
        # like where aircrack-ng stores it or wireshark.
        if os.path.exists(self.filename):
            return True
        try:
            oui_download = urllib2.urlopen(oui_url)
            with open(self.filename, 'w') as oui_file:
                oui_file.write(oui_download.read())
            return True
        except:
            print "Error downloading/saving the file"
            return False
    
    def loadobj(self):
        """ 
        Loads the object file in and makes a hash straightaway
        if it exists
        """
        if os.path.exists(self.pyobj) is False:
            return False
        with open(self.pyobj, 'r') as dumpfile:
            self.the_hash = marshal.loads(dumpfile.read())
    

    def parse(self):
        hash = {}
        """
        style allows us to overload method for different file formats
        """
        with open(self.filename, 'r') as oui_file:
            #IEEE STYLE OUI
            if self.style == "ieee":
                hex_re = re.compile('.*\(hex\).*')
                for line in oui_file.readlines():
                    match = hex_re.search(line)
                    if match is not None:
                        #print "boop."
                        split_line = line.split()
                        #print split_line[0]
                        #Create a hash that will allow two-way search
                        #remove - replace with 
                        ouihex_dashes = split_line[0]
                        ouihex = re.sub("-",":",ouihex_dashes)
                        throwaway = split_line[1]
                        company = ' '.join(split_line[2:]).lower().strip().lstrip()

                        #TODO: This as it's own def() since all parsers needit
                        #look up, if company has entry, add to their list
                        try:
                            existing_list = hash[company]
                            if existing_list:
                                existing_list.append(ouihex)
                        except:
                            hash[company] = [ouihex]
            else:
                #other parsing shemes will go here
                print "Not implemented, sorry"

        #pretty statistics now that we're done
        total = 0
        for mac in hash.values():
            total += len(mac)

        print str(len(hash.keys())) + " Total Companies with %s OUI's" %(total)
        print "Parsing complete.  Saving dictionary object to file" 

        #set hash and return
        self.the_hash = hash
        return hash

    def dumpobj(self):
        #Make a marshal object dump for superfast loading
        with open(self.pyobj, 'w') as dumpfile:
            dumpfile.write(marshal.dumps(self.the_hash))
        print "Pre-parsed dictionary dumped to %s" %(self.pyobj) 

    def buildindex(self):
        if self.the_hash == None:
            print "You didn't build the list, load it or parse it."
            return None
        self.keys = self.the_hash.keys()
        self.values = self.the_hash.values()
        return True

    def search(self, value, searchtype, greed = False):
        if self.buildindex() is None:
            print "failed to create index."
            return None
        #for looking up mac addresses by company
        if searchtype == 'c':
            if greed == True:
                #this will return a list of lists
                keys = self.the_hash.keys()
                list_hopper = []
                answer = []
                company_search = re.compile(value+'.*')
                for key in keys:
                    match = company_search.search(key)
                    if match is not None:
                        list_hopper.append(key)
                #Add all matches from the companies to a main list, then send the list to the requestor
                for key in list_hopper:
                    answer.extend(self.the_hash[key])
                return answer
            else:
                #bugfix
                return self.the_hash[value]

        #For looking up a company by mac address
        if searchtype == 'm':
            # grab just the ouiBytes
            if len(value) > 8:
                value = value[:8]
            index = 0
            for mac in self.values:
                for item in mac:
                    if item == value:
                        return self.keys[index]
                index = index + 1
            #we didn't find it
            return None


######################
#   Example Usages   #
######################
if __name__ == "__main__":
    print "This is a library, but some examples are included at the end of the file if you view the source."
    myoui = Oui('oui.txt')
    ##an overloaded method, see documentation
    print myoui.search('D0-E5-4D', 'm') # expected result from ieee file is "pace"
    mytype = typeCheck('whatcDB.csv')
    print mytype.search('58:55:CA:C3:C4') # expecte result is iphone 4
    print mytype.search('58:55:CA:C1:c5') # expecte result is iphone 4
