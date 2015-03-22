#!/usr/bin/python 
# -*- coding: utf-8 -*-

#######################################################
# Maltego Python Local Transform Helper               #
#   Version 0.2                           #
#                                                     #
# Local transform specification can be found at:      #
#    http://ctas.paterva.com/view/Specification       #
#                                                     #
# For more help and other local transforms            #
# try the forum or mail me:                           #
#                                                     #
#   http://www.paterva.com/forum                      #
#                                                     #
#  Andrew MacPherson [ andrew <<at>> Paterva.com ]    #
#                                                     #
#  glenn@sensepost.com:                               #
#   * Modified to allow multiple display args         #
#   * getVar() can have a default value set if non    #
#   * retabbed                                        #
#######################################################
import sys

class MaltegoEntity(object):
    value = "";
    weight = 100;
    displayInformation = [] #None; GW
    additionalFields = [];
    iconURL = "";
    entityType = "Phrase"
    
    def __init__(self,eT=None,v=None):
        if (eT is not None):
            self.entityType = eT;
        if (v is not None):
            self.value = sanitise(v);
        self.additionalFields = [];
        self.displayInformation = []; #None; GW
        
    def setType(self,eT=None):
        if (eT is not None):
            self.entityType = eT;
    
    def setValue(self,eV=None):
        if (eV is not None):
            self.value = sanitise(eV);
        
    def setWeight(self,w=None):
        if (w is not None):
            self.weight = w;
    

    def addDisplayInformation(self,di=None,dl='Info'):
        if (di is not None):
            self.displayInformation.append([dl,di])

#   def setDisplayInformation(self,di=None):
#       if (di is not None):
#           self.displayInformation = di;       
            
    def addAdditionalFields(self,fieldName=None,displayName=None,matchingRule=False,value=None):
        self.additionalFields.append([sanitise(fieldName),sanitise(displayName),matchingRule,sanitise(value)]);
    
    def setIconURL(self,iU=None):
        if (iU is not None):
            self.iconURL = iU;
            
    def returnEntity(self):
        print "<Entity Type=\"" + str(self.entityType) + "\">";
        #self.value = self.value.encode('utf-8')
        print "<Value>%s</Value>" % self.value
        #print "<Value>" + str(self.value) + "</Value>";
        print "<Weight>" + str(self.weight) + "</Weight>";
        if (len(self.displayInformation) > 0):
            print "<DisplayInformation>"
            for i in range(len(self.displayInformation)):
                print '<Label Name=\"'+self.displayInformation[i][0]+'\" Type=\"text/html\"><![CDATA[' + (self.displayInformation[i][1]) + ']]></Label>'
            print '</DisplayInformation>'


        if (len(self.additionalFields) > 0):
            print "<AdditionalFields>";
            for i in range(len(self.additionalFields)):
                if (str(self.additionalFields[i][2]) <> "strict"):
                    print "<Field Name=\"" + str(self.additionalFields[i][0]) + "\" DisplayName=\"" + str(self.additionalFields[i][1]) + "\">" + str(self.additionalFields[i][3]) + "</Field>";
                else:
                    print "<Field MatchingRule=\"" + str(self.additionalFields[i][2]) + "\" Name=\"" + str(self.additionalFields[i][0]) + "\" DisplayName=\"" + str(self.additionalFields[i][1]) + "\">" + str(self.additionalFields[i][3]) + "</Field>";
            print "</AdditionalFields>";
        if (len(self.iconURL) > 0):
            print "<IconURL>" + self.iconURL + "</IconURL>";
        print "</Entity>";



    def returnEntity_(self):
        print "<Entity Type=\"" + (self.entityType) + "\">";
        print "<Value>" + (self.value) + "</Value>";
        print "<Weight>" + str(self.weight) + "</Weight>";
#       if (self.displayInformation is not None):
#           print "<DisplayInformation><Label Name=\"\" Type=\"text/html\"><![CDATA[" + (self.displayInformation) + "]]></Label></DisplayInformation>";
        if (len(self.displayInformation) > 0):
            print "<DisplayInformation>"
            for i in range(len(self.displayInformation)):
                print '<Label Name=\"'+self.displayInformation[i][0]+'\" Type=\"text/html\"><![CDATA[' + (self.displayInformation[i][1]) + ']]></Label>'
            print '</DisplayInformation>'

        if (len(self.additionalFields) > 0):
            print "<AdditionalFields>";
            for i in range(len(self.additionalFields)):
                if ((self.additionalFields[i][2]) <> "ict"):
                    #print u"<Field Name=\"%s \" DisplayName=\"%s\">%s</Field>" %(self.additionalFields[i][0], self.additionalFields[i][1], self.additionalFields[i][3]);
                    print "<Field Name=\"" + (self.additionalFields[i][0]) + "\" DisplayName=\"" + (self.additionalFields[i][1]) + "\">" + (self.additionalFields[i][3]) + "</Field>";
                else:
                    print "<Field MatchingRule=\"" + str(self.additionalFields[i][2]) + "\" Name=\"" + str(self.additionalFields[i][0]) + "\" DisplayName=\"" + str(self.additionalFields[i][1]) + "\">" + str(self.additionalFields[i][3]) + "</Field>";
                    #print "<Field MatchingRule=\"" + (self.additionalFields[i][2]) + "\" Name=\"" + (self.additionalFields[i][0]) + "\" DisplayName=\"" + (self.additionalFields[i][1]) + "\">" + (self.additionalFields[i][3]) + "</Field>";
            print "</AdditionalFields>";
        if (len(self.iconURL) > 0):
            print "<IconURL>" + self.iconURL + "</IconURL>";
        print "</Entity>";
    
class MaltegoTransform(object):
    entities = []
    exceptions = []
    UIMessages = []
    values = {};
    
    def __init__(self):
        values = {};
        value = None;
    
    def parseArguments(self,argv):
        if (argv[1] is not None):
            self.value = argv[1];
            
        if (len(argv) > 2):
            if (argv[2] is not None):
                vars = argv[2].split('#');
                for x in range(0,len(vars)):
                    vars_values = vars[x].split('=')
                    if (len(vars_values) == 2):
                        self.values[vars_values[0]] = vars_values[1];
    
    def getValue(self):
        if (self.value is not None):
            return self.value;
    
    def getVar(self,varName,default=None):
        if (varName in self.values.keys()) and (self.values[varName] is not None):
            return self.values[varName];
        else:
            return default
    
    def addEntity(self,enType,enValue):
        me = MaltegoEntity(enType,enValue);
        self.addEntityToMessage(me);
        return self.entities[len(self.entities)-1];
    
    def addEntityToMessage(self,maltegoEntity):
        self.entities.append(maltegoEntity);
        
    def addUIMessage(self,message,messageType="Inform"):
        self.UIMessages.append([messageType,message]);
    
    def addException(self,exceptionString):
        self.exceptions.append(exceptionString);
        
    def throwExceptions(self):
        print "<MaltegoMessage>";
        print "<MaltegoTransformExceptionMessage>";
        print "<Exceptions>"
        
        for i in range(len(self.exceptions)):
            print "<Exception>" + self.exceptions[i] + "</Exception>";
        print "</Exceptions>"   
        print "</MaltegoTransformExceptionMessage>";
        print "</MaltegoMessage>";
        exit();
        
    def returnOutput(self):
        print "<MaltegoMessage>";
        print "<MaltegoTransformResponseMessage>";
                        
        print "<Entities>"
        for i in range(len(self.entities)):
            self.entities[i].returnEntity();
        print "</Entities>"
                        
        print "<UIMessages>"
        for i in range(len(self.UIMessages)):
            print "<UIMessage MessageType=\"" + self.UIMessages[i][0] + "\">" + self.UIMessages[i][1] + "</UIMessage>";
        print "</UIMessages>"
            
        print "</MaltegoTransformResponseMessage>";
        print "</MaltegoMessage>";
        
    def writeSTDERR(self,msg):
        sys.stderr.write((msg));
    
    def heartbeat(self):
        self.writeSTDERR("+");
    
    def progress(self,percent):
        self.writeSTDERR("%" + (percent));
    
    def debug(self,msg):
        self.writeSTDERR("D:" + (msg));
            


def sanitise(value):
    if value is None:
        return ""
    replace_these = ["&",">","<"];
    replace_with = ["&amp;","&gt;","&lt;"];
    tempvalue = value;
    for i in range(0,len(replace_these)):
        tempvalue = tempvalue.replace(replace_these[i],replace_with[i]);
    return tempvalue;
