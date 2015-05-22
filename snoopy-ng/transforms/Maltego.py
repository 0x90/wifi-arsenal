#!/usr/bin/python 
#
# This might be horrible code...
# ...but it works
# Feel free to re-write in a better way
# And if you want to - send it to us, we'll update ;)
# maltego@paterva.com (2010/10/18)
#
import sys
from xml.dom import minidom

class MaltegoEntity(object):
	value = "";
	weight = 100;
	displayInformation = "";
	additionalFields = [];
	iconURL = "";
	entityType = "Phrase"
	
	def __init__(self,eT=None,v=None):
		if (eT is not None):
			self.entityType = eT;
		if (v is not None):
			self.value = v;
		self.additionalFields = None;
		self.additionalFields = [];
		self.weight = 100;
		self.displayInformation = "";
		self.iconURL = "";
		
	def setType(self,eT=None):
		if (eT is not None):
			self.entityType = eT;
	
	def setValue(self,eV=None):
		if (eV is not None):
			self.value = eV;
		
	def setWeight(self,w=None):
		if (w is not None):
			self.weight = w;
	
	def setDisplayInformation(self,di=None):
		if (di is not None):
			self.displayInformation = di;		
			
	def addAdditionalFields(self,fieldName=None,displayName=None,matchingRule=False,value=None):
		self.additionalFields.append([fieldName,displayName,matchingRule,value]);
	
	def setIconURL(self,iU=None):
		if (iU is not None):
			self.iconURL = iU;
			
	def returnEntity(self):
		print "<Entity Type=\"" + str(self.entityType) + "\">";
		print "<Value>" + str(self.value) + "</Value>";
		print "<Weight>" + str(self.weight) + "</Weight>";
		if (self.displayInformation is not None):
			print "<DisplayInformation><Label Name=\"\" Type=\"text/html\"><![CDATA[" + str(self.displayInformation) + "]]></Label></DisplayInformation>";
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
	





class MaltegoTransform(object):
	entities = []
	exceptions = []
	UIMessages = []
	
	#def __init__(self):
		#empty.
	
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
			print "<Exception>" + self.exceptions[i] + "</Exceptions>";
		print "</Exceptions>"	
		print "</MaltegoTransformExceptionMessage>";
		print "</MaltegoMessage>";
		
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
		sys.stderr.write(str(msg));
	
	def heartbeat(self):
		self.writeSTDERR("+");
	
	def progress(self,percent):
		self.writeSTDERR("%" + str(percent));
	
	def debug(self,msg):
		self.writeSTDERR("D:" + str(msg));
			






class MaltegoMsg:

 def __init__(self,MaltegoXML=""):

    xmldoc = minidom.parseString(MaltegoXML)
    
    #read the easy stuff like value, limits etc
    self.Value = self.i_getNodeValue(xmldoc,"Value")
    self.Weight = self.i_getNodeValue(xmldoc,"Weight")
    self.Slider = self.i_getNodeAttributeValue(xmldoc,"Limits","SoftLimit")
    self.Type = self.i_getNodeAttributeValue(xmldoc,"Entity","Type")
    
    
    #read additional fields
    AdditionalFields = {}
    try:
    	AFNodes= xmldoc.getElementsByTagName("AdditionalFields")[0]
    	Settings = AFNodes.getElementsByTagName("Field")
    	for node in Settings:
    		AFName = node.attributes["Name"].value;
    		AFValue = self.i_getText(node.childNodes);
    		AdditionalFields[AFName] = AFValue
    except:  
        #sure this is not the right way...;)
    	dontcare=1
     

    #parse transform settings
    TransformSettings = {}
    try:
    	TSNodes= xmldoc.getElementsByTagName("TransformFields")[0]
    	Settings = TSNodes.getElementsByTagName("Field")
    	for node in Settings:
    		TSName = node.attributes["Name"].value;
    		TSValue = self.i_getText(node.childNodes);
        	TransformSettings[TSName] = TSValue
    except:
    	dontcare=1  
                        
    #load back into object
    self.AdditionalFields = AdditionalFields
    self.TransformSettings = TransformSettings

 def i_getText(self,nodelist):
    rc = []
    for node in nodelist:
        if node.nodeType == node.TEXT_NODE:
            rc.append(node.data)
    return ''.join(rc)


 def i_getNodeValue(self,node,Tag):
    return self.i_getText(node.getElementsByTagName(Tag)[0].childNodes)

 def i_getNodeAttributeValue(self,node,Tag,Attribute):
    return node.getElementsByTagName(Tag)[0].attributes[Attribute].value;


