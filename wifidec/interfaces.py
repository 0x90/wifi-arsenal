#thanks to https://gist.github.com/cnelson/1658752 for this code.
#GJ cnelson!
#
#Also added the ability to detect the driver which is being used for the interface using the getDriverName(<interface>) function.
import subprocess

def getDriverName(interface):
	data = ""
	try:
		data = subprocess.check_output(['ls', "/sys/class/net/" + interface + "/device/driver/module/drivers"]).split('\n')
	except:
		return []#not all interfaces have drivers
	ret = []
	for entry in data:
		spl = entry.split(":")
		if len(spl) < 2:
			continue
		ret.append((spl[1],spl[0]))
	return ret

from datetime import datetime
 
class ProcNetDev(object):
    """Parses /proc/net/dev into a usable python datastructure.
    
    By default each time you access the structure, /proc/net/dev is re-read 
    and parsed so data is always current.
    
    If you want to disable this feature, pass auto_update=False to the constructor.
    
    >>> pnd = ProcNetDev()
    >>> pnd['eth0']['receive']['bytes']
    976329938704
    
    """
    
    def __init__(self, auto_update=True):
        """Opens a handle to /proc/net/dev and sets up the initial object."""
        
        #we don't wrap this in a try as we want to raise an IOError if it's not there
        self.proc = open('/proc/net/dev', 'rb')
    
        #we store our data here, this is populated in update()
        self.data = None
        self.updated = None
        self.auto_update = auto_update
    
        self.update()
        
    def __getitem__(self, key):
        """Allows accessing the interfaces as self['eth0']"""
        if self.auto_update:
            self.update()
        
        return self.data[key]
        
    def __len__(self):
        """Returns the number of interfaces available."""
        return len(self.data.keys())
 
    def __contains__(self, key):
        """Implements contains by testing for a KeyError."""
        try:
            self[key]
            return True
        except KeyError:
            return False
    
    def __nonzero__(self):
        """Eval to true if we've gottend data"""
        if self.updated:
            return True
        else:
            return False
 
    
    def __del__(self):
        """Ensure our filehandle is closed when we shutdown."""
        try:
            self.proc.close()
        except AttributeError:
            pass
    
    def update(self):
        """Updates the instances internal datastructures."""
        
        #reset our location
        self.proc.seek(0)
        
        #read our first line, and note the character positions, it's important for later
        headerline = self.proc.readline()
        if not headerline.count('|'):
            raise ValueError("Header was not in the expected format")
        
        #we need to find out where all the pipes are
        sections = []
        
        position = -1
        while position:
            last_position = position+1
            position = headerline.find('|', last_position)
            
            if position < 0:
                position = None
                
            sections.append((last_position, position, headerline[last_position:position].strip().lower()))
        
        #first section is junk "Inter-
        sections.pop(0)
    
        #now get the labels
        labelline = self.proc.readline().strip("\n")
        labels = []
        for section in sections:
            labels.append(labelline[section[0]:section[1]].split())
        
        interfaces = {}
        #now get the good stuff
        for info in self.proc.readlines():
            info = info.strip("\n")
            
            #split the data into interface name and counters
            (name, data) = info.split(":", 1)
            
            #clean them up
            name = name.strip()
            data = data.split()
            
            interfaces[name] = {}
            absolute_position = 0
            
            #loop through each section, receive, transmit, etc
            for section_number in range(len(sections)):
                tmp = {}
                
                #now loop through each label in that section
                #they aren't always the same!  transmit doesn't have multicast for example
                for label_number in range(len(labels[section_number])):
                    #for each label, we need to associate it with it's data
                    #we use absolute position since the label_number resets for each section
                    tmp[labels[section_number][label_number]] = int(data[absolute_position])
                    absolute_position += 1
                
                #push our data into the final location
                #name=eth0, section[i][2] = receive (for example)
                interfaces[name][sections[section_number][2]] = tmp
        
        #update the instance level variables.
        self.data = interfaces
        self.updated = datetime.utcnow()
