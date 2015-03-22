import subprocess
from datetime import datetime
from datetime import date
from includes.mac_vendor import mac_vendor
import logging

flag_do_sdp = False
mv = mac_vendor()

def scan():
        cmd_scan = "hcitool scan --info --class --flush"
        try:
            cmd_scan_out = subprocess.Popen(cmd_scan.split(),stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()
        except Exception,e:
            logging.error("Unable to scan for Bluetooth devices: '%s'" %str(e))
        else:
            # parse scan results
            if len(cmd_scan_out[0]) > 16:
                devices = []
    
                for record in cmd_scan_out[0].split('\n\n')[1:-1]:
                    record = record.split('\n')
                    device = {'mac':'Unknown', 'vendor':'Unknown', 'vendorLong':'Unknown', 'name':'Unknown', 'classType':'Unknown','manufac':'Unknown','lmpVer':'Unknown'}         
     
                    try:
                        device['mac'] = mac = record[0][12:29:].replace(':','').lower()
                        device['vendor'], device['vendorLong'] = mv.lookup(mac[:6])
                        device['name'] = record[1][13:].replace('[cached]','') #name
                        device['classType'] = record[2][14:].replace("Device conforms to the ","") #class+type
        
                        if len(record)>3:
                            device['manufac'] = record[3][14:] # chip manufacturer
                            device['lmpVer'] = record[4][13:16:] # lmp ver
                    except Exception, e:
                        logging.warning("Trouble parsing Bluetooth output: %s" % str(e))
                
                    devices.append(device)
    
                    return devices

if __name__ == "__main__":
    print scan()
