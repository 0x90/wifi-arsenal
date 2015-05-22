#Doesn't seem to work across devices. When working correctly incorporate into includes/system_info.py

import serial
from smspdu import pdu, gsm0338
import time
import os
from serial.tools import list_ports
import logging

#Define your USB modem's ID here. Check it with lsusb.
usb_id="12d1:140c" #Huawei Technologies

def check_o2_balance():
    """Check o2 balance"""
    ser = serial.Serial(find_device())
    code = "*#10#"
    data="AT+CUSD=1,%s,15" % pdu.pack7bit(code)[1].encode('hex').upper()
    ser.write(data + "\r")
    start = int(os.times()[4])
    while start + 10 > int(os.times()[4]):
        line = ser.readline().replace('"',"")
        if "+CUSD:" in line:
            response = line.split(",")[1]
            result = gsm0338().decode(pdu.unpack7bit(response.decode('hex')))[0]
            result = result[:-1].replace(u'Your balance is \xa3','')
            logging.debug("Balance is %s" %result)
            return float(result)
    return -1

def find_device():
        """Return first instance of matching usb_id"""
        logging.debug("Looking for USB modem")
	usb_devices = list_ports.comports()
	for device in usb_devices:
		id = device[2].split("=")
		if len(id) > 1 and id[1] == usb_id:
                    logging.debug("Found USB modem at %s" % device[0])
	            return device[0]

if __name__ == "__main__":
    print "Balance is %f" % check_o2_balance()
