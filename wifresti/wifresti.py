#!/usr/bin/python

os = __import__('os')
from subprocess import check_output
import subprocess
import sys, traceback
import platform

def main():
        try:

                linux = "1"

                windows = "2"

                mac = "3"

                print " "
                print " "
                print"               /$$  /$$$$$$                                /$$     /$$"
                print"              |__/ /$$__  $$                              | $$    |__/"
                print" /$$  /$$  /$$ /$$| $$  \__//$$$$$$   /$$$$$$   /$$$$$$$ /$$$$$$   /$$"
                print"| $$ | $$ | $$| $$| $$$$   /$$__  $$ /$$__  $$ /$$_____/|_  $$_/  | $$"
                print"| $$ | $$ | $$| $$| $$_/  | $$  \__/| $$$$$$$$|  $$$$$$   | $$    | $$"
                print"| $$ | $$ | $$| $$| $$    | $$      | $$_____/ \____  $$  | $$ /$$| $$"
                print"|  $$$$$/$$$$/| $$| $$    | $$      |  $$$$$$$ /$$$$$$$/  |  $$$$/| $$"
                print" \_____/\___/ |__/|__/    |__/       \_______/|_______/    \___/  |__/"
                print" "
                print"	Author: LionSec | Website: www.lionsec.net | @lionsec1	V1.0			"


                print" "
                print "Please choose your operating system."
                print " "
                print " 1) linux"
                print " 2) Windows"
                print " 3) Mac OS"
                print" "

                entrada = raw_input("> ")

                while entrada == linux and platform.system() == "Linux":
                        print " "
                        print "All wireless networks :"
                        print " "
                        command = "ls -1 /etc/NetworkManager/system-connections/"
                        proc = subprocess.Popen(command,stdout=subprocess.PIPE,shell=True)
                        (out, err) = proc.communicate()
                        outwithoutreturn = out.rstrip('\n')
                        print outwithoutreturn
                        proc

                        print " "
                        
                        print "Insert the network name , or press (a) to see information about all networks."
                        print " "
                        nombre = raw_input("> ")
                        if nombre == "a":
                                print "\033[1;36m############################ - Information about all networks - ############################\033[1;m"                        	
                                wifi0 = os.system("egrep -h -s -A 9 --color -T 'ssid=' /etc/NetworkManager/system-connections/*")
                                print wifi0
                                print "\033[1;36m############################################################################################\033[1;m"                                
                        else:
                                print "\033[1;36m###################################### - " + nombre + " - ######################################\033[1;m"
                                print " "

                                wifi0 = str(os.system("egrep -h -s -A 0 --color -T 'security=|key-mgmt=|psk=' /etc/NetworkManager/system-connections/" + nombre))
                                print " "
                                print "\033[1;36m#############################################################################################\033[1;m"
                                print " "
                

                        
                       

                while entrada == windows and platform.system() == "Windows":

                        
                        print check_output("netsh wlan show profile key=clear", shell=True)
                        print "Insert the network name , or press (a) to see information about all networks."
                        print " "
                        nombre = raw_input("> ")
                        if nombre == "a":
                                print "############################ - Information about all networks - ############################"                          
                                print " "                            
                                wifi2 = check_output("netsh wlan show profile name=* key=clear", shell=True)
                                print wifi2
                                print " " 
                                print "#############################################################################################"
                        else:
                                print "###################################### - " + nombre + " - ######################################"
                                print " "                            
                                wifi2 = check_output("netsh wlan show profile name=" + nombre +" key=clear", shell=True)
                                print " "                            

                                print wifi2
                                print "#############################################################################################"
                                print " "  
                        guardar = raw_input("Do you want to save the result ? [y/n] > ")
                        if guardar == "y":
                                f = open(nombre+'.txt','w')
                                f.write(wifi2 + '\n')
                                f.close()
                                                   

                                        
                if entrada == mac:
                        print "Coming soon"

                else:
                        print "Please select an option . (1) for linux , (2) for windows , and (3) for Mac OS ."
        except KeyboardInterrupt:
                print "Shutdown requested...exiting"
        except Exception:
                traceback.print_exc(file=sys.stdout)
        sys.exit(0)

if __name__ == "__main__":
            main()
