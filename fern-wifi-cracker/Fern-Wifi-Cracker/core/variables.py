from core.fern import *

############# WEP/WPA/WPS GLOBAL VARIABLES #################

#
# WPS Variables
#
wps_functions = object()        # Instance of WPS class


#
# Network scan global variable
#
scan_control = 0
static_channel = str()
monitor_interface = str()
monitor_mac_address = str()
#
# Update checking loop (control variable)
#
updater_control = 0
xterm_setting = ''
#
# Wep Global variables
#
wep_details = {}
victim_mac = ''
victim_channel = ''
victim_access_point = ''
ivs_number = 0
WEP = ''
digit = 0
ivs_new = ivs_number + digit
#
# Wpa Global variables
#
wpa_details = {}
wpa_victim_mac_address = ''
wpa_victim_channel = ''
wpa_victim_access = ''
control = 0
current_word = ''

################### DIRECTORY GLOBAL VARIABLES ##################
#
# Creating /tmp/ directory for logging of wireless information
#

direc = '/tmp/'
log_direc = 'fern-log'
tmp_direc = os.listdir(direc)                                    # list/tmp/
directory = os.getcwd()

#
# Create temporary log directory
#
if 'fern-log' in tmp_direc:
    commands.getstatusoutput('rm -r %s'%(direc + log_direc))    # Delete directory in /fern-log if it already exists in /tmp/
    os.mkdir(direc + log_direc)
else:
    os.mkdir(direc + log_direc)                                 # Create /tmp/fern-log/

#
# Create Sub Temporary directory in /tmp/fern-log
#
os.mkdir('/tmp/fern-log/WPA')                                     # Create /tmp/fern-log/WPA

#
# Evecute commands without display to stdout
#
def exec_command(command,directory = None):
    output = open(os.devnull,'w')
    ret = subprocess.call(command,shell=True,stdout=output,stderr=output,cwd=directory)
    return(ret)




################## TOOL BOX VARIABLES #######################

# FERN GEOLOCATORY MAC-ADDRESS TRACKER VARIABLES

#
# Error Strings
#
database_null_error = 'There are currently no access points inserted into the database,\
Access points are added automatically after a successful attack,\
alternatively you can insert access point details manually using the\
 "Key Database" section of the main window,you can also input mac-addresses directly.\
'

invalid_mac_address_error = 'The MAC address inserted is invalid, \
a valid mac address has 6 segment with 2 hexadecimal values in each segment e.g 00:CA:56:12:8B:90'

#
# Html strings
#

# TOOLBOX OBJECTS

html_network_timeout_error = '''<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>Untitled Document</title>
<style type="text/css">
body,td,th {
	font-size: 12px;
}
</style>
</head>

<body>
<p><img src="file://%s/resources/map.png" alt="" width="108" height="87" /><strong> Fern GeoLocatory Mac Address Tracker
  </strong>
</p>
<p><font color="#FF0000">Network Timeout:</font></p>
<p>* The current network connection does not have access to the internet.</p>
<p>* Please check your internet connection to make sure its connected to the internet.</p>
<p>* Press the &quot;Track&quot; button when you're done.</p>
</body>
</html>
'''%(os.getcwd())

html_instructions_message = '''<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>Untitled Document</title>
<style type="text/css">
body,td,th {
	font-size: 12px;
}
</style>
</head>

<body>
<p><img src="file://%s/resources/map.png" alt="" width="108" height="87" /> <strong>Fern GeoLocatory Mac Address Tracker </strong></p>
<p><font color=blue>Instructions:</font></p>
<p>* Fern Geolocatory Mac Address Tracker allows you track the geographical coordinates of wifi mac-addresses.</p>
<p>* The geographical co-ordinates are retrived and the corresponding maps are displayed on this very area you are reading from.</p>
<p>* Mac-addresses can either be inserted from the list of mac-addresses in &quot;Fern Key Database&quot; or otherwise inserted manually.</p>
<p>* You can insert mac-addresses manually by using the &quot;Insert Mac Address&quot; radio button then inputing it into the combo-box.</p>
</body>
</html>
'''%(os.getcwd())




ray_fusion_reports_html = '''<html>
    <head>
        <title>Fern - Ray Fusion Report</title>
        <style type="text/css">
            h1{
                text-align: center;
            }
            h2{
                font-size: larger;
                text-decoration: underline;
            }
            .center{
                text-align: center;
                font-size: large;
            }
            #credentials{
                position: absolute;
            }

        </style>
    </head>
    <body>
        <h1>Ray Fusion Report</h1>
        <hr>
        <h2>Target Details</h2>
        <table>
            <tr>
                <td><b>Remote Address</b>:</td>
                <td>&nbsp; %s</td>
            </tr>
            <tr>
                <td><b>Remote Port</b>:</td>
                <td>&nbsp; %s</td>
            </tr>
            <tr>
                <td><b>Remote Service</b>:</td>
                <td>&nbsp; %s</td>
            </tr>
        </table>
        <hr>
        <h2 class="center">Report Details</h2>
        <table id="credentials" class="center">
            <tr>
                <td><b>Username</b></td>
                <td><b>Password</b></td>
            </tr>
'''


