#!/usr/bin/python
__author__ = 'Zack Smith (@acidprime)'
__version__ = '1.1'

import os
import getopt
import uuid
import plistlib
import sys
import shutil
import subprocess
import commands
import re
import time
import binascii
import urllib


from Cocoa import NSData,NSString,NSDictionary,NSMutableDictionary,NSPropertyListSerialization,NSDate
from Cocoa import NSUTF8StringEncoding,NSPropertyListImmutable
from subprocess import Popen, PIPE, STDOUT

# Commands used by this script
airport     = '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport'
eapolclient = '/System/Library/SystemConfiguration/EAPOLController.bundle/Contents/Resources/eapolclient'
if not os.path.exists(eapolclient):
  # Leopard Location, used by security command for ACL
  eapolclient = '/System/Library/SystemConfiguration/EAPOLController.bundle/Resources/eapolclient'

runDirectory = os.path.dirname(os.path.abspath(__file__))
curl            = '/usr/bin/curl'
dscl            = '/usr/bin/dscl'
grep            = '/usr/bin/grep'
kinit           = '/usr/bin/kinit'
networksetup    = '/usr/sbin/networksetup'
openssl         = '/usr/bin/openssl'
profiles        = '/usr/bin/profiles'
plutil          = '/usr/bin/plutil'
sysctl          = '/usr/sbin/sysctl'
security        = '/usr/bin/security'
sudo            = '/usr/bin/sudo'
system_profiler = '/usr/sbin/system_profiler'
uuidgen         = '/usr/bin/uuidgen'
who             = '/usr/bin/who'
whoami          = '/usr/bin/whoami'

# Constants
UUID            = os.system(uuidgen)

# Added for 10.5 support
kcutil = '%s/%s' % (runDirectory,'kcutil')

def showUsage():
  print '''
wifutil: A multi OS version wireless configuration tool

Syntax:
  ## 802.1X PEAP Example (Username & Password are Required for non WPA2)
  wifiutil --username="zsmith" --password='d0gc4t' --plist="settings.plist"

  ## WPA2 Example
  wifiutil --plist="/Library/Preferences/com.318.wifi.plist"

Options:
  -f | --plist=             ## Path to a plist to read configuration information from
                            This will override any other provided options!

  -u | --username=          ## The username used to access the wireless

  -p | --password=          ## The password used to access the wireless

  -c | --ca_server          ## The Microsoft IIS Certificate portal server

  -t | --cert_type          ## The certificate type (name of the Template)

  -d | --debug              ## Echo commands (and passwords!) in clear text

  -s | --secure_import      ## Securely import the pkcs12 into the keychain

   '''

# Check scripts as root
if not os.geteuid() == 0:
  showUsage()
  print '--> This script requires root access!'
  sys.exit(1)


# Generate csr with openssl for a machine
def generateMachineCSR(machine_name,key,csr):
  arguments = [
    openssl,
    'req',
    '-new',
    '-batch',
    '-newkey',
    'rsa:2048',
    '-nodes',
    '-keyout',
    '%s' % key,
    '-out',
    '%s' % csr,
    '-subj',
    '/CN=%s$' % machine_name ,
  ]

  execute = Popen(arguments, stdout=PIPE)
  out, err = execute.communicate()

# Generate csr with openssl for a user
def generateUserCSR(user_name,key,csr):
  arguments = [
    openssl,
    'req',
    '-new',
    '-batch',
    '-newkey',
    'rsa:2048',
    '-nodes',
    '-keyout',
    '%s' % key,
    '-out',
    '%s' % csr,
    '-subj',
    '/CN=%s$' % user_name,
  ]

  execute = Popen(arguments, stdout=PIPE)
  out, err = execute.communicate()

## curl the csr up
def curlCsr(csr,cert_type,ca_url):
  # Someday we might use this instead of curl
  # http://trac.calendarserver.org/browser/PyKerberos
  # First we get rid of some really really ugly-looking awk work to url-encode the csr
  # Later versions of curl do this for us... but we don't have that luxury.
  cert_request = open(csr, 'r').read()

  request_dict = { 'CertRequest' : cert_request }
  encoded_csr = urllib.urlencode(request_dict)

  arguments = [
    curl,
    '--negotiate',
    '-A',
    'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.0.5) Gecko/2008120122 Firefox/3.0.5',
    '-u',
    ':',
    '-d',
    encoded_csr,
    '-d',
    'SaveCert=yes',
    '-d',
    'Mode=newreq',
    '-d',
    "CertAttrib=CertificateTemplate:%s" % cert_type,
    "%s/certfnsh.asp" % ca_url,
  ]

  print 'Attempting to get Request ID...'

  execute = Popen(arguments, stdout=PIPE)
  out, err = execute.communicate()

  req_id_regex = re.search(".*location=\"certnew.cer\?ReqID=(\d+).*",out)

  req_id        = req_id_regex.group(1)

  print 'REQ_ID: %s' % req_id

def discoverADfacts():
  path  = '/Library/Preferences/DirectoryService/ActiveDirectory.plist'
  plist = NSDictionary.dictionaryWithContentsOfFile_(path)
  if not os.path.exists(path):
    print 'Active Directory plist is missing'
    return False

  return machineIsBound()

def machineIsBound(plist):
  if not 'AD Bound to Domain' in plist:
    return False
  else:
    return plist['AD Bound to Domain']

## Get TGT via kinit - If 2k3, use password method if 2k8
def getTGTkinit(machine_name):
  arguments = [
    kinit,
    '-k',
    '%s$' % machine_name,
  ]
  execute = Popen(arguments, stdout=PIPE)
  out, err = execute.communicate()

def getTGTpassword():
  path  = '/Library/Preferences/DirectoryService/ActiveDirectory.plist'
  plist = NSDictionary.dictionaryWithContentsOfFile_(path)

  if 'AD Computer Password' in plist:
    nsdata = plist['AD Computer Password']
    print nsdata
  else:
    print 'This machine does not appear to have a password'
  # Need expect script

## curl the csr up
def curlCert(pem,ca_url,req_id):
  print "CRT is %s, CA_URL is %s" % crt,ca_url

  arguments = [ curl,
    '-k',
    '-o',
    pem,
    '--negotiate',
    '-u',
    ':',
    "%s/certnew.cer?ReqID=%s&Enc=b64" % (ca_url,req_id) ,
  ]
  execute = Popen(arguments, stdout=PIPE)
  out, err = execute.communicate()


## Pick up the cert via dscl if it's a 2k8 domain and convert it into PEM format
# dsclMachineCert('WIN-7PO3B92M2FP','/tmp/userCertificate.pem')
def dsclMachineCert(machine_name,pem):
  dscl_args = [
    dscl,
    '-plist',
    'localhost',
    'read',
    '/Search/Computers/%s$' % machine_name,
    'userCertificate',
  ]
  #print ' '.join(arguments)
  dscl_process = Popen(dscl_args, stdout=PIPE)
  out, err = dscl_process.communicate()

  plist = plistlib.readPlistFromString(out)


  if 'dsAttrTypeNative:userCertificate' in plist:
    nsdata = plist['dsAttrTypeNative:userCertificate'][0]
    user_certificate = binascii.unhexlify(''.join(nsdata.split()))
    openssl_args = [
      openssl,
      'x509',
      '-inform',
      'DER',
      '-outform',
      'PEM',
      '-out',
      pem,
    ]

    openssl_process = Popen(openssl_args,stdin=PIPE,stdout=PIPE,stderr=STDOUT)
    output = openssl_process.communicate(input=user_certificate)[0]

  else:
    print 'This machine does not appear to have a certificate'

def dsclUserCert(pem):
  dscl_args = [
    dscl,
    '-plist',
    'localhost',
    'read',
    '/Active\ Directory/All\ Domains/Users/`%s`' % whoami,
    'userCertificate',
  ]
  #print ' '.join(arguments)
  dscl_process = Popen(dscl_args, stdout=PIPE)
  out, err = dscl_process.communicate()

  plist = plistlib.readPlistFromString(out)


  if 'dsAttrTypeNative:userCertificate' in plist:
    nsdata = plist['dsAttrTypeNative:userCertificate'][0]
    user_certificate = binascii.unhexlify(''.join(nsdata.split()))
    openssl_args = [
      openssl,
      'x509',
      '-inform',
      'DER',
      '-outform',
      'PEM',
      '-out',
      pem,
    ]

    openssl_process = Popen(openssl_args,stdin=PIPE,stdout=PIPE,stderr=STDOUT)
    output = openssl_process.communicate(input=user_certificate)[0]

#def curlTrustedCert(pem,ca_cert,keychain_path):
#  arguments = [ openssl,
#    'x509',
#    '-in',
#    pem,
#    '-text',
#    '|',
#    grep,
#    'CA Issuers - URI:http://',
#    '|',
#    awk,
#    '{ print $4 }'
#    '|',
#    sed,
#    's/URI://',
#  ]
#
#  execute = Popen(arguments, stdout=PIPE)
#  out, err = execute.communicate()
#
#  ca_url = out
#
#  arguments = [ curl,
#    '-o',
#    ca_cert,
#    ca_url,
#  ]
#
#  execute = Popen(arguments, stdout=PIPE)
#  out, err = execute.communicate()
#
#  arguments = [ security,
#    'add-trusted-cert',
#    '-k',
#    keychain_path,
#    ca_cert,
#  ]
#
## Not currently Implemented
#def evalCert(pem,keychain_path,ca_crt):
#  arguments = [ security,
#     'verify-cert',
#     '-c',
#     pem,
#     '|',
#     grep,
#     'successful',
#  ]
#
#  execute = Popen(arguments, stdout=PIPE)
#  out, err = execute.communicate()
#
#  # Find out if cert is trusted
#  try:
#    exit_code = subprocess.check_call(execute)
#    curlTrustedCert(pem,ca_cert,keychain_path)
#  except subprocess.CalledProcessError as e:
#    print "Certificate verification failed ...", e.returncode

def keychainPath(cert_style):
  if cert_style == 'USER':

    arguments = [
      security,
      'default-keychain',
    ]
    execute = Popen(arguments,stdout=PIPE)
    out, err = execute.communicate()

    keychain_regex  = re.search('.*\"(.*\.keychain)\".*',out)
    return keychain_regex.group(1)

  else:
    return '/Library/Keychains/System.keychain'

## Pack the cert up and import it ito the keychain
def packAndImport(pem,key,pk12,machine_name,keychain_path):

  uuid           = UUID
  secure_import  = True

  ## Build the cert and private key into a PKCS12
  arguments = [
    openssl,
    'pkcs12',
    '-export',
    '-in',
    pem,
    '-inkey',
    key,
    '-out',
    pk12,
    '-name',
    machine_name,
    '-passout',
    'pass:%s' % uuid,
  ]

  execute = Popen(arguments, stdout=PIPE)
  out, err = execute.communicate()

  arguments = [
    security,
    'import',
    pk12,
    '-k',
    keychain_path,
    '-f',
    'pkcs12',
    '-P',
    uuid,
  ]

  if secure_import :
    arguments.append('-x',arguments[1])

  execute = Popen(arguments, stdout=PIPE)
  out, err = execute.communicate()

def createEAPProfile(path,uid,gid,networkDict):
  if os.path.exists(path):
    plist = NSMutableDictionary.dictionaryWithContentsOfFile_(path)
  else:
    plist = NSMutableDictionary.alloc().init()
  plist['Profiles'] = []
  # item entry
  _Profiles = {}
  # EAPClientConfiguration
  EAPClientConfiguration = {}
  AcceptEAPTypes = []
  _AcceptEAPTypes = networkDict['eapt']
  AcceptEAPTypes = [_AcceptEAPTypes]

  # Top Level EAPClientConfiguration keys
  EAPClientConfiguration['AcceptEAPTypes'] = AcceptEAPTypes
  EAPClientConfiguration['Description'] = 'Automatic'
  EAPClientConfiguration['EAPFASTProvisionPAC'] = True
  EAPClientConfiguration['EAPFASTUsePAC'] = True
  EAPClientConfiguration['TLSVerifyServerCertificate'] = False
  EAPClientConfiguration['TTLSInnerAuthentication'] = networkDict['iath']
  EAPClientConfiguration['UserName'] = networkDict['user']
  EAPClientConfiguration['UserPasswordKeychainItemID'] = networkDict['keyc']

  if not osVersion['minor'] == LEOP:
    EAPClientConfiguration['Wireless Security'] = networkDict['type']

  # Top Level item keys
  _Profiles['EAPClientConfiguration'] = EAPClientConfiguration
  _Profiles['UniqueIdentifier'] = networkDict['keyc']
  _Profiles['UserDefinedName'] = 'WPA: %s' % networkDict['ssid']

  if not osVersion['minor'] == LEOP:
    _Profiles['Wireless Security'] = networkDict['type']

  # Merge the data with current plist
  plist['Profiles'].append(_Profiles)
  exportFile = path
  plist.writeToFile_atomically_(exportFile,True)
  try:
    os.chown(path,uid,gid)
  except:
    print 'Path not found %s' % path

def getAirportMac():
  # Script Created Entry
  port = getPlatformPortName()
  arguments = [
    networksetup,
    '-getmacaddress',
    port
  ]
  execute = Popen(arguments, stdout=PIPE)
  out, err = execute.communicate()
  parse = out.split()
  return parse[2]

def createEAPBinding(path,uid,gid,networkDict):
  macAddress = getAirportMac()
  if os.path.exists(path):
    plist = NSMutableDictionary.dictionaryWithContentsOfFile_(path)
  else:
    plist = NSMutableDictionary.alloc().init()
  plist[macAddress] = []
  _item = {}
  _item['UniqueIdentifier'] = networkDict['keyc']
  _item['Wireless Network'] = networkDict['ssid']
  plist[macAddress].append(_item)
  exportFile = path
  plist.writeToFile_atomically_(exportFile,True)
  try:
    os.chown(path,uid,gid)
  except:
    print 'Path not found %s' % path

def createRecentNetwork(networkDict):
  path = '/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist'
  # Set to root as the owner for good measure
  uid = 0
  gid = 80
  if os.path.exists(path):
    plist = NSMutableDictionary.dictionaryWithContentsOfFile_(path)
  else:
    plist = NSMutableDictionary.alloc().init()
  port = getPlatformPortName()
  # Check for non-existant keys
  if not port in plist.keys():
    plist[port] = {}
  # Make sure the Array is there
  if not 'RecentNetworks' in plist[port].keys():
    plist[port]['RecentNetworks'] = []
  _RecentNetworks = {}
  _RecentNetworks['SSID_STR'] = networkDict['ssid']
  _RecentNetworks['SecurityType'] = networkDict['sect']
  _RecentNetworks['Unique Network ID'] = networkDict['guid']
  _RecentNetworks['Unique Password ID'] = networkDict['keyc']
  plist[port]['RecentNetworks'].append(_RecentNetworks)
  exportFile = path
  plist.writeToFile_atomically_(exportFile,True)
  try:
    os.chown(path,uid,gid)
  except:
     print 'Path not found %s' % path

def createKnownNetwork(networkDict):
  print 'Creating KnownNetworks entry'
  # There were some MacBook Airs that shipped with 10.5
  path = '/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist'
  # Set to root as the owner for good measure
  uid = 0
  gid = 80
  if os.path.exists(path):
    plist = NSMutableDictionary.dictionaryWithContentsOfFile_(path)
  else:
    plist = NSMutableDictionary.alloc().init()
  plist['KnownNetworks'] = {}
  guid = networkDict['guid']
  plist['KnownNetworks'][guid] = {}
  plist['KnownNetworks'][guid]['SSID_STR'] = networkDict['ssid']
  plist['KnownNetworks'][guid]['Remembered channels'] = [networkDict['chan'],]
  plist['KnownNetworks'][guid]['SecurityType'] = networkDict['sect']
  # If we are adding a non WPA2 Enterprise network add the keychain item
  if networkDict['type'] == 'WPA2':
    plist['KnownNetworks'][guid]['Unique Password ID'] = networkDict['keyc']
  plist['KnownNetworks'][guid]['_timeStamp'] = NSDate.date()
  exportFile = path
  plist.writeToFile_atomically_(exportFile,True)
  try:
    os.chown(path,uid,gid)
  except:
    print 'Path not found %s' % path

def addKeychainPassword(arguments):
  # Script Created Entry
  print 'Adding password to keychain'
  if(debugEnabled):printCommand(arguments)
  execute = Popen(arguments, stdout=PIPE)
  out, err = execute.communicate()
  print out

def createLeopEAPkeychainEntry(networkDict):
  users = '/var/db/dslocal/nodes/Default/users'
  listing = os.listdir(users)
  for plist in listing:
    # Hardware test for Air
    excluded = re.compile("^((?!^_|root|daemon|nobody|com.apple.*).)*$")
    if excluded.match(plist):
      plistPath = '%s/%s' % (users,plist)
      print 'Processing: %s' % plistPath
      user = NSDictionary.dictionaryWithContentsOfFile_(plistPath)
      try:
        uid = int(user['uid'][0])
        gid = int(user['gid'][0])
        for home in user['home']:
          keychain = home + '/Library/Keychains/login.keychain'
          print 'Processing keychain: %s' % keychain
          if os.path.exists(keychain):
            if user['name'][0] == getConsoleUser():
              arguments = [
                security,
                "add-generic-password",
                '-a',
                networkDict['ssid'],
                '-l',
                '%s-%s' % (networkDict['ssid'],networkDict['user']),
                '-D',
                'Internet Connect',
                '-s',
                 networkDict['keyc'],
                '-w',
                networkDict['pass'],
                '-T',
                'group://Aiport',
                '-T',
                '/System/Library/CoreServices/SystemUIServer.app',
                '-T',
                '/Applications/System Preferences.app',
                '-T',
                '/usr/libexec/airportd',
                '-T',
                eapolclient,
                keychain
              ]

              addKeychainPassword(arguments)
              try:
                os.chown(keychain,uid,gid)
              except:
                print 'Path not found %s' % keychain
            else:
              print 'User will not be modified: %s' % user['name'][0]
      except:
        print 'Key Missing, Skipping'

def createSnowEAPkeychainEntry(networkDict):
  users = '/var/db/dslocal/nodes/Default/users'
  listing = os.listdir(users)
  for plist in listing:
    # Hardware test for Air
    excluded = re.compile("^((?!^_|root|daemon|nobody|com.apple.*).)*$")
    if excluded.match(plist):
      plistPath = '%s/%s' % (users,plist)
      print 'Processing: %s' % plistPath
      user = NSDictionary.dictionaryWithContentsOfFile_(plistPath)
      try:
        uid = int(user['uid'][0])
        gid = int(user['gid'][0])
        for home in user['home']:
          keychain = home + '/Library/Keychains/login.keychain'
          print 'Processing keychain: %s' % keychain
          if os.path.exists(keychain):
            if user['name'][0] == getConsoleUser():
              arguments = [
                security,
                "add-generic-password",
                '-a',
                networkDict['user'],
                '-l',
                'WPA: %s' % networkDict['ssid'],
                '-D',
                '802.1X Password',
                '-s',
                 networkDict['keyc'],
                '-w',
                networkDict['pass'],
                '-T',
                'group://Aiport',
                '-T',
                '/System/Library/CoreServices/SystemUIServer.app',
                '-T',
                '/Applications/System Preferences.app',
                '-T',
                eapolclient,
                keychain
              ]
              addKeychainPassword(arguments)
              try:
                os.chown(keychain,uid,gid)
              except:
                  print 'Path not found %s' % keychain
      except:
        print 'Key Missing, Skipping'

def createLionEAPkeychainEntry(networkDict):
  users = '/var/db/dslocal/nodes/Default/users'
  listing = os.listdir(users)
  for plist in listing:
    # Hardware test for Air
    excluded = re.compile("^((?!^_|root|daemon|nobody|com.apple.*).)*$")
    if excluded.match(plist):
      plistPath = '%s/%s' % (users,plist)
      print 'Processing: %s' % plistPath
      user = NSDictionary.dictionaryWithContentsOfFile_(plistPath)
      try:
        uid = int(user['uid'][0])
        gid = int(user['gid'][0])
        for home in user['home']:
          keychain = home + '/Library/Keychains/login.keychain'
          print 'Processing keychain: %s' % keychain
          if os.path.exists(keychain):
            # Clear old value
            if user['name'][0] == getConsoleUser():
              arguments = [
                security,
                "delete-generic-password",
                '-D',
                '802.1X Password',
                '-l',
                networkDict['ssid'],
                '-a',
                networkDict['user'],
                keychain
              ]
              deleteKeychainPassword(arguments)
              # Add New Value
              arguments = [
                security,
                "add-generic-password",
                '-a',
                networkDict['user'],
                '-l',
                networkDict['ssid'],
                '-D',
                '802.1X Password',
                '-s',
                 'com.apple.network.eap.user.item.wlan.ssid.%s' % networkDict['ssid'],
                '-w',
                networkDict['pass'],
                '-T',
                'group://Aiport',
                '-T',
                '/System/Library/CoreServices/SystemUIServer.app',
                '-T',
                '/Applications/System Preferences.app',
                '-T',
                eapolclient,
                keychain
              ]
              addKeychainPassword(arguments)
              try:
                os.chown(keychain,uid,gid)
              except:
                 print 'Path not found %s' % keychain
      except:
        print 'Key Missing, Skipping'

# Need to clean this up with defaults or a dict
def genLionProfile(networkDict={}):
  plist = NSMutableDictionary.alloc().init()

  # EAPClientConfiguration
  AcceptEAPTypes = []
  _AcceptEAPTypes = networkDict['eapt']
  AcceptEAPTypes = [_AcceptEAPTypes]

  tlsTrustedServerNames = []

  EAPClientConfiguration = {}
  EAPClientConfiguration['AcceptEAPTypes'] = AcceptEAPTypes
  EAPClientConfiguration['TTLSInnerAuthentication'] = networkDict['iath']
  EAPClientConfiguration['UserName'] = networkDict['user']
  EAPClientConfiguration['UserPassword'] = networkDict['pass']
  EAPClientConfiguration['tlsTrustedServerNames'] = tlsTrustedServerNames

  # PayloadContent
  PayloadContent = []
  _PayloadContent = {}
  _PayloadContent['AuthenticationMethod'] = ''
  _PayloadContent['EAPClientConfiguration'] = EAPClientConfiguration
  _PayloadContent['EncryptionType'] = 'WPA'
  _PayloadContent['HIDDEN_NETWORK'] = False
  _PayloadContent['Interface'] = 'BuiltInWireless'
  _PayloadContent['PayloadDisplayName'] = '%s-%s' % (networkDict['ssid'],networkDict['user'])
  _PayloadContent['PayloadEnabled'] = True
  _PayloadContent['PayloadIdentifier'] = '%s.%s.alacarte.interfaces.%s' % (networkDict['mdmh'],networkDict['puid'],networkDict['suid'])
  _PayloadContent['PayloadType'] = 'com.apple.wifi.managed'
  _PayloadContent['PayloadUUID'] = networkDict['suid']
  _PayloadContent['PayloadVersion'] = 1
  _PayloadContent['SSID_STR'] = networkDict['ssid']
  PayloadContent = [_PayloadContent]

  plist['PayloadContent'] = PayloadContent
  plist['PayloadDisplayName'] = networkDict['orgn']
  plist['PayloadIdentifier'] = '%s.%s.alacarte' % (networkDict['mdmh'],networkDict['puid'])
  plist['PayloadOrganization'] = networkDict['orgn']
  plist['PayloadRemovalDisallowed'] = False
  plist['PayloadScope'] = networkDict['scop']
  plist['PayloadType'] = 'Configuration'
  plist['PayloadUUID'] = networkDict['puid']
  plist['PayloadVersion'] = 1

  # Show the plist on debug
  if(debugEnabled):print plist
  exportFile = '/tmp/.%s-%s.mobileconfig' % (networkDict['user'],networkDict['ssid'])
  plist.writeToFile_atomically_(exportFile,True)
  return exportFile

def networksetupExecute(arguments):
  if(debugEnabled):printCommand(arguments)
  execute = Popen(arguments, stdout=PIPE)
  out, err = execute.communicate()
  print out

def profilesExecute(arguments):
  if(debugEnabled):printCommand(arguments)
  execute = Popen(arguments, stdout=PIPE)
  out, err = execute.communicate()
  print out

#-------------------------------------------------------------------------------
# This is currently not used as writing the keys seemed best for auto connect
def genSnowProfile(networkDict):
  # EAPClientConfiguration
  AcceptEAPTypes = []
  _AcceptEAPTypes = networkDict['eapt']
  AcceptEAPTypes = [_AcceptEAPTypes]

  EAPClientConfiguration = {}
  EAPClientConfiguration['AcceptEAPTypes'] = AcceptEAPTypes
  EAPClientConfiguration['UserName'] = networkDict['user']
  EAPClientConfiguration['UserPasswordKeychainItemID'] = networkDict['keyc']

  # UserProfiles
  UserProfiles = []
  _UserProfiles = {}
  _UserProfiles['ConnectByDefault'] = True
  _UserProfiles['EAPClientConfiguration'] = EAPClientConfiguration
  _UserProfiles['UniqueIdentifier'] = networkDict['keyc']
  _UserProfiles['UserDefinedName'] = '%s-%s' % (networkDict['ssid'],networkDict['user'])
  _UserProfiles['Wireless Network'] = networkDict['ssid']
  UserProfiles = [_UserProfiles]

  # 8021X
  plist = NSMutableDictionary.alloc().init()
  _8021X = {}
  _8021X['UserProfiles'] = UserProfiles
  plist['8021X'] = _8021X
  print plist
  exportFile = '/tmp/.importme.networkconnect'
  plist.writeToFile_atomically_(exportFile,True)
  return exportFile

#-------------------------------------------------------------------------------
# This is currently not used as writing the keys seemed best for auto connect
def importSnowProfile(exportFile):
  arguments = [
    networksetup,
    "-import8021xProfiles",
    "Airport",
    exportFile
  ]
  networksetupExecute(arguments)

def addPreferredNetwork(networkDict):
  path = '/Library/Preferences/SystemConfiguration/preferences.plist'
  plist = NSMutableDictionary.dictionaryWithContentsOfFile_(path)
  for _Sets in plist['Sets'].keys():
    for Interface in plist['Sets'][_Sets]['Network']['Interface'].keys():
      if 'AirPort' in plist['Sets'][_Sets]['Network']['Interface'][Interface].keys():
        if not 'PreferredNetworks' in plist['Sets'][_Sets]['Network']['Interface'][Interface]['AirPort'].keys():
          plist['Sets'][_Sets]['Network']['Interface'][Interface]['AirPort']['PreferredNetworks'] = []
      _PreferredNetworks = {}
      _PreferredNetworks['SSID_STR'] = networkDict['ssid']
      _PreferredNetworks['SecurityType'] = networkDict['sect']
      _PreferredNetworks['Unique Network ID'] = networkDict['guid']
      # Add keychain item reference if not 802.1x or Open
      if networkDict['type'] == 'WPA2':
        _PreferredNetworks['Unique Password ID'] = networkDict['keyc']

      # Fix for https://github.com/acidprime/WirelessConfig/issues/2
      if 'PreferredNetworks' in plist['Sets'][_Sets]['Network']['Interface'][Interface].keys():
        plist['Sets'][_Sets]['Network']['Interface'][Interface]['PreferredNetworks'].append(_PreferredNetworks)
      else:
        plist['Sets'][_Sets]['Network']['Interface'][Interface]['AirPort']['PreferredNetworks'].append(_PreferredNetworks)

    plist.writeToFile_atomically_(path,True)

def getSystemVersion():
  # Our Operating System Constants
  global LEOP,SNOW,LION,MLION,MAVRK
  LEOP = 5
  SNOW = 6
  LION = 7
  MLION = 8
  MAVRK = 9
  systemVersionPath = '/System/Library/CoreServices/SystemVersion.plist'
  try:
    systemVersion = plistlib.Plist.fromFile(systemVersionPath)
  except:
    print 'Unable to parse file at path: %s' % systemVersion
    sys.exit(1)
  ProductVersion = systemVersion['ProductVersion'].split('.')
  returnDict = {}
  returnDict['major'] = int(ProductVersion[0])
  returnDict['minor'] = int(ProductVersion[1])
  returnDict['bugfx'] = int(ProductVersion[2])
  return returnDict

def leopardAddWireless(networkDict={}):
  plistPath = '/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist'
  # Sanity check to make sure preferences are the there.
  if os.path.exists(plistPath):
    pl = NSMutableDictionary.dictionaryWithContentsOfFile_(plistPath)
  # Copy the dictionary for mutation during enumeration
  copy = NSMutableDictionary.dictionaryWithContentsOfFile_(plistPath)
  # 10.5 Style
  # Grab UUID if already in network list
  found = False
  print 'Checking for existing Keychain GUID in KnownNetworks'
  try:
    for key in copy['KnownNetworks'].keys():
      if copy['KnownNetworks'][key]['SSID_STR'] == networkDict['ssid']:
        networkDict['guid'] = copy['KnownNetworks'][key]['Unique Password ID']
        print 'Found existing reference to wireless password guid: %s' % networkDict['guid']
        found = True
  except:
    print 'Key KnownNetworks not found'
  # If this not an OPEN network then add keychain
  # Updated to not add blank keychain entry for Open networks
  if 'pass' in networkDict.keys() and not networkDict['type'] == "OPEN":
    """ Removing Keychain entries for system due to bug in 10.5 """
    #print 'Network has password generating keychain arguments...'
    #keychain = '/Library/Keychains/System.keychain'
    #arguments = [security,
    #             "add-generic-password",
    #             '-a',
    #             networkDict['ssid'],
    #             '-l',
    #             networkDict['ssid'],
    #             '-D',
    #             'AirPort network password',
    #             '-s',
    #              networkDict['guid'],
    #             '-w',
    #             networkDict['pass'],
    #             '-T',
    #             'group://Aiport',
    #             '-T',
    #             '/System/Library/CoreServices/SystemUIServer.app',
    #             '-T',
    #             '/Applications/System Preferences.app',
    #             '-T',
    #             '/usr/libexec/airportd',
    #             keychain]
    #addKeychainPassword(arguments)
    users = '/var/db/dslocal/nodes/Default/users'
    listing = os.listdir(users)
    for plist in listing:
        # Hardware test for Air
        excluded = re.compile("^((?!^_|root|daemon|nobody|com.apple.*).)*$")
        if excluded.match(plist):
          plistPath = '%s/%s' % (users,plist)
          print 'Processing: %s' % plistPath
          user = NSDictionary.dictionaryWithContentsOfFile_(plistPath)
          try:
            uid = int(user['uid'][0])
            gid = int(user['gid'][0])
            for home in user['home']:
              keychain = home + '/Library/Keychains/login.keychain'
              print 'Processing keychain: %s' % keychain
              if os.path.exists(keychain):
                # -U causing segmentation fault, removed sudo
                if user['name'][0] == getConsoleUser():
                  arguments = [
                    security,
                    "add-generic-password",
                    '-a',
                    networkDict['ssid'],
                    '-l',
                    networkDict['ssid'],
                    '-D',
                    'AirPort network password',
                    '-s',
                    'AirPort Network',
                    '-w',
                    networkDict['pass'],
                    '-T',
                    'group://Aiport',
                    '-T',
                    '/System/Library/CoreServices/SystemUIServer.app',
                    '-T',
                    '/Applications/System Preferences.app',
                    keychain
                  ]
                  addKeychainPassword(arguments)
                  arguments = [
                    kcutil,
                    user['home'][0],
                    user['name'][0],
                    networkDict['pass'],
                    configFile
                  ]
                  addKeychainPassword(arguments)
                  try:
                    os.chown(keychain,uid,gid)
                  except:
                    print 'Path not found: %s' % keychain
                else:
                  print 'Keychain file: %s does not exist' % keychain
          except:
            print 'User plist %s does not have a home key' % plistPath
  else:
    print 'No password is specified, skipping keychain actions'
  port = 'Airport'
  if networkDict['type'] == 'WPA2 Enterprise':
    createKnownNetwork(networkDict)
    createRecentNetwork(networkDict)
    addUsersEAPProfile(networkDict)
    createLeopEAPkeychainEntry(networkDict)
    addPreferredNetwork(networkDict)
  else:
    # We can automatically connect to WPA PSK type networks
    leopardRemoveWireless(networkDict['ssid'])
    connectToNewNetwork(port,networkDict)


def leopardRemoveWireless(networkName):
  plistPath = '/Library/Preferences/SystemConfiguration/preferences.plist'
  # Sanity checks for the plist
  if os.path.exists(plistPath):
    try:
      pl = NSMutableDictionary.dictionaryWithContentsOfFile_(plistPath)
    except:
      print 'Unable to parse file at path: %s' % plistPath
      sys.exit(1)
  else:
    print 'File does not exist at path: %s' % plistPath
    sys.exit(1)
  print 'Processing preference file: %s' % plistPath
  # Create a copy of the dictionary due to emuration
  copy = NSMutableDictionary.dictionaryWithContentsOfFile_(plistPath)
  # Iterate through network sets
  for Set in copy['Sets']:
    UserDefinedName = copy['Sets'][Set]['UserDefinedName']
    print 'Processing location: %s' % UserDefinedName

    for enX in copy['Sets'][Set]['Network']['Interface']:
      print 'Processing interface: %s' % enX
      # I think this will always be a single key but this works either way
      for key in copy['Sets'][Set]['Network']['Interface'][enX]:
        print 'Processing Service: %s' % key
        # Try to grab the PreferredNetworks key if any
        try:
          # Iterate through preferred network sets
          index = 0
          for PreferredNetwork in copy['Sets'][Set]['Network']['Interface'][enX][key]['PreferredNetworks']:
            SSID_STR = PreferredNetwork['SSID_STR']
            print 'Processing SSID: %s' % SSID_STR
            # If the preferred network matches our removal SSID
            if SSID_STR == networkName:
              print 'Found SSID %s to remove' % SSID_STR
              # Delete our in ram copy
              print 'Processing Set: %s' % Set
              print 'Processing enX: %s' % enX
              print 'Processing key: %s' % key
              try:
                print 'Attempting delete of Set: %s for Interface:%s Named:%s Index:%d' % (Set,enX,key,index)
                del pl['Sets'][Set]['Network']['Interface'][enX][key]['PreferredNetworks'][index]
                print 'Deleted set: %s' % Set
              except IndexError:
                print 'Unable to remove Received Out of bounds error for index %d' % index
            index += 1
        except KeyError:
           print 'Skipping interface without PreferredNetworks'
  # Make a copy of plist
  shutil.copy(plistPath,plistPath + '.old')

  # Write the plist to a file
  writePlist(pl,plistPath)
  removeKnownNetwork(networkName)
  deleteUsersKeychainPassword(networkName)
  deleteUsersEAPProfile(networkName)

#-------------------------------------------------------------------------------
# Snow Leopard
def snowLeopardRemoveWireless(networkName):
  port = 'Airport'
  arguments = [
    networksetup,
    "-removepreferredwirelessnetwork",
    port,
    networkName
  ]
  if(debugEnabled):printCommand(arguments)
  networksetupExecute(arguments)
  # Remove from the Known Network list
  removeKnownNetwork(networkName)
  deleteUsersKeychainPassword(networkName)
  deleteSystemKeychainPassword(networkName)
def snowLeopardAddWireless(networkDict={}):
  port = 'Airport'
  # Check if 802.1x profiles
  if networkDict['type'] == 'WPA2 Enterprise':
    addUsersEAPProfile(networkDict)
    createKnownNetwork(networkDict)
    createSnowEAPkeychainEntry(networkDict)
    #exportFile = genSnowProfile(networkDict)
    #importSnowProfile(exportFile)
    addPreferredNetwork(networkDict)
  else:
    if 'pass' in networkDict.keys():
      arguments = [
        networksetup,
        "-addpreferredwirelessnetworkatindex",
        port,
        networkDict['ssid'],
        '0',
        networkDict['type'],
        networkDict['pass'],
      ]
    else:
      arguments = [
        networksetup,
        "-addpreferredwirelessnetworkatindex",
        port,
        networkDict['ssid'],
        '0',
        networkDict['type'],
        ]
    networksetupExecute(arguments)
    connectToNewNetwork(port,networkDict)
#-------------------------------------------------------------------------------
# Lion
#-------------------------------------------------------------------------------
def lionRemoveWireless(networkName):
  port = getPlatformPortName()
  arguments = [networksetup,
              "-removepreferredwirelessnetwork",
              port,
              networkName]
  # Run the command
  networksetupExecute(arguments)
  # Remove from the Known Network list
  removeKnownNetwork(networkName)
  deleteUsersKeychainPassword(networkName)

#-------------------------------------------------------------------------------
def lionAddWireless(networkDict={}):
  # Set the bsd port name in Lion
  port = getPlatformPortName()
  print 'Removing any previous configurations for network %s' % networkDict['ssid']
  lionRemoveWireless(networkDict['ssid'])

  if networkDict['type'] == 'WPA2 Enterprise':
    # Generate the profile
    exportLionProfile = genLionProfile(networkDict)
    arguments = [
      profiles,
      "-I",
      "-v",
      "-f",
      '-F',
      exportLionProfile
    ]
    profilesExecute(arguments)
    # Removing the temp profile
    os.remove(exportLionProfile)
    # Adding this as System profiles don't seem to do this
    arguments = [
      networksetup,
      "-addpreferredwirelessnetworkatindex",
      port,
      networkDict['ssid'],
      '0',
      networkDict['tkey']
    ]
    networksetupExecute(arguments)
    createLionEAPkeychainEntry(networkDict)
  else:
    # Check for WPA2/OPEN network
    if 'pass' in networkDict.keys():
      arguments = [
        networksetup,
        "-addpreferredwirelessnetworkatindex",
        port,
        networkDict['ssid'],
        '0',
        networkDict['type'],
        networkDict['pass']
      ]

    else:
      arguments = [
        networksetup,
        "-addpreferredwirelessnetworkatindex",
        port,
        networkDict['ssid'],
        '0',
        networkDict['type']
      ]
    networksetupExecute(arguments)
    connectToNewNetwork(port,networkDict)

#-------------------------------------------------------------------------------
# Network Setup Sub Routine
def networksetupExecute(arguments):
  if(debugEnabled):printCommand(arguments)
  execute = Popen(arguments, stdout=PIPE)
  out, err = execute.communicate()
  print out

#-------------------------------------------------------------------------------
def removeKnownNetwork(networkName):
  plistPath = '/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist'
  # Sanity check to make sure preferences are the there.
  if os.path.exists(plistPath):
    pl = NSMutableDictionary.dictionaryWithContentsOfFile_(plistPath)
  else:
    return 1
  # Copy the dictionary for mutation during enumeration
  copy = NSMutableDictionary.dictionaryWithContentsOfFile_(plistPath)
  # 10.7 style
  try:
    index = 0
    for key in copy['RememberedNetworks']:
      name = pl['RememberedNetworks'][index]['SSIDString']
      if name == networkName:
        print 'Found %s at index %d' % (name,index)
        del pl['RememberedNetworks'][index]
      index += 1
  except:
    print 'Key RememberedNetworks not found'
  # 10.5 Style
  # Clean up KnownNetworks key
  try:
    for guid in copy['KnownNetworks'].keys():
      if copy['KnownNetworks'][guid]['SSID_STR'] == networkName:
        del pl['KnownNetworks'][guid]
  except:
    print 'Key KnownNetworks not found'
  # Clean up top level key
  port = getPlatformPortName()
  # There were some MacBook Airs that shipped with 10.5

  try:
    if port in copy.keys():
      index = 0
      try:
        for key in copy[port]['RecentNetworks']:
          if key['SSID_STR'] == networkName:
            del pl[port]['RecentNetworks'][index]
          index += 1
      except:
         print 'No key RecentNetworks'
  except:
    print 'Unable to cleanup %s' % port
  writePlist(pl,plistPath)

#-------------------------------------------------------------------------------
def writePlist(plist,filePath):
  # Make a copy of plist
  if os.path.exists(filePath):
    shutil.copy(filePath,filePath + '.old')
  # Write the new plist
  plist.writeToFile_atomically_(filePath,True)
  # Check the plist
  arguments = [plutil,filePath]
  execute = Popen(arguments, stdout=PIPE)
  out, err = execute.communicate()
  print execute.returncode

#-------------------------------------------------------------------------------
def getAirportInfo():
  # Pull info from the Airport command
  arguments = [airport,"--getinfo"]
  execute = Popen(arguments, stdout=PIPE)
  out, err = execute.communicate()
  dict = {}
  for line in out.split('\n'):
    parse = line.split(': ')
    try:
      key = parse[0].strip()
      value = parse[1]
      dict[key] = value
    except IndexError:
      None
  return dict
#-------------------------------------------------------------------------------

# Generic system_profiler parser
def systemReport():
  spx = {}
  # This is our key value schema
  SPHardwareDataType = {
    'platform_UUID': 'platform_UUID',
  }
  _dataTypes = {
   'SPHardwareDataType': SPHardwareDataType,
  }
  dataTypes = _dataTypes.keys()
  # run the system_profiler command with data types
  arguments = [system_profiler,"-xml"] + dataTypes
  getspx = Popen(arguments, stdout=PIPE)
  spxOut, err = getspx.communicate()
  # Someone give me an example of doing read from string via bridge and I will fix this
  #spxNSString = NSString.alloc().initWithString_(spxOut)
  #spxData = NSData.dataWithData_(spxNSString.dataUsingEncoding_(NSUTF8StringEncoding))
  #rootObject = NSPropertyListSerialization.propertyListFromData_mutabilityOption_format_errorDescription_(spxData,NSPropertyListImmutable,None,None)
  rootObject = plistlib.readPlistFromString(spxOut)

  # Parse datatype top level keys below
  for array in rootObject:
    for _dataType in _dataTypes:
      if array['_dataType'] == _dataType:
        _dataTypeSchema = _dataTypes[_dataType]
        for key in _dataTypeSchema:
          for item in array['_items']:
            # add a key to our dict per the schema
            spx[key] = item[_dataTypeSchema[key]]
  return spx

#-------------------------------------------------------------------------------
def getPlatformUUID():
  spx = systemReport()
  try:
    return spx['platform_UUID']
  except KeyError:
    return None

def scanAvailableNetworks(networkName):
  # Create a directed SSID scan
  directed = "--scan=%s" % networkName
  arguments = [airport,"--xml",directed]
  if(debugEnabled):printCommand(arguments)
  execute = Popen(arguments, stdout=PIPE)
  out, err = execute.communicate()
  try:
    avaiable = plistlib.readPlistFromString(out)
  except:
    # Might need to switch to Cocoa here
    print 'Unable to parse airport command output'
    print 'This error is not critical and can be ignored'
    return False

  print 'Search found following acess points available'
  found = False
  # Search the current list of APs
  for ap in avaiable:
    print 'SSID:\t%s BSSID:[%s]' % (ap['SSID_STR'],ap['BSSID'])
    # If we find the SSID then return True
    if networkName == ap['SSID_STR']:
      found = True
  return found

def printCommand(arguments):
  print '\'%s\'' % '\' \''.join(arguments)

def connectToNewNetwork(port,networkDict={}):
  toggleAirportPower('on')
  # If network is in range connect to it
  if osVersion['minor'] == LEOP:
    wireless = "-A%s" % networkDict['ssid']
    if 'pass' in networkDict.keys():
      password = "--password=%s" % networkDict['pass']
    else:
      password = ''
    arguments = [airport,wireless,password]
    if(debugEnabled):printCommand(arguments)
    execute = Popen(arguments, stdout=PIPE)
    out, err = execute.communicate()
    print out
  if scanAvailableNetworks(networkDict['ssid']):
    print "Waiting for interface to come up..."
    time.sleep(10)
    if osVersion['minor'] >= SNOW:
      if 'pass' in networkDict.keys():
        arguments = [
          networksetup,
          "-setairportnetwork",
          port,
          networkDict['ssid'],
          networkDict['pass']
        ]
      else:
        arguments = [
          networksetup,
          "-setairportnetwork",
          port,
          networkDict['ssid']
        ]
    if osVersion['minor'] == LEOP:
      if 'pass' in networkDict.keys():
        arguments = [
          networksetup,
          "-setairportnetwork",
          networkDict['ssid'],
          networkDict['pass']
        ]
      else:
        arguments = [
          networksetup,
          "-setairportnetwork",
          networkDict['ssid']
        ]
    networksetupExecute(arguments)
  else:
    print 'Network %s not found' % networkDict['ssid']

# Pull the current network from the airport command
def checkCurrenNetwork(networkName):
  airportInfo = getAirportInfo()
  try:
    if airportInfo['SSID'] ==  networkName:
      print 'We are currently connected to %s' % airportInfo['SSID']
  except KeyError:
    print 'No current wireless network detected'

# Hardware Test for MacbookAir,*
def getPlatformPortName():
  # Hardware test for Air
  airTest = re.compile(".*(a|A)ir.*")
  hwmodel = commands.getoutput(sysctl + " hw.model").split(' ')
  if osVersion['minor'] >= LION:
    # Updating this for retina displays and beyond?

    arguments = [networksetup,'-listallhardwareports']

    execute = Popen(arguments, stdout=PIPE)
    out, err = execute.communicate()
    retina_regex  = re.search(".*(Wi-Fi|AirPort).*\nDevice: (en\d+)*",out)
    bsd_port      = retina_regex.group(2)
    return bsd_port
  else:
    if airTest.match(hwmodel[-1]):
      return 'en0'
    else:
      return 'en1'

def getConsoleUser():
  arguments = [who]
  execute = Popen(arguments, stdout=PIPE)
  out, err = execute.communicate()
  parse = out.split()
  console = re.compile(".*console.*")
  if console.match(out):
    return parse[0]
  else:
    return None

def toggleAirportPower(value):
  # Returns the bsd style name of the port
  if osVersion['minor'] == LION or osVersion['minor'] == MLION:
    port = getPlatformPortName()
  else:
    port = 'Airport'

  if osVersion['minor'] >= SNOW:
    arguments = [
      networksetup,
      "-setairportpower",
      port,
      value
    ]
  if osVersion['minor'] == LEOP:
    arguments = [
      networksetup,
      "-setairportpower",
      value
    ]
  else:
    arguments = [
      networksetup,
      "-setairportpower",
      port,
      value
    ]

  networksetupExecute(arguments)

def deleteUsersKeychainPassword(networkName):
  users = '/var/db/dslocal/nodes/Default/users'
  listing = os.listdir(users)
  for plist in listing:
      # Hardware test for Air
      excluded = re.compile("^((?!^_|root|daemon|nobody|com.apple.*).)*$")
      if excluded.match(plist):
        plistPath = '%s/%s' % (users,plist)
        print 'Processing: %s' % plistPath
        user = NSDictionary.dictionaryWithContentsOfFile_(plistPath)
        try:
          uid = int(user['uid'][0])
          gid = int(user['gid'][0])
          for home in user['home']:
            keychain = home + '/Library/Keychains/login.keychain'
            print 'Processing keychain: %s' % keychain
            if os.path.exists(keychain):
              if user['name'][0] == getConsoleUser():
                # Lion
                arguments = [
                  security,
                  "delete-generic-password",
                  '-D',
                  'AirPort network password',
                  '-s',
                  'com.apple.network.wlan.ssid.%s' % networkName,
                  '-l',
                  networkName,
                  keychain
                ]
                deleteKeychainPassword(arguments)
                # Lion generic
                arguments = [
                  security,
                  "delete-generic-password",
                  '-D',
                  'AirPort network password',
                  '-l',
                  networkName,
                  keychain
                ]
                deleteKeychainPassword(arguments)
                # Snow Type 1
                arguments = [
                  security,
                  "delete-generic-password",
                  '-D',
                  'AirPort network password',
                  '-a',
                  networkName,
                  '-l',
                  networkName,
                  keychain
                ]
                deleteKeychainPassword(arguments)
                # Snow Type 2
                arguments = [
                  security,
                  "delete-generic-password",
                  '-D',
                  'AirPort network password',
                  '-a',
                  'Airport',
                  '-l',
                  networkName,
                  keychain
                ]
                deleteKeychainPassword(arguments)
                # Snow 802.1X type 1
                # Updated to remove account type as local user name may mismatch
                arguments = [
                  security,
                  "delete-generic-password",
                  '-D',
                  '802.1X Password',
                  '-l',
                  'WPA: %s' % networkName,
                  keychain
                ]
                deleteKeychainPassword(arguments)
                # Lion
                arguments = [
                  security,
                  "delete-generic-password",
                  '-D',
                  '802.1X Password',
                  '-l',
                  networkName,
                  keychain
                ]
                deleteKeychainPassword(arguments)
                try:
                  os.chown(keychain,uid,gid)
                except:
                  print 'Path not found %s' % keychain
              else:
                print 'Keychain file: %s does not exist' % keychain
        except KeyError:
          print 'User plist %s does not have a home key' % plistPath

def deleteUsersEAPProfile(networkName):
  users = '/var/db/dslocal/nodes/Default/users'
  listing = os.listdir(users)
  for plist in listing:
      # Hardware test for Air
      excluded = re.compile("^((?!^_|root|daemon|nobody|com.apple.*).)*$")
      if excluded.match(plist):
        plistPath = '%s/%s' % (users,plist)
        print 'Processing: %s' % plistPath
        user = NSDictionary.dictionaryWithContentsOfFile_(plistPath)
        try:
          uid = int(user['uid'][0])
          gid = int(user['gid'][0])
          for home in user['home']:
            profile = home + '/Library/Preferences/com.apple.eap.profiles.plist'
            print 'Processing profile: %s' % profile
            # Profile
            if os.path.exists(profile):
              profileFile = NSMutableDictionary.dictionaryWithContentsOfFile_(profile)
              profileByHost = home + '/Library/Preferences/ByHost/com.apple.eap.bindings.%s.plist' % getPlatformUUID()
              if os.path.exists(profileByHost):
                print 'Updating File: %s' % profileByHost
                profileByHostFile = NSMutableDictionary.dictionaryWithContentsOfFile_(profileByHost)
                # Make a copy for enumeration
                copy = NSDictionary.dictionaryWithDictionary_(profileByHostFile)
                # Multiple MAC Addresses may exist
                for mac in copy:
                  index = 0
                  for key in copy[mac]:
                    if key['Wireless Network'] == networkName:
                      UniqueIdentifier = key['UniqueIdentifier']
                      print 'Found Network with Identifier: %s' % UniqueIdentifier
                      # Delete the entry and update the file
                      del profileByHostFile[mac][index]
                      writePlist(profileByHostFile,profileByHost)
                      try:
                        os.chown(profileByHost,uid,gid)
                      except:
                        print 'Path not found: %s' % profileByHost
                      profileFileCopy = NSDictionary.dictionaryWithDictionary_(profileFile)
                      profileIndex = 0
                      print '-' * 80
                      for key in profileFileCopy['Profiles']:
                        if key['UniqueIdentifier'] == UniqueIdentifier:
                          print 'Found network: %s' % key['UserDefinedName']
                          # Delete the entry and update the file
                          del profileFile['Profiles'][index]
                          writePlist(profileFile,profile)
                          os.chown(profile,uid,gid)
                      profileIndex += 1
                    index += 1
              else:
                print 'File not found: %s' % profileByHost
            else:
              print 'Profile file: %s does not exist' % profile
        except KeyError:
          print 'User plist %s does not have a home key' % plistPath

def addUsersEAPProfile(networkDict):
  users = '/var/db/dslocal/nodes/Default/users'
  listing = os.listdir(users)
  for plist in listing:
      # Hardware test for Air
      excluded = re.compile("^((?!^_|root|daemon|nobody|com.apple.*).)*$")
      if excluded.match(plist):
        plistPath = '%s/%s' % (users,plist)
        print 'Processing: %s' % plistPath
        user = NSDictionary.dictionaryWithContentsOfFile_(plistPath)
        try:
          uid = int(user['uid'][0])
          gid = int(user['gid'][0])
          for home in user['home']:
	        # Process the eap profile
            profile = home + '/Library/Preferences/com.apple.eap.profiles.plist'
            createEAPProfile(profile,uid,gid,networkDict)
	        # Process the eap binding
            profileByHost = home + '/Library/Preferences/ByHost/com.apple.eap.bindings.%s.plist' % getPlatformUUID()
            createEAPBinding(profileByHost,uid,gid,networkDict)
        except KeyError:
          print 'User plist %s does not have a home key' % plistPath

# Handle the system keychain as root
def deleteSystemKeychainPassword(networkName):
  keychain = '/Library/Keychains/System.keychain'
  arguments = [
    security,
    "delete-generic-password",
    '-D',
    'AirPort network password',
    '-a',
    'Airport',
    '-l',
    networkName,
    keychain
  ]
  deleteKeychainPassword(arguments)
  arguments = [
    security,
    "delete-generic-password",
    '-D',
    'AirPort network password',
    '-a',
    networkName,
    '-l',
    networkName,
    keychain
  ]
  deleteKeychainPassword(arguments)

def addKeychainPassword(arguments):
  # Script Created Entry
  if(debugEnabled):printCommand(arguments)
  try:
    execute = Popen(arguments, stdout=PIPE)
    out, err = execute.communicate()
    print out
  except:
    print 'The command did not exit 0'

def deleteKeychainPassword(arguments):
  # Script Created Entry
  print 'Deleting keychain entries...'
  if(debugEnabled):printCommand(arguments)
  try:
    execute = Popen(arguments, stdout=PIPE)
    out, err = execute.communicate()
    print out
  except:
    print 'Deletion of keychain password may have failed'

def removeWireless(osVersion,network):
  print '-' * 80
  print 'Removing SSID: %s' % network
  print '-' * 80
  # Leopard Code
  if osVersion['minor'] == LEOP:
    leopardRemoveWireless(network)
  # Snow Leopard Code
  if osVersion['minor'] == SNOW:
    snowLeopardRemoveWireless(network)
  # Lion code
  if osVersion['minor'] == LION:
    lionRemoveWireless(network)
  # MLion Code
  if osVersion['minor'] == MLION:
    lionRemoveWireless(network)


def addWireless(osVersion,networkDict={}):
  print '-' * 80
  print 'Adding SSID: %s' % networkDict['ssid']
  print '-' * 80
  if networkDict['type'] == 'WPA2 Enterprise':
    if networkDict['user'] == '' or networkDict['pass'] == '':
      showUsage()
      print '--> You must specify a username and password for WPA2 Enterprise'
      return 1

  # Leopard Code
  if osVersion['minor'] == LEOP:
    leopardAddWireless(networkDict)
  # Snow Leopard Code
  if osVersion['minor'] == SNOW:
    snowLeopardAddWireless(networkDict)
  # Lion code
  if osVersion['minor'] == LION:
    lionAddWireless(networkDict)
  # MLion code
  if osVersion['minor'] == MLION:
    lionAddWireless(networkDict)
#-------------------------------------------------------------------------------
def main():
  global debugEnabled
  debugEnabled = False
  # Check for envrionmental variables
  try:
    userName = os.environ['USER_NAME']
  except KeyError:
    userName = ''
  try:
    userPass = os.environ['PASS_WORD']
  except KeyError:
    userPass = ''

  # Process Arguments
  if(debugEnabled): print 'Processing Arguments: ', sys.argv[1:]
  try:
    options, remainder = getopt.getopt(sys.argv[1:], 'c:u:t:p:f:ds', [
      'ca_server=',
      'cert_type=',
      'username=',
      'password=',
      'plist=',
      'debug',
      'secure_import',
      ])

  except getopt.GetoptError:
    print "Syntax Error!"
    return 1

  for opt, arg in options:
    if opt in ('-u', '--username'):
      userName = arg
    elif opt in ('-p', '--password'):
      userPass = arg
    elif opt in ('-f', '--plist'):
      plistPath = arg
    elif opt in ('-d', '--debug'):
      debugEnabled = True
    elif opt in ('-c', '--ca_server'):
      ca_server = arg
      ca_url    = "http://%s/certsrv" % ca_server
    elif opt in ('-t', '--cert_type'):
      cert_type = arg
    elif opt in ('-s', '--secure_import'):
      secure_import = True

  # Sanity Checks
  if len(options) < 1:
    showUsage()
    print '--> Not enough options given'
    return 1

  # Check the current directory
  if os.path.exists('wifiutil.settings.plist'):
    plistPath = 'wifiutil.settings.plist'
  try:
    plistPath
  except UnboundLocalError:
    showUsage()
    print '--> You must specify a plist path.'
    return 1

  if os.path.exists(plistPath):
    plist = NSMutableDictionary.dictionaryWithContentsOfFile_(plistPath)
  else:
    print 'File does not exist: %s' % plistPath
    return 1
  global configFile
  configFile = plistPath
  # Get OS Version
  global osVersion
  osVersion = getSystemVersion()

  # Disconnect from wireless
  toggleAirportPower('off')

  # Check for Networks to remove
  if 'networkRemoveList' in plist.keys():
    networkRemoveList = plist['networkRemoveList']
    # Loop through our remove list
    for network in networkRemoveList:
      # Process os specific directives
      removeWireless(osVersion,network)
  else:
    print 'No networks specified to remove'

  # Check for Networks to Add
  if 'networkAddList' in plist.keys():
    networkAddList    = plist['networkAddList']
    # Loop through our add list
    for networkDict in networkAddList:
      # Add our username and password to the config
      if 'user' not in networkDict.keys():
        networkDict['user'] = userName
      if 'pass' not in networkDict.keys():
        networkDict['pass'] = userPass
      # Remove the password for OPEN network
      if networkDict['type'] == 'OPEN':
        del networkDict['pass']

        # Generate our wireless & keychain entry guids, not recommended
	if not 'guid' in networkDict.keys():
          networkDict['guid'] = str(uuid.uuid1()).upper()
	if not 'keyc' in networkDict.keys():
          networkDict['keyc'] = str(uuid.uuid1()).upper()
      # Process os specific directives
      addWireless(osVersion,networkDict)
  else:
    print 'No networks specified to add'
  # Restore Airport Power
  toggleAirportPower('on')

if __name__ == "__main__":
  sys.exit(main())
