wifi
====
wifi is a command line tool written in python designed to manage a list of preferred 802.11 wireless networks and join them. Passwords are encrypted with GnuPG to help reduce the risk of security issue if file access was compromised.

## Features
* Add or delete access points
* Connect to registered access points
* Auto-connect to the nearest known access point
* List all registered access points
* Show current wireless status
* Scan for available access points
* Password encryption (RSA-4096 via GnuPG)

## Requirements
* python 3.4: https://www.python.org/
* docopt: http://docopt.org/
* python-gnupg: https://pypi.python.org/pypi/python-gnupg/
* requests: https://pypi.python.org/pypi/requests

## Installation
Edit the script and replace **iwn0** (_line 300_) with your wifi network interface. Then, use the **--init** argument to create necessary folders, json database and generate the GnuPG private key:

```sh
$ wifi --init
Directory structure: done
Database: done
Master password:
Retype password:
GnuPG: done
```
You're now ready to go.

## Usage
```sh
Manage Wifi access points.

Usage:
  wifi --add <alias> <nwid> [(<ip> <netmask> <gateway> <dns>)]
  wifi --remove <alias>
  wifi --connect (--auto | <alias>)
  wifi --disconnect
  wifi --list
  wifi --scan
  wifi --status
  wifi --init
  wifi --help
  wifi --version

Options:
  -h --help        Show this screen.
  -v --version     Show version.
  -a --add         Add an access point.
  -c --connect     Connect to an access point.
  -d --disconnect  Disconnect wireless interface.
  -r --remove      Remove an access point.
  -i --init        Initialize required files.
  -l --list        List available access points.
  -s --scan        Show the results of an access point scan.
  -A --auto        Auto-select nearest known access point.
  -S --status      Show the connexion status.
```

#### Flow
Here is an overview of the user flow, long arguments are used for clarity:
```sh
$ wifi --status
Disconnected

$ wifi --add home ACCESS_POINT1
Password:

$ wifi --add office ACCESS_POINT2 10.0.0.5 255.255.255.0 10.0.0.1 8.8.8.8
Password:

$ wifi --list
2 saved access points:
home (ACCESS_POINT1)
office (ACCESS_POINT2)

$ sudo wifi --connect home
Master password:
Connected to ACCESS_POINT1

$ sudo wifi --scan
11 available access points:
FreeWifi (204dB)
freebox_IMFGCN (203dB)
FreeWifi_secure (203dB)
Adrience (201dB)
Adrience (192dB)
Bbox-A90014 (187dB)
Vancesslas (179dB)
FreeWifi_secure (178dB)
Bbox-9BD917 (170dB)
freebox (168dB)
FreeWifi (168dB)

$ wifi --disconnect
Disconnected

$ wifi --remove home
```
Once moving to the office:
```sh
$ sudo wifi --connect --auto
Master password:
Connected to ACCESS_POINT2
```

## Additional notes
Access points config informations and passwords are stored in **wifi.json** (default: _~/.wifi_).

wifi is currently not ipv6 ready due to the fact I don't need so. That being said you can easily add this feature by adding some if statements in the _connect()_ function.

## Author
* Vincent Tantardini: http://www.vtcreative.fr/
* Thanks to my friend @Tamentis for his input on this project.
