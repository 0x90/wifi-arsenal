# hostapd-python-script

by Nimesh Ghelani (nims11) 

Python Script to make using and configuring hostapd easier.

## Dependencies

   * dhcpd
   * hostapd
   * python (2.7)

## Usage

hostapd.py requires root privileges to work.

```bash
$ chmod +x hostapd.py
```
```
Usage :
   hostapd.py [action] [<options>...]

Following actions are currently supported:
   start
   stop
   restart
   config
   help

Usage for action config:
   hostapd.py config                                       - list all attributes with values
   hostapd.py config section_name                          - list all attributes under secion_name with values
   hostapd.py config section_name attrib_name              - shows the value for section_name->attrib_name, if set
   hostapd.py config section_name attrib_name attrib_val   - modifies the value of section_name->attrib_name to attrib_val

```



## Configuring

hostapd.py generates the config file for hostapd and dhcpd each time it starts using /etc/py_hostapd.cfg, edit that file to make changes or use the config action in the script. You may also tweak the config.py file to suit your needs.

## Additional Reading

On how to setup hostapd by yourself, read my guide at http://nims11.wordpress.com/2012/04/27/hostapd-the-linux-way-to-create-virtual-wifi-access-point/
It will also help in way to understand the source code of my script better.

## Contribute

Feel free to fork and commit changes to the code. There is a lot of scope for improvement. Suggestions and Feedbacks are welcomed as well.
I have only tested this script well enough with ath9k wifi driver. Help me improve it through bug reports, or even confirmed working report with the environment under which it occured.
