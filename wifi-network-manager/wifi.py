#!/usr/bin/env python3.4

"""
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
"""

from getpass import getpass
import ipaddress
import json
import os
import re
from subprocess import call, check_output, DEVNULL
import sys

from docopt import docopt
import gnupg
import requests


def gpgcore(action, password=None):

    """ This function handles GnuPG related operations. """

    gpg = gnupg.GPG(gnupghome=basedir)
    gpg.encoding = 'utf-8'

    # Generate a new GnuPG private key.
    if action == 'genkey':
        try:
            pprompt = lambda: (
                getpass('Master password: '), getpass('Retype password: '))
            master, master2 = pprompt()
            while master != master2:
                print('Passwords do not match. Try again')
                master, master2 = pprompt()
            gpg.gen_key(gpg.gen_key_input(
                key_length=4096, name_email=receipt, passphrase=master))
        except KeyboardInterrupt:
            sys.exit(' ')

    # Return decrypted Password.
    if action == 'decrypt':
        try:
            master = getpass('Master Password: ')
        except KeyboardInterrupt:
            sys.exit(' ')
        pw = str(gpg.decrypt(password.encode('utf-8'), passphrase=master))
        return pw if pw else sys.exit('Error: invalid master password')

    # Return encrypted password.
    if action == 'encrypt':
        try:
            pw = getpass('Password: ')
        except KeyboardInterrupt:
            sys.exit(' ')
        cr = gpg.encrypt(pw, receipt)
        return cr if cr else sys.exit("Error: unable to create key")


def database(action):

    """ This function handles all database operations. """

    def _save():
        """ This function writes changes to the database. """
        with open(dbfile, 'w') as f:
            json.dump(db, f, indent=4, sort_keys=True)

    if action == 'create':
        dbfileobj = os.open(dbfile, os.O_WRONLY | os.O_CREAT, int("0600", 8))
        with os.fdopen(dbfileobj, 'w') as f:
            f.write('{}')
        return

    # Open database and store it as a dict.
    with open(dbfile) as f:
        db = json.load(f)
        dbkeys = sorted(db.keys())

    # Print all database entries and return.
    if action == 'list':
        print('{} saved access points:'.format(str(len(dbkeys))))
        for i in range(len(db)):
            print('{} ({})'.format(dbkeys[i], db[dbkeys[i]]['nwid']))
        return

    # Additional check: lookup for an alias occurency in the database.
    if (args['--remove'] or (args['--connect'] and not args['--auto'])) \
       and not args['<alias>'] in db:
        sys.exit('Error: unknown alias')
    if args['--add'] and args['<alias>'] in db:
        sys.exit('Error: alias already registered')

    # Look for a result matching both a scan result and a database entry.
    if args['--auto']:
        scan_results = scan()
        for i in scan_results:
            args['<alias>'] = [f for f in dbkeys if i[0] == db[f]['nwid']][0]
            if args['<alias>']:
                break
        if not args['<alias>']:
            sys.exit('No available access point.')

    # Return selected database entry as a dict.
    if action == 'get_entry':
        db[args['<alias>']]['password'] = gpgcore('decrypt', (db[args['<alias>']]['password']))
        return db[args['<alias>']]

    # Add a new entry into database.
    if action == 'add':
        entry = {args['<alias>']: {'nwid': args['<nwid>'], 'password': str(gpgcore('encrypt'))}}
        if args['<ip>']:
            for i in ['ip', 'netmask', 'gateway', 'dns']:
                entry[args['<alias>']][i] = args['<' + i + '>']
        db.update(entry)
        _save()

    # Remove current entry entry from database.
    if action == 'remove':
        del db[args['<alias>']]
        _save()


def init():

    """ Create and install all required components (one-time) """

    try:
        os.makedirs(basedir, int("0700", 8))
        print('Directory structure: done')
    except IOError:
        if os.path.isdir(basedir):
            sys.exit('Error: components already initialized')
        else:
            sys.exit('Error: permission denied')

    database('create')
    print('Database: done')

    gpgcore('genkey')
    print('GnuPG: done')


def connect():

    """ Connect to a wifi access point. """

    def cmd(command):
        call(command, stdout=DEVNULL, stderr=DEVNULL)

    # setup interface/route/dns
    conf = database('get_entry')
    cmd(["ifconfig", myif, "down"])
    cmd(['ifconfig', myif, 'nwid', conf['nwid'], 'wpakey', conf['password']])
    del conf['password']

    if len(conf) > 3:
        cmd(['ifconfig', myif, 'inet', conf['ip'], 'netmask', conf['netmask']])
        cmd(['route', 'delete', 'default'])
        cmd(['route', 'add', 'default', conf['gateway']])
        with open('/etc/resolv.conf', 'w') as f:
            f.write('nameserver ' + conf['dns'])
    else:
        cmd(['dhclient', myif])

    # restart firewall and flush rules
    cmd(["pfctl", "-d"])
    cmd(["pfctl", "-e", "-Fa", "-f/etc/pf.conf"])

    # check connectivity
    for count in range(15):
        try:
            r = requests.get('http://www.google.fr')
            print('Connected to {}.'.format(conf['nwid']))
            break
        except:
            if count == 14:
                sys.exit('Error: timeout')


def disconnect():

    """ Disconnect wireless interface. """

    call(["ifconfig", myif, "down"], stdout=DEVNULL, stderr=DEVNULL)
    print('Disconnected')


def status():

    """ Output wireless interface status. """

    cmd = str(check_output("ifconfig " + myif, shell=True), 'utf-8').strip()
    results = [i for i in cmd.split('\n') if 'nwid' in i or 'status' in i]
    status = results[0].split(' ', 1)[1]
    confirm = 'Connected to ' + results[1].split('nwid ')[1].split(' chan')[0]
    print(confirm) if status == 'active' else print('Disconnected')


def scan():

    """ Scan wifi networks. """

    cmd = "ifconfig " + myif + " scan | grep bssid"
    ifscan = str(check_output(cmd, shell=True), 'utf-8').strip().split('\n')

    if not ifscan:
        sys.exit('Scan ends with no result.')

    # Sort results by attenuation
    for idx, i in enumerate(ifscan):
        i = i.replace('""', 'unknown').replace('"', '').split('chan')
        ifscan[idx] = (i[0].replace('nwid', '').strip(), i[1].split(' ')[4])
    ap_list = sorted(ifscan, key=lambda ap: ap[1], reverse=True)

    if args['--auto']:
        return ap_list
    else:
        print('{} available access points:'.format(str(len(ap_list))))
        [print(p[0] + ' (' + p[1] + ')') for p in ap_list]


def check_args():

    """ Arguments extra checks. """

    if args['<ip>']:
        try:
            for i in [args['<ip>'], args['<netmask>'], args['<dns>']]:
                ipaddress.ip_address(i)

            try:
                ipaddress.ip_address(args['gateway'])
            except:
                args['<gateway>'] = re.sub('\.$', '', args['<gateway>'][-1])
                valid_host = re.compile("(?![-\.])[A-Za-z\d\.-]{1,63}(?<!-)$")
                if not re.match(valid_host, args['<gateway>']) or \
                   len(args['<gateway>']) > 255:
                    raise
        except:
            sys.exit('Error: invalid network configuration')

    elif (args['--connect'] or args['--scan'] or args['--disconnect']) \
            and os.getenv('USER') != 'root':
        sys.exit('Error: this command should be run as root')


def main():

    """ Main function. """

    if args['--init']:
        init()
    elif args['--scan']:
        scan()
    elif args['--connect']:
        connect()
    elif args['--disconnect']:
        disconnect()
    elif args['--status']:
        status()
    elif args['--list']:
        database('list')
    elif args['--add']:
        database('add')
    elif args['--remove']:
        database('remove')


if __name__ == "__main__":
    basedir = os.path.expanduser('~/.wifi/')
    dbfile = basedir + 'wifi.json'
    myif = 'iwn0'  # Change this to fit your needs
    receipt = os.getlogin() + '@' + os.uname()[1]

    args = docopt(__doc__, version='wifi 0.4.0')
    check_args()
    main()
