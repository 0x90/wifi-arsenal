from __future__ import division

import re
import textwrap

import wifi.subprocess_compat as subprocess
from wifi.utils import db2dbm
from wifi.exceptions import InterfaceError


class Cell(object):
    """
    Presents a Python interface to the output of iwlist.
    """

    def __init__(self):
        self.bitrates = []

    def __repr__(self):
        return 'Cell(ssid={ssid})'.format(**vars(self))

    @classmethod
    def all(cls, interface):
        """
        Returns a list of all cells extracted from the output of iwlist.
        """
        try:
            iwlist_scan = subprocess.check_output(['/sbin/iwlist', interface, 'scan'],
                                                  stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            raise InterfaceError(e.output.strip())
        else:
            iwlist_scan = iwlist_scan.decode('utf-8')
        cells = map(Cell.from_string, cells_re.split(iwlist_scan)[1:])

        return cells

    @classmethod
    def from_string(cls, cell_string):
        """
        Parses the output of iwlist scan for one cell and returns a Cell
        object for it.
        """
        return normalize(cell_string)

    @classmethod
    def where(cls, interface, fn):
        """
        Runs a filter over the output of :meth:`all` and the returns
        a list of cells that match that filter.
        """
        return list(filter(fn, cls.all(interface)))


cells_re = re.compile(r'Cell \d+ - ')
quality_re_dict = {'dBm': re.compile(r'Quality=(\d+/\d+).*Signal level=(-\d+) dBm'),
                   'relative': re.compile(r'Quality=(\d+/\d+).*Signal level=(\d+/\d+)'),
                   'absolute': re.compile(r'Quality:(\d+).*Signal level:(\d+)')}
frequency_re = re.compile(r'^(?P<frequency>[\d\.]+ .Hz)(?:[\s\(]+Channel\s+(?P<channel>\d+)[\s\)]+)?$')


identity = lambda x: x

key_translations = {
    'encryption key': 'encrypted',
    'essid': 'ssid',
}


def normalize_key(key):
    key = key.strip().lower()

    key = key_translations.get(key, key)

    return key.replace(' ', '')

normalize_value = {
    'ssid': lambda v: v.strip('"'),
    'encrypted': lambda v: v == 'on',
    'address': identity,
    'mode': identity,
    'channel': int,
}


def split_on_colon(string):
    key, _, value = map(lambda s: s.strip(), string.partition(':'))

    return key, value


def normalize(cell_block):
    # The cell blocks come in with every line except the first indented at
    # least 20 spaces.  This removes the first 20 spaces off of those lines.
    lines = textwrap.dedent(' ' * 20 + cell_block).splitlines()
    cell = Cell()

    while lines:
        line = lines.pop(0)

        if line.startswith('Quality'):
            for re_name, quality_re in quality_re_dict.items():
                match_result = quality_re.search(line)
                if match_result is not None:
                    cell.quality, signal = match_result.groups()
                    if re_name == 'relative':
                        actual, total = map(int, signal.split('/'))
                        cell.signal = db2dbm(int((actual / total) * 100))
                    elif re_name == 'absolute':
                        cell.quality = cell.quality + '/100'
                        cell.signal = db2dbm(int(signal))
                    else:
                        cell.signal = int(signal)
                    break

        elif line.startswith('Bit Rates'):
            values = split_on_colon(line)[1].split('; ')

            # consume next line of bit rates, because they are split on
            # different lines, sometimes...
            if lines:
                while lines[0].startswith(' ' * 10):
                    values += lines.pop(0).strip().split('; ')

            cell.bitrates.extend(values)
        elif ':' in line:
            key, value = split_on_colon(line)
            key = normalize_key(key)

            if key == 'ie':
                if 'Unknown' in value:
                    continue

                # consume remaining block
                values = [value]
                while lines and lines[0].startswith(' ' * 4):
                    values.append(lines.pop(0).strip())

                if 'WPA2' in value:
                    cell.encryption_type = 'wpa2'
                elif 'WPA' in value:
                    cell.encryption_type = 'wpa'
            if key == 'frequency':
                matches = frequency_re.search(value)
                cell.frequency = matches.group('frequency')
                if matches.group('channel'):
                    cell.channel = int(matches.group('channel'))
            elif key in normalize_value:
                setattr(cell, key, normalize_value[key](value))

    # It seems that encryption types other than WEP need to specify their
    # existence.
    if cell.encrypted and not hasattr(cell, 'encryption_type'):
        cell.encryption_type = 'wep'

    return cell
