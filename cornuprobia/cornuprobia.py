"""
Copyright (C) 2014 Anders Sundman <anders@4zm.org>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import sys, signal
import random
import argparse
import daemon
from time import sleep
from scapy.all import *

def rand_ssid(wordlist):
  return random.choice(wordlist).strip()[:32]

def send_probereq(intf='', ssid_gen=None, dst='', src='', bssid='', count=0):

  # Configure defaults
  if not ssid_gen: ssid_gen = lambda : 'w00p'
  if not dst: dst = 'ff:ff:ff:ff:ff:ff'
  if not src: src = RandMAC()
  if not bssid: bssid = 'ff:ff:ff:ff:ff:ff'
  if not intf: intf = 'mon0'
  if count < 1: count = random.randint(1,5)

  # Beacon interface
  conf.iface = intf

  # Build probe request package
  ssid = ssid_gen()
  param = Dot11ProbeReq()
  essid = Dot11Elt(ID='SSID',info=ssid)
  rates  = Dot11Elt(ID='Rates',info='\x03\x12\x96\x18\x24\x30\x48\x60')
  dsset = Dot11Elt(ID='DSset',info='\x01')
  pkt = RadioTap()/Dot11(type=0, subtype=4, addr1=dst, addr2=src, addr3=bssid)/param/essid/rates/dsset

  # Send the packets
  print '[*] Sending %d probe(s): %s \'%s\'' % (count, src,ssid)
  try:
    sendp(pkt, count=count, inter=0.1, verbose=0)
  except:
    raise

# Handle Ctrl-C to exit
def sig_handler(sig, frame):
  print '[*] Turning off goodness'
  sys.exit(0)

def parse_args():
  # Parse cmd line
  parser = argparse.ArgumentParser()
  parser.add_argument('interface',
                      help='The network interface to use (must be in monitor mode)')
  parser.add_argument('-d', '--daemonize',
                      help='detach and run in the background',
                      action='store_true')
  parser.add_argument('-w', '--wordlist',
                      metavar='FILE',
                      help='use word list for SSID names')
  return parser.parse_args()

def get_ssid_gen(args):
    if args.wordlist:
      print '[*] Loading SSID wordlist: %s' % args.wordlist
      with open(args.wordlist) as f:
        words = f.readlines()
      return lambda: rand_ssid(words)
    else:
      return None

def cornuprobia(args):
  print '[*] Cornuprobia - Fountain of 802.11 Probe Requests (%s)' % args.interface

  # Listen for termination requests
  signal.signal(signal.SIGINT, sig_handler)
  signal.signal(signal.SIGTERM, sig_handler)

  # Send probes
  ssid_gen = get_ssid_gen(args)
  while True:
    send_probereq(intf=args.interface, ssid_gen=ssid_gen)
    sleep(random.uniform(0, 0.2))

def main():
  args = parse_args()

  if args.daemonize:
    with daemon.DaemonContext():
      cornuprobia(args)
  else:
    cornuprobia(args)

if __name__ == "__main__":
  main()
