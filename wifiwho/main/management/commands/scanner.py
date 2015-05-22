from django.core.management.base import BaseCommand, CommandError
from main.models import Device, Probe
import radiotap as r, pcap
import we
from django.utils import timezone
import time
from django.db import transaction

class Command(BaseCommand):
    help = 'Scan for wifi networks'
    channels = (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140,)
    channel = 0
    queue = 0

    def handle(self, *args, **options):
        pc = pcap.pcap(name='mon0')
        pc.setnonblock(True)
        w = we.WirelessExtension('mon0')
        while 1:
            with transaction.atomic():
                while (time.time() < self.queue):
                    result = pc.next()
                    if not result: continue
                    tstamp, pkt = result
                    off, radiotap = r.radiotap_parse(pkt)
                    off, pkt = r.ieee80211_parse(pkt, off)
                    if not pkt: continue
                    if pkt['from_ds']:
                        if pkt['to_ds']:
                            device, create = Device.objects.get_or_create(src_mac=pkt['addr4'])
                        else:
                            device, create = Device.objects.get_or_create(src_mac=pkt['addr2'])
                    else:
                        device, create = Device.objects.get_or_create(src_mac=pkt['addr2'])
                    if pkt['to_ds']:
                        if pkt['addr3'] != 'ff:ff:ff:ff:ff:ff':
                            device.dst_mac = pkt['addr3']
                    else:
                        if pkt['addr1'] != 'ff:ff:ff:ff:ff:ff':
                            device.dst_mac = pkt['addr1']

                    device.signal = radiotap['dbm_antsignal']
                    device.lastseen = timezone.now()

                    device.save()

                    if pkt['type'] == 0 and pkt['subtype'] == 4:
                        if pkt['data'][0] != '\x01':
                            Probe.objects.get_or_create(device=device, probe=pkt['data'].split('\x01')[0])
                    if pkt['type'] == 0 and pkt['subtype'] == 8:
                        essid = pkt['data'][12:]
                        if essid != '\x01':
                            Probe.objects.get_or_create(device=device, probe=essid.split('\x01')[0])

            self.queue = time.time()+10
            self.channel += 1
            if (self.channel > len(self.channels)):
                self.channel = 0
            print self.channel
            w.set_channel(self.channels[self.channel])

