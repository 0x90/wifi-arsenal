# Wording

Trying to name things:

- Sender / Host - any 802.11 transmitter
- Client - wifi client, probably a mobile device, also: Station
- AP - access point
- Knowledge - aggregated information on Senders.
- Event - seeing a client on the ether for a period of time.

# Features

## Sniffer

Separate process sniffing metadata from Wifi packets and storing
them in MongoDB backend. Can use multiple sniffers with the same
backends each with differently tagged location.

Gathers metadata from radiotap (strength, source, destination),
Dot11, Dot11Elt frames (probe request, response, beacons) and for
not encrypted packets from IP/TCP/UDP frames (source, destination,
protocol, DNS queries) - for a highlevel aggregation can certainly
be improved.

## Analyzer

Parses packets stored in the collection by sniffers and updates
the \`knowledge' about access points (AP) and clients - senders.

Knowledge consists of:

-   user supllied metadata (alias, owner, notes)
-   simple statistics, first seen, last seen metadata
-   device vendor from MAC database
-   Recent signal strength reading (running average)
-   Probed SSIDs
-   Beaconed SSIDs
-   AP geolocation data using openwlan database
-   \`Events' - when host was seen, TODO: Needs better handling

## Web interface

-   Clickable, interactive web application created with AngularJS,
    Bootstrap and other - ChartJS. Responsive UI.
-   Observing surroundings within specified time window (10s - 24h)
-   Creating presence snapshots - currently present clients (within time
    window) on the context of surrounding APs.
-   Investigating details about each sniffed node.
-   See screenshots in docs/ for a feel.

## Marauder's Map

-   Select point on map and store information about surrounding
    stations (their macs and average strength from a time window)
-   Display all stored points
-   TODO: Estimate position on map using stored info.

# How to use

- Start Mongo
- Create monitoring interface 
  iwconfig wlan0 mode monitor or airmon-ng start wlan1
- Download oui.txt 
  wget <http://www.ieee.org/netstorage/standards/oui.txt>
- Download OpenWlanMAP:
  wget --no-check-certificate 'https://openwlanmap.org/db.tar.bz2'
  ./wifistalker --load-geo db/;
- Start sniffing process wifistalker -s
  You can name it with -l sniffer<sub>name</sub>. Not really usable at this
  point, but useful to distinguish parallel sniffers.
- Start analyzing process - wifistalker -a
- Start webapp - wifistalker -w
- Open page in your browser to see results.

## Tips:

Theoretically you can start multiple sniffers with different labels
pointed to the same mongodb backend. Run only single analyzer
thread.

If you don't purge \`all<sub>frames'</sub> table you can reanalyze your whole
Knowledge with --analyze-full

You can sniff with a detached device and then merge all<sub>frames</sub>
tables into one (TODO: There should be an easy option for
that). You can sniff using a device in a backpack and access it
using different channel (bluetooth/other wifi) to use webapp on a
mobile (TODO: Check how it works on mobile, TODO: Check for
sniffing options on an Android).

Sniffer requires root, rest of modes should run on less privileged
user.

## Concept

Sniffed data can be split into mobile (mostly) client devices and
background - beacons. Beacons create context which is usable to
determining location

## Reasons to write

Learning AngularJS and Bootstrap. Curiosity. Extending home alarm
with a wifi-based monitoring against a common robbery.

# LICENSE

Backend is licensed under GNU GPLv2 - mostly because it uses GPLv2
Scapy. Frontend license - MIT.


# See README for org-mode TODO list and details.
