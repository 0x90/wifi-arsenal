A test tool for 802.11 monitor mode frame injection and reception
=================================================================

Wperf is an iperf-like test tool for injecting and receiving 802.11 frames
using the mac80211 wireless stack in Linux. The tool kan be run in client
mode (transmitting data to a wperf server) or in server mode (receiving data
from a wperf client). Each end-point may use either monitor mode or the
native in-kernel UDP/IP/802.11 stack. For example, AP-side frame injection
can be tested by running the wperf client in monitor mode on the AP,
transmitting data to a wperf server running in native UDP mode on the STA side.


## Command line options

```
  Usage: wperf [-s|-c host] [options]
         wperf [-h|--help]

  Options:
         -p, --port     <port> server UDP port to listen on/connect to
         -m, --mtu      <mtu>  set the MTU size, default 1500
         -s, --server          run in server mode
         -c, --client   <host> run in client mode, connecting to <host>
         -b, --bandwidh <bps>  set the bandwidth in [G|M|k]bit/s
         -M, --monitor  <if>   use a monitor interface for send/receive
         -D, --dhost    <mac>  dest MAC address (monitor only)
         -S, --shost    <mac>  source MAC address (monitor only)
         -B, --bssid    <mac>  AP BSSID MAC address (monitor only)
         -q, --tid      <tid>  set TID, -1 for non-QoS (monitor only)
         -t, --sta             run as STA instead of AP (monitor only)
         -i, --interval <sec>  set the printout interval (default 1s)
         -h, --help            display this help and exit
```

## Examples

Native UDP server

```
  wperf -s
```

Monitor mode server (AP side)

```
  wperf -s --monitor=<ifname> --bssid=<bssid> --shost=<mac> [--dhost=<mac>]
```

Monitor mode server (STA side)

```
  wperf -s --sta --monitor=<ifname> --bssid=<bssid> --dhost=<mac> [--shost=<mac>]
```

Native UDP client

```
  wperf -c <ip>
```

Monitor mode client (AP side)

```
  wperf -c <ip> --monitor=<ifname> --bssid=<bssid> --dhost=<mac> [--shost=<mac>]
```

Monitor mode client (STA side)

```
  wperf -c <ip> --sta --monitor=<ifname> --bssid=<bssid> --shost=<mac> [--dhost=<mac>]
```
