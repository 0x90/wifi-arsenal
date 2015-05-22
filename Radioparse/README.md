Radioparse
========

## 802.11 frame and radiotap header parser

A WiFi protocol parser that can be used with radiotap packets and node-pcap.

## Example

```javascript
var pcap = require("pcap")
var radioparse = require("radioparse")

var session = pcap.createSession("mon0")

session.on("packet", function(rawPacket) {
  var packet = radioparse.parse(radioparse.slice_packet(rawPacket))
})

```

## API

### .slice\_packet

Convert node-pcap packet to a radiotap packet with correct length

### .parse

Parse a radiotap packet (and all wifi packets inside)
