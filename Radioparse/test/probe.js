var pcap = require("pcap")
var radioparse = require("../index")

var session = pcap.createSession("mon0")

session.on("packet", function(raw) {
  var packet = radioparse.parse(radioparse.slice_packet(raw))

  if (packet.frame) {
    if (packet.frame.type === 0 && packet.frame.subtype === 8)  {
      packet.frame.tags.forEach(function(tag) {
        if (tag.type === "ssid") {
          console.log(tag)
        }
      })
    }
  }
})
