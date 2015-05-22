var radiotap = require("./radiotap")
var frame = require("./80211_frame")
var tags = require("./80211_tags")

function slice_packet(raw) {
  var len = raw.header.readUInt32LE(12)
  return raw.buf.slice(0, len)
}

module.exports = {
  slice_packet: slice_packet,
  parse: radiotap.parse
}
