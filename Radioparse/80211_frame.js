
/* 802.11 frame parser */

var tools = require("./tools")
var parse_tags = require("./80211_tags").parse_tags
var read_mac = tools.read_mac
var flags_to_array = tools.flags_to_array

function merge(obj1, obj2) {
  Object.keys(obj2).forEach(function(key) {
    if (!obj1.hasOwnProperty(key))
      obj1[key] = obj2[key]
  })
}

function data_frame(packet) {
  var frame = {}

  frame.ccmp_params = packet.slice(24, 32)

  return frame
}

function beacon(packet) {
    var pos = 24 // skip frame control, addresses
    var frame = {}

    // fixed parameters (12 bytes)
    frame.timestamp = packet.slice(pos, pos + 8)
    pos += 8

    frame.beacon_interval = packet.readUInt16BE(pos)
    pos += 2

    frame.capabilities = flags_to_array(packet.readUInt16BE(pos), 16)
    pos += 2

    frame.tags = parse_tags(packet.slice(pos, packet.length - 4))

    return frame
}

function probe_request(packet) {
  return {
    tags: parse_tags(packet.slice(24, packet.length))
  }
}

function probe_response(packet) {
  var pos = 24
  var frame = {}

    frame.timestamp = packet.slice(pos, pos + 8)
    pos += 8

    frame.beacon_interval = packet.readUInt16BE(pos)
    pos += 2

    frame.capabilities = flags_to_array(packet.readUInt16BE(pos), 16)
    pos += 2

    frame.tags = parse_tags(packet.slice(pos, packet.length - 4))

    return frame
}

module.exports = {
  parse: function(packet) {

    // There are quite a few of those packets...
    if (packet.length < 24)
      return null

    var frame = {}

    frame.frame_control = packet.readUInt16BE(0)
    var type_subtype = packet.readUInt8(0)
    frame.subtype = (type_subtype >> 4)
    frame.type = (type_subtype >> 2) & 3
    frame.version = type_subtype & 3 // 0b00000011
    frame.fc_flags = flags_to_array(packet.readUInt8(1), 8)

    // currently all packets use version 0
    if (frame.version !== 0) {
      return null
    }

    frame.duration_id = packet.readUInt16BE(2)
    frame.fcs = packet.readUInt32BE(packet.length - 4)

    var to_ds = frame.fc_flags[0],
        from_ds = frame.fc_flags[1]

    if (to_ds === 0 && from_ds === 0) {
      frame.dst_addr = read_mac(packet, 4)
      
      frame.src_addr = read_mac(packet, 10)
    
      frame.bbs_addr = read_mac(packet, 16)

      frame.sequence_control = packet.readUInt16BE(18)

      // no address 4 from 18 - 24 
    }
    if (to_ds === 0 && from_ds === 1) {
      frame.dst_addr = read_mac(packet, 4)
      
      frame.bss_addr = read_mac(packet, 10)
    
      frame.src_addr = read_mac(packet, 16)

      frame.sequence_control = packet.readUInt16BE(18)
      
    }
    if (to_ds === 1 && from_ds === 0) {
      frame.bss_addr = read_mac(packet, 4)
      
      frame.src_addr = read_mac(packet, 10)
    
      frame.dst_addr = read_mac(packet, 16)

      frame.sequence_control = packet.readUInt16BE(18)

    }
    if (to_ds === 1 && from_ds === 1) {
      frame.receiver = read_mac(packet, 4)
      
      frame.src_addr = read_mac(packet, 10)
    
      frame.dst_addr = read_mac(packet, 16)

      frame.sequence_control = packet.readUInt16BE(18)

      frame.orig_addr = read_mac(packet, 18)
    }

    // Management Frame
    if (frame.type === 0) {
      if (frame.subtype === 4) // 0100
        merge(frame, probe_request(packet))
      if (frame.subtype === 5) // 0101
        merge(frame, probe_response(packet))
      if (frame.subtype === 8) // 1000
        merge(frame, beacon(packet))
    }
    // Control Frame
    if (frame.type === 1) {
      
    }
    // Data Frame
    if (frame.type === 2) {
      if (frame.subtype === 0)
        merge(frame, data_frame(packet))
    }
    
    return frame
  }
}
