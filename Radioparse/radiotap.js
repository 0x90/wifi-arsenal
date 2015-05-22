var tools = require("./tools")
var frame = require("./80211_frame")

var flags_to_array = tools.flags_to_array

var rt_types = {
	"TSFT": 0,
	"FLAGS": 1,
	"RATE": 2,
	"CHANNEL": 3,
	"FHSS": 4,
	"DBM_ANTSIGNAL": 5,
	"DBM_ANTNOISE": 6,
	"LOCK_QUALITY": 7,
	"TX_ATTENUATION": 8,
	"DB_TX_ATTENUATION": 9,
	"DBM_TX_POWER": 10,
	"ANTENNA": 11,
	"DB_ANTSIGNAL": 12,
	"DB_ANTNOISE": 13,
	"RX_FLAGS": 14,
	"TX_FLAGS": 15,
	"RTS_RETRIES": 16,
	"DATA_RETRIES": 17,
	"EXT": 31
}

function parse(buf) {
  var header = {}
  /* Radiotap Header */
  var pos = 0

  header.revision = buf.readUInt8(pos)
  pos += 1
  
  header.pad = buf.readUInt8(pos)
  pos += 1
  
  header.length = buf.readUInt16LE(pos)
  pos += 2
  
  var flags = flags_to_array(buf.readUInt32LE(pos), 32)
  pos += 4

  var extraFlags = flags
  while (extraFlags[rt_types.EXT]) {
    pos += 4
    extraFlags = flags_to_array(buf.readUInt32LE(pos), 32)
  }

  header.present_flags = flags

  /* Variable part, depending on present flags */

  if (flags[rt_types.TSFT]) {
    pos += 8
    header.tsft = buf.slice(pos, pos + 8)
    pos += 8
  }

  if (flags[rt_types.FLAGS]) {
    header.flags = flags_to_array(buf.readUInt8(pos), 8)
    pos += 1
  }

  if (flags[rt_types.RATE]) {
    header.rate = buf.readUInt8(pos)
    pos += 1
  }
  
  if (flags[rt_types.CHANNEL]) {
    header.channel = buf.readUInt16LE(pos)
    pos += 2
    header.channel_type = flags_to_array(buf.readUInt16LE(pos), 16)
    pos += 2
  }

  if (flags[rt_types.FHSS]) {
    header.fhss = {
      hop_set: buf.readUInt8(pos),
      hop_pattern: buf.readUInt8(pos + 1)
    }
    pos += 2 
  }

  if (flags[rt_types.DBM_ANTSIGNAL]) {
    header.dbm_signal = buf.readInt8(pos)
    pos += 1
  }
  
  if (flags[rt_types.DBM_ANTNOISE]) {
    header.dbm_noise = buf.readInt8(pos)
    pos += 1
  }

  if (flags[rt_types.LOCK_QUALITY]) {
    header.lock_quality = buf.readUInt16LE(pos)
    pos += 2
  }

  if (flags[rt_types.TX_ATTENUATION]) {
    header.tx_attenuation = buf.readUInt8(pos)
    pos += 1
  }

	if (flags[rt_types.DB_TX_ATTENUATION]) {
    header.db_tx_attenuation = buf.readUInt16LE(pos)
    pos += 2
  }
	
  if (flags[rt_types.DBM_TX_POWER]) {
    header.dbm_tx_power = buf.readUInt8(pos)
    pos += 1
  }

	if (flags[rt_types.ANTENNA]) {
    header.antenna = buf.readUInt8(pos)
    pos += 1
  }

	if (flags[rt_types.DB_ANTSIGNAL]) {
    header.db_antenna_signal = buf.readUInt8(pos)
    pos += 1
  }

	if (flags[rt_types.DB_ANTNOISE]) {
    header.db_antenna_noise = buf.readUInt8(pos)
    pos += 1
  }

	if (flags[rt_types.RX_FLAGS]) {
    pos += 1
    header.rx_flags = buf.readUInt16LE(pos)
    pos += 2
  }

	if (flags[rt_types.TX_FLAGS]) {
    pos += 1
    header.tx_flags = buf.readUInt16LE(pos)
    pos += 2
  }

	if (flags[rt_types.RTS_RETRIES]) {
    header.rts_retries = buf.readUInt8(pos)
    pos += 1
  }
  
	if (flags[rt_types.DATA_RETRIES]) {
    header.data_retries = buf.readUInt8(pos)
    pos += 1
  }

  /* 802.11 header */

  // if the radiotap parser screws up, the 802.11 frame is still accessible
  header.frame = frame.parse(buf.slice(header.length, buf.length)) 

  return header
}

module.exports = {
  parse: parse
}
