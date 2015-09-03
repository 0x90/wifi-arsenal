var flags_to_array = require("./tools").flags_to_array

function parse_vendor_specific(tag) {
  var data = {
    oui: tag.slice(0, 3),
    type: tag.readUInt8(3),
  }

  // Microsoft WPS thing
  if (data.oui.toString("hex") === "0050f2" && data.type === 0x04) {
    data.fields = []

    var pos = 4

    while (pos < tag.length) {
      var type = tag.readUInt16BE(pos); pos += 2
      var len = tag.readUInt16BE(pos); pos += 2

      var field = {
        type: type
      }

      if (type === 0x104a) {
        field.version = tag.readUInt8(pos)
      }
      if (type === 0x103a) {
        field.request_type = tag.readUInt8(pos)
      }
      if (type === 0x1008) {
        field.config_methods = flags_to_array(tag.readUInt16BE(pos), 16)
      }
      if (type === 0x1047) {
        field.uuid = tag.slice(pos, 16)
      }
      if (type === 0x1054) {
        field.device_type = {
          category: tag.readUInt16BE(pos),
          subcategory: tag.readUInt16BE(pos + 6)
        }
      }
      if (type === 0x103c) {
        field.rf_bands = tag.readUInt8(pos)
      }
      if (type === 0x1002) {
        field.association_state = tag.readUInt16BE(pos)
      }
      if (type === 0x1009) {
        field.configuration_error = tag.readUInt16BE(pos)
      }
      if (type === 0x1012) {
        field.password_id = tag.readUInt16BE(pos)
      }
      if (type === 0x1021) {
        field.manufacturer = new String(tag.slice(pos, pos + len))
      }
      if (type === 0x1023) {
        field.model_name = new String(tag.slice(pos, pos + len)) 
      }
      if (type === 0x1024) {
        field.model_number = new String(tag.slice(pos, pos + len))
      }
      if (type === 0x1011) {
        field.device_name = new String(tag.slice(pos, pos + len))
      } 
      if (type === 0x1049) {
        field.data = tag.slice(pos, pos + len)
      }

      pos += len
      data.fields.push(field)
    }
  }

  return data
}

function parse_tag(tag, type) {
  // SSID
  if (type === 0) {
    return {
      type: "ssid",
      ssid: new String(tag.slice(0, tag.length))
    }
  }
  // rates
  if (type === 1) {
    var rates = []
    for (var i = 0; i < tag.length; i++) {
      rates.push(tag.readUInt8(i))
    }
    return {
      type: "rates",
      rates: rates
    }
  }
  // Channel
  if (type === 3) {
    return {
      type: "channel",
      channel: tag.readUInt8(0)
    }
  }
  // traffic indication map
  if (type === 5) {
    return {
      type: "traffic_indication_map",
      dtim_count: tag.readUInt8(0),
      dtim_period: tag.readUInt8(1),
      bitmap_control: tag.readUInt8(2),
      partial_virtual_bitmap: tag.readUInt8(3)
    }
  }
  // ERP information
  if (type === 42) {
    return {
      type: "erp_information"
    }
  }
  // RSN information
  if (type === 48) {
    return {
      type: "rsn_information"
    }
  }
  // extended rates
  if (type === 50) {
    var rates = []
    for (var i = 0; i < tag.length; i++) {
      rates.push(tag.readUInt8(i))
    }
    return {
      type: "extended_rates",
      rates: rates
    }
  }
  // HT capabilities
  if (type === 45) {
    return {
      type: "ht_capabilities",
    }
  }
  // internetworking
  if (type === 107) {
    var info = tag.readUInt8(0)

    return {
      type: "interworking",
      access_network_type: info & 0x0f,
      internet: new Boolean(info & (1 << 4)),
      asra: new Boolean(info & (1 << 3)),
      esr: new Boolean(info & (1 << 2)),
      uesa: new Boolean(info & 1),
      hessid: tag.slice(1, 7)
    }
  }
  // extended capabilities
  if (type === 127) {
    return {
      type: "extended_capabilities"
    }
  }
  // vendor specific
  if (type === 221) {
    var vendorSpecific = parse_vendor_specific(tag)

    vendorSpecific.type = "vendor_specific"
    return vendorSpecific
  }

  return {
    type: null
  }
}

function parse_tags(buffer) {
  var tags = []
  var pos = 0

  while (pos < buffer.length) {
    if (buffer.length - pos >= 2) {
      var tagType = buffer.readUInt8(pos)
      var tagLen = buffer.readUInt8(pos + 1)

      // be sure that there is actually enough space for the tag type to exist
      if (buffer.length - pos >= tagLen) {
        var content = buffer.slice(pos + 2, pos + tagLen + 2)
        var tag = parse_tag(content, tagType)
        tag.type_number = tagType
        tag.content = content
        tags.push(tag)
      }
    }

    pos += tagLen + 2
  }

  return tags
}

module.exports = {
  parse_tags: parse_tags,
  parse_tag: parse_tag
}
