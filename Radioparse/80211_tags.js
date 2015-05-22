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
    return {
      type: "rates"
    }
  }
  // DS parameter set
  if (type === 3) {
    return {
      type: "ds_parameters"
    }
  }
  // traffic indication map
  if (type === 5) {
    return {
      type: "traffic_indication_map"
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
    return {
      type: "extended_rates"
    }
  }
  // HT capabilities
  if (type === 45) {
    return {
      type: "ht_capabilities"
    }
  }
  // internetworking
  if (type === 107) {
    return {
      type: "internetworking"
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
    return {
      type: "vendor_specific"
    }
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

      var content = buffer.slice(pos + 2, pos + tagLen + 2)
      var tag = parse_tag(content, tagType)
      tag.type_number = tagType
      tag.content = content
      tags.push(tag)
    }

    pos += tagLen + 2
  }

  return tags
}

module.exports = {
  parse_tags: parse_tags,
  parse_tag: parse_tag
}
