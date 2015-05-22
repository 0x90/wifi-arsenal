// buffer to array of (0,1) flags
module.exports.flags_to_array = function(n, size) {
  var flags = []
  for (var i = 0; i < size; i++) {
    if ((n & (1 << i)) > 0)
      flags.push(1)
    else
      flags.push(0)
  }
  return flags
}

module.exports.read_mac = function(buffer, pos) {
  var bytes = []
  for (var i = 0; i < 6; i++) {
    bytes.push(buffer.readUInt8(pos + i))
  }
  return bytes
}
