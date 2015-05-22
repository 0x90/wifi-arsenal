#include "util.h"

#include <stdio.h>

static char output_buffer[1024];

const char* buffer_to_hex(uint8_t* buffer, int len) {
  if (len > sizeof(output_buffer) - 1) {
    fprintf(stderr, "Exceeded max buffer size for hex conversion.\n");
    return NULL;
  }
  int idx;
  for (idx = 0; idx < len; ++idx) {
    if (sprintf(output_buffer + 2 * idx, "%02x", buffer[idx]) < 2) {
      perror("Error converting buffer to hex.\n");
      return NULL;
    }
  }
  output_buffer[2 * len] = '\0';
  return output_buffer;
}

inline int is_address_private(uint32_t address) {
  return (address & 0xff000000) == 0x0a000000
      || (address & 0xfff00000) == 0xac100000
      || (address & 0xffff0000) == 0xc0a80000;
}
