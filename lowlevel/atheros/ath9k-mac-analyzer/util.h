#ifndef _BISMARK_PASSIVE_UTIL_H_
#define _BISMARK_PASSIVE_UTIL_H_

#include <stdint.h>

#define ANONYMIZATION_SEED_LEN 16
#ifndef ANONYMIZATION_SEED_FILE
#define ANONYMIZATION_SEED_FILE "/etc/bismark/passive.key"
#endif
const char* buffer_to_hex(uint8_t* buffer, int len);
inline int is_address_private(uint32_t address);

#endif
