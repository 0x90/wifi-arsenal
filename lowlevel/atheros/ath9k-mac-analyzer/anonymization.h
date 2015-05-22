#ifndef _BISMARK_PASSIVE_ANONYMIZATION_H_
#define _BISMARK_PASSIVE_ANONYMIZATION_H_

#include <stdint.h>
#include <zlib.h>
#include <net/ethernet.h>
#include <openssl/sha.h>

#define ANONYMIZATION_DIGEST_LENGTH SHA_DIGEST_LENGTH

#define ANONYMIZATION
/* Must call exactly once per process, before any anonymization is performed. */
int anonymization_init();
/* Anonymize the lower 24 bits of a MAC address into the provided buffer. The
 * digest buffer must be at least ANONYMIZATION_DIGEST_LENGTH bytes long. */
inline int anonymize_mac(uint8_t mac[ETH_ALEN], uint8_t digest[ETH_ALEN]);

/* Write an anonymized version of the anonymization key as part of an update.
 * We do this so that the server can identify updates that were prepared using
 * the same anonymization key, without actually knowing what that key is. */
int anonymization_write_update(gzFile);

#endif

