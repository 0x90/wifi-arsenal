/*
 * Copyright (c) Tim Hockin, Cobalt Networks Inc. and others
 *
 * crypto routines used by multiple c files 
 */
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/param.h>
#include "DESSupport.h"

#ifndef USE_CRYPT
#define DES_CBLOCK_SIZE		8

static unsigned char odd_parity[256] = {
    1,  1,  2,  2,  4,  4,  7,  7,  8,  8, 11, 11, 13, 13, 14, 14,
    16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
    32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
    49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
    64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
    81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
    97, 97, 98, 98, 100, 100, 103, 103, 104, 104, 107, 107, 109, 109, 110, 110,
    112, 112, 115, 115, 117, 117, 118, 118, 121, 121, 122, 122, 124, 124, 127, 127,
    128, 128, 131, 131, 133, 133, 134, 134, 137, 137, 138, 138, 140, 140, 143, 143,
    145, 145, 146, 146, 148, 148, 151, 151, 152, 152, 155, 155, 157, 157, 158, 158,
    161, 161, 162, 162, 164, 164, 167, 167, 168, 168, 171, 171, 173, 173, 174, 174,
    176, 176, 179, 179, 181, 181, 182, 182, 185, 185, 186, 186, 188, 188, 191, 191,
    193, 193, 194, 194, 196, 196, 199, 199, 200, 200, 203, 203, 205, 205, 206, 206,
    208, 208, 211, 211, 213, 213, 214, 214, 217, 217, 218, 218, 220, 220, 223, 223,
    224, 224, 227, 227, 229, 229, 230, 230, 233, 233, 234, 234, 236, 236, 239, 239,
    241, 241, 242, 242, 244, 244, 247, 247, 248, 248, 251, 251, 253, 253, 254, 254};

static void 
set_odd_parity(unsigned char *key)
{
    int idx;
    for (idx = 0; idx < DES_CBLOCK_SIZE; idx++)
	key[idx] = odd_parity[key[idx]];
}

#include <CommonCrypto/CommonCryptor.h>
#endif

static u_char Get7Bits(const unsigned char *input, int startBit)
{
    register unsigned int       word;

    word  = (unsigned)input[startBit / 8] << 8;
    word |= (unsigned)input[startBit / 8 + 1];

    word >>= 15 - (startBit % 8 + 7);

    return word & 0xFE;
}


static void MakeKey(const unsigned char *key, unsigned char *des_key)
{
    des_key[0] = Get7Bits(key,  0);
    des_key[1] = Get7Bits(key,  7);
    des_key[2] = Get7Bits(key, 14);
    des_key[3] = Get7Bits(key, 21);
    des_key[4] = Get7Bits(key, 28);
    des_key[5] = Get7Bits(key, 35);
    des_key[6] = Get7Bits(key, 42);
    des_key[7] = Get7Bits(key, 49);

#ifndef USE_CRYPT
    set_odd_parity(des_key);
#endif
}


#ifdef USE_CRYPT
/* in == 8-byte string (expanded version of the 56-bit key)
 * out == 64-byte string where each byte is either 1 or 0
 * Note that the low-order "bit" is always ignored by by setkey()
 */
static void Expand(unsigned char *in, unsigned char *out)
{
        int j, c;
        int i;

        for(i = 0; i < 64; in++){
		c = *in;
                for(j = 7; j >= 0; j--)
                        *out++ = (c >> j) & 01;
                i += 8;
        }
}

/* The inverse of Expand
 */
static void Collapse(unsigned char *in, unsigned char *out)
{
        int j;
        int i;
	unsigned int c;

	for (i = 0; i < 64; i += 8, out++) {
	    c = 0;
	    for (j = 7; j >= 0; j--, in++)
		c |= *in << j;
	    *out = c & 0xff;
	}
}

__private_extern__ void
DesEncrypt(const unsigned char *clear, const unsigned char *key, 
	   unsigned char *cipher)
{
    u_char des_key[8];
    u_char crypt_key[66];
    u_char des_input[66];

    MakeKey(key, des_key);

    Expand(des_key, crypt_key);
    setkey(crypt_key);

    Expand(clear, des_input);
    encrypt(des_input, 0);
    Collapse(des_input, cipher);
}
#else /* don't USE_CRYPT */
__private_extern__ void
DesEncrypt(const unsigned char * clear, const unsigned char * key,
	   unsigned char * cipher)
{
    CCCryptorStatus	c_status;
    u_char		des_key[DES_CBLOCK_SIZE];
    size_t		output_bytes;

    MakeKey(key, des_key);
    c_status = CCCrypt(kCCEncrypt, kCCAlgorithmDES, 0,
		       des_key, sizeof(des_key),
		       NULL,
		       clear, DES_CBLOCK_SIZE,
		       cipher, DES_CBLOCK_SIZE, &output_bytes);
    if (c_status != kCCSuccess) {
	fprintf(stderr,
		"DESEncrypt: CCCrypt failed with %d\n",
		c_status);
    }
    return;
}
#endif /* USE_CRYPT */


