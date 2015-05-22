/*
 * coWPAtty - Brute-force dictionary attack against WPA-PSK.
 *
 * Copyright (c) 2004, Joshua Wright <jwright@hasborg.com>
 *
 * $Id: sha1.c,v 1.1.1.1 2004/11/02 11:43:30 jwright Exp $
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See COPYING for more
 * details.
 *
 * coWPAtty is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

/*
 * Significant code is graciously taken from the following:
 * wpa_supplicant by Jouni Malinen.  This tool would have been MUCH more
 * difficult for me if not for this code.  Thanks Jouni.
 *
 * i386 assembly SHA code taken from the umac.c message auth code by
 * Ted Krovetz (tdk@acm.org):
 * http://www.cs.ucdavis.edu/~rogaway/umac/umac.c
 * (dragorn)
 */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "common.h"
#include "sha1.h"

/* hack, hack, hack */
SHA1_CACHE cached;

void sha1_mac(unsigned char *key, unsigned int key_len,
unsigned char *data, unsigned int data_len,
unsigned char *mac)
{
    SHA1_CTX context;
    SHA1Init(&context);
    SHA1Update(&context, key, key_len);
    SHA1Update(&context, data, data_len);
    SHA1Update(&context, key, key_len);
    SHA1Final(mac, &context);
}

/* HMAC code is based on RFC 2104 
   Modifications (hacks) by Joshua Wright.  Optimized a bit for pbkdf2
   processing by caching values that are repetitive.  There is some repetitive
   code in this function, which I've retained to make it more readable (for my
   sanity's sake).
 */ 
void hmac_sha1_vector(unsigned char *key, unsigned int key_len,
		      size_t num_elem, unsigned char *addr[],
		      unsigned int *len, unsigned char *mac, int usecached)
{
	SHA1_CTX context;
	unsigned char k_ipad[65]; /* inner padding - key XORd with ipad */
	unsigned char k_opad[65]; /* outer padding - key XORd with opad */
	int i;

	/* the HMAC_SHA1 transform looks like:
	 *
	 * SHA1(K XOR opad, SHA1(K XOR ipad, text))
	 *
	 * where K is an n byte key
	 * ipad is the byte 0x36 repeated 64 times
	 * opad is the byte 0x5c repeated 64 times
	 * and text is the data being protected */

    if (usecached == NOCACHED || !cached.k_ipad_set || !cached.k_opad_set) {
        /* We either don't want to cache values, or we do want to cache but
           haven't cached them yet. */

        /* start out by storing key in pads */
        memset(k_ipad, 0, sizeof(k_ipad));
        memset(k_opad, 0, sizeof(k_opad));
        memcpy(k_ipad, key, key_len);
        memcpy(k_opad, key, key_len);

	    /* XOR key with ipad and opad values */
        for (i = 0; i < 64; i++) {
            k_ipad[i] ^= 0x36;
            k_opad[i] ^= 0x5c;
        }

        SHA1Init(&context);                   /* init context for 1st pass */
        SHA1Update(&context, k_ipad, 64);     /* start with inner pad */

        if (usecached) {
            /* Cached the context value */
            memcpy(&cached.k_ipad, &context, sizeof(context));
            cached.k_ipad_set=1;
        }

	    /* then text of datagram; all fragments */
        for (i = 0; i < num_elem; i++) {
            SHA1Update(&context, addr[i], len[i]);
        }
        SHA1Final(mac, &context);             /* finish up 1st pass */

        /* perform outer SHA1 */
        SHA1Init(&context);                   /* init context for 2nd pass */
        SHA1Update(&context, k_opad, 64);     /* start with outer pad */

        if (usecached) {
            /* Cached the context value */
            memcpy(&cached.k_opad, &context, sizeof(context));
            cached.k_opad_set=1;
        }

        SHA1Update(&context, mac, 20);        /* then results of 1st hash */
        SHA1Final(mac, &context);             /* finish up 2nd pass */

        return;

    } /* End NOCACHED SHA1 processing */

     
    /* This code attempts to optimize the hmac-sha1 process by caching
       values that remain constant for the same key.  This code is called
       many times by pbkdf2, so all optimizations help. 
       
       If we've gotten here, we want to use caching, and have already cached
       the values for k_ipad and k_opad after SHA1Update. */

    memcpy(&context, &cached.k_ipad, sizeof(context));
    for (i = 0; i < num_elem; i++) {
        SHA1Update(&context, addr[i], len[i]);
    }
    SHA1Final(mac, &context);

    memcpy(&context, &cached.k_opad, sizeof(context));
    SHA1Update(&context, mac, 20);
    SHA1Final(mac, &context);
    return;
}

static void pbkdf2_sha1_f(char *passphrase, char *ssid,
			  size_t ssid_len, int iterations, int count,
			  unsigned char *digest, int usecached)
{
	unsigned char tmp[SHA1_MAC_LEN], tmp2[SHA1_MAC_LEN];
	int i, j;
	unsigned char count_buf[4];
	unsigned char *addr[] = { ssid, count_buf };
	unsigned int len[] = { ssid_len, 4 };
	size_t passphrase_len = strlen(passphrase);

	/* F(P, S, c, i) = U1 xor U2 xor ... Uc
	 * U1 = PRF(P, S || i)
	 * U2 = PRF(P, U1)
	 * Uc = PRF(P, Uc-1)
	 */

	count_buf[0] = (count >> 24) & 0xff;
	count_buf[1] = (count >> 16) & 0xff;
	count_buf[2] = (count >> 8) & 0xff;
	count_buf[3] = count & 0xff;


	hmac_sha1_vector(passphrase, passphrase_len, 2, addr, len, tmp, NOCACHED);
	memcpy(digest, tmp, SHA1_MAC_LEN);

	for (i = 1; i < iterations; i++) {
		hmac_sha1(passphrase, passphrase_len, tmp, SHA1_MAC_LEN,
			  tmp2, USECACHED);
		memcpy(tmp, tmp2, SHA1_MAC_LEN);
		for (j = 0; j < SHA1_MAC_LEN; j++)
			digest[j] ^= tmp2[j];
	}

    /* clear the cached data set */
    memset(&cached, 0, sizeof(cached));
}


void pbkdf2_sha1(char *passphrase, char *ssid, size_t ssid_len, int iterations,
		 unsigned char *buf, size_t buflen, int usecached)
{
	int count = 0;
	unsigned char *pos = buf;
	size_t left = buflen, plen;
	unsigned char digest[SHA1_MAC_LEN];

	while (left > 0) {
		count++;
		pbkdf2_sha1_f(passphrase, ssid, ssid_len, iterations, count,
			      digest, NOCACHED);
		plen = left > SHA1_MAC_LEN ? SHA1_MAC_LEN : left;
		memcpy(pos, digest, plen);
		pos += plen;
		left -= plen;
	}
}


void hmac_sha1(unsigned char *key, unsigned int key_len,
	       unsigned char *data, unsigned int data_len,
	       unsigned char *mac, int usecached)
{
	hmac_sha1_vector(key, key_len, 1, &data, &data_len, mac, usecached);
}


void sha1_prf(unsigned char *key, unsigned int key_len,
	      char *label, unsigned char *data, unsigned int data_len,
	      unsigned char *buf, size_t buf_len)
{
	char zero = 0, counter = 0;
	size_t pos, plen;
	u8 hash[SHA1_MAC_LEN];
	size_t label_len = strlen(label);
	unsigned char *addr[] = { label, &zero, data, &counter };
	unsigned int len[] = { label_len, 1, data_len, 1 };

	pos = 0;
	while (pos < buf_len) {
		plen = buf_len - pos;
		if (plen >= SHA1_MAC_LEN) {
			hmac_sha1_vector(key, key_len, 4, addr, len,
					 &buf[pos], NOCACHED);
			pos += SHA1_MAC_LEN;
		} else {
			hmac_sha1_vector(key, key_len, 4, addr, len,
					 hash, NOCACHED);
			memcpy(&buf[pos], hash, plen);
			break;
		}
		counter++;
	}
}

#ifndef OPENSSL

#define SHA1HANDSOFF

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

/* blk0() and blk() perform the initial expand. */
/* I got the idea of expanding during the round function from SSLeay */
#ifndef WORDS_BIGENDIAN
#define blk0(i) (block->l[i] = (rol(block->l[i], 24) & 0xFF00FF00) | \
	(rol(block->l[i], 8) & 0x00FF00FF))
#else
#define blk0(i) block->l[i]
#endif
#define blk(i) (block->l[i & 15] = rol(block->l[(i + 13) & 15] ^ \
	block->l[(i + 8) & 15] ^ block->l[(i + 2) & 15] ^ block->l[i & 15], 1))

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#ifndef i386_ASM
#define R0(v,w,x,y,z,i) \
	z += ((w & (x ^ y)) ^ y) + blk0(i) + 0x5A827999 + rol(v, 5); \
	w = rol(w, 30);
#define R1(v,w,x,y,z,i) \
	z += ((w & (x ^ y)) ^ y) + blk(i) + 0x5A827999 + rol(v, 5); \
	w = rol(w, 30);
#define R2(v,w,x,y,z,i) \
	z += (w ^ x ^ y) + blk(i) + 0x6ED9EBA1 + rol(v, 5); w = rol(w, 30);
#define R3(v,w,x,y,z,i) \
	z += (((w | x) & y) | (w & x)) + blk(i) + 0x8F1BBCDC + rol(v, 5); \
	w = rol(w, 30);
#define R4(v,w,x,y,z,i) \
	z += (w ^ x ^ y) + blk(i) + 0xCA62C1D6 + rol(v, 5); \
	w=rol(w, 30);
#else
#define R0(v,w,x,y,z,i) \
"movl %%"#x",%%edi\n\t" \
    "xorl %%"#y",%%edi\n\t" \
    "andl %%"#w",%%edi\n\t" \
    "xorl %%"#y",%%edi\n\t" \
    "leal 0x5A827999(%%"#z",%%edi),%%"#z"\n\t" \
    "movl %%"#v",%%edi\n\t" \
    "roll $5,%%edi\n\t" \
    "addl %%edi,%%"#z"\n\t" \
    "movl (("#i"*4)&63)(%%ebp),%%edi\n\t" \
    "bswap %%edi\n\t" \
    "movl %%edi,(("#i"*4)&63)(%%ebp)\n\t" \
    "addl %%edi,%%"#z"\n\t" \
    "roll $30,%%"#w"\n\t"

#define R1(v,w,x,y,z,i) \
    "movl %%"#x",%%edi\n\t" \
    "xorl %%"#y",%%edi\n\t" \
    "andl %%"#w",%%edi\n\t" \
    "xorl %%"#y",%%edi\n\t" \
    "leal 0x5A827999(%%"#z",%%edi),%%"#z"\n\t" \
    "movl %%"#v",%%edi\n\t" \
    "roll $5,%%edi\n\t" \
    "addl %%edi,%%"#z"\n\t" \
    "movl (("#i"*4)&63)(%%ebp),%%edi\n\t" \
    "xorl (("#i"*4+8)&63)(%%ebp),%%edi\n\t" \
    "xorl (("#i"*4+32)&63)(%%ebp),%%edi\n\t" \
    "xorl (("#i"*4+52)&63)(%%ebp),%%edi\n\t" \
    "roll $1,%%edi\n\t" \
    "movl %%edi,(("#i"*4)&63)(%%ebp)\n\t" \
    "addl %%edi,%%"#z"\n\t" \
    "roll $30,%%"#w"\n\t"

#define R2(v,w,x,y,z,i) \
    "movl %%"#x",%%edi\n\t" \
    "xorl %%"#y",%%edi\n\t" \
    "xorl %%"#w",%%edi\n\t" \
    "leal 0x6ED9EBA1(%%"#z",%%edi),%%"#z"\n\t" \
    "movl %%"#v",%%edi\n\t" \
    "roll $5,%%edi\n\t" \
    "addl %%edi,%%"#z"\n\t" \
    "movl (("#i"*4)&63)(%%ebp),%%edi\n\t" \
    "xorl (("#i"*4+8)&63)(%%ebp),%%edi\n\t" \
    "xorl (("#i"*4+32)&63)(%%ebp),%%edi\n\t" \
    "xorl (("#i"*4+52)&63)(%%ebp),%%edi\n\t" \
    "roll $1,%%edi\n\t" \
    "movl %%edi,(("#i"*4)&63)(%%ebp)\n\t" \
    "addl %%edi,%%"#z"\n\t" \
    "roll $30,%%"#w"\n\t"

#define R3(v,w,x,y,z,i) \
    "movl %%"#x",%%edi\n\t" \
    "orl %%"#w",%%edi\n\t" \
    "andl %%"#y",%%edi\n\t" \
    "movl %%"#x",%%ebp\n\t" \
    "andl %%"#w",%%ebp\n\t" \
    "orl %%ebp,%%edi\n\t" \
    "movl (%%esp),%%ebp\n\t" \
    "leal 0x8F1BBCDC(%%"#z",%%edi),%%"#z"\n\t" \
    "movl %%"#v",%%edi\n\t" \
    "roll $5,%%edi\n\t" \
    "addl %%edi,%%"#z"\n\t" \
    "movl (("#i"*4)&63)(%%ebp),%%edi\n\t" \
    "xorl (("#i"*4+8)&63)(%%ebp),%%edi\n\t" \
    "xorl (("#i"*4+32)&63)(%%ebp),%%edi\n\t" \
    "xorl (("#i"*4+52)&63)(%%ebp),%%edi\n\t" \
    "roll $1,%%edi\n\t" \
    "movl %%edi,(("#i"*4)&63)(%%ebp)\n\t" \
    "addl %%edi,%%"#z"\n\t" \
    "roll $30,%%"#w"\n\t"

#define R4(v,w,x,y,z,i) \
    "movl %%"#x",%%edi\n\t" \
    "xorl %%"#y",%%edi\n\t" \
    "xorl %%"#w",%%edi\n\t" \
    "leal 0xCA62C1D6(%%"#z",%%edi),%%"#z"\n\t" \
    "movl %%"#v",%%edi\n\t" \
    "roll $5,%%edi\n\t" \
    "addl %%edi,%%"#z"\n\t" \
    "movl (("#i"*4)&63)(%%ebp),%%edi\n\t" \
    "xorl (("#i"*4+8)&63)(%%ebp),%%edi\n\t" \
    "xorl (("#i"*4+32)&63)(%%ebp),%%edi\n\t" \
    "xorl (("#i"*4+52)&63)(%%ebp),%%edi\n\t" \
    "roll $1,%%edi\n\t" \
    "movl %%edi,(("#i"*4)&63)(%%ebp)\n\t" \
    "addl %%edi,%%"#z"\n\t" \
    "roll $30,%%"#w"\n\t"
#endif

#ifdef VERBOSE  /* SAK */
void SHAPrintContext(SHA1_CTX *context, char *msg)
{
	printf("%s (%d,%d) %x %x %x %x %x\n",
	       msg,
	       context->count[0], context->count[1], 
	       context->state[0],
	       context->state[1],
	       context->state[2],
	       context->state[3],
	       context->state[4]);
}
#endif

/* Hash a single 512-bit block. This is the core of the algorithm. */


void SHA1Transform(u32 state[5], u32 state_out[5], unsigned char buffer[64])
{
#ifdef i386_ASM
    u32 block[16];        /* Copy data to temporary buffer for */
    memcpy(block,buffer,64); /* endian reversal required by sha1  */

    asm volatile (
                  "pushl %%ebp\n\t"  /* push ebp */
                  "pushl %%eax\n\t"  /* push state_out */
                  "pushl %%edi\n\t"  /* push state_in */
                  "pushl %%ebx\n\t"  /* push buffer */
                  "movl %%ebx,%%ebp\n\t"
                  "movl 0(%%edi),%%eax\n\t"
                  "movl 4(%%edi),%%ebx\n\t"
                  "movl 8(%%edi),%%ecx\n\t"
                  "movl 12(%%edi),%%edx\n\t"
                  "movl 16(%%edi),%%esi\n\t"
                  R0(eax,ebx,ecx,edx,esi, 0) R0(esi,eax,ebx,ecx,edx, 1) 
                  R0(edx,esi,eax,ebx,ecx, 2) R0(ecx,edx,esi,eax,ebx, 3)
                  R0(ebx,ecx,edx,esi,eax, 4) R0(eax,ebx,ecx,edx,esi, 5) 
                  R0(esi,eax,ebx,ecx,edx, 6) R0(edx,esi,eax,ebx,ecx, 7)
                  R0(ecx,edx,esi,eax,ebx, 8) R0(ebx,ecx,edx,esi,eax, 9) 
                  R0(eax,ebx,ecx,edx,esi,10) R0(esi,eax,ebx,ecx,edx,11)
                  R0(edx,esi,eax,ebx,ecx,12) R0(ecx,edx,esi,eax,ebx,13) 
                  R0(ebx,ecx,edx,esi,eax,14) R0(eax,ebx,ecx,edx,esi,15)
                  R1(esi,eax,ebx,ecx,edx,16) R1(edx,esi,eax,ebx,ecx,17) 
                  R1(ecx,edx,esi,eax,ebx,18) R1(ebx,ecx,edx,esi,eax,19)
                  R2(eax,ebx,ecx,edx,esi,20) R2(esi,eax,ebx,ecx,edx,21) 
                  R2(edx,esi,eax,ebx,ecx,22) R2(ecx,edx,esi,eax,ebx,23)
                  R2(ebx,ecx,edx,esi,eax,24) R2(eax,ebx,ecx,edx,esi,25) 
                  R2(esi,eax,ebx,ecx,edx,26) R2(edx,esi,eax,ebx,ecx,27)
                  R2(ecx,edx,esi,eax,ebx,28) R2(ebx,ecx,edx,esi,eax,29) 
                  R2(eax,ebx,ecx,edx,esi,30) R2(esi,eax,ebx,ecx,edx,31)
                  R2(edx,esi,eax,ebx,ecx,32) R2(ecx,edx,esi,eax,ebx,33) 
                  R2(ebx,ecx,edx,esi,eax,34) R2(eax,ebx,ecx,edx,esi,35)
                  R2(esi,eax,ebx,ecx,edx,36) R2(edx,esi,eax,ebx,ecx,37) 
                  R2(ecx,edx,esi,eax,ebx,38) R2(ebx,ecx,edx,esi,eax,39)
                  R3(eax,ebx,ecx,edx,esi,40) R3(esi,eax,ebx,ecx,edx,41) 
                  R3(edx,esi,eax,ebx,ecx,42) R3(ecx,edx,esi,eax,ebx,43)
                  R3(ebx,ecx,edx,esi,eax,44) R3(eax,ebx,ecx,edx,esi,45) 
                  R3(esi,eax,ebx,ecx,edx,46) R3(edx,esi,eax,ebx,ecx,47)
                  R3(ecx,edx,esi,eax,ebx,48) R3(ebx,ecx,edx,esi,eax,49) 
                  R3(eax,ebx,ecx,edx,esi,50) R3(esi,eax,ebx,ecx,edx,51)
                  R3(edx,esi,eax,ebx,ecx,52) R3(ecx,edx,esi,eax,ebx,53) 
                  R3(ebx,ecx,edx,esi,eax,54) R3(eax,ebx,ecx,edx,esi,55)
                  R3(esi,eax,ebx,ecx,edx,56) R3(edx,esi,eax,ebx,ecx,57) 
                  R3(ecx,edx,esi,eax,ebx,58) R3(ebx,ecx,edx,esi,eax,59)
                  R4(eax,ebx,ecx,edx,esi,60) R4(esi,eax,ebx,ecx,edx,61) 
                  R4(edx,esi,eax,ebx,ecx,62) R4(ecx,edx,esi,eax,ebx,63)
                  R4(ebx,ecx,edx,esi,eax,64) R4(eax,ebx,ecx,edx,esi,65) 
                  R4(esi,eax,ebx,ecx,edx,66) R4(edx,esi,eax,ebx,ecx,67)
                  R4(ecx,edx,esi,eax,ebx,68) R4(ebx,ecx,edx,esi,eax,69) 
                  R4(eax,ebx,ecx,edx,esi,70) R4(esi,eax,ebx,ecx,edx,71)
                  R4(edx,esi,eax,ebx,ecx,72) R4(ecx,edx,esi,eax,ebx,73) 
                  R4(ebx,ecx,edx,esi,eax,74) R4(eax,ebx,ecx,edx,esi,75)
                  R4(esi,eax,ebx,ecx,edx,76) R4(edx,esi,eax,ebx,ecx,77) 
                  R4(ecx,edx,esi,eax,ebx,78) R4(ebx,ecx,edx,esi,eax,79)
                  "popl %%ebp\n\t"
                  "popl %%edi\n\t"
                  "popl %%ebp\n\t"
                  "addl 0(%%edi),%%eax\n\t"
                  "addl 4(%%edi),%%ebx\n\t"
                  "addl 8(%%edi),%%ecx\n\t"
                  "addl 12(%%edi),%%edx\n\t"
                  "addl 16(%%edi),%%esi\n\t"
                  "movl %%eax,0(%%ebp)\n\t"
                  "movl %%ebx,4(%%ebp)\n\t"
                  "movl %%ecx,8(%%ebp)\n\t"
                  "movl %%edx,12(%%ebp)\n\t"
                  "movl %%esi,16(%%ebp)\n\t"
                  "popl %%ebp"
                  : 
                  : "D" (state), "a" (state_out), "b" (block)
                  : "memory");
#else
	u32 a, b, c, d, e;
	typedef union {
		unsigned char c[64];
		u32 l[16];
	} CHAR64LONG16;
	CHAR64LONG16* block;
#ifdef SHA1HANDSOFF
	static unsigned char workspace[64];
	block = (CHAR64LONG16 *) workspace;
	memcpy(block, buffer, 64);
#else
	block = (CHAR64LONG16 *) buffer;
#endif
	/* Copy context->state[] to working vars */
	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	e = state[4];
	/* 4 rounds of 20 operations each. Loop unrolled. */
	R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
	R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
	R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
	R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
	R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
	R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
	R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
	R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
	R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
	R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
	R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
	R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
	R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
	R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
	R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
	R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
	R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
	R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
	R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
	R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);
	/* Add the working vars back into context.state[] */
	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
	/* Wipe variables */
	a = b = c = d = e = 0;
#endif
}


/* SHA1Init - Initialize new context */

void SHA1Init(SHA1_CTX* context)
{
	/* SHA1 initialization constants */
	context->state[0] = 0x67452301;
	context->state[1] = 0xEFCDAB89;
	context->state[2] = 0x98BADCFE;
	context->state[3] = 0x10325476;
	context->state[4] = 0xC3D2E1F0;
	context->count[0] = context->count[1] = 0;
}


/* Run your data through this. */

void SHA1Update(SHA1_CTX* context, unsigned char* data, u32 len)
{
	u32 i, j;

#ifdef VERBOSE
	SHAPrintContext(context, "before");
#endif
	j = (context->count[0] >> 3) & 63;
	if ((context->count[0] += len << 3) < (len << 3))
		context->count[1]++;
	context->count[1] += (len >> 29);
	if ((j + len) > 63) {
		memcpy(&context->buffer[j], data, (i = 64-j));
		SHA1Transform(context->state, context->state, context->buffer);
		for ( ; i + 63 < len; i += 64) {
			SHA1Transform(context->state, context->state, &data[i]);
		}
		j = 0;
	}
	else i = 0;
	memcpy(&context->buffer[j], &data[i], len - i);
#ifdef VERBOSE
	SHAPrintContext(context, "after ");
#endif
}


/* Add padding and return the message digest. */

void SHA1Final(unsigned char digest[20], SHA1_CTX* context)
{
	u32 i;
	unsigned char finalcount[8];

	for (i = 0; i < 8; i++) {
		finalcount[i] = (unsigned char)
			((context->count[(i >= 4 ? 0 : 1)] >>
			  ((3-(i & 3)) * 8) ) & 255);  /* Endian independent */
	}
	SHA1Update(context, (unsigned char *) "\200", 1);
	while ((context->count[0] & 504) != 448) {
		SHA1Update(context, (unsigned char *) "\0", 1);
	}
	SHA1Update(context, finalcount, 8);  /* Should cause a SHA1Transform()
					      */
	for (i = 0; i < 20; i++) {
		digest[i] = (unsigned char)
			((context->state[i >> 2] >> ((3 - (i & 3)) * 8)) &
			 255);
	}
	/* Wipe variables */
	i = 0;
	memset(context->buffer, 0, 64);
	memset(context->state, 0, 20);
	memset(context->count, 0, 8);
	memset(finalcount, 0, 8);
#ifdef SHA1HANDSOFF  /* make SHA1Transform overwrite it's own static vars */
	SHA1Transform(context->state, context->state, context->buffer);
#endif
}

#endif /* OPENSSL */
