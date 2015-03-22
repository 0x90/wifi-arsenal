/* This file is part of Lorcon
    
    lorcon is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    lorcon is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with lorcon; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

    Copyright (c) 2005 dragorn and Joshua Wright
*/

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <stdint.h>
#include <time.h>
#include <pcap.h>
#include <signal.h>
#include <tx80211.h>
#include <lorcon_forge.h>

#include "l2ping80211.h"
#include "ieee80211.h"

/* Globals */
struct tx80211 tx;
pcap_t *p = NULL;
unsigned char *packet;
struct pcap_pkthdr *h;
char pcaperrbuf[PCAP_ERRBUF_SIZE];
int offset; /* Offset to the beginning of the 802.11 header */
int exitval=1;

void sigexit()
{
	tx80211_close(&tx);
	if (p != NULL) {
		pcap_close(p);
	}
	exit(exitval);
}


void usage() {
	struct tx80211_cardlist *cardlist = NULL;
	int i;

	cardlist = tx80211_getcardlist();

	printf("l2ping80211\n"
		   "Usage : l2ping80211 [options] -i interface [-d driver] "
		   "-T targetmac -C testcase\n"
		   "  [-S sourcemac -B bssidmac -D destmac -t usectimer"
		   " -n count -c channel -V]\n");
	printf("\nSupported test cases:\n");

	i=0;
	while(testcases[i].testname != NULL) {
		printf("\t%d\t%s\n", testcases[i].testnum, 
				testcases[i].testname);
		i++;
	}

	if (cardlist == NULL) {
		fprintf(stderr, "Error accessing supported cardlist\n");
	} else {
		printf("\nSupported drivers: ");
		for (i = 1; i < cardlist->num_cards; i++) {
			printf("%s ", cardlist->cardnames[i]);
		}
		printf("\n");
	}

	tx80211_freecardlist(cardlist);
}

/* Converts a string to uppercase */
void to_upper (char *s) 
{
	char *p, offset;
	offset = 'A' - 'a';
	for(p=s;*p != '\0';p++) {
		if(islower(*p)) {
			*p += offset;
		}
	}
}


/* Determine radiotap data length (including header) and return offset for the
beginning of the 802.11 header */
int radiotap_offset(pcap_t *p, struct pcap_pkthdr *h)
{
	struct tx80211_radiotap_header *rtaphdr;
	int rtaphdrlen=0;

	/* Grab a packet to examine radiotap header */
	if (pcap_next_ex(p, &h, (const u_char **) &packet) > -1) {
		rtaphdr = (struct tx80211_radiotap_header *) packet;
		rtaphdrlen = tx80211_le16(rtaphdr->it_len); /* rtap is LE */

		/* Sanity check on header length */
		if (rtaphdrlen > (h->len - 10)) {
			return -2; /* Bad radiotap data */
		}

		return rtaphdrlen;
	}

	return -1;
}

void lamont_hdump(unsigned char *bp, unsigned int length) {

  /* stolen from tcpdump, then kludged extensively */

  static const char asciify[] = "................................ !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~.................................................................................................................................";

  const unsigned short *sp;
  const unsigned char *ap;
  unsigned int i, j;
  int nshorts, nshorts2;
  int padding;

  printf("\n\t");
  padding = 0;
  sp = (unsigned short *)bp;
  ap = (unsigned char *)bp;
  nshorts = (unsigned int) length / sizeof(unsigned short);
  nshorts2 = (unsigned int) length / sizeof(unsigned short);
  i = 0;
  j = 0;
  while(1) {
    while (--nshorts >= 0) {
      printf(" %04x", tx80211_ntoh16(*sp));
      sp++;
      if ((++i % 8) == 0)
        break;
    }
    if (nshorts < 0) {
      if ((length & 1) && (((i-1) % 8) != 0)) {
        printf(" %02x  ", *(unsigned char *)sp);
        padding++;
      }
      nshorts = (8 - (nshorts2 - nshorts));
      while(--nshorts >= 0) {
        printf("     ");
      }
      if (!padding) printf("     ");
    }
    printf("  ");

    while (--nshorts2 >= 0) {
      printf("%c%c", asciify[*ap], asciify[*(ap+1)]);
      ap += 2;
      if ((++j % 8) == 0) {
        printf("\n\t");
        break;
      }
    }
    if (nshorts2 < 0) {
      if ((length & 1) && (((j-1) % 8) != 0)) {
        printf("%c", asciify[*ap]);
      }
      break;
    }
  }
  if ((length & 1) && (((i-1) % 8) == 0)) {
    printf(" %02x", *(unsigned char *)sp);
    printf("                                       %c", asciify[*ap]);
  }
  printf("\n");
}

/* Converts a MAC address string to a u8 array, returns -1 on error */
int string2mac (char *string, uint8_t *mac_buf) 
{
    char *ptr, *next;
    unsigned long val;
    int	i;

    to_upper(string);

    ptr = next = string;
    for(i=0;i < 6;i++) {
        if((val = strtoul(next, &ptr, 16)) > 255) {
            return(-1);
        }
        mac_buf[i] = (unsigned char)val;
        if((next == ptr) && (i != 6 - 1)) {
            return(-1);
        }
        next = ptr + 1;
    }

    return(0);
}

char *printmac(unsigned char *mac)
{
	static char macstring[18];

	memset(&macstring, 0, sizeof(macstring));
	(void)snprintf(macstring, sizeof(macstring),
		       "%02x:%02x:%02x:%02x:%02x:%02x",
		       mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return (macstring);
}

/* Look for frames matching the specified attributes, returning the delta 
 * time. */
int watchfor(int type, int subtype, uint8_t *addr1,
		uint8_t *addr2, uint8_t *addr3, int flags, int timeout) {

	struct ieee80211_hdr *dot11hdr;

	struct timeval starttime, now;
	gettimeofday(&starttime, NULL);
	unsigned int elapsed;
	unsigned int finishtime = ((starttime.tv_sec * 1000000) + starttime.tv_usec + timeout);


	gettimeofday(&now, NULL);
	while ((unsigned int)((now.tv_sec * 1000000) + now.tv_usec) < finishtime) {
		if (pcap_next_ex(p, &h, (const u_char **) &packet) != 1) {
			return -1;
		}

		if (h->len < offset)
			continue;

		gettimeofday(&now, NULL);

		dot11hdr = (struct ieee80211_hdr *) &(packet[offset]);

		if (dot11hdr->u1.fc.type != type) continue;
		if (dot11hdr->u1.fc.subtype != subtype) continue;
		if ((dot11hdr->u1.fchdr & tx80211_hton16(0x00ff)) != flags)
			continue;
		if (addr1 != NULL && (memcmp(addr1, dot11hdr->addr1, 6) != 0)) 
			continue;
		if (addr2 != NULL && (memcmp(addr2, dot11hdr->addr2, 6) != 0)) 
			continue;
		if (addr3 != NULL && (memcmp(addr3, dot11hdr->addr3, 6) != 0)) 
			continue;

		elapsed = ((unsigned int)((now.tv_sec * 1000000) + (now.tv_usec)) - (unsigned int)((starttime.tv_sec * 1000000) + (starttime.tv_usec)));

		return elapsed;
	}

	return 0;
}

/* Send a NULL data frame to the target with a false BSSID, watch for the
 * DEAUTH that follows.
 */
void l2ping_test_datainvalidbssiddeauth(tx80211_t *in_tx, int npacks, 
		uint8_t *targetmac, uint32_t usectimeout)
{
	int i, duration;
	struct lcpa_metapack *metapack;
	tx80211_packet_t txpack;
	uint8_t sourcemac[6];
	uint8_t bssidmac[6];

	metapack = lcpa_init();
	tx80211_initpacket(&txpack);

	srand(time(NULL));
	lcpf_randmac(sourcemac, 1);
	lcpf_randmac(bssidmac, 1);

	lcpf_80211headers(metapack, 
			WLAN_FC_TYPE_DATA,
			WLAN_FC_SUBTYPE_DATANULL,
			0x02, /* fcflags, FromDS */
			0x00, /* duration */
			targetmac,
			bssidmac,
			sourcemac,
			NULL, /* addr4 */
			0, /* Fragment number */
			0); /* Sequence number */

	lcpa_freeze(metapack, &txpack);
	lcpa_free(metapack);

	for(i=0; i < npacks; i++) {
		if (tx80211_txpacket(in_tx, &txpack) < 0) {
			fprintf(stderr, "Unable to inject packet: %s\n",
					tx80211_geterrstr(in_tx));
			return;
		}
		duration = watchfor(WLAN_FC_TYPE_MGMT, WLAN_FC_SUBTYPE_DEAUTH,
				bssidmac, targetmac, NULL, 0, usectimeout);
		if (duration > 0) {
			print_response(targetmac, i+1, h->len, duration);
		} else {
			print_noresponse(targetmac, i+1, usectimeout);
		}

		sleep(1);
					
	}

	return;
}

/* Send a NULL data frame to the target with a false BSSID, watch for the
 * ACK that follows.
 */
void l2ping_test_datainvalidbssid(tx80211_t *in_tx, int npacks, 
		uint8_t *targetmac, uint32_t usectimeout)
{
	int i, duration;
	struct lcpa_metapack *metapack;
	tx80211_packet_t txpack;
	uint8_t sourcemac[6];
	uint8_t bssidmac[6];

	metapack = lcpa_init();
	tx80211_initpacket(&txpack);

	srand(time(NULL));
	lcpf_randmac(sourcemac, 1);
	lcpf_randmac(bssidmac, 1);

	lcpf_80211headers(metapack, 
			WLAN_FC_TYPE_DATA,
			WLAN_FC_SUBTYPE_DATANULL,
			0x02, /* fcflags, FromDS */
			0x00, /* duration */
			targetmac,
			bssidmac,
			sourcemac,
			NULL, /* addr4 */
			0, /* Fragment number */
			0); /* Sequence number */

	lcpa_freeze(metapack, &txpack);
	lcpa_free(metapack);

	for(i=0; i < npacks; i++) {
		if (tx80211_txpacket(in_tx, &txpack) < 0) {
			fprintf(stderr, "Unable to inject packet: %s\n",
					tx80211_geterrstr(in_tx));
			return;
		}
		duration = watchfor(WLAN_FC_TYPE_CTRL, WLAN_FC_SUBTYPE_ACK,
				bssidmac, NULL, NULL, 0, usectimeout);
		if (duration > 0) {
			print_response(targetmac, i+1, h->len, duration);
		} else {
			print_noresponse(targetmac, i+1, usectimeout);
		}

		sleep(1);
					
	}

	return;
}

/* 
 * Send a NULL data frame to the AP target with a valid BSSID, valid source
 * and a destination multicast address.  Watch for the multicast data
 * frame response with FromDS set that follows.
 */
void l2ping_test_nulldatamcast(tx80211_t *in_tx, int npacks, 
		uint8_t *bssid, uint8_t *source, uint32_t usectimeout)
{
	int i, duration;
	struct lcpa_metapack *metapack;
	tx80211_packet_t txpack;
	uint8_t mcastdest[6];

	metapack = lcpa_init();
	tx80211_initpacket(&txpack);

	srand(time(NULL));
	lcpf_randmac(mcastdest, 1);
	mcastdest[0] = 0xff; /* multicast bit set */

	lcpf_80211headers(metapack, 
			WLAN_FC_TYPE_DATA,
			WLAN_FC_SUBTYPE_DATANULL,
			0x01, /* fcflags, ToDS */
			0x00, /* duration */
			bssid, /* target */
			source,
			mcastdest,
			NULL, /* addr4 */
			0, /* Fragment number */
			0); /* Sequence number */

	lcpa_freeze(metapack, &txpack);
	lcpa_free(metapack);

	for(i=0; i < npacks; i++) {
		if (tx80211_txpacket(in_tx, &txpack) < 0) {
			fprintf(stderr, "Unable to inject packet: %s\n",
					tx80211_geterrstr(in_tx));
			return;
		}
		duration = watchfor(WLAN_FC_TYPE_DATA, WLAN_FC_SUBTYPE_DATANULL,
				mcastdest, bssid, source, 0, usectimeout);
		if (duration > 0) {
			print_response(bssid, i+1, h->len, duration);
		} else {
			print_noresponse(bssid, i+1, usectimeout);
		}

		sleep(1);
					
	}

	return;
}

/* 
 * Send a NULL data frame to the target with a valid BSSID, watch for the
 * ACK that follows.
 */
void l2ping_test_datavalidbssid(tx80211_t *in_tx, int npacks, 
		uint8_t *targetmac, uint8_t *bssid, uint32_t usectimeout)
{
	int i, duration;
	struct lcpa_metapack *metapack;
	tx80211_packet_t txpack;
	uint8_t sourcemac[6];

	metapack = lcpa_init();
	tx80211_initpacket(&txpack);

	srand(time(NULL));
	lcpf_randmac(sourcemac, 1);

	lcpf_80211headers(metapack, 
			WLAN_FC_TYPE_DATA,
			WLAN_FC_SUBTYPE_DATANULL,
			0x02, /* fcflags, FromDS */
			0x00, /* duration */
			targetmac,
			bssid,
			sourcemac,
			NULL, /* addr4 */
			0, /* Fragment number */
			0); /* Sequence number */

	lcpa_freeze(metapack, &txpack);
	lcpa_free(metapack);

	for(i=0; i < npacks; i++) {
		if (tx80211_txpacket(in_tx, &txpack) < 0) {
			fprintf(stderr, "Unable to inject packet: %s\n",
					tx80211_geterrstr(in_tx));
			return;
		}
		duration = watchfor(WLAN_FC_TYPE_CTRL, WLAN_FC_SUBTYPE_ACK,
				bssid, NULL, NULL, 0, usectimeout);
		if (duration > 0) {
			print_response(targetmac, i+1, h->len, duration);
		} else {
			print_noresponse(targetmac, i+1, usectimeout);
		}

		sleep(1);
					
	}

	return;
}

/* Send an RTS frame to the target station, watch for CTS response */
void l2ping_test_rtscts(tx80211_t *in_tx, int npacks, uint8_t *targetmac,
		uint32_t usectimeout)
{
	int i, duration;
	struct lcpa_metapack *metapack;
	tx80211_packet_t txpack;
	uint8_t transmittermac[6];

	metapack = lcpa_init();
	tx80211_initpacket(&txpack);

	srand(time(NULL));
	lcpf_randmac(transmittermac, 1);

	lcpf_rts(metapack, 
			targetmac,
			transmittermac,
			0x00, /* fcflags */
			0x00); /* duration */

	lcpa_freeze(metapack, &txpack);
	lcpa_free(metapack);

	//lamont_hdump(txpack.packet, txpack.plen);

	for(i=0; i < npacks; i++) {
		if (tx80211_txpacket(in_tx, &txpack) < 0) {
			fprintf(stderr, "Unable to inject packet: %s\n",
					tx80211_geterrstr(in_tx));
			return;
		}
		duration = watchfor(WLAN_FC_TYPE_CTRL, WLAN_FC_SUBTYPE_CTS,
				transmittermac, NULL, NULL, 0, usectimeout);
		if (duration > 0) {
			print_response(targetmac, i+1, h->len, duration);
		} else {
			print_noresponse(targetmac, i+1, usectimeout);
		}
		sleep(1);
					
	}

	return;
}

/* 
 * Send a NULL data frame to the AP target with a valid BSSID, invalid source
 * and a destination broadcast address.  Watch for the deauth
 * frame response from the AP.
 */
void l2ping_test_nulldatainvalidsrc(tx80211_t *in_tx, int npacks, 
		uint8_t *targetmac, uint32_t usectimeout)
{
	int i, duration;
	struct lcpa_metapack *metapack;
	tx80211_packet_t txpack;
	uint8_t invalidsource[6];
	uint8_t broadcastdest[] = "\xff\xff\xff\xff\xff\xff";

	metapack = lcpa_init();
	tx80211_initpacket(&txpack);

	srand(time(NULL));
	lcpf_randmac(invalidsource, 1);

	lcpf_80211headers(metapack, 
			WLAN_FC_TYPE_DATA,
			WLAN_FC_SUBTYPE_DATANULL,
			0x01, /* fcflags, ToDS */
			0x00, /* duration */
			targetmac, /* target/BSSID */
			invalidsource,
			broadcastdest,
			NULL, /* addr4 */
			0, /* Fragment number */
			0); /* Sequence number */

	lcpa_freeze(metapack, &txpack);
	lcpa_free(metapack);

	//lamont_hdump(txpack.packet, txpack.plen);

	for(i=0; i < npacks; i++) {
		if (tx80211_txpacket(in_tx, &txpack) < 0) {
			fprintf(stderr, "Unable to inject packet: %s\n",
					tx80211_geterrstr(in_tx));
			return;
		}
		duration = watchfor(WLAN_FC_TYPE_MGMT, WLAN_FC_SUBTYPE_DEAUTH,
				invalidsource, targetmac, targetmac, 0,
				usectimeout);
		if (duration > 0) {
			print_response(targetmac, i+1, h->len, duration);
		} else {
			print_noresponse(targetmac, i+1, usectimeout);
		}

		sleep(1);
					
	}

	return;
}
void print_noresponse(uint8_t *mac, int num, int timeout)
{
	printf("No response from %s : num=%d time=%d usec\n",
			printmac(mac), num, timeout);
}
void print_response(uint8_t *mac, int num, int len, int time)
{
	/* Set exitval to 0 since we got a response */
	exitval = 0;
	printf("%d bytes from %s : num=%d time=%d usec\n",
			len, printmac(mac), num, time);
}

void print_test_detail() {
	int i=0;
	while(testcases[i].testdesc != NULL) {
		printf("Test Case:\t%d\n", testcases[i].testnum);
		printf("Test Name:\t%s\n", testcases[i].testname);
		printf("Test Desc:\t%s\n", testcases[i].testdesc);
		printf("Test Reqs:\t");
		if (testcases[i].asmac) printf("source (-S) ");
		if (testcases[i].admac) printf("dest (-D) ");
		if (testcases[i].abmac) printf("BSSID (-B) ");
		if (!(testcases[i].abmac || testcases[i].admac,
				testcases[i].asmac)) {
			printf("None.");
		}
		printf("\n\n");
		i++;
	}
}


int main(int argc, char *argv[]) {
	uint8_t smac[6], dmac[6], bmac[6], tmac[6];
	int asmac = 0, admac = 0, abmac = 0, atmac = 0, atestcase = 0, i;
	int optmissing = 0, pcaptype=0;

	char *interface = NULL;
	char *driver = NULL;
	int channel = 0;

	/* Default number of packets to send, override with -n */
	int npacks = 4;

	struct testcase *testc = NULL;
	int txdrv = INJ_NODRIVER;
	uint32_t usectimeout=10000; /* Default 10000 usec */

	int c = 0;


	while ((c = getopt(argc, argv, "i:t:c:d:S:B:D:n:h?C:T:V")) != EOF) {
		switch (c) {
			case 'V':
				print_test_detail();
				return 0;
				break;
			case 'C':
				if (sscanf(optarg, "%d", &atestcase) != 1) {
					fprintf(stderr, "%s: Illegal test case,"
							" expected number\n",
							argv[0]);
					usage();
					return -1;
				}
				break;
			case 'i':
				interface = strdup(optarg);
				break;
			case 't':
				if (sscanf(optarg, "%d", &usectimeout) != 1) {
					fprintf(stderr, "%s: Illegal usec time,"
							" expected number\n",
							argv[0]);
					usage();
					return -1;
				}
				break;
			case 'c':
				if (sscanf(optarg, "%d", &channel) != 1) {
					fprintf(stderr, "%s: Illegal channel, "
							"expected number\n",
							argv[0]);
					usage();
					return -1;
				}
				break;
			case 'd':
				txdrv = tx80211_resolvecard(optarg);
				break;
			case 'T':
				if (string2mac(optarg, tmac) < 0) {
					fprintf(stderr, "%s: Illegal target "
							"mac, expected "
							"aa:bb:cc:dd:ee:ff or "
							"aabbccddeeff\n",
							argv[0]);
					usage();
					return -1;
				}
				atmac = 1;
				break;
			case 'S':
				if (string2mac(optarg, smac) < 0) {
					fprintf(stderr, "%s: Illegal sourcemac,"
							" expected "
							"aa:bb:cc:dd:ee:ff or "
							"aabbccddeeff\n",
							argv[0]);
					usage();
					return -1;
				}
				asmac = 1;
				break;
			case 'D':
				if (string2mac(optarg, dmac) < 0) {
					fprintf(stderr, "%s: Illegal destmac, "
							"expected "
							"aa:bb:cc:dd:ee:ff or "
							"aabbccddeeff\n", 
							argv[0]);
					usage();
					return -1;
				}
				admac = 1;
				break;
			case 'B':
				if (string2mac(optarg, bmac) < 0) {
					fprintf(stderr, "%s: Illegal bssidmac, "
							"expected "
							"aa:bb:cc:dd:ee:ff or "
							"aabbccddeeff\n", 
							argv[0]);
					usage();
					return -1;
				}
				abmac = 1;
				break;
			case 'n':
				if (sscanf(optarg, "%d", &npacks) != 1) {
					fprintf(stderr, "%s: Illegal number of "
							" packets\n", argv[0]);
					usage();
					return -1;
				}
				break;
			case '?':
			case 'h':
			default:
				usage();
				return -1;
				break;
		}
	}

	if (interface != NULL && txdrv == INJ_NODRIVER) {
		fprintf(stderr, "%s: Attempting to detect driver type for "
				"interface '%s'\n", argv[0], interface);
		if ((txdrv = tx80211_resolveinterface(interface)) == INJ_NODRIVER) {
			fprintf(stderr, "%s: Unable to autodetect a driver for '%s', "
					"specify one using -d [driver name]\n", argv[0], 
					interface);
			usage();
			return -1;
		}
		driver = tx80211_getdrivername(txdrv);
		fprintf(stderr, "%s: Found driver '%s' for interface '%s'\n",
				argv[0], driver, interface);
	}

	if (interface == NULL || txdrv == INJ_NODRIVER || 
			atmac == 0 || atestcase == 0) {
		usage();
		return -1;
	}

	/* See if this is a valid test case */
	i=0;
	testc = NULL;
	while (testcases[i].testdesc != NULL) {
		if (testcases[i].testnum == atestcase) {
			testc = &testcases[i];
			break;
		}
		i++;
	}

	if (testc == NULL) {
		fprintf(stderr, "Unsupported test case selected (%d)\n", 
				atestcase);
		usage();
		return -1;
	}

	/* 
	 * Examine the addresses supplied for the specified test case,
	 * error if we don't have the right addresses
	 */

	if (testc->abmac && testc->abmac != abmac) {
		fprintf(stderr, "Must specify the BSSID address for this test "
				"case.\n");
		optmissing = 1;
	}
	if (testc->asmac && testc->asmac != asmac) {
		fprintf(stderr, "Must specify the source address for this test "
				"case.\n");
		optmissing = 1;
	}

	if (testc->admac && testc->admac != admac) {
		fprintf(stderr, "Must specify the destination address for "
				"this test case.\n");
		optmissing = 1;
	}

	if (optmissing == 1) {
		usage();
		return -1;
	}

	/* Setup the signal handler */
	signal(SIGINT, sigexit);
	signal(SIGTERM, sigexit);
	signal(SIGQUIT, sigexit);

	if (tx80211_init(&tx, interface, txdrv) < 0) {
		fprintf(stderr, "Error initializing interface: %s\n",
				tx80211_geterrstr(&tx));
		return 1;
	}

	if (tx80211_setfunctionalmode(&tx, TX80211_FUNCMODE_INJMON) < 0) {
		fprintf(stderr, "Error setting functional mode: %s\n",
				tx80211_geterrstr(&tx));
		tx80211_close(&tx);
		return 1;
	}
	
	if (channel != 0) {
		if (tx80211_setchannel(&tx, channel) < 0) {
			fprintf(stderr, "Error setting channel: %s\n",
				tx80211_geterrstr(&tx));
			tx80211_close(&tx);
			return 1;
		}
	}

	if (tx80211_open(&tx) < 0) {
		fprintf(stderr, "Unable to open interface: %s\n",
				tx80211_geterrstr(&tx));
		tx80211_close(&tx);
		return 1;
	}

	/* Assume for now it's a libpcap file */
	p = pcap_open_live(interface, SNAPLEN, PROMISC, TIMEOUT, pcaperrbuf);
	if (p == NULL) {
		perror("Unable to open capture file");
		return (-1);
	}

	/* Determine link type */
	pcaptype = pcap_datalink(p);

	/* Determine offset to EAP frame based on link type */
	switch (pcaptype) {
		case DLT_PRISM_HEADER:
			offset = 144;
			break;
		case DLT_IEEE802_11:
			offset = 0;
			break;
		case DLT_IEEE802_11_RADIO:
			offset = radiotap_offset(p, h);
			if (offset < 0) {
				fprintf(stderr, "Error determining size of the"
						" radiotap header.\n");
				tx80211_close(&tx);
				pcap_close(p);
				return -1;
			}
			break;
		default:
			fprintf(stderr, "Unsupported link type: %d\n", 
					pcaptype);
			break;
	}


	printf("L2PING %s using test case %d (%s)\n", printmac(tmac),
			atestcase, testc->testname);
	switch(atestcase) {
		case L2PING_TEST_NULLDATAMCAST:
		l2ping_test_nulldatamcast(&tx, npacks, tmac, smac, usectimeout);
		break;

		case L2PING_TEST_RTSCTS:
		l2ping_test_rtscts(&tx, npacks, tmac, usectimeout);
		break;

		case L2PING_TEST_DATAINVALIDBSSID:
		l2ping_test_datainvalidbssid(&tx, npacks, tmac, usectimeout);
		break;

		case L2PING_TEST_DATAINVALIDBSSIDDEAUTH:
		l2ping_test_datainvalidbssiddeauth(&tx, npacks, tmac,
				usectimeout);
		break;

		case L2PING_TEST_DATAVALIDBSSID:
		l2ping_test_datavalidbssid(&tx, npacks, tmac, bmac,
				usectimeout);
		break;

		case L2PING_TEST_NULLDATAINVALIDSRC:
		l2ping_test_nulldatainvalidsrc(&tx, npacks, tmac, usectimeout);
		break;

		default:
		fprintf(stderr, "Unsupported test case: %d\n", atestcase);
		return -1;
	}

	return exitval;

}
