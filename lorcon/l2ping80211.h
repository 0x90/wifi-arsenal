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

/* Prototypes */
void usage();
void to_upper (char *s);
int radiotap_offset(pcap_t *p, struct pcap_pkthdr *h);
void lamont_hdump(unsigned char *bp, unsigned int length);
int string2mac (char *string, uint8_t *mac_buf);
char *printmac(unsigned char *mac);
int watchfor(int type, int subtype, uint8_t *addr1,
		uint8_t *addr2, uint8_t *addr3, int flags, int timeout);
void l2ping_test_datainvalidbssiddeauth(tx80211_t *in_tx, int npacks, 
		uint8_t *targetmac, uint32_t usectimeout);
void print_noresponse(uint8_t *mac, int num, int timeout);
void print_response(uint8_t *mac, int num, int len, int time);
void l2ping_test_datainvalidbssid(tx80211_t *in_tx, int npacks, 
		uint8_t *targetmac, uint32_t usectimeout);
void l2ping_test_rtscts(tx80211_t *in_tx, int npacks, uint8_t *targetmac,
		uint32_t usectimeout);

#define SNAPLEN 2312
#define PROMISC 1
#define TIMEOUT 500 /* for pcap */
#define TRUE 1
#define FALSE 0

enum l2ping_test_type {
	L2PING_TEST_NULLDATAMCAST=1,
	L2PING_TEST_RTSCTS,
	L2PING_TEST_DATAINVALIDBSSID,
	L2PING_TEST_DATAINVALIDBSSIDDEAUTH,
	L2PING_TEST_DATAVALIDBSSID,
	L2PING_TEST_NULLDATAINVALIDSRC,
};

struct testcase {
	uint32_t testnum;
	char *testname;
	char *testdesc;
	/* Indicators for the MAC addresses the user must specify. */
	int asmac;
	int admac;
	int abmac;
};

struct testcase testcases[] = {
	{ L2PING_TEST_NULLDATAMCAST, 
	"NULL Data Multicast to AP",
	"Multicast NULL data frames sent ToDS from an authorized station "
	"address.  AP will send frame to WLAN stations with FromDS set.  Must "
	"specify a valid station MAC address and BSSID.  Destination address "
	"is broadcast.",
	TRUE,
	FALSE,
	FALSE /* We use the target address as the BSSID here */
	},

	{ L2PING_TEST_RTSCTS,
	"RTS/CTS to STA",
	"Send an RTS frame to a specified station address using an invalid "
	"source (transmitter) MAC address.  Station will send a CTS in "
	"response to the transmitter address.",
	FALSE,
	FALSE, /* We use the target address as the dest here */
	FALSE
	},

	{ L2PING_TEST_DATAINVALIDBSSID,
	"NULL data frame to STA with invalid BSSID",
	"Send a NULL data frame to a specified station address using an "
	"invalid source and an invalid BSSID address, causing the station "
	"to ACK the frame.",
	FALSE,
	FALSE, /* We use the target address as the dest here */
	FALSE
	},

	{ L2PING_TEST_DATAINVALIDBSSIDDEAUTH,
	"NULL data frame to STA with invalid BSSID, deauth resp",
	"Send a NULL data frame to a specified station address using an "
	"invalid source and an invalid BSSID address, causing the station "
	"to ACK the frame.  Many drivers will also spaz out deauth messages "
	"following this test since they don't like receiving data frames from "
	"a BSSID other than the one they are associated to. Measure response "
	"on the deauth message since this comes from the driver itself, not "
	"the card hardware (unlike the ACK which comes from the hardware).",
	FALSE,
	FALSE, /* We use the target address as the dest here */
	FALSE
	},

	{ L2PING_TEST_DATAVALIDBSSID,
	"NULL data frame to STA with valid BSSID",
	"Send a NULL data frame to a specified station address using an "
	"invalid source and a valid BSSID address, causing the station "
	"to ACK the frame.  This test will be more reliable than the "
	"DATAINVALIDBSSID test, since the frame comes from a legitimate "
	"BSSID, but we may observe \"false-positive\" responses, since an ACK "
	"frame that is observed as the response can come from a different "
	"data frame.  Use a small timeout with this test for better accuracy.",
	FALSE,
	FALSE, /* We use the target address as the dest here */
	TRUE
	},
	
	{ L2PING_TEST_NULLDATAINVALIDSRC,
	"NULL data frame to AP with invalid source",
	"Send a NULL data frame to an AP with an invalid source address, "
	"prompting the AP to send a deauth frame in response.  Uses the "
	"broadcast destination address.",
	FALSE,
	FALSE, 
	FALSE, /* We use the target address as the bssid here */
	},

	{ 0, NULL, NULL, 0, 0, 0 },
};
