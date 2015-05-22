/*
    This file is part of lorcon

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

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include <net/if_arp.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>

// Because some kernels include ethtool which breaks horribly...
// // The stock ones don't but others seem to
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;
#include <linux/types.h>
#include <linux/if.h>
#include <linux/wireless.h>

#include <errno.h>
#include <string.h>

#include <lorcon2/lorcon.h>
#include <lorcon2/lorcon_packet.h>

#include <pcap.h>

#define MAX_PACKET_LEN 8192

void usage()
{
	lorcon_driver_t *drvlist, *dri;

	printf("txtun (c) 2005 Joshua Wright and dragorn\n"
	       "Usage : txtun [options]\n"
	       "  -i <interface>       specify the interface name\n"
		   "  -t <interface>       specify the tuntap interface name\n"
	       "  -c <channel>         channel to transmit packets on.\n"
	       "  -d <drivername>      string indicating driver used on interface\n");

	dri = drvlist = lorcon_list_drivers();

	printf("Supported LORCON drivers:\n");
	while (dri) {
		printf("%-10.10s %s\n", dri->name, dri->details);
		dri = dri->next;
	}

	lorcon_free_driver_list(drvlist);
}

int main(int argc, char *argv[])
{
	lorcon_driver_t *drvlist, *dri;
	char *driver = NULL, *interface = NULL, *tface = NULL;
	lorcon_t *ctx;
	lorcon_packet_t *lpacket;
	struct ifreq ifr;

	int ret = 0, channel = 0, c = 0, ttfd = -1, intfd = -1, flags = 0;

	char errstr[PCAP_ERRBUF_SIZE + 1];

	pcap_t *pd;

	const u_char *pcap_pkt;
	struct pcap_pkthdr pcap_hdr;

	while ((c = getopt(argc, argv, "i:t:d:c:")) != EOF) {
		switch (c) {
		case 'i':
			interface = strdup(optarg);
			break;
		case 't':
			tface = strdup(optarg);
			break;
		case 'd':
			driver = strdup(optarg);
			break;
		case 'c':
			if (sscanf(optarg, "%d", &channel) != 1) {
				fprintf(stderr,
					"%s: Illegal channel on cmd line",
					argv[0]);
				usage();
				return -1;
			}
			break;
		default:
			break;
		}
	}

	if (interface == NULL) {
		fprintf(stderr, "Must specify an interface name.\n");
		usage();
		return -1;
	}

	if (tface == NULL) {
		fprintf(stderr, "Must specify a tuntap interface name.\n");
		usage();
		return -1;
	}

	if (driver != NULL) {
		dri = lorcon_find_driver(driver);

		if (dri == NULL) {
			fprintf(stderr, "Couldn't find driver %s for %s\n", driver,
					interface);
			usage();
			return -1;
		}
	} else {
		dri = lorcon_auto_driver(interface);

		if (dri == NULL) {
			fprintf(stderr, "Couldn't detect driver or no supported driver "
					"for %s\n", interface);
			return -1;
		}

		printf("Detected driver %s for %s\n", dri->name, interface);
	}

	if ((ctx = lorcon_create(interface, dri)) == NULL) {
		fprintf(stderr, "Failed to create LORCON context for %s %s\n",
				interface, dri->name);
		return -1;
	}

	if (lorcon_open_injmon(ctx) < 0) {
		fprintf(stderr, "Failed to open %s %s in injmon: %s\n",
				lorcon_get_capiface(ctx), dri->name, lorcon_get_error(ctx));
		return -1;
	}

	if (channel > 0) {
		if (lorcon_set_channel(ctx, channel) < 0) {
			fprintf(stderr, "Failed to set channel %d on %s %s: %s\n",
					channel, lorcon_get_capiface(ctx), dri->name,
					lorcon_get_error(ctx));
			return -1;
		}
	}

	/* Create the tuntap device */
	if ((ttfd = open("/dev/net/tun", O_RDWR)) < 0) {
		perror("Could not open /dev/net/tun control file");
		return -1;
	}
	
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = (IFF_TAP | IFF_NO_PI);
	strncpy(ifr.ifr_name, tface, sizeof(tface) - 1);

	if (ioctl(ttfd, TUNSETIFF, (void *) &ifr) < 0) {
		perror("Unable to create tuntap interface");
		return -1;
	}

	/* bring the tuntap up */
	if ((intfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("Failed to create AF_INET socket");
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, tface, IFNAMSIZ);
	if (ioctl(intfd, SIOCGIFFLAGS, &ifr) < 0) {
		perror("Failed to get interface flags for tuntap");
		return -1;
	}

	flags = ifr.ifr_flags;
	flags |= (IFF_UP | IFF_RUNNING | IFF_PROMISC);
	ifr.ifr_flags = flags;

	if (ioctl(intfd, SIOCSIFFLAGS, &ifr) < 0) {
		perror("Failed to set interface flags for tuntap");
		return -1;
	}

	close(intfd);

	/* Open the pcap interface */
	pd = pcap_open_live(tface, MAX_PACKET_LEN, 1, 1000, errstr);
	if (pd == NULL) {
		perror("Failed to open tuntap with pcap");
		fprintf(stderr, "%s\n", errstr);
		return 1;
	}

	fprintf(stderr, "Linked %s to %s, waiting for packets...\n", tface, interface);
	
	while (1) {
		if ((pcap_pkt = pcap_next(pd, &pcap_hdr)) == NULL) {
			pcap_perror(pd, "Failed to get next packet from tuntap");
			break;
		}

		lpacket = lorcon_packet_from_pcap(ctx, &pcap_hdr, pcap_pkt);

		ret = lorcon_inject(ctx, lpacket);

		if (ret < 0) {
			fprintf(stderr, "Unable to transmit packet: %s.\n", 
					lorcon_get_error(ctx));
			break;
		}
	}

	lorcon_free(ctx);
	return 0;
}
