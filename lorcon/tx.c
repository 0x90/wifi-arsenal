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

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

#include <lorcon2/lorcon.h>
#include <lorcon2/lorcon_packet.h>

void usage()
{
	lorcon_driver_t *drvlist, *dri;

	printf("tx (c) 2005 Joshua Wright and dragorn\n"
	       "Usage : tx [options]\n"
	       "  -i <interface>       specify the interface name\n"
	       "  -n <number>          number of packets to send\n"
	       "  -c <channel>         channel to transmit packets on.\n"
	       "  -s <sleep>           sleep time in usec between packets.\n"
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

	// WEP encrypted packet 
	unsigned char packet[108] = {
		0x08, 0x41, 0x0a, 0x00, 0x00, 0x03, 0x1b, 0xc2,
		0x45, 0x33, 0x00, 0x1b, 0x4b, 0x29, 0x61, 0xb1,
		0xff, 0x10, 0x07, 0x00, 0x12, 0x53, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3e, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00,
		0x00, 0x00, 0x75, 0x41, 0x37, 0x5a, 0x4b, 0xbc,
		0x55, 0x69, 0x07, 0x58, 0x4c, 0x03, 0xf4, 0xa7,
		0x69, 0xbc, 0xdf, 0x46, 0x27, 0x4d, 0xd0, 0xb6,
		0xcc, 0x7c, 0x8b, 0x8b, 0x46, 0x06, 0x30, 0x72,
		0x67, 0x72, 0x5d, 0x49, 0xe6, 0x0a, 0xfb, 0x74,
		0xef, 0x59, 0x1c, 0x24, 0x0b, 0x07, 0x60, 0xee,
		0x1b, 0x87, 0xf1, 0x6f, 0x3a, 0x88, 0x54, 0x25,
		0x5a, 0x90, 0xb4, 0x68
	};

//ACK frame
    /*
    unsigned char packet[10] = {
        0xd4, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x66, 0xe3,
        0x76, 0x3b};
    */

    // Beacon frame
    /*
    unsigned char packet[115] = {
        0x80, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dur ffff
        0xff, 0xff, 0x00, 0x0f, 0x66, 0xe3, 0xe4, 0x03, 
        0x00, 0x0f, 0x66, 0xe3, 0xe4, 0x03, 0x00, 0x00, // 0x0000 - seq no.
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // BSS timestamp 
        0x64, 0x00, 0x11, 0x00, 0x00, 0x0f, 0x73, 0x6f, 
        0x6d, 0x65, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x63, 
        0x6c, 0x65, 0x76, 0x65, 0x72, 0x01, 0x08, 0x82, 
        0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c, 0x03, 
        0x01, 0x01, 0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 
        0x2a, 0x01, 0x05, 0x2f, 0x01, 0x05, 0x32, 0x04, 
        0x0c, 0x12, 0x18, 0x60, 0xdd, 0x05, 0x00, 0x10, 
        0x18, 0x01, 0x01, 0xdd, 0x16, 0x00, 0x50, 0xf2, 
        0x01, 0x01, 0x00, 0x00, 0x50, 0xf2, 0x02, 0x01, 
        0x00, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x00, 0x00, 
        0x50, 0xf2, 0x02};
    */

    // small fragmented WEP packet
    /*
    unsigned char packet[] = {
        0x08, 0x45, 0xd5, 0x00, 0x00, 0x0f, 0x66, 0xe3, 
        0x76, 0x3b, 0x00, 0x02, 0x6f, 0x35, 0x73, 0x0f, 
        0x00, 0x0f, 0x66, 0xe3, 0xe4, 0x01, 0xa3, 0x4c, 
        0xa8, 0x34, 0x00, 0x00, 0xc4, 0x42, 0x86, 0x90, 
        0x4f, 0x76, 0xa5, 0x4d};
    */

/*
    char packet[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
*/

	lorcon_driver_t *drvlist, *dri;
	char *driver = NULL, *interface = NULL;
	int cnt = 1, delay = 0, ret = 0, c = 0, channel = 0, txcnt = 0;
	lorcon_t *ctx;

	while ((c = getopt(argc, argv, "n:i:d:c:s:")) != EOF) {
		switch (c) {
		case 's':
			if (sscanf(optarg, "%d", &delay) != 1) {
				fprintf(stderr, "%s: Illegal delay on cmd line\n", argv[0]);
				usage();
				return -1;
			}
			break;
		case 'n':
			if (sscanf(optarg, "%d", &cnt) != 1) {
				fprintf(stderr, "%s: Illegal count on cmd line.\n", argv[0]);
				usage();
				return -1;
			}
			break;
		case 'i':
			interface = strdup(optarg);
			break;
		case 'd':
			driver = strdup(optarg);
			break;
		case 'c':
			if (sscanf(optarg, "%d", &channel) != 1) {
				fprintf(stderr, "%s: Illegal channel on cmd line.\n", argv[0]);
				usage();
				return -1;
			}
			break;
		default:
			break;
		}
	}

	if (interface == NULL) {
		fprintf(stderr, "Must specify an interface\n");
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

	/* Send the packets */
	for (; cnt > 0; cnt--) {
		ret = lorcon_send_bytes(ctx, sizeof(packet), packet);
		if (ret < 0) {
			fprintf(stderr, "Failed to transmit packet on %s %s: %s\n",
					lorcon_get_capiface(ctx), dri->name,
					lorcon_get_error(ctx));
			return -1;
		}

		txcnt++;
		if (delay > 0) {
			usleep(delay);
		}
	}

	printf("%d packets transmitted on %s %s channel %d.\n", 
		   txcnt, lorcon_get_capiface(ctx), dri->name,
		   lorcon_get_channel(ctx));

	lorcon_free(ctx);
	return 0;
}
