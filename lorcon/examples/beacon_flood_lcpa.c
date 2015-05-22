/*
	beacon_flood_lcpa.c 
	by brad.antoniewicz@foundstone.com	

	simple IEEE 802.11 beacon flooder using LORCON2's 
	packet assembly functionality

*/

#include <stdio.h>
#include <getopt.h>
#include <string.h>

#include <sys/time.h> // Needed for timestamp

#include <lorcon2/lorcon.h> // For LORCON 
#include <lorcon2/lorcon_packasm.h> // For metapack packet assembly

void usage(char *argv[]) {
	printf("\t-s <SSID>\tSSID to flood\n");
	printf("\t-i <int> \tInterface\n");
	printf("\t-c <channel>\tChannel\n");
	printf("\nExample:\n");
	printf("\t%s -s brad -i wlan0 -c 1\n\n",argv[0]);
}
int main(int argc, char *argv[]) {

	char *interface = NULL, *ssid = NULL;
	int c;
	uint8_t channel;
	unsigned int count=0;

	lorcon_driver_t *drvlist, *driver; // Needed to set up interface/context
	lorcon_t *context; // LORCON context

	lcpa_metapack_t *metapack; // metapack for LORCON packet assembly 
	lorcon_packet_t *txpack; // The raw packet to be sent

	/* 
		These are needed for the actual beacon frame
	*/
		
	// BSSID and source MAC address
	uint8_t *mac = "\x00\xDE\xAD\xBE\xEF\x00";

	// Timestamp
        struct timeval time; 
        uint64_t timestamp; 
	
	// Supported Rates  
	uint8_t rates[] = "\x8c\x12\x98\x24\xb0\x48\x60\x6c"; // 6,9,12,18,24,36,48,54

	// Beacon Interval
	int interval = 100;

	// Capabilities
	int capabilities = 0x0421;


	printf ("%s - Simple 802.11 Beacon Flooder\n", argv[0]);
	printf ("-----------------------------------------------------\n\n");

	/* 
		This handles all of the command line arguments
	*/
	
	while ((c = getopt(argc, argv, "i:s:hc:")) != EOF) {
		switch (c) {
			case 'i': 
				interface = strdup(optarg);
				break;
			case 's': 
				if ( strlen(strdup(optarg)) < 255 ) {
					ssid = strdup(optarg);
				} else {
					printf("ERROR: SSID Length too long! Should not exceed 255 characters\n");
					return -1;
				}
				break;
			case 'c':
				channel = atoi(optarg);
				break;
			case 'h':
				usage(argv);
				break;
			default:
				usage(argv);
				break;
			}
	}

	if ( interface == NULL || ssid == NULL ) { 
		printf ("ERROR: Interface, channel, or SSID not set (see -h for more info)\n");
		return -1;
	}

	printf("[+] Using interface %s\n",interface);
	
	/*	
	 	The following is all of the standard interface, driver, and context setup
	*/

	// Automatically determine the driver of the interface
	
	if ( (driver = lorcon_auto_driver(interface)) == NULL) {
		printf("[!] Could not determine the driver for %s\n",interface);
		return -1;
	} else {
		printf("[+]\t Driver: %s\n",driver->name);
	}

	// Create LORCON context
        if ((context = lorcon_create(interface, driver)) == NULL) {
                printf("[!]\t Failed to create context");
               	return -1; 
        }

	// Create Monitor Mode Interface
	if (lorcon_open_injmon(context) < 0) {
		printf("[!]\t Could not create Monitor Mode interface!\n");
		return -1;
	} else {
		printf("[+]\t Monitor Mode VAP: %s\n",lorcon_get_vap(context));
		lorcon_free_driver_list(driver);
	}

	// Set the channel we'll be injecting on
	lorcon_set_channel(context, channel);
	printf("[+]\t Using channel: %d\n\n",channel);

	/* 
		The following is the packet creation and sending code
	*/

	// Keep sending frames until interrupted
	while(1) {

		// Create timestamp
		gettimeofday(&time, NULL);
		timestamp = time.tv_sec * 1000000 + time.tv_usec;

		// Initialize the LORCON metapack	
		metapack = lcpa_init();
		
		// Create a Beacon frame from 00:DE:AD:BE:EF:00
		lcpf_beacon(metapack, mac, mac, 0x00, 0x00, 0x00, 0x00, timestamp, interval, capabilities);

		// Append IE Tag 0 for SSID
		lcpf_add_ie(metapack, 0, strlen(ssid),ssid);

		// Most of the following IE tags are not needed, but added here as examples

		// Append IE Tag 1 for rates
               	lcpf_add_ie(metapack, 1, sizeof(rates)-1, rates);

		// Append IE Tag 3 for Channel 
		lcpf_add_ie(metapack, 3, 1, &channel);

		// Append IE Tags 42/47 for ERP Info 
		lcpf_add_ie(metapack, 42, 1, "\x05");
		lcpf_add_ie(metapack, 47, 1, "\x05");
	
		// Convert the LORCON metapack to a LORCON packet for sending
		txpack = (lorcon_packet_t *) lorcon_packet_from_lcpa(context, metapack);
		
		// Send and exit if error
		if ( lorcon_inject(context,txpack) < 0 ) 
			return -1;

               // Wait interval before next beacon
                usleep(interval * 1000);

		// Print nice and pretty
		printf("\033[K\r");
		printf("[+] Sent %d frames, Hit CTRL + C to stop...", count);
		fflush(stdout);
		count++;

		// Free the metapack
		lcpa_free(metapack);
	}

	/* 
	 	The following is all of the standard cleanup stuff
	*/

	// Close the interface
	lorcon_close(context);

	// Free the LORCON Context
	lorcon_free(context);	
	
	return 0;
}

