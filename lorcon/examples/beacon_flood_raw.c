/*
	beacon_flood_raw.c 
	by brad.antoniewicz@foundstone.com	

	simple IEEE 802.11 beacon flooder using LORCON2's 
	raw sending capabilities

*/

#include <stdio.h>
#include <getopt.h>

#include <lorcon2/lorcon.h> // For LORCON 

void usage(char *argv[]) {
	printf("\t-i <int> \tInterface\n");
	printf("\t-c <channel>\tChannel\n");
	printf("\nExample:\n");
	printf("\t%s -i wlan0 -c 1\n\n",argv[0]);
}
int main(int argc, char *argv[]) {

	char *interface = NULL, *ssid = NULL;
	int c, channel;
	unsigned int count=0;

	lorcon_driver_t *drvlist, *driver; // Needed to set up interface/context
	lorcon_t *context; // LORCON context

	// Beacon Interval
        int interval = 100;

	// Raw packet bytes (from capture_example.c included within LORCON)
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



	printf ("%s - Simple 802.11 beacon flooder\n", argv[0]);
	printf ("-----------------------------------------------------\n\n");

	/* 
		This handles all of the command line arguments
	*/
	
	while ((c = getopt(argc, argv, "i:s:hc:")) != EOF) {
		switch (c) {
			case 'i': 
				interface = strdup(optarg);
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

	if ( interface == NULL  ) { 
		printf ("ERROR: Interface not set (see -h for more info)\n");
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

		// Send and exit if error
		if ( lorcon_send_bytes(context, sizeof(packet), packet) < 0 ) 
			return -1;

               // Wait interval before next beacon
                usleep(interval * 1000);

		// Print nice and pretty
		printf("\033[K\r");
		printf("[+] Sent %d frames, Hit CTRL + C to stop...", count);
		fflush(stdout);
		count++;

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

