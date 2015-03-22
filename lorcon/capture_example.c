#include <stdint.h>
#include <lorcon.h>
#include <getopt.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

void apitest_packet_hdlr(lorcon_t *context, lorcon_packet_t *packet, 
						 u_char *user) {
	u_char *dot3;
	int len;

	printf("apitest - %s drv %s got packet len %d\n",
		   lorcon_get_capiface(context), lorcon_get_driver_name(context),
		   packet->length);

	if (packet->length_header != 0) {
		printf("          decoded length %d\n", packet->length_header);
	}

	if (packet->length_data != 0) {
		printf("          decoded data length %d\n", packet->length_data);
	}

	len = lorcon_packet_to_dot3(packet, &dot3);

	printf("          dot3 length %d\n", len);

	free(dot3);

	lorcon_packet_free(packet);
}

int main(int argc, char *argv[]) {
	lorcon_driver_t *drvlist, *dri;
	char *interface = NULL, *driver = NULL;
	int c;
	lorcon_t *ctx;

	while ((c = getopt(argc, argv, "i:h:d:")) != EOF) {
		switch (c) {
			case 'h':
				dri = drvlist = lorcon_list_drivers();

				printf("Supported LORCON drivers:\n");
				while (dri) {
					printf("%-10.10s %s\n", dri->name, dri->details);
					dri = dri->next;
				}

				lorcon_free_driver_list(drvlist);
				break;

			case 'i':
				interface = strdup(optarg);
				break;

			case 'd':
				driver = strdup(optarg);
				break;

		}
	}

	if (interface == NULL) {
		printf("no interface\n");
		exit(1);
	}

	if (driver != NULL) {
		dri = lorcon_find_driver(driver);

		if (dri == NULL) {
			printf("couldn't find driver %s for %s\n", driver, interface);
			exit(1);
		}
	} else {
		dri = lorcon_auto_driver(interface);

		if (dri == NULL) {
			printf("Couldn't detect driver for %s\n", interface);
			exit(1);
		}

		printf("Detected driver %s for %s\n", dri->name, interface);
	}

	if ((ctx = lorcon_create(interface, dri)) == NULL) {
		printf("Failed to create context for %s %s\n", interface, dri->name);
		exit(1);
	}

	if (lorcon_open_injmon(ctx) < 0) {
		printf("Failed to open %s %s in injmon: %s\n", lorcon_get_capiface(ctx), 
			   dri->name, lorcon_get_error(ctx));
		exit(1);
	}

	lorcon_free_driver_list(dri);

	lorcon_loop(ctx, 0, apitest_packet_hdlr, NULL);

	lorcon_free(ctx);
}
