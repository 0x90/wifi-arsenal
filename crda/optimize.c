#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h> /* ntohl */
#include <string.h>

#include "nl80211.h"
#include "reglib.h"

int main(int argc, char **argv)
{
	struct ieee80211_regdomain *rd = NULL, *rd_opt = NULL;
	FILE *fp;

	if (argc != 1) {
		fprintf(stderr, "Usage: cat db.txt | %s\n", argv[0]);
		return -EINVAL;
	}

	fp = reglib_create_parse_stream(stdin);
	if (!fp)
		return -EINVAL;

	reglib_for_each_country_stream(fp, rd) {
		rd_opt = reglib_optimize_regdom(rd);
		if (!rd_opt){
			fprintf(stderr, "Unable to optimize %c%c\n",
				rd->alpha2[0],
				rd->alpha2[1]);
			free(rd);
			continue;
		}
		reglib_print_regdom(rd_opt);
		free(rd);
		free(rd_opt);
	}

	fclose(fp);
	return 0;
}
