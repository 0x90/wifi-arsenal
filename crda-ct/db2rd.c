#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h> /* ntohl */
#include <string.h>

#include "nl80211.h"
#include "reglib.h"

int main(int argc, char **argv)
{
	struct ieee80211_regdomain *rd = NULL;
	FILE *fp;

	if (argc != 1) {
		fprintf(stderr, "Usage: cat db.txt | %s\n", argv[0]);
		return -EINVAL;
	}

	fp = reglib_create_parse_stream(stdin);
	if (!fp)
		return -EINVAL;

	reglib_for_each_country_stream(fp, rd) {
		reglib_print_regdom(rd);
		free(rd);
	}

	fclose(fp);

	return 0;
}
