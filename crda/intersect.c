#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h> /* ntohl */
#include <string.h>

#include "reglib.h"

int main(int argc, char **argv)
{
	const struct reglib_regdb_ctx *ctx;
	const struct ieee80211_regdomain *rd;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <regulatory-binary-file>\n", argv[0]);
		return -EINVAL;
	}

	ctx = reglib_malloc_regdb_ctx(argv[1]);
	if (!ctx) {
		fprintf(stderr, "Invalid or empty regulatory file, note: "
			"a binary regulatory file should be used.\n");
		return -EINVAL;
	}

	rd = reglib_intersect_regdb(ctx);
	if (!rd) {
		fprintf(stderr, "Intersection not possible\n");
		reglib_free_regdb_ctx(ctx);
		return -ENOENT;
	}

	reglib_print_regdom(rd);

	free((struct ieee80211_regdomain *) rd);

	reglib_free_regdb_ctx(ctx);
	return 0;
}
