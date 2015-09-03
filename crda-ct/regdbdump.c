#include <stdio.h>
#include <errno.h>
#include "reglib.h"

static void reglib_regdbdump(const struct reglib_regdb_ctx *ctx)
{
	const struct ieee80211_regdomain *rd = NULL;
	unsigned int idx = 0;

	reglib_for_each_country(rd, idx, ctx) {
		if (!reglib_is_valid_rd(rd)) {
			fprintf(stderr, "country %.2s: invalid\n", rd->alpha2);
			free((struct ieee80211_regdomain *) rd);
			continue;
		}
		reglib_print_regdom(rd);
		free((struct ieee80211_regdomain *) rd);
	}
}

int main(int argc, char **argv)
{
	const struct reglib_regdb_ctx *ctx;

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

	reglib_regdbdump(ctx);
	reglib_free_regdb_ctx(ctx);

	return 0;
}
