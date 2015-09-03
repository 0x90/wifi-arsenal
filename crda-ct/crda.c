/*
 * Central Regulatory Domain Agent for Linux
 *
 * Userspace helper which sends regulatory domains to Linux via nl80211
 */

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include "nl80211.h"

#include "reglib.h"

#if !defined(CONFIG_LIBNL20) && !defined(CONFIG_LIBNL30) && !defined(CONFIG_LIBNL32)
/* libnl 2.0 compatibility code */
static inline struct nl_handle *nl_socket_alloc(void)
{
       return nl_handle_alloc();
}

static inline void nl_socket_free(struct nl_handle *h)
{
       nl_handle_destroy(h);
}

static inline int __genl_ctrl_alloc_cache(struct nl_handle *h, struct nl_cache **cache)
{
       struct nl_cache *tmp = genl_ctrl_alloc_cache(h);
       if (!tmp)
               return -ENOMEM;
       *cache = tmp;
       return 0;
}

#define genl_ctrl_alloc_cache __genl_ctrl_alloc_cache
#define nl_sock nl_handle
#endif /* CONFIG_LIBNL20 && CONFIG_LIBNL30 && CONFIG_LIBNL32 */

struct nl80211_state {
	struct nl_sock *nl_sock;
	struct nl_cache *nl_cache;
	struct genl_family *nl80211;
};

static int nl80211_init(struct nl80211_state *state)
{
	int err;

	state->nl_sock = nl_socket_alloc();
	if (!state->nl_sock) {
		fprintf(stderr, "Failed to allocate netlink sock.\n");
		return -ENOMEM;
	}

	if (genl_connect(state->nl_sock)) {
		fprintf(stderr, "Failed to connect to generic netlink.\n");
		err = -ENOLINK;
		goto out_sock_destroy;
	}

	if (genl_ctrl_alloc_cache(state->nl_sock, &state->nl_cache)) {
		fprintf(stderr, "Failed to allocate generic netlink cache.\n");
		err = -ENOMEM;
		goto out_sock_destroy;
	}

	state->nl80211 = genl_ctrl_search_by_name(state->nl_cache, "nl80211");
	if (!state->nl80211) {
		fprintf(stderr, "nl80211 not found.\n");
		err = -ENOENT;
		goto out_cache_free;
	}

	return 0;

 out_cache_free:
	nl_cache_free(state->nl_cache);
 out_sock_destroy:
	nl_socket_free(state->nl_sock);
	return err;
}

static void nl80211_cleanup(struct nl80211_state *state)
{
	genl_family_put(state->nl80211);
	nl_cache_free(state->nl_cache);
	nl_socket_free(state->nl_sock);
}

static int reg_handler(struct nl_msg __attribute__((unused)) *msg,
			void __attribute__((unused)) *arg)
{
	return NL_SKIP;
}

static int wait_handler(struct nl_msg __attribute__((unused)) *msg, void *arg)
{
	int *finished = arg;
	*finished = 1;
	return NL_STOP;
}

static int error_handler(struct sockaddr_nl __attribute__((unused)) *nla,
			    struct nlmsgerr *err,
			    void __attribute__((unused)) *arg)
{
	fprintf(stderr, "nl80211 error %d\n", err->error);
	exit(err->error);
}

static int put_reg_rule(const struct ieee80211_reg_rule *rule, struct nl_msg *msg)
{
	const struct ieee80211_freq_range *freq_range;
	const struct ieee80211_power_rule *power_rule;

	freq_range = &rule->freq_range;
	power_rule = &rule->power_rule;

	NLA_PUT_U32(msg, NL80211_ATTR_REG_RULE_FLAGS,		rule->flags);
	NLA_PUT_U32(msg, NL80211_ATTR_FREQ_RANGE_START,		freq_range->start_freq_khz);
	NLA_PUT_U32(msg, NL80211_ATTR_FREQ_RANGE_END,		freq_range->end_freq_khz);
	NLA_PUT_U32(msg, NL80211_ATTR_FREQ_RANGE_MAX_BW,	freq_range->max_bandwidth_khz);
	NLA_PUT_U32(msg, NL80211_ATTR_POWER_RULE_MAX_ANT_GAIN,	power_rule->max_antenna_gain);
	NLA_PUT_U32(msg, NL80211_ATTR_POWER_RULE_MAX_EIRP,	power_rule->max_eirp);

	if (rule->dfs_cac_ms)
		NLA_PUT_U32(msg, NL80211_ATTR_DFS_CAC_TIME, rule->dfs_cac_ms);

	return 0;

nla_put_failure:
	return -1;
}

int main(int argc, char **argv)
{
	int fd = -1;
	int i = 0, j, r;
	char alpha2[3];
	char *env_country;
	struct nl80211_state nlstate;
	struct nl_cb *cb = NULL;
	struct nl_msg *msg;
	int finished = 0;

	memset(alpha2, 0, 3);

	struct nlattr *nl_reg_rules;
	const struct ieee80211_regdomain *rd = NULL;

	const char *regdb_paths[] = {
		"/usr/local/lib/crda/regulatory.bin", /* Users/preloads can override */
		"/usr/lib/crda/regulatory.bin", /* General distribution package usage */
		"/lib/crda/regulatory.bin", /* alternative for distributions */
		NULL
	};
	const char **regdb = regdb_paths;

	if (argc != 1) {
		fprintf(stderr, "Usage: %s\n", argv[0]);
		return -EINVAL;
	}

	env_country = getenv("COUNTRY");
	if (!env_country) {
		fprintf(stderr, "COUNTRY environment variable not set.\n");
		return -EINVAL;
	}

	if (!reglib_is_valid_regdom(env_country)) {
		fprintf(stderr, "COUNTRY environment variable must be an "
			"ISO ISO 3166-1-alpha-2 (uppercase) or 00\n");
		return -EINVAL;
	}

	memcpy(alpha2, env_country, 2);

	while (*regdb != NULL) {
		fd = open(*regdb, O_RDONLY);
		if (fd >= 0)
			break;
		regdb++;
	}
	if (fd < 0) {
		perror("failed to open db file");
		return -ENOENT;
	}

	close(fd);

	rd = reglib_get_rd_alpha2(alpha2, *regdb);
	if (!rd) {
		fprintf(stderr, "No country match in regulatory database.\n");
		return -1;
	}

	r = nl80211_init(&nlstate);
	if (r) {
		free((struct ieee80211_regdomain *) rd);
		return -EIO;
	}

	msg = nlmsg_alloc();
	if (!msg) {
		fprintf(stderr, "Failed to allocate netlink message.\n");
		r = -1;
		goto out;
	}

	genlmsg_put(msg, 0, 0, genl_family_get_id(nlstate.nl80211), 0,
		0, NL80211_CMD_SET_REG, 0);

	NLA_PUT_STRING(msg, NL80211_ATTR_REG_ALPHA2, alpha2);
	NLA_PUT_U8(msg, NL80211_ATTR_DFS_REGION, rd->dfs_region);

	nl_reg_rules = nla_nest_start(msg, NL80211_ATTR_REG_RULES);
	if (!nl_reg_rules) {
		r = -1;
		goto nla_put_failure;
	}

	for (j = 0; j < rd->n_reg_rules; j++) {
		struct nlattr *nl_reg_rule;
		nl_reg_rule = nla_nest_start(msg, i);
		if (!nl_reg_rule)
			goto nla_put_failure;

		r = put_reg_rule(&rd->reg_rules[j], msg);
		if (r)
			goto nla_put_failure;

		nla_nest_end(msg, nl_reg_rule);
	}

	nla_nest_end(msg, nl_reg_rules);

	cb = nl_cb_alloc(NL_CB_CUSTOM);
	if (!cb)
		goto cb_out;

	r = nl_send_auto_complete(nlstate.nl_sock, msg);

	if (r < 0) {
		fprintf(stderr, "Failed to send regulatory request: %d\n", r);
		goto cb_out;
	}

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, reg_handler, NULL);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, wait_handler, &finished);
	nl_cb_err(cb, NL_CB_CUSTOM, error_handler, NULL);

	if (!finished) {
		r = nl_wait_for_ack(nlstate.nl_sock);
		if (r < 0) {
			fprintf(stderr, "Failed to set regulatory domain: "
				"%d\n", r);
			goto cb_out;
		}
	}

cb_out:
	nl_cb_put(cb);
nla_put_failure:
	nlmsg_free(msg);
out:
	nl80211_cleanup(&nlstate);
	free((struct ieee80211_regdomain *) rd);

	return r;
}
