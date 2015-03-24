#ifndef __ACS_H
#define __ACS_H

#include <stdbool.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>

#include "nl80211.h"
#include "list.h"

#define ETH_ALEN 6
#define ARRAY_SIZE(ar) (sizeof(ar)/sizeof(ar[0]))
#define DIV_ROUND_UP(x, y) (((x) + (y - 1)) / (y))
#define BIT(x) (1ULL<<(x))

#ifdef CONFIG_LIBNL1
#  define nl_sock nl_handle
#endif

extern struct dl_list freq_list;

struct nl80211_state {
	struct nl_sock *nl_sock;
	struct nl_cache *nl_cache;
	struct genl_family *nl80211;
};

struct freq_item {
	__u16 center_freq;
	bool enabled;
	__s8 max_noise;
	__s8 min_noise;
	/* An alternative is to use __float128 for low noise environments */
	long double interference_factor;
	struct dl_list list_member;
	unsigned int survey_count;
	struct dl_list survey_list;
};

int handle_survey_dump(struct nl_msg *msg, void *arg);
void parse_freq_list(void);
void parse_freq_int_factor(void);
void annotate_enabled_chans(void);
void clean_freq_list(void);
void clear_freq_surveys(void);
__u32 wait_for_offchan_op(struct nl80211_state *state,
			  int devidx, int freq,
			  const int n_waits, const __u32 *waits);
void clear_offchan_ops_list(void);

int nl_get_multicast_id(struct nl_sock *sock, const char *family, const char *group);

int nl80211_add_membership_mlme(struct nl80211_state *state);

extern const char acs_version[];
extern int nl_debug;

#endif /* __ACS_H */
