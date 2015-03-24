#ifndef __IW_H
#define __IW_H

#include <stdbool.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <endian.h>

#include "nl80211.h"
#include "ieee80211-iw.h"

#define ETH_ALEN 6

/* libnl 1.x compatibility code */
#if !defined(CONFIG_LIBNL20) && !defined(CONFIG_LIBNL30)
#  define nl_sock nl_handle
#endif

struct nl80211_state {
	struct nl_sock *nl_sock;
	int nl80211_id;
};

enum command_identify_by {
	CIB_NONE,
	CIB_PHY,
	CIB_NETDEV,
};

enum id_input {
	II_NONE,
	II_NETDEV,
	II_PHY_NAME,
	II_PHY_IDX,
};
//int mac_addr_a2n(unsigned char *mac_addr, char *arg);
//void mac_addr_n2a(char *mac_addr, unsigned char *arg);
#endif /* __IW_H */
