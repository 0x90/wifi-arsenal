#ifndef _NL_FUNC_H
#define _NL_FUNC_H
#include "nl80211.h"
#include "iw.h"

void mac_addr_n2a(char *mac_addr, unsigned char *arg);
int ack_handler(struct nl_msg *msg, void *arg);
int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg);
int finish_handler(struct nl_msg *msg, void *arg);
int query_kernel();
#if !defined(CONFIG_LIBNL20) && !defined(CONFIG_LIBNL30)
 inline struct nl_handle *nl_socket_alloc(void);
 inline void nl_socket_free(struct nl_sock *h);
#endif /* CONFIG_LIBNL20 && CONFIG_LIBNL30 */

int print_sta_handler(struct nl_msg *msg, void *arg);
int nl80211_init(struct nl80211_state *state);
void nl80211_cleanup(struct nl80211_state *state);

#endif /*NL_FUNC_H*/
