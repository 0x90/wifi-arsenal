#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <net/if.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/select.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include "clients_table.h"
#include "nl80211.h"
#include "iw.h"

#ifdef DEBUG
void mac_addr_n2a(char *mac_addr, unsigned char *arg)
{ 
  int i, l;

  l = 0;
  for (i = 0; i < ETH_ALEN ; i++) {
    if (i == 0) {
      sprintf(mac_addr+l, "%02x", arg[i]);
      l += 2;
    } else {
      sprintf(mac_addr+l, ":%02x", arg[i]);
      l += 3;
    }
  }
}
#endif

void mac_conv(u_int8_t *mac_addr, unsigned char *arg)
{ 
  int i;
  for (i = 0; i < ETH_ALEN ; i++) 
      mac_addr[i]= (u_int8_t)arg[i];
}


int ack_handler(struct nl_msg *msg, void *arg)
{ 
  int *ret = arg;
  *ret = 0;
  return NL_STOP;
}


int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err,
                         void *arg)
{ 
  int *ret = arg;
  *ret = err->error;
  return NL_STOP;
}

int finish_handler(struct nl_msg *msg, void *arg)
{
  int *ret = arg;
  *ret = 0;
  return NL_SKIP;
}

#if !defined(CONFIG_LIBNL20) && !defined(CONFIG_LIBNL30)
inline struct nl_handle *nl_socket_alloc(void)
{
  return nl_handle_alloc();
}

inline void nl_socket_free(struct nl_sock *h)
{
  nl_handle_destroy(h);
}
#endif /* CONFIG_LIBNL20 && CONFIG_LIBNL30 */

int handler_1(struct nl_msg *msg, void *arg)
{ 
//	printf("handle  1  \n"); 
  struct nlattr *tb[NL80211_ATTR_MAX + 1];
  struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
  struct nlattr *sinfo[NL80211_STA_INFO_MAX + 1];
  struct nlattr *rinfo[NL80211_RATE_INFO_MAX + 1];
  char mac_addr[20], state_name[10], dev[20];
  struct nl80211_sta_flag_update *sta_flags;
	u_int8_t mac_ad[6];
  int rx_bitrate, tx_bitrate;
  u_int32_t c_tx_failed,c_tx_pkts, c_tx_retries, c_rx_pkts;

  static struct nla_policy stats_policy[NL80211_STA_INFO_MAX + 1] = {
    [NL80211_STA_INFO_INACTIVE_TIME] = { .type = NLA_U32 },
    [NL80211_STA_INFO_RX_BYTES] = { .type = NLA_U32 },
    [NL80211_STA_INFO_TX_BYTES] = { .type = NLA_U32 },
    [NL80211_STA_INFO_RX_PACKETS] = { .type = NLA_U32 },
    [NL80211_STA_INFO_TX_PACKETS] = { .type = NLA_U32 },
    [NL80211_STA_INFO_SIGNAL] = { .type = NLA_U8 },
    [NL80211_STA_INFO_TX_BITRATE] = { .type = NLA_NESTED },
    [NL80211_STA_INFO_RX_BITRATE] = { .type = NLA_NESTED },
    [NL80211_STA_INFO_LLID] = { .type = NLA_U16 },
    [NL80211_STA_INFO_PLID] = { .type = NLA_U16 },
    [NL80211_STA_INFO_PLINK_STATE] = { .type = NLA_U8 },
    [NL80211_STA_INFO_TX_RETRIES] = { .type = NLA_U32 },
    [NL80211_STA_INFO_TX_FAILED] = { .type = NLA_U32 },
  };


  static struct nla_policy rate_policy[NL80211_RATE_INFO_MAX + 1] = {
    [NL80211_RATE_INFO_BITRATE] = { .type = NLA_U16 },
    [NL80211_RATE_INFO_MCS] = { .type = NLA_U8 },
    [NL80211_RATE_INFO_40_MHZ_WIDTH] = { .type = NLA_FLAG },
    [NL80211_RATE_INFO_SHORT_GI] = { .type = NLA_FLAG },
  };

  nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
            genlmsg_attrlen(gnlh, 0), NULL);

  /*
   * TODO: validate the interface and mac address!
   * Otherwise, there's a race condition as soon as
   * the kernel starts sending station notifications.
   */

  if (!tb[NL80211_ATTR_STA_INFO]) {
    fprintf(stderr, "station stats missing!\n");
    return NL_SKIP;
  }
  if (nla_parse_nested(sinfo, NL80211_STA_INFO_MAX,
                       tb[NL80211_ATTR_STA_INFO],
                       stats_policy)) {
    fprintf(stderr, "failed to parse nested attributes!\n");
    return NL_SKIP;
  }
#ifdef DEBUG
  mac_addr_n2a(mac_addr, nla_data(tb[NL80211_ATTR_MAC]));
#endif
  mac_conv(mac_ad, nla_data(tb[NL80211_ATTR_MAC]));
  if_indextoname(nla_get_u32(tb[NL80211_ATTR_IFINDEX]), dev);
#ifdef DEBUG
  printf("Station %s (on %s)\n", mac_addr, dev);
#endif

  if (sinfo[NL80211_STA_INFO_TX_FAILED])
    c_tx_failed= nla_get_u32(sinfo[NL80211_STA_INFO_TX_FAILED]) ;
	else {
    fprintf(stderr,"tx failed error \n");
		goto end;
	}
  if (sinfo[NL80211_STA_INFO_TX_RETRIES])
    c_tx_retries = nla_get_u32(sinfo[NL80211_STA_INFO_TX_RETRIES]) ;
  else {
    fprintf(stderr,"tx retried failed \n");
    goto end;
  }
  if (sinfo[NL80211_STA_INFO_TX_PACKETS])				 
    c_tx_pkts = nla_get_u32(sinfo[NL80211_STA_INFO_TX_PACKETS]); 
  else {
    fprintf(stderr," tx packets failed  \n");
    goto end;
	}
  if (sinfo[NL80211_STA_INFO_RX_PACKETS])						
    c_rx_pkts = nla_get_u32(sinfo[NL80211_STA_INFO_RX_PACKETS]);
  else{
    fprintf(stderr," rx packets failed  \n");
    goto end;  
  }
  if (sinfo[NL80211_STA_INFO_TX_BITRATE]) {		
    if (nla_parse_nested(rinfo, NL80211_RATE_INFO_MAX,
			 sinfo[NL80211_STA_INFO_TX_BITRATE], rate_policy)) {
      fprintf(stderr, "failed to parse nested tx rate attributes!\n");
      goto end; 
    } else {
      if (rinfo[NL80211_RATE_INFO_BITRATE])
	tx_bitrate= nla_get_u16(rinfo[NL80211_RATE_INFO_BITRATE]);            
    }
  } else{
	fprintf(stderr,"tx bitrate failed\n");
    goto end ; 
   }
    if (sinfo[NL80211_STA_INFO_RX_BITRATE]) {		
      if (nla_parse_nested(rinfo, NL80211_RATE_INFO_MAX,
			   sinfo[NL80211_STA_INFO_RX_BITRATE], rate_policy)) {
	fprintf(stderr, "failed to parse nested rx rate attributes!\n");
	goto end; 
      } else {
	if (rinfo[NL80211_RATE_INFO_BITRATE])
	  rx_bitrate= nla_get_u16(rinfo[NL80211_RATE_INFO_BITRATE]);            
      }
    } else {
   fprintf(stderr,"failed rx bitrate\n");
      goto end ; 
   }
    address_client_table_lookup(&client_address_table,c_tx_failed, c_tx_retries , 
				c_tx_pkts, c_rx_pkts, mac_ad , 
				1,tx_bitrate, rx_bitrate );
 end :
   
    return 0;
}

int handler_0(struct nl_msg *msg, void *arg)
{
//  printf("handle 0 \n"); 
  struct nlattr *tb[NL80211_ATTR_MAX + 1];
  struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
  struct nlattr *sinfo[NL80211_STA_INFO_MAX + 1];
  struct nlattr *rinfo[NL80211_RATE_INFO_MAX + 1];
  char mac_addr[20], state_name[10], dev[20];
  struct nl80211_sta_flag_update *sta_flags;
	u_int8_t mac_ad[6];

  static struct nla_policy stats_policy[NL80211_STA_INFO_MAX + 1] = {
    [NL80211_STA_INFO_INACTIVE_TIME] = { .type = NLA_U32 },
    [NL80211_STA_INFO_RX_BYTES] = { .type = NLA_U32 },
    [NL80211_STA_INFO_TX_BYTES] = { .type = NLA_U32 },
    [NL80211_STA_INFO_RX_PACKETS] = { .type = NLA_U32 },
    [NL80211_STA_INFO_TX_PACKETS] = { .type = NLA_U32 },
    [NL80211_STA_INFO_SIGNAL] = { .type = NLA_U8 },
    [NL80211_STA_INFO_TX_BITRATE] = { .type = NLA_NESTED },
    [NL80211_STA_INFO_RX_BITRATE] = { .type = NLA_NESTED },
    [NL80211_STA_INFO_LLID] = { .type = NLA_U16 },
    [NL80211_STA_INFO_PLID] = { .type = NLA_U16 },
    [NL80211_STA_INFO_PLINK_STATE] = { .type = NLA_U8 },
    [NL80211_STA_INFO_TX_RETRIES] = { .type = NLA_U32 },
    [NL80211_STA_INFO_TX_FAILED] = { .type = NLA_U32 },
  };


  static struct nla_policy rate_policy[NL80211_RATE_INFO_MAX + 1] = {
    [NL80211_RATE_INFO_BITRATE] = { .type = NLA_U16 },
    [NL80211_RATE_INFO_MCS] = { .type = NLA_U8 },
    [NL80211_RATE_INFO_40_MHZ_WIDTH] = { .type = NLA_FLAG },
    [NL80211_RATE_INFO_SHORT_GI] = { .type = NLA_FLAG },
  };

  nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
            genlmsg_attrlen(gnlh, 0), NULL);

  /*
   * TODO: validate the interface and mac address!
   * Otherwise, there's a race condition as soon as
   * the kernel starts sending station notifications.
   */

  if (!tb[NL80211_ATTR_STA_INFO]) {
    fprintf(stderr, "station stats missing!\n");
    return NL_SKIP;
  }
  if (nla_parse_nested(sinfo, NL80211_STA_INFO_MAX,
                       tb[NL80211_ATTR_STA_INFO],
                       stats_policy)) {
    fprintf(stderr, "failed to parse nested attributes!\n");
    return NL_SKIP;
  }
#ifdef DEBUG
  mac_addr_n2a(mac_addr, nla_data(tb[NL80211_ATTR_MAC]));
#endif 
  mac_conv(mac_ad, nla_data(tb[NL80211_ATTR_MAC]));
  if_indextoname(nla_get_u32(tb[NL80211_ATTR_IFINDEX]), dev);
#ifdef DEBUG
  printf("Station %s (on %s)\n", mac_addr, dev);
#endif 
  int rx_bitrate, tx_bitrate;
  u_int32_t c_tx_failed,c_tx_pkts, c_tx_retries, c_rx_pkts;
  if (sinfo[NL80211_STA_INFO_TX_FAILED])
    c_tx_failed= nla_get_u32(sinfo[NL80211_STA_INFO_TX_FAILED]) ;
	else {
    fprintf(stderr,"tx failed error \n");
		goto end;
	}
  if (sinfo[NL80211_STA_INFO_TX_RETRIES])
    c_tx_retries = nla_get_u32(sinfo[NL80211_STA_INFO_TX_RETRIES]) ;
  else {
    fprintf(stderr,"tx retried failed \n");
    goto end;
  }
  if (sinfo[NL80211_STA_INFO_TX_PACKETS])				 
    c_tx_pkts = nla_get_u32(sinfo[NL80211_STA_INFO_TX_PACKETS]); 
  else {
    fprintf(stderr," tx packets failed  \n");
    goto end;
	}
  if (sinfo[NL80211_STA_INFO_RX_PACKETS])						
    c_rx_pkts = nla_get_u32(sinfo[NL80211_STA_INFO_RX_PACKETS]);
  else{
    fprintf(stderr," rx packets failed  \n");
    goto end;  
  }
  if (sinfo[NL80211_STA_INFO_TX_BITRATE]) {		
    if (nla_parse_nested(rinfo, NL80211_RATE_INFO_MAX,
			 sinfo[NL80211_STA_INFO_TX_BITRATE], rate_policy)) {
      fprintf(stderr, "failed to parse nested tx rate attributes!\n");
      goto end; 
    } else {
      if (rinfo[NL80211_RATE_INFO_BITRATE])
	tx_bitrate= nla_get_u16(rinfo[NL80211_RATE_INFO_BITRATE]);            
    }
  } else{
	fprintf(stderr,"tx bitrate failed\n");
    goto end ; 
   }
    if (sinfo[NL80211_STA_INFO_RX_BITRATE]) {		
      if (nla_parse_nested(rinfo, NL80211_RATE_INFO_MAX,
			   sinfo[NL80211_STA_INFO_RX_BITRATE], rate_policy)) {
	fprintf(stderr, "failed to parse nested rx rate attributes!\n");
	goto end; 
      } else {
	if (rinfo[NL80211_RATE_INFO_BITRATE])
	  rx_bitrate= nla_get_u16(rinfo[NL80211_RATE_INFO_BITRATE]);            
      }
    } else {
   fprintf(stderr,"failed rx bitrate\n");
      goto end ; 
   }
    address_client_table_lookup(&client_address_table,c_tx_failed, c_tx_retries , 
				c_tx_pkts, c_rx_pkts, mac_ad , 
				0,tx_bitrate, rx_bitrate );
 end :
   
    return 0;
}


int nl80211_init(struct nl80211_state *state)
{
  int err;

  state->nl_sock = nl_socket_alloc();
  if (!state->nl_sock) {
    fprintf(stderr, "Failed to allocate netlink socket.\n");
    return -ENOMEM;
  }

  if (genl_connect(state->nl_sock)) {
    fprintf(stderr, "Failed to connect to generic netlink.\n");
    err = -ENOLINK;
    goto out_handle_destroy;
  }

  state->nl80211_id = genl_ctrl_resolve(state->nl_sock, "nl80211");
  if (state->nl80211_id < 0) {
    fprintf(stderr, "nl80211 not found.\n");
    err = -ENOENT;
    goto out_handle_destroy;
  }

  return 0;

 out_handle_destroy:
  nl_socket_free(state->nl_sock);
  return err;
}

void nl80211_cleanup(struct nl80211_state *state)
{
  nl_socket_free(state->nl_sock);
}

int query_kernel(){
 int err_0, err_1, fd_0, fd_1,retval ,devidx_0 = 0, devidx_1=0;
  devidx_0 = if_nametoindex("wlan0");
  devidx_1 = if_nametoindex("wlan1");
    struct nl80211_state nlstate_0, nlstate_1;
    struct nl_cb *cb_0,*cb_1;
    struct nl_cb *s_cb_0, *s_cb_1;
    struct nl_msg *msg_0, *msg_1;
    err_0 = nl80211_init(&nlstate_0);
    err_1 = nl80211_init(&nlstate_1);
    if (err_1 || err_0)
      return -1;
    msg_0 = nlmsg_alloc();
    msg_1 = nlmsg_alloc();

    if (!msg_0 || !msg_1) {
      perror("failed to allocate netlink message\n");
      return -1;
    }
    cb_0 = nl_cb_alloc(NL_CB_DEFAULT);
    s_cb_0 = nl_cb_alloc( NL_CB_DEFAULT);
    cb_1 = nl_cb_alloc( NL_CB_DEFAULT);
    s_cb_1 = nl_cb_alloc( NL_CB_DEFAULT);

    if (!cb_1 || !s_cb_1 || !cb_0 || !s_cb_0) {
      perror("failed to allocate netlink callbacks\n");
      nlmsg_free(msg_1);
      nlmsg_free(msg_0);
      nl80211_cleanup(&nlstate_0);
      nl80211_cleanup(&nlstate_1);
      return -1;
    }
    genlmsg_put(msg_0, 0, 0, nlstate_0.nl80211_id, 0,768, 17, 0);
    genlmsg_put(msg_1, 0, 0, nlstate_1.nl80211_id, 0,768, 17, 0);
    NLA_PUT_U32(msg_0, NL80211_ATTR_IFINDEX, devidx_0);
    NLA_PUT_U32(msg_1, NL80211_ATTR_IFINDEX, devidx_1);
    nl_cb_set(cb_0, NL_CB_VALID, NL_CB_CUSTOM, handler_0, NULL);
    nl_cb_set(cb_1, NL_CB_VALID, NL_CB_CUSTOM, handler_1, NULL);
    nl_socket_set_cb(nlstate_0.nl_sock, s_cb_0);
    nl_socket_set_cb(nlstate_1.nl_sock, s_cb_1);

    err_0 = nl_send_auto_complete(nlstate_0.nl_sock, msg_0);
    err_1 = nl_send_auto_complete(nlstate_1.nl_sock, msg_1);
    if (err_0 < 0 || err_1 <0 ){
      nl_cb_put(cb_0);
      nl_cb_put(s_cb_0);
      nlmsg_free(msg_0);
      nl_cb_put(cb_1);
      nl_cb_put(s_cb_1);
      nlmsg_free(msg_1);

    nla_put_failure :
      nl80211_cleanup(&nlstate_0); // come back again next iteration ...
      nl80211_cleanup(&nlstate_1); // come back again next iteration ...
      return 1 ; //  continue ; // right  ? 
    }

    nl_cb_err(cb_0, NL_CB_CUSTOM, error_handler, &err_0);
    nl_cb_set(cb_0, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err_0);
    nl_cb_set(cb_0, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err_0);


    nl_cb_err(cb_1, NL_CB_CUSTOM, error_handler, &err_1);
    nl_cb_set(cb_1, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err_1);
    nl_cb_set(cb_1, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err_1);

    fd_0=nl_socket_get_fd(nlstate_0.nl_sock);
    fd_1=nl_socket_get_fd(nlstate_1.nl_sock);
        nl_recvmsgs(nlstate_0.nl_sock, cb_0);
        nl_recvmsgs(nlstate_1.nl_sock, cb_1);
    nl_cb_put(cb_0);
    nl_cb_put(s_cb_0);
    nlmsg_free(msg_0);
    nl80211_cleanup(&nlstate_0);

    nl_cb_put(cb_1);
    nl_cb_put(s_cb_1);
    nlmsg_free(msg_1);
    nl80211_cleanup(&nlstate_1);
   return 0;

}
