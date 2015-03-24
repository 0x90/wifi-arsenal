#pragma once

struct sk_buff* bcmon_decode_skb(struct sk_buff* skb);
void register_mon_dev(struct net_device * netdev);
void delete_mon_dev(void);
