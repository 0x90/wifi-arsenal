#ifndef __DEBUG_H_
#define __DEBUG_H_

#include <linux/skbuff.h>
#include <net/mac80211.h>
#include "grt.h"

 #define GRT_DEBUG
// #define GRT_INFO

#ifdef GRT_DEBUG
#define GRT_PRINT_DEBUG(fmt, ...) printk(fmt,##__VA_ARGS__)
#else
#define GRT_PRINT_DEBUG(fmt, ...)
#endif

#ifdef GRT_INFO
#define GRT_PRINT_INFO(fmt, ...) printk(fmt,##__VA_ARGS__)
#else
#define GRT_PRINT_INFO(fmt, ...)
#endif

void grt_debug_print_skb(char * label, struct sk_buff * skb);
void grt_info_print_bf(char * label, struct grt_buf * bf);
#endif
