#ifndef __MAC80211OPS_H_
#define __MAC80211OPS_H_

#include <linux/etherdevice.h>
#include <linux/nl80211.h>
#include <linux/pci.h>
#include <net/mac80211.h>
#include "grt.h"
#include "debug.h"

/*Init and exit functions, deal with queues*/
int grt_mac_init(struct grt_hw * gh);
void grt_mac_exit(struct grt_hw * gh);

extern const struct ieee80211_ops grt_80211_ops;

#endif
