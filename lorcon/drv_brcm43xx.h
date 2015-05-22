#ifndef __BCM43XXINJECT_H__
#define __BCM43XXINJECT_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef SYS_LINUX

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include <net/if_arp.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <sys/poll.h>
#include <sys/types.h>

#ifdef HAVE_LINUX_WIRELESS
#include <linux/types.h>
#include <linux/if.h>
#include <linux/wireless.h>
#else
#include <net/if.h>
#endif

#include <net/ethernet.h>
#include <netpacket/packet.h>

#include "wtinject.h"

int tx80211_bcm43xx_init(struct tx80211 *in_tx);

int tx80211_bcm43xx_capabilities();

int bcm43xx_open(struct tx80211 *in_tx);
int bcm43xx_close(struct tx80211 *in_tx);

#endif /* linux */

#endif

