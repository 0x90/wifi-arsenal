#ifndef __INTR_H_
#define __INTR_H_

#include <net/mac80211.h>
#include <linux/jiffies.h>
#include "grt.h"
#include "debug.h"

/*Software interrupt call backs*/
void grt_tasklet_tx_int(unsigned long data);
void grt_tasklet_tx(unsigned long data);
void grt_tasklet_rx(unsigned long data);
void grt_tasklet_bc(unsigned long data);

/*IRQ handler*/
irqreturn_t grt_intr(int irq, void *dev_id);

/*Interrupt init and exit functions*/
int grt_intr_init(struct grt_hw * gh);
void grt_intr_exit(struct grt_hw * gh);

#endif

