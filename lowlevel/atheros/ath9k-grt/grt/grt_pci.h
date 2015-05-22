#ifndef __GRT_PCI_H_
#define __GRT_PCI_H_

/**
 * File grt_pci.h and grt_pci.c handles operations in PCI bus. This includes device init and 
 * exit, PIO read and write, DMA read and write. The device init and exit functions will not
 * be used by other files. So those functions are not in grt_pci.h.
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/pci-aspm.h>
#include <linux/pci.h>
#include <net/mac80211.h>
#include "grt.h"

/*PIO operations in PCI bus*/
u32 grt_pio_read(struct grt_hw *gh, int reg);
void grt_pio_write(struct grt_hw *gh, int reg, u32 data);

/*Other functions*/
int grt_pci_read_cachesize(struct grt_hw * gh);

/*sk_buff DMA operations*/
int grt_dma_skb_from_device(struct grt_hw *gh, struct grt_buf *bf);
int grt_dma_skb_to_device(struct grt_hw *gh, struct grt_buf *bf);

#endif
