/*  hello-1.c - The simplest kernel module.
 *
 *  Copyright (C) 2001 by Peter Jay Salzman
 *
 *  08/02/2006 - Updated by Rodrigo Rubira Branco <rodrigo@kernelhacking.com>
 */

/* Kernel Programming */
#define LINUX

#include "grt_redirect.h"
#include <linux/module.h>  /* Needed by all modules */
#include <linux/kernel.h>  /* Needed for KERN_ALERT */

int _pci_read_config_byte(const struct pci_dev *dev, int where, u8 *val){
	return pci_read_config_byte(   dev,  where,  val);
}
EXPORT_SYMBOL(_pci_read_config_byte);

static int _pci_write_config_byte(const struct pci_dev *dev, int where, u8 val){
	printk("a write op was performed!\n");
	return pci_write_config_byte(   dev,  where,  val);
}
EXPORT_SYMBOL(_pci_write_config_byte);

static int _pci_read_config_dword(const struct pci_dev *dev, int where, u32 *val){
	return pci_read_config_dword(   dev,  where,  val);
}
EXPORT_SYMBOL(_pci_read_config_dword);

static int _pci_write_config_dword(const struct pci_dev *dev, int where, u32 val){
	return pci_write_config_dword(   dev,  where,  val);
}
EXPORT_SYMBOL(_pci_write_config_dword);

int _pci_register_driver(struct pci_driver* driver){
	return pci_register_driver(  driver);
}
EXPORT_SYMBOL(_pci_register_driver);

void _pci_unregister_driver(struct pci_driver* driver){
	return pci_unregister_driver(  driver);
}
EXPORT_SYMBOL(_pci_unregister_driver);

int _pcie_capability_clear_word(struct pci_dev *dev, int pos, u16 clear){
	return pcie_capability_clear_word(  dev,  pos,  clear);
}
EXPORT_SYMBOL(_pcie_capability_clear_word);

int _pcie_capability_read_word(struct pci_dev *dev, int pos, u16 *val){
	return pcie_capability_read_word(  dev,  pos,  val);
}
EXPORT_SYMBOL(_pcie_capability_read_word);

int _pcim_enable_device(struct pci_dev *pdev){
	return pcim_enable_device(  pdev);
}
EXPORT_SYMBOL(_pcim_enable_device);

static int _pci_set_dma_mask(struct pci_dev *dev, u64 mask){
	return pci_set_dma_mask(  dev,  mask);
}
EXPORT_SYMBOL(_pci_set_dma_mask);

static int _pci_set_consistent_dma_mask(struct pci_dev *dev, u64 mask){
	return pci_set_consistent_dma_mask(  dev,  mask);
}
EXPORT_SYMBOL(_pci_set_consistent_dma_mask);

void _pci_set_master(struct pci_dev *dev){
	return pci_set_master(  dev);
}
EXPORT_SYMBOL(_pci_set_master);

int _pcim_iomap_regions(struct pci_dev *pdev, int mask, const char *name){
	return pcim_iomap_regions(  pdev,  mask,   name);
}
EXPORT_SYMBOL(_pcim_iomap_regions);

void _pci_set_drvdata(struct pci_dev *pdev, void *data){
	return pci_set_drvdata(  pdev,  data);
}
EXPORT_SYMBOL(_pci_set_drvdata);

void *_pci_get_drvdata(struct pci_dev *pdev){
	return pci_get_drvdata(  pdev);
}
EXPORT_SYMBOL(_pci_get_drvdata);

void __iomem * pci_base_address;

void __iomem * const *_pcim_iomap_table(struct pci_dev *pdev){
	void __iomem * const * result =  pcim_iomap_table(  pdev);
	pci_base_address = result[0];
	return result;
}
EXPORT_SYMBOL(_pcim_iomap_table);

unsigned dma_desp_addr[10];

void _iowrite32(u32 val, void __iomem *addr){
	//printk("ATH9K_GRT: iowrite32(%p:%x)\n",addr, val);
	unsigned long uladdr = (unsigned long)(addr-pci_base_address);
	if((uladdr&0xff00) == 0x0800){
		unsigned q = (unsigned)(uladdr&0xff)>>2;
		if(q<10){
			dma_desp_addr[q] = val;
			printk("%x\n", DMA_BIT_MASK(32));
			printk("ATH9K_GRT: dma descriptor catched: addr=%x q=%x\n",dma_desp_addr[q], q);
		}
	}
	if((uladdr&0xffff) == 0x0880){
		int q =  __builtin_ctz(uladdr);
		printk("ATH9K_GRT: q=%x val=%x\n",q, val);
	}
	//printk("ATH9K_GRT: %x\n",uladdr);
	return iowrite32(val, addr);
}
EXPORT_SYMBOL(_iowrite32);

unsigned int _ioread32(void __iomem *addr){
	unsigned int result = ioread32(addr);
	int i;
//	for(i = 0; i<(sizeof(register_map)/sizeof(register_map[0])); i++){
//		if(register_map[i][0]== (u64)(addr-pci_base_address)){
//			printk("ATH9K_GRT: ioreadstatic32(%x:%x)\n",register_map[i][0], result);
//			if (register_map[i][1] != result){
//				printk("ATH9K_GRT: ioreaderror32(%x:%x)\n",register_map[i][0], register_map[i][1]);
//			}
//			return (unsigned int) register_map[i][1];
//		}
//	}
	//printk("ATH9K_GRT: ioread32(%p:%x)\n",addr-pci_base_address, result);
	return result;
}
EXPORT_SYMBOL(_ioread32);


int init_module(void)
{
   printk("<1>Hello world 1.\n");

   // A non 0 return means init_module failed; module can't be loaded.
   return 0;
}


void cleanup_module(void)
{
  printk(KERN_ALERT "Goodbye world 1.\n");
}

MODULE_LICENSE("GPL");
