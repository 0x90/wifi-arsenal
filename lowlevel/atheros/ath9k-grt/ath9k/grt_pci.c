#include "grt_pci.h"
#include "grt_intr.h"
#include "grt_mac80211ops.h"

MODULE_LICENSE("GPL");

/*probe and remove functinos*/
int grt_pci_probe(struct pci_dev *pdev, const struct pci_device_id * id);
void grt_pci_remove(struct pci_dev *pdev);

/*DMA operations in PCI bus*/
int grt_dma_read(struct grt_hw *gh, dma_addr_t daddr, int dcount);
int grt_dma_write(struct grt_hw *gh, dma_addr_t daddr, int dcount);

/*DMA descriptor generation*/
int grt_desc_gen_single(struct grt_buf *bf, enum dma_data_direction dir);


static struct pci_device_id grt_pci_id_table[] = {
  { PCI_DEVICE(0x10ee, 0x6011), },
  { PCI_DEVICE(0x10ee, 0x6022), },
  { PCI_DEVICE(0x10ee, 0x6024), },
  { PCI_DEVICE(0x10ee, 0x7011), },
  { PCI_DEVICE(0x10ee, 0x7022), },
  { PCI_DEVICE(0x10ee, 0x7024), },
  { PCI_DEVICE(0x10ee, 0x7028), },
  { 0, }
};

static struct pci_driver grt_pci_driver = {
  .name = GRT_MODNAME,
  .id_table = grt_pci_id_table,
  .probe = grt_pci_probe,
  .remove = grt_pci_remove,
};

/**
 * grt_pci_probe() - Init function of PCI driver
 * @pdev: PCI device struct
 * @id: The device ID
 */
int grt_pci_probe(struct pci_dev *pdev, const struct pci_device_id * id)
{
  unsigned long pci_bar_size;
  void __iomem * pci_bar_vir_addr;
  struct grt_hw * gh = NULL;
  struct ieee80211_hw *hw = NULL;
  int ret;
  /*
   *disable unsupported PCI states
   *Our device doesn't support any power save status
   */
  pci_disable_link_state(pdev, PCIE_LINK_STATE_L0S | \
			 PCIE_LINK_STATE_L1 | PCIE_LINK_STATE_CLKPM);
  /*enable device*/
  ret = pci_enable_device(pdev);
  if(ret){
    printk("GRT: Can't enable device\n");
    goto err;
  }
  /*remap the IO memory space*/
  ret = pci_request_region(pdev, 0, "grt");
  if(ret){
    printk("GRT: Can't reserve PCI memory region\n");
    goto err_dis;
  }
  pci_bar_vir_addr = pci_iomap(pdev, 0, 0);
  if(!pci_bar_vir_addr){
    printk("GRT: Can't remap PCI memory region\n");
    ret = -EIO;
    goto err_reg;
  }
  pci_bar_size = pci_resource_len(pdev, 0);
  /*set DMA mask. If not do this, DMA from FPGA to host memory can go wrong and we may see some ALL ZERO frames in RX*/
  ret = dma_set_mask(&pdev->dev, GRT_DMA_MASK);
  if(0 != ret){
    printk("GRT: Can't set DMA mask\n");
    ret = -EIO;
    goto err_map;
  }
  /*enable bus master*/
  pci_set_master(pdev);
  /*alloc ieee80211 device*/
  hw = ieee80211_alloc_hw(sizeof(struct grt_hw), &grt_80211_ops);
  if(NULL == hw){
    printk("GRT: Can't alloc 80211 device.\n");
    ret = -ENOMEM;
    goto err_map;
  }
  /*record data in private data struct : grt_hw*/
  gh = hw->priv;
  gh->pdev = pdev;
  gh->dev = &pdev->dev;
  gh->hw = hw;
  gh->irq = pdev->irq;
  gh->pci_bar_size = pci_bar_size;
  gh->pci_bar_vir_addr = pci_bar_vir_addr;
  /*initialize 802.11 operations and data structures*/
  ret = grt_mac_init(gh);
  if(ret){
    printk("GRT: error initializing 80211 operations.\n");
    goto err_free;
  }
  /*initialize interrupt and software interrupt*/
  ret = grt_intr_init(gh);
  if(ret){
    printk("GRT: error initializing interrupt.\n");
    goto err_free;
  }
  /*register 802.11 device*/
  ret = ieee80211_register_hw(hw);
  if(ret){
    printk("GRT: error registering 802.11 device.\n");
    goto err_free;
  }
  else{
    printk("GRT: register 802.11 device successfully.\n");
  }
  /* Set private data */
  pci_set_drvdata(pdev, hw);
  /* Alloc DMA buffers */
  gh->dma_to_device_buf =  pci_alloc_consistent(gh->pdev, 4096, &gh->dma_to_device_dma);
  gh->dma_from_device_buf =  pci_alloc_consistent(gh->pdev, 4096, &gh->dma_from_device_dma);
  if(gh->dma_to_device_buf == NULL || gh->dma_from_device_buf == NULL){
    ret = -1;
    goto err_free;
  }
  /* Init the spinlocks */
  spin_lock_init(&gh->dma_read_lock);
  spin_lock_init(&gh->dma_write_lock);
  return 0;
 err_free:
  ieee80211_free_hw(hw);
 err_map:
  pci_iounmap(pdev, pci_bar_vir_addr);
 err_reg:
  pci_release_region(pdev, 0);
 err_dis:
  pci_disable_device(pdev);
 err:
  return ret;
}

/**
 * grt_pci_remove() - Exit function of PCI driver
 * @pdev: PCI device struct
 */
void grt_pci_remove(struct pci_dev *pdev)
{
  struct ieee80211_hw *hw = pci_get_drvdata(pdev);
  struct grt_hw *gh = hw->priv;
  ieee80211_unregister_hw(hw);
  /*finalize interrupt*/
  grt_intr_exit(gh);
  /*finalize 80211 operations and data structs*/
  grt_mac_exit(gh);
  /*release resourses*/
  pci_free_consistent(gh->pdev, 4096, gh->dma_to_device_buf, gh->dma_to_device_dma);
  pci_free_consistent(gh->pdev, 4096, gh->dma_from_device_buf, gh->dma_from_device_dma);
  pci_iounmap(pdev, gh->pci_bar_vir_addr);
  pci_release_region(pdev, 0);
  pci_disable_device(pdev);
  ieee80211_free_hw(hw);
}

/**
 * grt_pio_read() - PIO read function
 * @gh: Private data in driver
 * @reg_num: The offset of the reg. It should be 4 byte alianed.
 * @return: The data read from the reg
 */
u32 grt_pio_read(struct grt_hw *gh, int reg)
{
  u32 val;
  if(reg > gh->pci_bar_size )
    return -1;
  val = ioread32(gh->pci_bar_vir_addr + reg);
  return __swab32(val);
}

/**
 * grt_pio_write() - PIO write function
 * @gh: Private data in driver
 * @reg_num: The offset of the reg. It should be 4 byte alianed
 * @data: The data to be written to reg
 */
void grt_pio_write(struct grt_hw *gh, int reg, u32 data)
{
  if(reg > gh->pci_bar_size)
    return ;
  iowrite32(__swab32(data), gh->pci_bar_vir_addr + reg);
}

/**
 * grt_dma_read() - DMA read operatoin (DMA host -> board)
 * @gh: Driver's private data
 * @daddr: the DMA address of the first descriptor
 * @dcount: the number of descriptors
 * @return: return 0 when success, -1 when error occurred
 * DMA data from host to hardware. DMA itself will not generate interrupt. This function will
 * wait until DMA has been done.
 */
int grt_dma_read(struct grt_hw *gh, dma_addr_t daddr, int dcount)
{
  u32 status_reg = 0;
  spin_lock(&gh->dma_read_lock);
  /*start DMA*/
  grt_pio_write(gh, REG_DMA_R_DESCRIPTOR_ADDR_L, daddr & 0x0FFFFFFFF);
  grt_pio_write(gh, REG_DMA_R_DESCRIPTOR_ADDR_H, (daddr >> 32) & 0x0FFFFFFFF);
  grt_pio_write(gh, REG_DMA_R_CTRL, 0x00000007 | (0x3FFF0000 & dcount << 16));
  /*wait for DMA complete*/
  do
    status_reg = grt_pio_read(gh, REG_HW_STATE);
  while(0 == (status_reg & 0x0000000C));
  spin_unlock(&gh->dma_read_lock);
  if(status_reg & 0x00000004)/*DMA done*/
    return 0;
  else/*DMA error*/
    return -1;
}

/**
 * grt_dma_write() - DMA write operation (DMA board -> host)
 * @gh: Driver's private data
 * @daddr: the DMA address of the first descriptor
 * @dcount: the number of descriptors
 * @return: return 0 when success, -1 when error occurred
 * DMA data from hardware to host. DMA itself will not generate interrupt. This function will 
 * wait until DMA has been done.
 */
int grt_dma_write(struct grt_hw *gh, dma_addr_t daddr, int dcount)
{

  u32 status_reg = 0;
  spin_lock(&gh->dma_write_lock);
  /*start DMA*/
  grt_pio_write(gh, REG_DMA_W_DESCRIPTOR_ADDR_L, daddr & 0x0FFFFFFFF);
  grt_pio_write(gh, REG_DMA_W_DESCRIPTOR_ADDR_H, (daddr >> 32) & 0x0FFFFFFFF);
  grt_pio_write(gh, REG_DMA_W_CTRL, 0x00000007 | (0x3FFF0000 & dcount << 16));
  /* Read once to flush the above writes:
   * Bug can be caused without the following register read.
   * The last time's dma_w_done may be read out so that the do-while will not wait until the 
   * DMA write this time really done.
   */
  status_reg = grt_pio_read(gh, REG_HW_STATE);
  /*wait for DMA complete*/
  do
    status_reg = grt_pio_read(gh, REG_HW_STATE);
  while(0 == (status_reg & 0x00000300));
  spin_unlock(&gh->dma_write_lock);
  if(status_reg & 0x00000100)/*DMA done*/
    return 0;
  else/*DMA error*/
    return -1;
}

/**
 * grt_desc_gen_single() - Discriptor generator
 * @bf: Buffer holding descriptor and sk_buff. It should contain skb's dma address
 * @dir: DMA direction, DMA_TO_DEVICE stands for DMA read, DMA_FROM_DEVICE stands for DMA write.
 * @return: Return 0 when successful, -1 when error (e.g. arguments invalid)
 * Generate DMA descriptor for a single grt_buf. For DMA write, 2 descriptors will be generated
 * in bf->grt_descs including a zero read descriptor; for DMA read, only 1 descriptor will be 
 * generated. "skbaddr" should be ready using dma_map_single before calling this function.
 */
int grt_desc_gen_single(struct grt_buf *bf, enum dma_data_direction dir)
{
  /*skb_dma_len: DMA length(size) of the skb, count in DWs*/
  int skb_dma_len;
  if(bf == NULL)
    return -1;
  if(bf->skb == NULL)
    return -1;
  if(dir != DMA_TO_DEVICE && dir != DMA_FROM_DEVICE)
    return -1;
  /*DMA address of skb*/
  bf->grt_descs[4] = (bf->skbaddr >> 56) & 0xFF;
  bf->grt_descs[5] = (bf->skbaddr >> 48) & 0xFF;
  bf->grt_descs[6] = (bf->skbaddr >> 40) & 0xFF;
  bf->grt_descs[7] = (bf->skbaddr >> 32) & 0xFF;
  bf->grt_descs[8] = (bf->skbaddr >> 24) & 0xFF;
  bf->grt_descs[9] = (bf->skbaddr >> 16) & 0xFF;
  bf->grt_descs[10] = (bf->skbaddr >> 8) & 0xFF;
  bf->grt_descs[11] = (bf->skbaddr >> 0) & 0xFF;
  /*DMA length (in DW), current PHY's DMA is QW aligned, so if DMA size is not 8 bytes aligned, we should pad it to QW aligned*/
  if(bf->skb->len % 8 == 0)
    skb_dma_len = (bf->skb->len / 8) * 2;
  else
    skb_dma_len = (bf->skb->len / 8 + 1) * 2;
  bf->grt_descs[2] = (skb_dma_len >> 8) & 0xFF;
  bf->grt_descs[3] = (skb_dma_len >> 0) & 0xFF;
  /*other bits depending on DMA read / DMA write*/
  if(dir == DMA_TO_DEVICE){/*DMA read*/
    bf->grt_descs[0] = 0x14;
    bf->grt_descs[1] = 0x00;
  }
  else{/*DMA write*/
    bf->grt_descs[0] = 0x0C;
    bf->grt_descs[1] = 0x00;
    /*fill the zero-read descriptor*/
    memcpy(&bf->grt_descs[16], bf->grt_descs, 16);
    bf->grt_descs[16] = 0x14;
    bf->grt_descs[17] = 0x00;
    bf->grt_descs[18] = 0x00;
    bf->grt_descs[19] = 0x00;
  }
  return 0;
}

/**
 * grt_pci_read_cachesize() - read cache line size
 * @gh: private data of the driver
 * @return: cache line size in byte
 * This function will return cache line size in byte
 */
int grt_pci_read_cachesize(struct grt_hw *gh)
{
  u8 u8tmp;
  pci_read_config_byte(gh->pdev, PCI_CACHE_LINE_SIZE, &u8tmp);
  if(u8tmp == 0)
    return L1_CACHE_BYTES;
  return ((int)u8tmp) << 2;
}

/**
 * grt_dma_skb_from_device() - dma a sk_buff from device to memory (dma write)
 * @gh: Private data of the driver
 * @bf: The grt_buf containing the sk_buff. Descriptor buffer in bf should be ready for DMA.
 * @return: Return -1 when error, otherwise return 0.
 */
int grt_dma_skb_from_device(struct grt_hw *gh, struct grt_buf *bf)
{
  int dma_size;
  if(gh == NULL || bf == NULL || bf->skb == NULL)
    return -1;
  if(bf->skb->len < 0 || bf->skb->len > IEEE80211_MAX_FRAME_LEN)
    return -1;
  /*Prepare DMA write*/
  dma_size = roundup(bf->skb->len, grt_pci_read_cachesize(gh));
  bf->grt_desc_count = 2;
  /*Use the DMA conherence buffer instead of map DMA address to avoid align issues*/
  /* bf->skbaddr = dma_map_single(gh->dev, bf->skb->data, dma_size, DMA_FROM_DEVICE);
  if(unlikely(dma_mapping_error(gh->dev, bf->skbaddr))){
    printk("GRT: grt_dma_skb_from_device dma map error.\n");
    return -1;
  }*/
  bf->skbaddr = gh->dma_from_device_dma;
  if(unlikely(grt_desc_gen_single(bf, DMA_FROM_DEVICE))){
    // dma_unmap_single(gh->dev, bf->skbaddr, dma_size, DMA_FROM_DEVICE);
    printk("GRT: grt_dma_skb_from_device dma descriptor generation error.\n");
    return -1;
  }
  /*DMA write data*/
  if(0 != grt_dma_write(gh, bf->daddr, bf->grt_desc_count)){
    // dma_unmap_single(gh->dev, bf->skbaddr, dma_size, DMA_FROM_DEVICE);
    printk("GRT: grt_dma_skb_from_device dma error.\n");
    return -1;
  }
  memcpy(bf->skb->data, gh->dma_from_device_buf, dma_size);
  // dma_unmap_single(gh->dev, bf->skbaddr, dma_size, DMA_FROM_DEVICE);
  return 0;
}

/**
 * grt_dma_skb_to_device() - dma a sk_buff from memory to device (dma read)
 * @gh: Private data of the driver
 * @bf: The grt_buf containing the sk_buff. Descriptor buffer in bf should be ready for DMA.
 * @return: Return -1 when error, otherwise return 0.
 */
int grt_dma_skb_to_device(struct grt_hw *gh, struct grt_buf *bf)
{
  int dma_size;
  if(gh == NULL || bf == NULL || bf->skb == NULL)
    return -1;
  if(bf->skb->len < 0 || bf->skb->len > IEEE80211_MAX_FRAME_LEN)
    return -1;
  /*prepare DMA read*/
  dma_size = roundup(bf->skb->len, grt_pci_read_cachesize(gh));
  bf->grt_desc_count = 1;
  /*Use the DMA conherence buffer instead of map DMA address to avoid align issues*/
  /*bf->skbaddr = dma_map_single(gh->dev, bf->skb->data, dma_size, DMA_TO_DEVICE);
  if(unlikely(dma_mapping_error(gh->dev, bf->skbaddr))){
    printk("GRT: grt_dma_skb_to_device dma map error.\n");
    return -1;
  }*/
  memcpy(gh->dma_to_device_buf, bf->skb->data, dma_size);
  bf->skbaddr = gh->dma_to_device_dma;
  if(unlikely(grt_desc_gen_single(bf, DMA_TO_DEVICE))){
    // dma_unmap_single(gh->dev, bf->skbaddr, dma_size, DMA_TO_DEVICE);
    printk("GRT: grt_dma_skb_to_device dma descriptor generation error.\n");
    return -1;
  }
  /*DMA read data*/
  if(0 != grt_dma_read(gh, bf->daddr, bf->grt_desc_count)){
    // dma_unmap_single(gh->dev, bf->skbaddr, dma_size, DMA_TO_DEVICE);
    printk("GRT: grt_dma_skb_to_device dma error.\n");
    return -1;
  }
  // dma_unmap_single(gh->dev, bf->skbaddr, dma_size, DMA_TO_DEVICE);
  return 0;
}

///**
// * grt_init - Initialize function of the module
// */
//static int __init grt_init(void)
//{
//  int i;
//  /*check if there is our hardware in the PCIe bus*/
//  for(i = 0; i < (sizeof(grt_pci_id_table) / sizeof(struct pci_device_id)); i++){
//    if(grt_pci_id_table[i].vendor != 0){
//  	  if(NULL != pci_get_device(grt_pci_id_table[i].vendor, grt_pci_id_table[i].device, NULL)){
//  	    printk("GRT: Found GRT hardware vendor_id = 0x%x device_id = 0x%x", \
//                      grt_pci_id_table[i].vendor, grt_pci_id_table[i].device);
//  	    return pci_register_driver(&grt_pci_driver);
//  	  }
//	 }
//  }
//  printk("GRT: No GRT hardware found.\n");
//  return -1;
//}
//module_init(grt_init);
//
///**
// * grt_exit - Exit function of the module
// */
//static void grt_exit(void)
//{
//  pci_unregister_driver(&grt_pci_driver);
//}
//module_exit(grt_exit);
