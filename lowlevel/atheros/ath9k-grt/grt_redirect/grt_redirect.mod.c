#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xca05c877, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x70778d8f, __VMLINUX_SYMBOL_STR(pci_bus_read_config_byte) },
	{ 0x1e5f41a1, __VMLINUX_SYMBOL_STR(pcim_enable_device) },
	{ 0x1c8c9783, __VMLINUX_SYMBOL_STR(dev_set_drvdata) },
	{ 0xb0d94c01, __VMLINUX_SYMBOL_STR(pcim_iomap_table) },
	{ 0x3616ceb8, __VMLINUX_SYMBOL_STR(dma_set_mask) },
	{ 0x3c7ed187, __VMLINUX_SYMBOL_STR(pcie_capability_clear_and_set_word) },
	{ 0xae074132, __VMLINUX_SYMBOL_STR(pci_set_master) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0xbdf4c9b3, __VMLINUX_SYMBOL_STR(pci_bus_write_config_dword) },
	{ 0xa896fcca, __VMLINUX_SYMBOL_STR(pcim_iomap_regions) },
	{ 0x78bc02d7, __VMLINUX_SYMBOL_STR(pci_bus_read_config_dword) },
	{ 0xbdfb6dbb, __VMLINUX_SYMBOL_STR(__fentry__) },
	{ 0x7ac3714, __VMLINUX_SYMBOL_STR(pci_unregister_driver) },
	{ 0xd5673c5a, __VMLINUX_SYMBOL_STR(pci_bus_write_config_byte) },
	{ 0xd8eb900a, __VMLINUX_SYMBOL_STR(dma_supported) },
	{ 0x5551511f, __VMLINUX_SYMBOL_STR(__pci_register_driver) },
	{ 0x436c2179, __VMLINUX_SYMBOL_STR(iowrite32) },
	{ 0x5907da33, __VMLINUX_SYMBOL_STR(dev_get_drvdata) },
	{ 0xe484e35f, __VMLINUX_SYMBOL_STR(ioread32) },
	{ 0x71c8b3f1, __VMLINUX_SYMBOL_STR(pcie_capability_read_word) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "F98ADFE3DC608666789078E");
