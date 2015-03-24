# 
# Copyright (C) 2007 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=fixsum
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/fixsum
  SECTION:=admin
  CATEGORY:=Administration
  TITLE:=Fix atheros ath9k chipset EEPROM checksum
  URL:=http://www.home-wifi.com/thread-6667-1-1.html
endef

define Package/fixsum/description
	Fix atheros ath9k chipset EEPROM checksum.
	Binary file is wholeflash data or "EEPROM" partition.
endef

define Build/Prepare
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) -Os $(PKG_BUILD_DIR)/fixsum.c -o $(PKG_BUILD_DIR)/$(PKG_NAME)
endef

define Package/fixsum/install
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/fixsum $(1)/sbin/
endef

$(eval $(call BuildPackage,fixsum))
