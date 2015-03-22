include $(TOPDIR)/rules.mk

include version.mk

include $(INCLUDE_DIR)/package.mk

define Package/bully
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=wireless
  TITLE:=Brute force attack against WPS, that actually works
  DEPENDS:=+libpcap +libopenssl
endef

define Package/bully/description
  Brute force attack against WPS, that actually works
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) -rf ./src $(PKG_BUILD_DIR)/
endef

CONFIGURE_PATH:=src

MAKE_PATH:=src

TARGET_CFLAGS+=$(TARGET_CPPFLAGS)

define Package/bully/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/bully $(1)/usr/bin/
endef

$(eval $(call BuildPackage,bully)) 
