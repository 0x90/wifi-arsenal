# bcmdhd
DHDCFLAGS = -Wall -Wstrict-prototypes -Dlinux -DBCMDRIVER                     \
        -DBCMDONGLEHOST -DUNRELEASEDCHIP -DBCMDMA32 -DWLBTAMP -DBCMFILEIMAGE  \
        -DDHDTHREAD -DDHD_GPL -DDHD_SCHED -DDHD_DEBUG -DBDC -DTOE    \
        -DDHD_BCMEVENTS -DSHOW_EVENTS -DDONGLEOVERLAYS -DBCMDBG               \
        -DCUSTOMER_HW_SAMSUNG -DOOB_INTR_ONLY                                 \
        -DMMC_SDIO_ABORT -DBCMSDIO -DBCMLXSDMMC -DBCMPLATFORM_BUS -DWLP2P     \
        -DNEW_COMPAT_WIRELESS -DWIFI_ACT_FRAME -DARP_OFFLOAD_SUPPORT          \
        -DKEEP_ALIVE -DCSCAN -DPKT_FILTER_SUPPORT                             \
        -DEMBEDDED_PLATFORM -DPNO_SUPPORT

# distinguish between the 43xx chip
ifeq ($(CONFIG_BCM4334),m)
DHDCFLAGS += -DBCM4334_CHIP -DHW_OOB -DBCM4334_CHECK_CHIP_REV
DHDCFLAGS += -DUSE_CID_CHECK -DCONFIG_CONTROL_PM
DHDCFLAGS += -DPROP_TXSTATUS
DHDCFLAGS += -DVSDB -DHT40_GO
DHDCFLAGS += -DWL_CFG80211_VSDB_PRIORITIZE_SCAN_REQUEST
DHDCFLAGS += -DDHD_USE_IDLECOUNT
endif
ifeq ($(CONFIG_BCM4334),y)
DHDCFLAGS += -DBCM4334_CHIP -DHW_OOB -DBCM4334_CHECK_CHIP_REV
DHDCFLAGS += -DUSE_CID_CHECK -DCONFIG_CONTROL_PM
DHDCFLAGS += -DPROP_TXSTATUS
DHDCFLAGS += -DVSDB -DHT40_GO
DHDCFLAGS += -DWL_CFG80211_VSDB_PRIORITIZE_SCAN_REQUEST
DHDCFLAGS += -DDHD_USE_IDLECOUNT
endif
ifeq ($(CONFIG_BCM4330),m)
DHDCFLAGS += -DBCM4330_CHIP
DHDCFLAGS += -DMCAST_LIST_ACCUMULATION
DHDCFLAGS += -DCONFIG_CONTROL_PM
endif

ifeq ($(CONFIG_BCM4330),y)
DHDCFLAGS += -DBCM4330_CHIP
DHDCFLAGS += -DMCAST_LIST_ACCUMULATION
DHDCFLAGS += -DCONFIG_CONTROL_PM
endif
ifeq ($(CONFIG_BCM43241),m)
DHDCFLAGS += -DBCM43241_CHIP -DHW_OOB
DHDCFLAGS += -DMCAST_LIST_ACCUMULATION
DHDCFLAGS += -fno-pic
endif
ifeq ($(CONFIG_BCM43241),y)
DHDCFLAGS += -DBCM43241_CHIP -DHW_OOB
DHDCFLAGS += -DMCAST_LIST_ACCUMULATION
endif

# For p2p connection issue
DHDCFLAGS += -DWL_CFG80211_GON_COLLISION
DHDCFLAGS += -DWL_CFG80211_SYNC_GON_TIME
#end p2p connection

# For Passing all multicast packets to host when not in suspend mode.
DHDCFLAGS += -DPASS_ALL_MCAST_PKTS

#For INITIAL 2G scan features
#select only one from USE_INIITAL_2G_SCAN and INITIAL_2G_SCAN_ORG

DHDCFLAGS += -DUSE_INITIAL_2G_SCAN
#DHDCFLAGS += -DUSE_INITIAL_2G_SCAN_ORG

DHDCFLAGS +=-DINITIAL_2G_SCAN_BY_ESCAN

# For Scan result patch
DHDCFLAGS += -DESCAN_RESULT_PATCH

ifeq ($(CONFIG_MACH_SAMSUNG_T1),y)
DHDCFLAGS += -DUSE_CID_CHECK -DWRITE_MACADDR
endif

DHDCFLAGS += -DROAM_ENABLE -DROAM_CHANNEL_CACHE -DROAM_API

# For Static Buffer
ifeq ($(CONFIG_BROADCOM_WIFI_RESERVED_MEM),y)
DHDCFLAGS += -DCONFIG_DHD_USE_STATIC_BUF
endif

# For CCX
ifneq ($(CONFIG_TARGET_LOCALE_KOR),y)
DHDCFLAGS += -DBCMCCX
endif

# For SLP feature
ifeq ($(CONFIG_SLP),y)
DHDCFLAGS += -DSLP_PATH -DWRITE_MACADDR
endif

# 5GHz channels setting
ifeq ($(CONFIG_WLAN_COUNTRY_CODE),y)
DHDCFLAGS += -DGLOBALCONFIG_WLAN_COUNTRY_CODE
endif

# For ICS SEC Features
ifneq ($(findstring GlobalConfig, $(wildcard $(srctree)/include/sec_feature/*)),)
DHDCFLAGS += -DUSE_SECFEATURE
endif

##############################################################
# dhd_sec_feature.h

REGION_CODE := $(CONFIG_WLAN_REGION_CODE)

ifeq ($(CONFIG_TARGET_LOCALE_KOR),y)
REGION_CODE=200
endif

ifeq ($(CONFIG_MACH_U1_KOR_KT), y)
REGION_CODE=202
endif

ifeq ($(CONFIG_TARGET_LOCALE_CHN),y)
REGION_CODE=300
endif

ifeq ($(SEC_MODEL_NAME),U1)
ifeq ($(X_BUILD_LOCALE),EUR_ORG)
REGION_CODE=101
endif
endif

DHDCFLAGS += -DWLAN_REGION_CODE=$(REGION_CODE)

##############################################################

# For Debug
EXTRA_CFLAGS += $(DHDCFLAGS) -DWL_CFG80211 -DRSSI_OFFSET=0
EXTRA_CFLAGS += -DDHD_DEBUG -DSRCBASE=\"$(src)/src\"

EXTRA_CFLAGS += -I$(src)/src/include/
EXTRA_CFLAGS += -I$(src)/src/dhd/sys/
EXTRA_CFLAGS += -I$(src)/src/dongle/
EXTRA_CFLAGS += -I$(src)/src/bcmsdio/sys/
EXTRA_CFLAGS += -I$(src)/src/wl/sys/
EXTRA_CFLAGS += -I$(src)/src/shared/
EXTRA_CFLAGS += -I$(src)/src/wl/bcmwifi/src/
EXTRA_CFLAGS += -I$(src)/src/wl/bcmwifi/include/

EXTRA_LDFLAGS += --strip-debug
KBUILD_CFLAGS += -I$(LINUXDIR)/include -I$(shell pwd)

obj-m   += dhd.o

dhd-y := src/bcmsdio/sys/bcmsdh.o	src/bcmsdio/sys/bcmsdh_linux.o \
	 src/bcmsdio/sys/bcmsdh_sdmmc.o	src/bcmsdio/sys/bcmsdh_sdmmc_linux.o \
	 src/dhd/sys/dhd_bta.o		src/dhd/sys/dhd_cdc.o \
	 src/dhd/sys/dhd_common.o	src/dhd/sys/dhd_custom_gpio.o \
	 src/dhd/sys/dhd_custom_sec.o \
	 src/dhd/sys/dhd_linux.o	src/dhd/sys/dhd_linux_sched.o \
	 src/dhd/sys/dhd_cfg80211.o	src/dhd/sys/dhd_sdio.o \
	 src/shared/aiutils.o		src/shared/bcmevent.o \
	 src/shared/bcmutils.o		src/wl/bcmwifi/src/bcmwifi_channels.o \
	 src/shared/hndpmu.o		src/shared/linux_osl.o \
	 src/shared/sbutils.o		src/shared/siutils.o \
	 src/wl/sys/wl_android.o	src/wl/sys/wl_cfg80211.o \
	 src/wl/sys/wl_cfgp2p.o		src/wl/sys/wldev_common.o \
	 src/wl/sys/wl_linux_mon.o	src/wl/sys/wl_roam.o \
	 src/dhd/sys/bcmon.o

all:
	@echo "$(MAKE) --no-print-directory -C $(KDIR) SUBDIRS=$(CURDIR) modules"
	@$(MAKE) --no-print-directory -C $(KDIR) \
		SUBDIRS=$(CURDIR) modules

clean:
	rm -rf *.o *.ko *.mod.c *~ .*.cmd \
	Module.symvers modules.order .tmp_versions modules.builtin \
	src/bcmsdio/sys/*.o \
	src/bcmsdio/sys/*.o.cmd \
	src/bcmsdio/sys/.*.o.cmd \
        src/dhd/sys/*.o \
	src/dhd/sys/*.o.cmd \
        src/dhd/sys/.*.o.cmd \
        src/shared/*.o \
	src/shared/*.o.cmd \
        src/shared/.*.o.cmd \
        src/wl/sys/*.o \
        src/wl/sys/*.o.cmd \
	src/wl/sys/.*.o.cmd \
	src/wl/bcmwifi/src/bcmwifi_channels.o \
	src/wl/bcmwifi/src/.*.o.cmd

install:
	@$(MAKE) --no-print-directory -C $(KDIR) \
		SUBDIRS=$(CURDIR) modules_install
