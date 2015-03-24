#define u32 __u32
#define u64 __u64
#define u_int32_t __u32

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "sha1.h"

typedef uint32_t u32;
typedef long long unsigned int u64;

struct initval_family {
	const char *name;
	const char *header_def;
	const char *header_ver;

	void (*print)(bool check);
};

/*
 * compile with -DATHEROS if you want to use the upstream Atheros initvals
 * and have them handy.
 */
#ifndef ATHEROS

#include <ar5008_initvals.h>
#include <ar9001_initvals.h>

#define ar5416Bank0_9100					ar5416Bank0
#define ar5416Bank1_9100					ar5416Bank1
#define ar5416Bank2_9100					ar5416Bank2
#define ar5416Bank3_9100					ar5416Bank3
#define ar5416Bank7_9100					ar5416Bank7
#define ar5416BB_RfGain_9100					ar5416BB_RfGain

#define ar5416Bank0_9160					ar5416Bank0
#define ar5416Bank1_9160					ar5416Bank1
#define ar5416Bank2_9160					ar5416Bank2
#define ar5416Bank3_9160					ar5416Bank3
#define ar5416Bank6_9160					ar5416Bank6
#define ar5416Bank6TPC_9160					ar5416Bank6TPC_9100
#define ar5416Bank7_9160					ar5416Bank7
#define ar5416BB_RfGain_9160					ar5416BB_RfGain

#include <ar9002_initvals.h>

#define ar9285PciePhy_clkreq_always_on_L1_9285			ar9280PciePhy_clkreq_always_on_L1_9280
#define ar9285PciePhy_clkreq_off_L1_9285			ar9280PciePhy_clkreq_off_L1_9280
#define ar9285PciePhy_clkreq_always_on_L1_9285_1_2		ar9280PciePhy_clkreq_always_on_L1_9280
#define ar9285PciePhy_clkreq_off_L1_9285_1_2			ar9280PciePhy_clkreq_off_L1_9280
#define ar9287PciePhy_clkreq_always_on_L1_9287_1_1		ar9280PciePhy_clkreq_always_on_L1_9280
#define ar9287PciePhy_clkreq_off_L1_9287_1_1			ar9280PciePhy_clkreq_off_L1_9280
#define ar9271Common_normal_cck_fir_coeff_9271			ar9287Common_normal_cck_fir_coeff_9287_1_1
#define ar9271Common_japan_2484_cck_fir_coeff_9271		ar9287Common_japan_2484_cck_fir_coeff_9287_1_1

#include <ar9003_2p2_initvals.h>
#include <ar9330_1p1_initvals.h>
#include <ar9330_1p2_initvals.h>
#include <ar9340_initvals.h>
#include <ar9485_initvals.h>
#include <ar955x_1p0_initvals.h>
#include <ar9580_1p0_initvals.h>
#include <ar9462_2p0_initvals.h>
#include <ar9462_2p1_initvals.h>
#include <ar9565_1p0_initvals.h>

#else

#include "ar5416.ini"

#define ar5416Modes						ar5416Modes_9100
#define ar5416Common						ar5416Common_9100
#define ar5416Bank0						ar5416Bank0_9100
#define ar5416BB_RfGain						ar5416BB_RfGain_9100
#define ar5416Bank1						ar5416Bank1_9100
#define ar5416Bank2						ar5416Bank2_9100
#define ar5416Bank3						ar5416Bank3_9100
#define ar5416Bank6						ar5416Bank6_9100
#define ar5416Bank6TPC						ar5416Bank6TPC_9100
#define ar5416Bank7						ar5416Bank7_9100
#define ar5416Addac						ar5416Addac_9100

#include "ar5416_howl.ini"

#undef ar5416Modes
#undef ar5416Common
#undef ar5416Bank0
#undef ar5416BB_RfGain
#undef ar5416Bank1
#undef ar5416Bank2
#undef ar5416Bank3
#undef ar5416Bank6
#undef ar5416Bank6TPC
#undef ar5416Bank7
#undef ar5416Addac

#define ar5416Modes_sowl					ar5416Modes_9160
#define ar5416Common_sowl					ar5416Common_9160
#define ar5416Bank0_sowl					ar5416Bank0_9160
#define ar5416BB_RfGain_sowl					ar5416BB_RfGain_9160
#define ar5416Bank1_sowl					ar5416Bank1_9160
#define ar5416Bank2_sowl					ar5416Bank2_9160
#define ar5416Bank3_sowl					ar5416Bank3_9160
#define ar5416Bank6_sowl					ar5416Bank6_9160
#define ar5416Bank6TPC_sowl					ar5416Bank6TPC_9160
#define ar5416Bank7_sowl					ar5416Bank7_9160
#define ar5416Addac_sowl					ar5416Addac_9160
#define ar5416Addac_sowl1_1					ar5416Addac_9160_1_1

#include "ar5416_sowl.ini"

#define ar9280Modes_merlin2					ar9280Modes_9280_2
#define ar9280Common_merlin2					ar9280Common_9280_2
#define ar9280Modes_fast_clock_merlin2				ar9280Modes_fast_clock_9280_2
#define ar9280Modes_backoff_23db_rxgain_merlin2			ar9280Modes_backoff_23db_rxgain_9280_2
#define ar9280Modes_original_rxgain_merlin2			ar9280Modes_original_rxgain_9280_2
#define ar9280Modes_backoff_13db_rxgain_merlin2			ar9280Modes_backoff_13db_rxgain_9280_2
#define ar9280Modes_high_power_tx_gain_merlin2			ar9280Modes_high_power_tx_gain_9280_2
#define ar9280Modes_original_tx_gain_merlin2			ar9280Modes_original_tx_gain_9280_2
#define ar9280Modes_mixed_power_tx_gain_merlin2			ar9280Modes_mixed_power_tx_gain_9280_2
#define ar9280PciePhy_clkreq_off_L1_merlin			ar9280PciePhy_clkreq_off_L1_9280
#define ar9280PciePhy_clkreq_always_on_L1_merlin		ar9280PciePhy_clkreq_always_on_L1_9280
#define ar9280PciePhy_AWOW_merlin				ar9280PciePhy_awow

#include "ar9280_merlin2.ini"

#define ar9285PciePhy_clkreq_always_on_L1_kite			ar9285PciePhy_clkreq_always_on_L1_9285
#define ar9285PciePhy_clkreq_off_L1_kite			ar9285PciePhy_clkreq_off_L1_9285

#include "ar9285.ini"

#define ar9285Modes_kite1_2					ar9285Modes_9285_1_2
#define ar9285Common_kite1_2					ar9285Common_9285_1_2
#define ar9285Modes_high_power_tx_gain_kite1_2			ar9285Modes_high_power_tx_gain_9285_1_2
#define ar9285Modes_original_tx_gain_kite1_2			ar9285Modes_original_tx_gain_9285_1_2
#define ar9285PciePhy_clkreq_always_on_L1_kite1_2		ar9285PciePhy_clkreq_always_on_L1_9285_1_2
#define ar9285PciePhy_clkreq_off_L1_kite1_2			ar9285PciePhy_clkreq_off_L1_9285_1_2
#define ar9285PciePhy_AWOW_kite1_2				ar9285PciePhy_AWOW_9285_1_2

#define ar9285Modes_Elijah2_0_normal_power			ar9285Modes_XE2_0_normal_power
#define ar9285Modes_Elijah2_0_high_power			ar9285Modes_XE2_0_high_power

#include "ar9285_v1_2.ini"

#define ar9287Modes_kiwi1_1					ar9287Modes_9287_1_1
#define ar9287Common_kiwi1_1					ar9287Common_9287_1_1
#define ar9287Common_normal_cck_fir_coeff_kiwi1_1		ar9287Common_normal_cck_fir_coeff_9287_1_1
#define ar9287Common_japan_2484_cck_fir_coeff_kiwi1_1		ar9287Common_japan_2484_cck_fir_coeff_9287_1_1
#define ar9287Modes_tx_gain_kiwi1_1				ar9287Modes_tx_gain_9287_1_1
#define ar9287Modes_rx_gain_kiwi1_1				ar9287Modes_rx_gain_9287_1_1
#define ar9287PciePhy_clkreq_always_on_L1_kiwi1_1		ar9287PciePhy_clkreq_always_on_L1_9287_1_1
#define ar9287PciePhy_clkreq_off_L1_kiwi1_1			ar9287PciePhy_clkreq_off_L1_9287_1_1
#define ar9287PciePhy_AWOW_kiwi1_1				ar9287PciePhy_AWOW_9287_1_1

#include "ar9287_1_1.ini"

#define ar9271Modes_K2						ar9271Modes_9271
#define ar9271Common_K2						ar9271Common_9271
#define ar9271Common_normal_cck_fir_coeff_K2			ar9271Common_normal_cck_fir_coeff_9271
#define ar9271Common_japan_2484_cck_fir_coeff_K2		ar9271Common_japan_2484_cck_fir_coeff_9271
#define ar9271Modes_K2_1_0_only					ar9271Modes_9271_1_0_only
#define ar9271Modes_K2_ANI_reg					ar9271Modes_9271_ANI_reg
#define ar9271Modes_normal_power_tx_gain_K2			ar9271Modes_normal_power_tx_gain_9271
#define ar9271Modes_high_power_tx_gain_K2			ar9271Modes_high_power_tx_gain_9271

#include "ar9271.ini"


/* This is what these are called on the Atheros HAL */

/* AR9003 2.2 */
#define ar9300_osprey_2p2_radio_postamble			ar9300_2p2_radio_postamble
#define ar9300_modes_lowest_ob_db_tx_gain_table_osprey_2p2	ar9300Modes_lowest_ob_db_tx_gain_table_2p2
#define ar9300Modes_fast_clock_osprey_2p2			ar9300Modes_fast_clock_2p2
#define ar9300_osprey_2p2_radio_core				ar9300_2p2_radio_core
#define ar9300_osprey_2p2_mac_postamble				ar9300_2p2_mac_postamble
#define ar9300_osprey_2p2_soc_postamble				ar9300_2p2_soc_postamble
#define ar9300_osprey_2p2_baseband_postamble			ar9300_2p2_baseband_postamble
#define ar9300_osprey_2p2_baseband_core				ar9300_2p2_baseband_core
#define ar9300Modes_high_power_tx_gain_table_osprey_2p2		ar9300Modes_high_power_tx_gain_table_2p2
#define ar9300Modes_high_ob_db_tx_gain_table_osprey_2p2		ar9300Modes_high_ob_db_tx_gain_table_2p2
#define ar9300_common_rx_gain_table_osprey_2p2			ar9300Common_rx_gain_table_2p2
#define ar9300Modes_low_ob_db_tx_gain_table_osprey_2p2		ar9300Modes_low_ob_db_tx_gain_table_2p2
#define ar9300_osprey_2p2_mac_core				ar9300_2p2_mac_core
#define ar9300Common_wo_xlna_rx_gain_table_osprey_2p2		ar9300Common_wo_xlna_rx_gain_table_2p2
#define ar9300_osprey_2p2_soc_preamble				ar9300_2p2_soc_preamble
#define ar9300PciePhy_pll_on_clkreq_disable_L1_osprey_2p2	ar9300PciePhy_pll_on_clkreq_disable_L1_2p2
#define ar9300PciePhy_clkreq_enable_L1_osprey_2p2		ar9300PciePhy_clkreq_enable_L1_2p2
#define ar9300PciePhy_clkreq_disable_L1_osprey_2p2		ar9300PciePhy_clkreq_disable_L1_2p2

#include "ar9300_osprey22.ini"

#define ar9331_modes_lowest_ob_db_tx_gain_hornet1_1		ar9331_modes_lowest_ob_db_tx_gain_1p1
#define ar9331_hornet1_1_baseband_postamble			ar9331_1p1_baseband_postamble
#define ar9331_modes_high_ob_db_tx_gain_hornet1_1		ar9331_modes_high_ob_db_tx_gain_1p1
#define ar9331_modes_low_ob_db_tx_gain_hornet1_1		ar9331_modes_low_ob_db_tx_gain_1p1
#define ar9331_hornet1_1_baseband_core_txfir_coeff_japan_2484	ar9331_1p1_baseband_core_txfir_coeff_japan_2484
#define ar9331_hornet1_1_xtal_25M				ar9331_1p1_xtal_25M
#define ar9331_hornet1_1_radio_core				ar9331_1p1_radio_core
#define ar9331_hornet1_1_soc_postamble				ar9331_1p1_soc_postamble
#define ar9331_common_wo_xlna_rx_gain_hornet1_1			ar9331_common_wo_xlna_rx_gain_1p1
#define ar9331_hornet1_1_baseband_core				ar9331_1p1_baseband_core
#define ar9331_modes_high_power_tx_gain_hornet1_1		ar9331_modes_high_power_tx_gain_1p1
#define ar9331_hornet1_1_mac_postamble				ar9331_1p1_mac_postamble
#define ar9331_hornet1_1_soc_preamble				ar9331_1p1_soc_preamble
#define ar9331_hornet1_1_xtal_40M				ar9331_1p1_xtal_40M
#define ar9331_hornet1_1_mac_core				ar9331_1p1_mac_core
#define ar9331_common_rx_gain_hornet1_1				ar9331_common_rx_gain_1p1
#define ar9331_common_tx_gain_offset1_1				ar9331_common_tx_gain_offset1_1

#include "ar9330_11.ini"

#define ar9331_modes_lowest_ob_db_tx_gain_hornet1_2		ar9331_modes_lowest_ob_db_tx_gain_1p2
#define ar9331_hornet1_2_baseband_postamble			ar9331_1p2_baseband_postamble
#define ar9331_modes_high_ob_db_tx_gain_hornet1_2		ar9331_modes_high_ob_db_tx_gain_1p2
#define ar9331_modes_low_ob_db_tx_gain_hornet1_2		ar9331_modes_low_ob_db_tx_gain_1p2
#define ar9331_hornet1_2_baseband_core_txfir_coeff_japan_2484	ar9331_1p2_baseband_core_txfir_coeff_japan_2484
#define ar9331_hornet1_2_xtal_25M				ar9331_1p2_xtal_25M
#define ar9331_hornet1_2_radio_core				ar9331_1p2_radio_core
#define ar9331_hornet1_2_soc_postamble				ar9331_1p2_soc_postamble
#define ar9331_common_wo_xlna_rx_gain_hornet1_2			ar9331_common_wo_xlna_rx_gain_1p2
#define ar9331_hornet1_2_baseband_core				ar9331_1p2_baseband_core
#define ar9331_modes_high_power_tx_gain_hornet1_2		ar9331_modes_high_power_tx_gain_1p2
#define ar9331_hornet1_2_mac_postamble				ar9331_1p2_mac_postamble
#define ar9331_hornet1_2_soc_preamble				ar9331_1p2_soc_preamble
#define ar9331_hornet1_2_xtal_40M				ar9331_1p2_xtal_40M
#define ar9331_hornet1_2_mac_core				ar9331_1p2_mac_core
#define ar9331_common_rx_gain_hornet1_2				ar9331_common_rx_gain_1p2
#define ar9331_common_tx_gain_offset1_2				ar9331_common_tx_gain_offset1_2

#include "ar9330_12.ini"

#define ar9485_poseidon1_1_mac_postamble			ar9485_1_1_mac_postamble
#define ar9485_poseidon1_1_pcie_phy_pll_on_clkreq_disable_L1	ar9485_1_1_pcie_phy_pll_on_clkreq_disable_L1
#define ar9485_common_wo_xlna_rx_gain_poseidon1_1		ar9485Common_wo_xlna_rx_gain_1_1
#define ar9485_modes_high_power_tx_gain_poseidon1_1		ar9485Modes_high_power_tx_gain_1_1
#define ar9485_poseidon1_1					ar9485_1_1
#define ar9485_poseidon1_1_radio_core				ar9485_1_1_radio_core
#define ar9485_modes_lowest_ob_db_tx_gain_poseidon1_1		ar9485_modes_lowest_ob_db_tx_gain_1_1
#define ar9485_poseidon1_1_baseband_core			ar9485_1_1_baseband_core
#define ar9485_modes_high_ob_db_tx_gain_poseidon1_1		ar9485Modes_high_ob_db_tx_gain_1_1
#define ar9485_common_rx_gain_poseidon1_1			ar9485_common_rx_gain_1_1
#define ar9485_poseidon1_1_pcie_phy_clkreq_enable_L1		ar9485_1_1_pcie_phy_clkreq_enable_L1
#define ar9485_fast_clock_poseidon1_1_baseband_postamble	ar9485_fast_clock_1_1_baseband_postamble
#define ar9485_poseidon1_1_soc_preamble				ar9485_1_1_soc_preamble
#define ar9485_poseidon1_1_baseband_postamble			ar9485_1_1_baseband_postamble
#define ar9485_poseidon1_1_pcie_phy_pll_on_clkreq_enable_L1	ar9485_1_1_pcie_phy_pll_on_clkreq_enable_L1
#define ar9485_modes_low_ob_db_tx_gain_poseidon1_1		ar9485Modes_low_ob_db_tx_gain_1_1
#define ar9485_poseidon1_1_pcie_phy_clkreq_disable_L1		ar9485_1_1_pcie_phy_clkreq_disable_L1
#define ar9485_poseidon1_1_radio_postamble			ar9485_1_1_radio_postamble
#define ar9485_poseidon1_1_mac_core				ar9485_1_1_mac_core
#define ar9485_poseidon1_1_baseband_core_txfir_coeff_japan_2484 ar9485_1_1_baseband_core_txfir_coeff_japan_2484

#include "ar9485_1_1.ini"

#define ar955x_scorpion_1p0_radio_postamble			ar955x_1p0_radio_postamble
#define ar955x_scorpion_1p0_baseband_core_txfir_coeff_japan_2484 ar955x_1p0_baseband_core_txfir_coeff_japan_2484
#define ar955x_scorpion_1p0_baseband_postamble			ar955x_1p0_baseband_postamble
#define ar955x_scorpion_1p0_radio_core				ar955x_1p0_radio_core
#define ar955xModes_xpa_tx_gain_table_scorpion_1p0		ar955x_1p0_modes_xpa_tx_gain_table
#define ar955x_scorpion_1p0_mac_core				ar955x_1p0_mac_core
#define ar955xCommon_rx_gain_table_scorpion_1p0			ar955x_1p0_common_rx_gain_table
#define ar955x_scorpion_1p0_baseband_core			ar955x_1p0_baseband_core
#define ar955xCommon_wo_xlna_rx_gain_table_scorpion_1p0		ar955x_1p0_common_wo_xlna_rx_gain_table
#define ar955x_scorpion_1p0_soc_preamble			ar955x_1p0_soc_preamble
#define ar955xCommon_wo_xlna_rx_gain_bounds_scorpion_1p0	ar955x_1p0_common_wo_xlna_rx_gain_bounds
#define ar955x_scorpion_1p0_mac_postamble			ar955x_1p0_mac_postamble
#define ar955xCommon_rx_gain_bounds_scorpion_1p0		ar955x_1p0_common_rx_gain_bounds
#define ar955xModes_no_xpa_tx_gain_table_scorpion_1p0		ar955x_1p0_modes_no_xpa_tx_gain_table
#define ar955x_scorpion_1p0_soc_postamble			ar955x_1p0_soc_postamble
#define ar955xModes_fast_clock_scorpion_1p0			ar955x_1p0_modes_fast_clock

#include "ar955x.ini"

#define ar9300Modes_fast_clock_ar9580_1p0			ar9580_1p0_modes_fast_clock
#define ar9300_ar9580_1p0_radio_postamble			ar9580_1p0_radio_postamble
#define ar9300_ar9580_1p0_baseband_core				ar9580_1p0_baseband_core
#define ar9300_ar9580_1p0_mac_postamble				ar9580_1p0_mac_postamble
#define ar9300Modes_low_ob_db_tx_gain_table_ar9580_1p0		ar9580_1p0_low_ob_db_tx_gain_table
#define ar9300Modes_high_power_tx_gain_table_ar9580_1p0		ar9580_1p0_high_power_tx_gain_table
#define ar9300Modes_lowest_ob_db_tx_gain_table_ar9580_1p0	ar9580_1p0_lowest_ob_db_tx_gain_table
#define ar9300_ar9580_1p0_baseband_core_txfir_coeff_japan_2484	ar9580_1p0_baseband_core_txfir_coeff_japan_2484
#define ar9300_ar9580_1p0_mac_core				ar9580_1p0_mac_core
#define ar9300_modes_mixed_ob_db_tx_gain_table_ar9580_1p0	ar9580_1p0_mixed_ob_db_tx_gain_table
#define ar9300_common_wo_xlna_rx_gain_table_ar9580_1p0		ar9580_1p0_wo_xlna_rx_gain_table
#define ar9300_ar9580_1p0_soc_postamble				ar9580_1p0_soc_postamble
#define ar9300Modes_high_ob_db_tx_gain_table_ar9580_1p0		ar9580_1p0_high_ob_db_tx_gain_table
#define ar9300_ar9580_1p0_soc_preamble				ar9580_1p0_soc_preamble
#define ar9300_common_rx_gain_table_ar9580_1p0			ar9580_1p0_rx_gain_table
#define ar9300_ar9580_1p0_radio_core				ar9580_1p0_radio_core
#define ar9300_ar9580_1p0_baseband_postamble			ar9580_1p0_baseband_postamble
#define ar9300PciePhy_clkreq_enable_L1_ar9580_1p0		ar9580_1p0_pcie_phy_clkreq_enable_L1
#define ar9300PciePhy_clkreq_disable_L1_ar9580_1p0		ar9580_1p0_pcie_phy_clkreq_disable_L1
#define ar9300PciePhy_pll_on_clkreq_disable_L1_ar9580_1p0	ar9580_1p0_pcie_phy_pll_on_clkreq

#include "ar9580.ini"

#define ar9300Modes_fast_clock_jupiter_2p0			ar9462_modes_fast_clock_2p0
#define ar9300_PciePhy_clkreq_enable_L1_jupiter_2p0		ar9462_pciephy_clkreq_enable_L1_2p0
#define ar9300_PciePhy_clkreq_disable_L1_jupiter_2p0		ar9462_pciephy_clkreq_disable_L1_2p0
#define ar9300_jupiter_2p0_baseband_postamble			ar9462_2p0_baseband_postamble
#define ar9300Common_rx_gain_table_jupiter_2p0			ar9462_common_rx_gain_table_2p0
#define ar9300_PciePhy_pll_on_clkreq_disable_L1_jupiter_2p0	ar9462_pciephy_pll_on_clkreq_disable_L1_2p0
#define ar9300_jupiter_2p0_radio_postamble_sys2ant		ar9462_2p0_radio_postamble_sys2ant
#define ar9300Common_wo_xlna_rx_gain_table_jupiter_2p0		ar9462_common_wo_xlna_rx_gain_table_2p0
#define ar9300_jupiter_2p0_baseband_core_txfir_coeff_japan_2484 ar9462_2p0_baseband_core_txfir_coeff_japan_2484
#define ar9300Modes_low_ob_db_tx_gain_table_jupiter_2p0		ar9462_modes_low_ob_db_tx_gain_table_2p0
#define ar9300_jupiter_2p0_soc_postamble			ar9462_2p0_soc_postamble
#define ar9300_jupiter_2p0_baseband_core			ar9462_2p0_baseband_core
#define ar9300_jupiter_2p0_radio_postamble			ar9462_2p0_radio_postamble
#define ar9300Modes_mix_ob_db_tx_gain_table_jupiter_2p0         ar9462_modes_mix_ob_db_tx_gain_table_2p0
#define ar9300Modes_high_ob_db_tx_gain_table_jupiter_2p0	ar9462_modes_high_ob_db_tx_gain_table_2p0
#define ar9300_jupiter_2p0_radio_core				ar9462_2p0_radio_core
#define ar9300_jupiter_2p0_soc_preamble				ar9462_2p0_soc_preamble
#define ar9300_jupiter_2p0_mac_core				ar9462_2p0_mac_core
#define ar9300_jupiter_2p0_mac_postamble			ar9462_2p0_mac_postamble
#define ar9300Common_mixed_rx_gain_table_jupiter_2p0		ar9462_common_mixed_rx_gain_table_2p0
#define ar9300_jupiter_2p0_baseband_postamble_5g_xlna		ar9462_2p0_baseband_postamble_5g_xlna
#define ar9300Common_5g_xlna_only_rx_gain_table_jupiter_2p0	ar9462_2p0_5g_xlna_only_rxgain
#define ar9300_jupiter_2p0_baseband_core_mix_rxgain		ar9462_2p0_baseband_core_mix_rxgain
#define ar9300_jupiter_2p0_baseband_postamble_mix_rxgain	ar9462_2p0_baseband_postamble_mix_rxgain

#include "ar9300_jupiter20.ini"

#define ar9300_jupiter_2p1_mac_core                             ar9462_2p1_mac_core
#define ar9300_jupiter_2p1_mac_postamble                        ar9462_2p1_mac_postamble
#define ar9300_jupiter_2p1_baseband_core                        ar9462_2p1_baseband_core
#define ar9300_jupiter_2p1_baseband_postamble                   ar9462_2p1_baseband_postamble
#define ar9300_jupiter_2p1_radio_core                           ar9462_2p1_radio_core
#define ar9300_jupiter_2p1_radio_postamble                      ar9462_2p1_radio_postamble
#define ar9300_jupiter_2p1_soc_preamble                         ar9462_2p1_soc_preamble
#define ar9300_jupiter_2p1_soc_postamble                        ar9462_2p1_soc_postamble
#define ar9300_jupiter_2p1_radio_postamble_sys2ant              ar9462_2p1_radio_postamble_sys2ant
#define ar9300Common_rx_gain_table_jupiter_2p1                  ar9462_2p1_common_rx_gain
#define ar9300Common_mixed_rx_gain_table_jupiter_2p1            ar9462_2p1_common_mixed_rx_gain
#define ar9300_jupiter_2p1_baseband_core_mix_rxgain             ar9462_2p1_baseband_core_mix_rxgain
#define ar9300_jupiter_2p1_baseband_postamble_mix_rxgain        ar9462_2p1_baseband_postamble_mix_rxgain
#define ar9300_jupiter_2p1_baseband_postamble_5g_xlna           ar9462_2p1_baseband_postamble_5g_xlna
#define ar9300Common_wo_xlna_rx_gain_table_jupiter_2p1          ar9462_2p1_common_wo_xlna_rx_gain
#define ar9300Common_5g_xlna_only_rx_gain_table_jupiter_2p1     ar9462_2p1_common_5g_xlna_only_rx_gain
#define ar9300Modes_low_ob_db_tx_gain_table_jupiter_2p1         ar9462_2p1_modes_low_ob_db_tx_gain
#define ar9300Modes_high_ob_db_tx_gain_table_jupiter_2p1        ar9462_2p1_modes_high_ob_db_tx_gain
#define ar9300Modes_mix_ob_db_tx_gain_table_jupiter_2p1         ar9462_2p1_modes_mix_ob_db_tx_gain
#define ar9300Modes_fast_clock_jupiter_2p1                      ar9462_2p1_modes_fast_clock
#define ar9300_jupiter_2p1_baseband_core_txfir_coeff_japan_2484 ar9462_2p1_baseband_core_txfir_coeff_japan_2484

#include "ar9300_jupiter21.ini"

#define ar9340_wasp_1p0_radio_postamble				ar9340_1p0_radio_postamble
#define ar9340Modes_lowest_ob_db_tx_gain_table_wasp_1p0		ar9340Modes_lowest_ob_db_tx_gain_table_1p0
#define ar9340Modes_fast_clock_wasp_1p0				ar9340Modes_fast_clock_1p0
#define ar9340_wasp_1p0_radio_core				ar9340_1p0_radio_core
#define ar9340_wasp_1p0_radio_core_40M				ar9340_1p0_radio_core_40M
#define ar9340_wasp_1p0_mac_postamble				ar9340_1p0_mac_postamble
#define ar9340_wasp_1p0_soc_postamble				ar9340_1p0_soc_postamble
#define ar9340_wasp_1p0_baseband_postamble			ar9340_1p0_baseband_postamble
#define ar9340_wasp_1p0_baseband_core				ar9340_1p0_baseband_core
#define ar9340Modes_high_power_tx_gain_table_wasp_1p0		ar9340Modes_high_power_tx_gain_table_1p0
#define ar9340Modes_high_ob_db_tx_gain_table_wasp_1p0		ar9340Modes_high_ob_db_tx_gain_table_1p0
#define ar9340_modes_ub124_tx_gain_table_wasp_1p0		ar9340Modes_ub124_tx_gain_table_1p0
#define ar9340Common_rx_gain_table_wasp_1p0			ar9340Common_rx_gain_table_1p0
#define ar9340Modes_low_ob_db_tx_gain_table_wasp_1p0		ar9340Modes_low_ob_db_tx_gain_table_1p0
#define ar9340Modes_mixed_ob_db_tx_gain_table_wasp_1p0		ar9340Modes_mixed_ob_db_tx_gain_table_1p0
#define ar9340_wasp_1p0_mac_core				ar9340_1p0_mac_core
#define ar9340Common_wo_xlna_rx_gain_table_wasp_1p0		ar9340Common_wo_xlna_rx_gain_table_1p0
#define ar9340_wasp_1p0_soc_preamble				ar9340_1p0_soc_preamble

#include "ar9300_aphrodite10.ini"

#define ar9565_1p0_tx_gain_table_baseband_postamble_emulation	ar956X_aphrodite_1p0_tx_gain_table_baseband_postamble_emulation
#define ar9565_1p0_baseband_core				ar956X_aphrodite_1p0_baseband_core
#define ar9565_1p0_modes_fast_clock				ar956XModes_fast_clock_aphrodite_1p0
#define ar9565_1p0_common_wo_xlna_rx_gain_table			ar956XCommon_wo_xlna_rx_gain_table_aphrodite_1p0
#define ar9565_1p0_mac_core_emulation				ar956X_aphrodite_1p0_mac_core_emulation
#define ar9565_1p0_modes_low_ob_db_tx_gain_table		ar956XModes_low_ob_db_tx_gain_table_aphrodite_1p0
#define ar9565_1p0_Modes_lowest_ob_db_tx_gain_table		ar956XModes_lowest_ob_db_tx_gain_table_aphrodite_1p0
#define ar9565_1p0_mac_core					ar956X_aphrodite_1p0_mac_core
#define ar9565_1p0_baseband_core_txfir_coeff_japan_2484		ar956X_aphrodite_1p0_baseband_core_txfir_coeff_japan_2484
#define ar9565_1p0_mac_postamble_emulation			ar956X_aphrodite_1p0_mac_postamble_emulation
#define ar9565_1p0_glb_wlan_bt					ar956X_glb_wlan_bt_aphrodite_1p0
#define ar9565_1p0_pciephy_clkreq_enable_L1			ar956X_PciePhy_clkreq_enable_L1_aphrodite_1p0
#define ar9565_1p0_modes_high_power_tx_gain_table		ar956XModes_high_power_tx_gain_table_aphrodite_1p0
#define ar9565_1p0_modes_high_ob_db_tx_gain_table		ar956XModes_high_ob_db_tx_gain_table_aphrodite_1p0
#define ar9200_9280_2p0_9565_radio_core				ar9200_merlin_2p0_aphrodite_radio_core
#define ar9565_1p0_Common_rx_gain_table_9280_2p0		ar956XCommon_rx_gain_table_merlin_2p0
#define ar9565_1p0_PciePhy_clkreq_disable_L1			ar956X_PciePhy_clkreq_disable_L1_aphrodite_1p0
#define ar9565_1p0_baseband_core_emulation			ar956X_aphrodite_1p0_baseband_core_emulation
#define ar9565_1p0_soc_preamble					ar956X_aphrodite_1p0_soc_preamble
#define ar9565_1p0_soc_postamble				ar956X_aphrodite_1p0_soc_postamble
#define ar9565_1p0_mac_postamble				ar956X_aphrodite_1p0_mac_postamble
#define ar9565_1p0_radio_postamble				ar956X_aphrodite_1p0_radio_postamble
#define ar9565_1p0_Common_rx_gain_table				ar956XCommon_rx_gain_table_aphrodite_1p0
#define ar9565_1p0_pciephy_clkreq_disable_L1			ar956X_PciePhy_pll_on_clkreq_disable_L1_aphrodite_1p0
#define ar9565_1p0_baseband_postamble_emulation			ar956X_aphrodite_1p0_baseband_postamble_emulation
#define ar9565_1p0_radio_core					ar956X_aphrodite_1p0_radio_core
#define ar9565_1p0_baseband_postamble				ar956X_aphrodite_1p0_baseband_postamble

#include "ar9340.ini"

#endif /* ATHEROS */

#define INI_PRINT_DUP(_array, _ref) do { \
	if (check) { \
		char *sha1sum; \
		sha1sum = ath9k_hw_check_initval(#_array, \
						(const u32 *) &_array,\
						ARRAY_SIZE(_array), \
						ARRAY_SIZE((_array)[0])); \
		printf("%s        "#_array"\n", sha1sum); \
	} else { \
		if (sizeof(_ref) == sizeof(_array) && \
		    !memcmp(&_ref, &_array, sizeof(_ref))) { \
			printf("#define " #_array " " #_ref "\n\n"); \
			break; \
		} \
		ath9k_hw_print_initval(#_array, (const u32 *) _array, \
				       ARRAY_SIZE(_array), \
				       ARRAY_SIZE((_array)[0]), \
				       false); \
	} \
    } while (0)

/*
 * For some duplicated initval arrays, ath9k directly
 * uses the reference array instead of adding a define.
 * Show a warning message if the given array is not a
 * dupe of the referenced one.
 */
#define INI_PRINT_DUP2(_array, _ref) do { \
	if (check) { \
		char *sha1sum; \
		sha1sum = ath9k_hw_check_initval(#_array, \
						(const u32 *) &_array,\
						ARRAY_SIZE(_array), \
						ARRAY_SIZE((_array)[0])); \
		printf("%s        "#_array"\n", sha1sum); \
	} else { \
		if (sizeof(_ref) != sizeof(_array) || \
		    memcmp(&_ref, &_array, sizeof(_ref))) { \
			printf("#warning " #_array " is not a dupe of " #_ref "\n\n"); \
			break; \
		} \
	} \
    } while (0)

/*
 * Some initval arrays are inlined in the ath9k
 * sources. Keep the symbol, but don't do anything
 * with the array,
 */
#define INI_PRINT_INLINE(_array) do { } while (0)

#define INI_PRINT(_array) do { \
	if (check) { \
		char *sha1sum; \
		sha1sum = ath9k_hw_check_initval(#_array, \
						(const u32 *) &_array,\
						ARRAY_SIZE(_array), \
						ARRAY_SIZE((_array)[0])); \
		printf("%s        " #_array "\n", sha1sum); \
	} else { \
		ath9k_hw_print_initval(#_array, (const u32 *) _array, \
				       ARRAY_SIZE(_array), \
				       ARRAY_SIZE((_array)[0]), \
				       false); \
	} \
    } while (0)


#define INI_PRINT_ONEDIM(_array) do { \
	if (check) { \
		char *sha1sum; \
		sha1sum = ath9k_hw_check_initval((const u32 *) &_array,\
						ARRAY_SIZE(_array), 1, false); \
		printf("%s        "#_array"\n", sha1sum); \
	} else { \
		ath9k_hw_print_initval(#_array, (const u32 *) _array, \
				       ARRAY_SIZE(_array), 1, true, false); \
	} \
    } while (0)

static void print_license(void)
{
	printf("/*\n");
	printf(" * Copyright (c) 2010-2011 Atheros Communications Inc.\n");
	printf(" * Copyright (c) 2011-2012 Qualcomm Atheros Inc.\n");
	printf(" *\n");
	printf(" * Permission to use, copy, modify, and/or distribute this software for any\n");
	printf(" * purpose with or without fee is hereby granted, provided that the above\n");
	printf(" * copyright notice and this permission notice appear in all copies.\n");
	printf(" *\n");
	printf(" * THE SOFTWARE IS PROVIDED \"AS IS\" AND THE AUTHOR DISCLAIMS ALL WARRANTIES\n");
	printf(" * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF\n");
	printf(" * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR\n");
	printf(" * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES\n");
	printf(" * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN\n");
	printf(" * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF\n");
	printf(" * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.\n");
	printf(" */\n");
	printf("\n");
}

static u32 ath9k_patch_initval(u32 idx, u32 val)
{
	switch(idx) {
	/* CRC error fix submitted upstream, but not in Atheros initvals yet */
	case 0x00008264:
		val &= ~(1 << 29);
		break;

	default:
		break;
	}

	return val;
}

static u32 ath9k_get_p_columns(const char *name, u32 columns)
{
	if (columns == 6 && strstr(name, "Modes")) {
		/*
		 * The last column contain values for Turbo mode.
		 * Don't print that because it is not used in ath9k.
		 */
		return 5;
	}

	return columns;
}

static void ath9k_hw_print_initval(const char *name, const u32 *array, u32 rows,
				   u32 columns, bool onedim)
{
	u32 p_columns;
	u32 col, row;

	p_columns = ath9k_get_p_columns(name, columns);

	if (onedim)
		printf("static const u32 %s[] = {\n", name);
	else
		printf("static const u32 %s[][%d] = {\n", name, p_columns);

	switch (p_columns) {
	case 9:
		printf("\t/* Addr      5G_HT20_L   5G_HT40_L   5G_HT20_M   5G_HT40_M   5G_HT20_H   5G_HT40_H   2G_HT40     2G_HT20  */\n");
		break;
	case 5:
		printf("\t/* Addr      5G_HT20     5G_HT40     2G_HT40     2G_HT20   */\n");
		break;
	case 3:
		if (strstr(name, "fast_clock"))
			printf("\t/* Addr      5G_HT20     5G_HT40   */\n");
		else
			printf("\t/* Addr      5G          2G        */\n");
		break;
	case 2:
		printf("\t/* Addr      allmodes  */\n");
		break;
	default:
		break;
	}

	for (row = 0; row < rows; row++) {
		for (col = 0; col < p_columns; col++) {
			u32 idx;
			u32 val;
			if (!col)
				printf("\t%s", onedim ? "" : "{");
			val = array[row * columns + col];
			if (col > 0) {
				idx = array[row * columns];
				val = ath9k_patch_initval(idx, val);
			}
			printf("0x%08x", val);
			if (col + 1 < p_columns)
				printf(", ");
		}
		printf("%s,\n", onedim ? "" : "}");
	}
	printf("};\n\n");
}

static char *ath9k_hw_check_initval(const char *name, const u32 *array,
				    u32 rows, u32 columns)
{
	SHA1_CTX ctx;
	unsigned char digest[SHA1_DIGEST_SIZE];
	static char buf[64];
	u32 p_columns;
	u32 col, row;

	p_columns = ath9k_get_p_columns(name, columns);

	SHA1_Init(&ctx);
	for (row = 0; row < rows; row++) {
		for (col = 0; col < p_columns; col++) {
			unsigned char sha1_buf[4];
			u32 val;

			val = array[row * columns + col];

			sha1_buf[0] = (val >> 24) & 0xff;
			sha1_buf[1] = (val >> 16) & 0xff;
			sha1_buf[2] = (val >> 8) & 0xff;
			sha1_buf[3] = val & 0xff;
			SHA1_Update(&ctx, sha1_buf, sizeof(sha1_buf));
		}
	}

	SHA1_Final(&ctx, digest);
	for (col = 0; col < SHA1_DIGEST_SIZE; col++)
		sprintf(&buf[col * 2], "%02x", digest[col]);
	buf[col * 2] = '\0';

	return buf;
}

static void ar5008_hw_print_initvals(bool check)
{
	INI_PRINT(ar5416Modes);
	INI_PRINT(ar5416Common);
	INI_PRINT(ar5416Bank0);
	INI_PRINT(ar5416BB_RfGain);
	INI_PRINT(ar5416Bank1);
	INI_PRINT(ar5416Bank2);
	INI_PRINT(ar5416Bank3);
	INI_PRINT(ar5416Bank6);
	INI_PRINT(ar5416Bank6TPC);
	INI_PRINT(ar5416Bank7);
	INI_PRINT(ar5416Addac);
}

static void ar9001_hw_print_initvals(bool check)
{
	INI_PRINT(ar5416Modes_9100);
	INI_PRINT(ar5416Common_9100);
	INI_PRINT_DUP2(ar5416Bank0_9100, ar5416Bank0);
	INI_PRINT_DUP2(ar5416BB_RfGain_9100,  ar5416BB_RfGain);
	INI_PRINT_DUP2(ar5416Bank1_9100, ar5416Bank1);
	INI_PRINT_DUP2(ar5416Bank2_9100, ar5416Bank2);
	INI_PRINT_DUP2(ar5416Bank3_9100, ar5416Bank3);
	INI_PRINT(ar5416Bank6_9100);
	INI_PRINT(ar5416Bank6TPC_9100);
	INI_PRINT_DUP2(ar5416Bank7_9100, ar5416Bank7);
	INI_PRINT(ar5416Addac_9100);
	INI_PRINT(ar5416Modes_9160);
	INI_PRINT(ar5416Common_9160);
	INI_PRINT_DUP2(ar5416Bank0_9160, ar5416Bank0);
	INI_PRINT_DUP2(ar5416BB_RfGain_9160, ar5416BB_RfGain);
	INI_PRINT_DUP2(ar5416Bank1_9160, ar5416Bank1);
	INI_PRINT_DUP2(ar5416Bank2_9160, ar5416Bank2);
	INI_PRINT_DUP2(ar5416Bank3_9160, ar5416Bank3);
	INI_PRINT_DUP2(ar5416Bank6_9160, ar5416Bank6);
	INI_PRINT_DUP2(ar5416Bank6TPC_9160, ar5416Bank6TPC_9100);
	INI_PRINT_DUP2(ar5416Bank7_9160, ar5416Bank7);
	INI_PRINT(ar5416Addac_9160);
	INI_PRINT(ar5416Addac_9160_1_1);
}

static void ar9002_hw_print_initvals(bool check)
{
	INI_PRINT(ar9280Modes_9280_2);
	INI_PRINT(ar9280Common_9280_2);
	INI_PRINT(ar9280Modes_fast_clock_9280_2);
	INI_PRINT(ar9280Modes_backoff_23db_rxgain_9280_2);
	INI_PRINT(ar9280Modes_original_rxgain_9280_2);
	INI_PRINT(ar9280Modes_backoff_13db_rxgain_9280_2);
	INI_PRINT(ar9280Modes_high_power_tx_gain_9280_2);
	INI_PRINT(ar9280Modes_original_tx_gain_9280_2);
	INI_PRINT(ar9280PciePhy_clkreq_off_L1_9280);
	INI_PRINT(ar9280PciePhy_clkreq_always_on_L1_9280);
	INI_PRINT(ar9280PciePhy_awow);

	INI_PRINT_DUP2(ar9285PciePhy_clkreq_always_on_L1_9285,
		      ar9280PciePhy_clkreq_always_on_L1_9280);
	INI_PRINT_DUP2(ar9285PciePhy_clkreq_off_L1_9285,
		       ar9280PciePhy_clkreq_off_L1_9280);
	INI_PRINT(ar9285Modes_9285_1_2);
	INI_PRINT(ar9285Common_9285_1_2);
	INI_PRINT(ar9285Modes_high_power_tx_gain_9285_1_2);
	INI_PRINT(ar9285Modes_original_tx_gain_9285_1_2);
	INI_PRINT(ar9285Modes_XE2_0_normal_power);
	INI_PRINT(ar9285Modes_XE2_0_high_power);
	INI_PRINT_DUP2(ar9285PciePhy_clkreq_always_on_L1_9285_1_2,
		      ar9280PciePhy_clkreq_always_on_L1_9280);
	INI_PRINT_DUP2(ar9285PciePhy_clkreq_off_L1_9285_1_2,
		      ar9280PciePhy_clkreq_off_L1_9280);

	INI_PRINT(ar9287Modes_9287_1_1);
	INI_PRINT(ar9287Common_9287_1_1);
	INI_PRINT(ar9287Common_normal_cck_fir_coeff_9287_1_1);
	INI_PRINT(ar9287Common_japan_2484_cck_fir_coeff_9287_1_1);
	INI_PRINT(ar9287Modes_tx_gain_9287_1_1);
	INI_PRINT(ar9287Modes_rx_gain_9287_1_1);
	INI_PRINT_DUP2(ar9287PciePhy_clkreq_always_on_L1_9287_1_1,
		      ar9280PciePhy_clkreq_always_on_L1_9280);
	INI_PRINT_DUP2(ar9287PciePhy_clkreq_off_L1_9287_1_1,
		      ar9280PciePhy_clkreq_off_L1_9280);

	INI_PRINT(ar9271Modes_9271);
	INI_PRINT(ar9271Common_9271);
	INI_PRINT_DUP2(ar9271Common_normal_cck_fir_coeff_9271,
		      ar9287Common_normal_cck_fir_coeff_9287_1_1);
	INI_PRINT_DUP2(ar9271Common_japan_2484_cck_fir_coeff_9271,
		      ar9287Common_japan_2484_cck_fir_coeff_9287_1_1);
	INI_PRINT_INLINE(ar9271Modes_9271_1_0_only);
	INI_PRINT(ar9271Modes_9271_ANI_reg);
	INI_PRINT(ar9271Modes_normal_power_tx_gain_9271);
	INI_PRINT(ar9271Modes_high_power_tx_gain_9271);
}

static void ar9003_2p2_hw_print_initvals(bool check)
{
	INI_PRINT(ar9300_2p2_radio_postamble);
	INI_PRINT(ar9300Modes_lowest_ob_db_tx_gain_table_2p2);
	INI_PRINT(ar9300Modes_fast_clock_2p2);
	INI_PRINT(ar9300_2p2_radio_core);
	INI_PRINT(ar9300_2p2_mac_postamble);
	INI_PRINT(ar9300_2p2_soc_postamble);
	INI_PRINT(ar9300_2p2_baseband_postamble);
	INI_PRINT(ar9300_2p2_baseband_core);
	INI_PRINT(ar9300Modes_high_power_tx_gain_table_2p2);
	INI_PRINT(ar9300Modes_high_ob_db_tx_gain_table_2p2);
	INI_PRINT(ar9300Common_rx_gain_table_2p2);
	INI_PRINT(ar9300Modes_low_ob_db_tx_gain_table_2p2);
	INI_PRINT(ar9300_2p2_mac_core);
	INI_PRINT(ar9300Common_wo_xlna_rx_gain_table_2p2);
	INI_PRINT(ar9300_2p2_soc_preamble);
	INI_PRINT(ar9300PciePhy_pll_on_clkreq_disable_L1_2p2);
	INI_PRINT(ar9300PciePhy_clkreq_enable_L1_2p2);
	INI_PRINT(ar9300PciePhy_clkreq_disable_L1_2p2);
}

static void ar9330_1p1_hw_print_initvals(bool check)
{
	INI_PRINT(ar9331_1p1_baseband_postamble);
	INI_PRINT(ar9331_modes_lowest_ob_db_tx_gain_1p1);
	INI_PRINT(ar9331_modes_high_ob_db_tx_gain_1p1);
	INI_PRINT(ar9331_modes_low_ob_db_tx_gain_1p1);
	INI_PRINT_DUP(ar9331_1p1_baseband_core_txfir_coeff_japan_2484,
		      ar9462_2p0_baseband_core_txfir_coeff_japan_2484);
	INI_PRINT(ar9331_1p1_xtal_25M);
	INI_PRINT(ar9331_1p1_radio_core);
	INI_PRINT(ar9331_1p1_soc_postamble);
	INI_PRINT(ar9331_common_wo_xlna_rx_gain_1p1);
	INI_PRINT(ar9331_1p1_baseband_core);
	INI_PRINT(ar9331_modes_high_power_tx_gain_1p1);
	INI_PRINT_DUP(ar9331_1p1_mac_postamble,
		      ar9300_2p2_mac_postamble);
	INI_PRINT(ar9331_1p1_soc_preamble);
	INI_PRINT(ar9331_1p1_xtal_40M);
	INI_PRINT(ar9331_1p1_mac_core);
	INI_PRINT(ar9331_common_rx_gain_1p1);
	INI_PRINT(ar9331_common_tx_gain_offset1_1);
}

static void ar9330_1p2_hw_print_initvals(bool check)
{
	INI_PRINT(ar9331_modes_high_ob_db_tx_gain_1p2);
	INI_PRINT_DUP(ar9331_modes_high_power_tx_gain_1p2,
		      ar9331_modes_high_ob_db_tx_gain_1p2);
	INI_PRINT_DUP(ar9331_modes_low_ob_db_tx_gain_1p2,
		      ar9331_modes_high_power_tx_gain_1p2);
	INI_PRINT_DUP(ar9331_modes_lowest_ob_db_tx_gain_1p2,
		      ar9331_modes_low_ob_db_tx_gain_1p2);

	INI_PRINT_DUP(ar9331_1p2_baseband_postamble,
		      ar9331_1p1_baseband_postamble);

	INI_PRINT(ar9331_1p2_radio_core);
	INI_PRINT_DUP(ar9331_1p2_baseband_core_txfir_coeff_japan_2484,
		      ar9331_1p1_baseband_core_txfir_coeff_japan_2484);

	INI_PRINT_DUP(ar9331_1p2_xtal_25M, ar9331_1p1_xtal_25M);
	INI_PRINT_DUP(ar9331_1p2_xtal_40M, ar9331_1p1_xtal_40M);

	INI_PRINT_DUP(ar9331_1p2_baseband_core,
		      ar9331_1p1_baseband_core);

	INI_PRINT_DUP(ar9331_1p2_soc_postamble,
		      ar9331_1p1_soc_postamble);

	INI_PRINT_DUP(ar9331_1p2_mac_postamble,
		      ar9331_1p1_mac_postamble);

	INI_PRINT_DUP(ar9331_1p2_soc_preamble,
		      ar9331_1p1_soc_preamble);

	INI_PRINT_DUP(ar9331_1p2_mac_core,
		      ar9331_1p1_mac_core);

	INI_PRINT_DUP(ar9331_common_wo_xlna_rx_gain_1p2,
		      ar9331_common_wo_xlna_rx_gain_1p1);

	INI_PRINT(ar9331_common_rx_gain_1p2);
}

static void ar9340_hw_print_initvals(bool check)
{
	INI_PRINT(ar9340_1p0_radio_postamble);
	INI_PRINT(ar9340Modes_lowest_ob_db_tx_gain_table_1p0);
	INI_PRINT_DUP(ar9340Modes_fast_clock_1p0,
		      ar9300Modes_fast_clock_2p2);
	INI_PRINT(ar9340_1p0_radio_core);
	INI_PRINT(ar9340_1p0_radio_core_40M);
	INI_PRINT_DUP(ar9340_1p0_mac_postamble,
		      ar9300_2p2_mac_postamble);
	INI_PRINT_DUP(ar9340_1p0_soc_postamble,
		      ar9300_2p2_soc_postamble);
	INI_PRINT(ar9340_1p0_baseband_postamble);
	INI_PRINT(ar9340_1p0_baseband_core);
	INI_PRINT(ar9340Modes_high_power_tx_gain_table_1p0);
	INI_PRINT(ar9340Modes_high_ob_db_tx_gain_table_1p0);
	INI_PRINT(ar9340Modes_ub124_tx_gain_table_1p0);
	INI_PRINT(ar9340Common_rx_gain_table_1p0);
	INI_PRINT(ar9340Modes_low_ob_db_tx_gain_table_1p0);
	INI_PRINT(ar9340Modes_mixed_ob_db_tx_gain_table_1p0);
	INI_PRINT(ar9340_1p0_mac_core);
	INI_PRINT_DUP(ar9340Common_wo_xlna_rx_gain_table_1p0,
		      ar9300Common_wo_xlna_rx_gain_table_2p2);
	INI_PRINT(ar9340_1p0_soc_preamble);
}

static void ar9485_hw_print_initvals(bool check)
{
	INI_PRINT_DUP(ar9485_1_1_mac_postamble,
		      ar9300_2p2_mac_postamble);
	INI_PRINT(ar9485_1_1_pcie_phy_pll_on_clkreq_disable_L1);
	INI_PRINT(ar9485Common_wo_xlna_rx_gain_1_1);

	INI_PRINT(ar9485Modes_high_power_tx_gain_1_1);
	INI_PRINT_DUP(ar9485Modes_high_ob_db_tx_gain_1_1,
		      ar9485Modes_high_power_tx_gain_1_1);
	INI_PRINT_DUP(ar9485Modes_low_ob_db_tx_gain_1_1,
		      ar9485Modes_high_ob_db_tx_gain_1_1);
	INI_PRINT_DUP(ar9485_modes_lowest_ob_db_tx_gain_1_1,
		      ar9485Modes_low_ob_db_tx_gain_1_1);

	INI_PRINT(ar9485_1_1);
	INI_PRINT(ar9485_1_1_radio_core);
	INI_PRINT(ar9485_1_1_baseband_core);
	INI_PRINT(ar9485_common_rx_gain_1_1);
	INI_PRINT(ar9485_1_1_pcie_phy_pll_on_clkreq_enable_L1);
	INI_PRINT(ar9485_1_1_pcie_phy_clkreq_enable_L1);
	INI_PRINT(ar9485_1_1_soc_preamble);
	INI_PRINT(ar9485_fast_clock_1_1_baseband_postamble);
	INI_PRINT(ar9485_1_1_baseband_postamble);
	INI_PRINT(ar9485_1_1_pcie_phy_clkreq_disable_L1);
	INI_PRINT(ar9485_1_1_radio_postamble);
	INI_PRINT(ar9485_1_1_mac_core);

	INI_PRINT_DUP(ar9485_1_1_baseband_core_txfir_coeff_japan_2484,
		      ar9462_2p0_baseband_core_txfir_coeff_japan_2484);
}

static void ar955x_1p0_hw_print_initvals(bool check)
{
	INI_PRINT(ar955x_1p0_radio_postamble);
	INI_PRINT(ar955x_1p0_baseband_core_txfir_coeff_japan_2484);
	INI_PRINT(ar955x_1p0_baseband_postamble);
	INI_PRINT(ar955x_1p0_radio_core);
	INI_PRINT(ar955x_1p0_modes_xpa_tx_gain_table);
	INI_PRINT(ar955x_1p0_mac_core);
	INI_PRINT(ar955x_1p0_common_rx_gain_table);
	INI_PRINT(ar955x_1p0_baseband_core);
	INI_PRINT(ar955x_1p0_common_wo_xlna_rx_gain_table);
	INI_PRINT(ar955x_1p0_soc_preamble);
	INI_PRINT(ar955x_1p0_common_wo_xlna_rx_gain_bounds);
	INI_PRINT(ar955x_1p0_mac_postamble);
	INI_PRINT(ar955x_1p0_common_rx_gain_bounds);
	INI_PRINT(ar955x_1p0_modes_no_xpa_tx_gain_table);
	INI_PRINT(ar955x_1p0_soc_postamble);
	INI_PRINT(ar955x_1p0_modes_fast_clock);
}

static void ar9580_1p0_hw_print_initvals(bool check)
{
	INI_PRINT_DUP(ar9580_1p0_modes_fast_clock,
		      ar9300Modes_fast_clock_2p2);
	INI_PRINT(ar9580_1p0_radio_postamble);
	INI_PRINT(ar9580_1p0_baseband_core);
	INI_PRINT_DUP(ar9580_1p0_mac_postamble,
		      ar9300_2p2_mac_postamble);
	INI_PRINT(ar9580_1p0_low_ob_db_tx_gain_table);
	INI_PRINT_DUP(ar9580_1p0_high_power_tx_gain_table,
		      ar9580_1p0_low_ob_db_tx_gain_table);
	INI_PRINT(ar9580_1p0_lowest_ob_db_tx_gain_table);
	INI_PRINT_DUP(ar9580_1p0_baseband_core_txfir_coeff_japan_2484,
		      ar9462_2p0_baseband_core_txfir_coeff_japan_2484);
	INI_PRINT(ar9580_1p0_mac_core);
	INI_PRINT(ar9580_1p0_mixed_ob_db_tx_gain_table);
	INI_PRINT_DUP(ar9580_1p0_wo_xlna_rx_gain_table,
		      ar9300Common_wo_xlna_rx_gain_table_2p2);
	INI_PRINT_DUP(ar9580_1p0_soc_postamble,
		      ar9300_2p2_soc_postamble);
	INI_PRINT_DUP(ar9580_1p0_high_ob_db_tx_gain_table,
		      ar9300Modes_high_ob_db_tx_gain_table_2p2);
	INI_PRINT_DUP(ar9580_1p0_soc_preamble,
		      ar9300_2p2_soc_postamble);
	INI_PRINT_DUP(ar9580_1p0_rx_gain_table,
		      ar9462_common_rx_gain_table_2p0);
	INI_PRINT(ar9580_1p0_radio_core);
	INI_PRINT(ar9580_1p0_baseband_postamble);
	INI_PRINT(ar9580_1p0_pcie_phy_clkreq_enable_L1);
	INI_PRINT(ar9580_1p0_pcie_phy_clkreq_disable_L1);
	INI_PRINT(ar9580_1p0_pcie_phy_pll_on_clkreq);
}

static void ar9462_2p0_hw_print_initvals(bool check)
{
	INI_PRINT(ar9462_modes_fast_clock_2p0);
	INI_PRINT(ar9462_pciephy_clkreq_enable_L1_2p0);
	INI_PRINT(ar9462_2p0_baseband_postamble);
	INI_PRINT(ar9462_common_rx_gain_table_2p0);
	INI_PRINT(ar9462_pciephy_clkreq_disable_L1_2p0);
	INI_PRINT(ar9462_pciephy_pll_on_clkreq_disable_L1_2p0);
	INI_PRINT(ar9462_2p0_radio_postamble_sys2ant);
	INI_PRINT(ar9462_common_wo_xlna_rx_gain_table_2p0);
	INI_PRINT(ar9462_2p0_baseband_core_txfir_coeff_japan_2484);
	INI_PRINT(ar9462_modes_low_ob_db_tx_gain_table_2p0);
	INI_PRINT(ar9462_2p0_soc_postamble);
	INI_PRINT(ar9462_2p0_baseband_core);
	INI_PRINT(ar9462_2p0_radio_postamble);
	INI_PRINT(ar9462_modes_mix_ob_db_tx_gain_table_2p0);
	INI_PRINT(ar9462_modes_high_ob_db_tx_gain_table_2p0);
	INI_PRINT(ar9462_2p0_radio_core);
	INI_PRINT(ar9462_2p0_soc_preamble);
	INI_PRINT(ar9462_2p0_mac_core);
	INI_PRINT(ar9462_2p0_mac_postamble);
	INI_PRINT(ar9462_common_mixed_rx_gain_table_2p0);
	INI_PRINT(ar9462_2p0_baseband_postamble_5g_xlna);
	INI_PRINT(ar9462_2p0_5g_xlna_only_rxgain);
	INI_PRINT(ar9462_2p0_baseband_core_mix_rxgain);
	INI_PRINT(ar9462_2p0_baseband_postamble_mix_rxgain);
}

static void ar9462_2p1_hw_print_initvals(bool check)
{
	INI_PRINT(ar9462_2p1_mac_core);
	INI_PRINT(ar9462_2p1_mac_postamble);
	INI_PRINT(ar9462_2p1_baseband_core);
	INI_PRINT(ar9462_2p1_baseband_postamble);
	INI_PRINT(ar9462_2p1_radio_core);
	INI_PRINT(ar9462_2p1_radio_postamble);
	INI_PRINT(ar9462_2p1_soc_preamble);
	INI_PRINT(ar9462_2p1_soc_postamble);
	INI_PRINT(ar9462_2p1_radio_postamble_sys2ant);
	INI_PRINT(ar9462_2p1_common_rx_gain);
	INI_PRINT(ar9462_2p1_common_mixed_rx_gain);
	INI_PRINT(ar9462_2p1_baseband_core_mix_rxgain);
	INI_PRINT(ar9462_2p1_baseband_postamble_mix_rxgain);
	INI_PRINT(ar9462_2p1_baseband_postamble_5g_xlna);
	INI_PRINT(ar9462_2p1_common_wo_xlna_rx_gain);
	INI_PRINT(ar9462_2p1_common_5g_xlna_only_rx_gain);
	INI_PRINT(ar9462_2p1_modes_low_ob_db_tx_gain);
	INI_PRINT(ar9462_2p1_modes_high_ob_db_tx_gain);
	INI_PRINT(ar9462_2p1_modes_mix_ob_db_tx_gain);
	INI_PRINT(ar9462_2p1_modes_fast_clock);
	INI_PRINT(ar9462_2p1_baseband_core_txfir_coeff_japan_2484);
}

static void ar9565_1p0_hw_print_initvals(bool check)
{
	INI_PRINT(ar9565_1p0_mac_core);
	INI_PRINT(ar9565_1p0_mac_postamble);
	INI_PRINT(ar9565_1p0_baseband_core);
	INI_PRINT(ar9565_1p0_baseband_postamble);
	INI_PRINT(ar9565_1p0_radio_core);
	INI_PRINT(ar9565_1p0_radio_postamble);
	INI_PRINT(ar9565_1p0_soc_preamble);
	INI_PRINT(ar9565_1p0_soc_postamble);
	INI_PRINT(ar9565_1p0_Common_rx_gain_table);
	INI_PRINT(ar9565_1p0_Modes_lowest_ob_db_tx_gain_table);
	INI_PRINT(ar9565_1p0_pciephy_clkreq_disable_L1);
	INI_PRINT(ar9565_1p0_modes_fast_clock);
	INI_PRINT(ar9565_1p0_common_wo_xlna_rx_gain_table);
	INI_PRINT(ar9565_1p0_modes_low_ob_db_tx_gain_table);
	INI_PRINT(ar9565_1p0_modes_high_ob_db_tx_gain_table);
	INI_PRINT(ar9565_1p0_modes_high_power_tx_gain_table);
}

#define FAM(_name, _def, _ver, _print) {	\
	.name = _name,				\
	.header_def = _def,			\
	.header_ver = _ver,			\
	.print = _print				\
}

struct initval_family families[] = {
	FAM("ar5008"    , NULL      , NULL        , ar5008_hw_print_initvals),
	FAM("ar9001"    , NULL      , NULL        , ar9001_hw_print_initvals),
	FAM("ar9002"    , NULL      , NULL        , ar9002_hw_print_initvals),
	FAM("ar9003-2p2", "9003_2P2", "AR9003 2.2", ar9003_2p2_hw_print_initvals),
	FAM("ar9330-1p1", "9330_1P1", NULL        , ar9330_1p1_hw_print_initvals),
	FAM("ar9330-1p2", "9330_1P2", NULL        , ar9330_1p2_hw_print_initvals),
	FAM("ar9340"    , "9340"    , NULL        , ar9340_hw_print_initvals),
	FAM("ar9462-2p0", "9462_2P0", "AR9462 2.0", ar9462_2p0_hw_print_initvals),
	FAM("ar9462-2p1", "9462_2P1", "AR9462 2.1", ar9462_2p1_hw_print_initvals),
	FAM("ar9485"    , "9485"    , "AR9485 1.1", ar9485_hw_print_initvals),
	FAM("ar955x-1p0", "955X_1P0", "AR955X 1.0", ar955x_1p0_hw_print_initvals),
	FAM("ar9565-1p0", "9565_1P0", "AR9565 1.0", ar9565_1p0_hw_print_initvals),
	FAM("ar9580"    , "9580_1P0", "AR9580 1.0", ar9580_1p0_hw_print_initvals),
};

static struct initval_family *find_family(const char *name)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(families); i++) {
		struct initval_family *fam;

		fam = &families[i];
		if (strncmp(fam->name, name, strlen(fam->name)) == 0)
			return fam;
	}

	return NULL;
}

static void print_family(struct initval_family *family, bool check)
{
	if (!check) {
		print_license();

		if (family->header_def) {
			printf("#ifndef INITVALS_%s_H\n", family->header_def);
			printf("#define INITVALS_%s_H\n", family->header_def);
			printf("\n");
		}

		if (family->header_ver) {
			printf("/* %s */\n", family->header_ver);
			printf("\n");
		}
	}

	family->print(check);

	if (!check && family->header_def)
		printf("#endif /* INITVALS_%s_H */\n", family->header_def);
}

static void usage()
{
	int i;

	printf("Usage: initvals [-w] [-f <family>]\n");
	printf("valid <family> values:\n");
	for (i = 0; i < ARRAY_SIZE(families); i++)
		printf("\t%s\n", families[i].name);
}

static void print_initvals_family(char *name, bool check)
{
	struct initval_family *family;

	family = find_family(name);
	if (!family)
		return;

	print_family(family, check);
}

static void print_initvals_family_all(bool check)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(families); i++)
		print_family(&families[i], check);
}

int main(int argc, char *argv[])
{
	if (argc > 1) {
		if (argc == 2) {
			if (strncmp(argv[1], "-w", 2) != 0)
				return -1;

			print_initvals_family_all(false);
			return 0;
		}

		if (argc != 3 && argc != 4) {
			usage();
			return -1;
		}

		if (argc == 3) {
			print_initvals_family(argv[2], true);
			return 0;
		}

		if (strncmp(argv[1], "-w", 2) != 0)
			return -1;

		print_initvals_family(argv[3], false);

		return 0;
	}

	print_initvals_family_all(true);

	return 0;
}
