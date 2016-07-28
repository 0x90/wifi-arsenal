/*
 * These attribute policies are from linux kernel (net/wireless/nl80211.c)
 *
 * Copyright 2006-2010  Johannes Berg <johannes@sipsolutions.net>
 */

#include <linux/if_ether.h>

#include <moep80211/ieee80211_frametypes.h>

#include "../../netlink/attr.h"

#include "nl80211.h"


/* policy for the attributes */
const struct nla_policy nl80211_policy[NL80211_ATTR_MAX+1] = {
	[NL80211_ATTR_WIPHY] = { .type = NLA_U32 },
	[NL80211_ATTR_WIPHY_NAME] = { .type = NLA_NUL_STRING,
				      .maxlen = 20-1 },
	[NL80211_ATTR_WIPHY_TXQ_PARAMS] = { .type = NLA_NESTED },

	[NL80211_ATTR_WIPHY_FREQ] = { .type = NLA_U32 },
	[NL80211_ATTR_WIPHY_CHANNEL_TYPE] = { .type = NLA_U32 },
	[NL80211_ATTR_CHANNEL_WIDTH] = { .type = NLA_U32 },
	[NL80211_ATTR_CENTER_FREQ1] = { .type = NLA_U32 },
	[NL80211_ATTR_CENTER_FREQ2] = { .type = NLA_U32 },

	[NL80211_ATTR_WIPHY_RETRY_SHORT] = { .type = NLA_U8 },
	[NL80211_ATTR_WIPHY_RETRY_LONG] = { .type = NLA_U8 },
	[NL80211_ATTR_WIPHY_FRAG_THRESHOLD] = { .type = NLA_U32 },
	[NL80211_ATTR_WIPHY_RTS_THRESHOLD] = { .type = NLA_U32 },
	[NL80211_ATTR_WIPHY_COVERAGE_CLASS] = { .type = NLA_U8 },

	[NL80211_ATTR_IFTYPE] = { .type = NLA_U32 },
	[NL80211_ATTR_IFINDEX] = { .type = NLA_U32 },
	[NL80211_ATTR_IFNAME] = { .type = NLA_NUL_STRING, .maxlen = IFNAMSIZ-1 },

	[NL80211_ATTR_MAC] = { .maxlen = ETH_ALEN },
	[NL80211_ATTR_PREV_BSSID] = { .maxlen = ETH_ALEN },

	[NL80211_ATTR_KEY] = { .type = NLA_NESTED, },
	[NL80211_ATTR_KEY_DATA] = { .type = NLA_BINARY,
				    .maxlen = WLAN_MAX_KEY_LEN },
	[NL80211_ATTR_KEY_IDX] = { .type = NLA_U8 },
	[NL80211_ATTR_KEY_CIPHER] = { .type = NLA_U32 },
	[NL80211_ATTR_KEY_DEFAULT] = { .type = NLA_FLAG },
	[NL80211_ATTR_KEY_SEQ] = { .type = NLA_BINARY, .maxlen = 16 },
	[NL80211_ATTR_KEY_TYPE] = { .type = NLA_U32 },

	[NL80211_ATTR_BEACON_INTERVAL] = { .type = NLA_U32 },
	[NL80211_ATTR_DTIM_PERIOD] = { .type = NLA_U32 },
	[NL80211_ATTR_BEACON_HEAD] = { .type = NLA_BINARY,
				       .maxlen = IEEE80211_MAX_DATA_LEN },
	[NL80211_ATTR_BEACON_TAIL] = { .type = NLA_BINARY,
				       .maxlen = IEEE80211_MAX_DATA_LEN },
	[NL80211_ATTR_STA_AID] = { .type = NLA_U16 },
	[NL80211_ATTR_STA_FLAGS] = { .type = NLA_NESTED },
	[NL80211_ATTR_STA_LISTEN_INTERVAL] = { .type = NLA_U16 },
	[NL80211_ATTR_STA_SUPPORTED_RATES] = { .type = NLA_BINARY,
					       .maxlen = NL80211_MAX_SUPP_RATES },
	[NL80211_ATTR_STA_PLINK_ACTION] = { .type = NLA_U8 },
	[NL80211_ATTR_STA_VLAN] = { .type = NLA_U32 },
	[NL80211_ATTR_MNTR_FLAGS] = { /* NLA_NESTED can't be empty */ },
	[NL80211_ATTR_MESH_ID] = { .type = NLA_BINARY,
				   .maxlen = IEEE80211_MAX_MESH_ID_LEN },
	[NL80211_ATTR_MPATH_NEXT_HOP] = { .type = NLA_U32 },

	[NL80211_ATTR_REG_ALPHA2] = { .type = NLA_STRING, .maxlen = 2 },
	[NL80211_ATTR_REG_RULES] = { .type = NLA_NESTED },

	[NL80211_ATTR_BSS_CTS_PROT] = { .type = NLA_U8 },
	[NL80211_ATTR_BSS_SHORT_PREAMBLE] = { .type = NLA_U8 },
	[NL80211_ATTR_BSS_SHORT_SLOT_TIME] = { .type = NLA_U8 },
	[NL80211_ATTR_BSS_BASIC_RATES] = { .type = NLA_BINARY,
					   .maxlen = NL80211_MAX_SUPP_RATES },
	[NL80211_ATTR_BSS_HT_OPMODE] = { .type = NLA_U16 },

	[NL80211_ATTR_MESH_CONFIG] = { .type = NLA_NESTED },
	[NL80211_ATTR_SUPPORT_MESH_AUTH] = { .type = NLA_FLAG },

	[NL80211_ATTR_HT_CAPABILITY] = { .maxlen = NL80211_HT_CAPABILITY_LEN },

	[NL80211_ATTR_MGMT_SUBTYPE] = { .type = NLA_U8 },
	[NL80211_ATTR_IE] = { .type = NLA_BINARY,
			      .maxlen = IEEE80211_MAX_DATA_LEN },
	[NL80211_ATTR_SCAN_FREQUENCIES] = { .type = NLA_NESTED },
	[NL80211_ATTR_SCAN_SSIDS] = { .type = NLA_NESTED },

	[NL80211_ATTR_SSID] = { .type = NLA_BINARY,
				.maxlen = IEEE80211_MAX_SSID_LEN },
	[NL80211_ATTR_AUTH_TYPE] = { .type = NLA_U32 },
	[NL80211_ATTR_REASON_CODE] = { .type = NLA_U16 },
	[NL80211_ATTR_FREQ_FIXED] = { .type = NLA_FLAG },
	[NL80211_ATTR_TIMED_OUT] = { .type = NLA_FLAG },
	[NL80211_ATTR_USE_MFP] = { .type = NLA_U32 },
	[NL80211_ATTR_STA_FLAGS2] = {
		.maxlen = sizeof(struct nl80211_sta_flag_update),
	},
	[NL80211_ATTR_CONTROL_PORT] = { .type = NLA_FLAG },
	[NL80211_ATTR_CONTROL_PORT_ETHERTYPE] = { .type = NLA_U16 },
	[NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT] = { .type = NLA_FLAG },
	[NL80211_ATTR_PRIVACY] = { .type = NLA_FLAG },
	[NL80211_ATTR_CIPHER_SUITE_GROUP] = { .type = NLA_U32 },
	[NL80211_ATTR_WPA_VERSIONS] = { .type = NLA_U32 },
	[NL80211_ATTR_PID] = { .type = NLA_U32 },
	[NL80211_ATTR_4ADDR] = { .type = NLA_U8 },
	[NL80211_ATTR_PMKID] = { .type = NLA_BINARY,
				 .maxlen = WLAN_PMKID_LEN },
	[NL80211_ATTR_DURATION] = { .type = NLA_U32 },
	[NL80211_ATTR_COOKIE] = { .type = NLA_U64 },
	[NL80211_ATTR_TX_RATES] = { .type = NLA_NESTED },
	[NL80211_ATTR_FRAME] = { .type = NLA_BINARY,
				 .maxlen = IEEE80211_MAX_DATA_LEN },
	[NL80211_ATTR_FRAME_MATCH] = { .type = NLA_BINARY, },
	[NL80211_ATTR_PS_STATE] = { .type = NLA_U32 },
	[NL80211_ATTR_CQM] = { .type = NLA_NESTED, },
	[NL80211_ATTR_LOCAL_STATE_CHANGE] = { .type = NLA_FLAG },
	[NL80211_ATTR_AP_ISOLATE] = { .type = NLA_U8 },
	[NL80211_ATTR_WIPHY_TX_POWER_SETTING] = { .type = NLA_U32 },
	[NL80211_ATTR_WIPHY_TX_POWER_LEVEL] = { .type = NLA_U32 },
	[NL80211_ATTR_FRAME_TYPE] = { .type = NLA_U16 },
	[NL80211_ATTR_WIPHY_ANTENNA_TX] = { .type = NLA_U32 },
	[NL80211_ATTR_WIPHY_ANTENNA_RX] = { .type = NLA_U32 },
	[NL80211_ATTR_MCAST_RATE] = { .type = NLA_U32 },
	[NL80211_ATTR_OFFCHANNEL_TX_OK] = { .type = NLA_FLAG },
	[NL80211_ATTR_KEY_DEFAULT_TYPES] = { .type = NLA_NESTED },
	[NL80211_ATTR_WOWLAN_TRIGGERS] = { .type = NLA_NESTED },
	[NL80211_ATTR_STA_PLINK_STATE] = { .type = NLA_U8 },
	[NL80211_ATTR_SCHED_SCAN_INTERVAL] = { .type = NLA_U32 },
	[NL80211_ATTR_REKEY_DATA] = { .type = NLA_NESTED },
	[NL80211_ATTR_SCAN_SUPP_RATES] = { .type = NLA_NESTED },
	[NL80211_ATTR_HIDDEN_SSID] = { .type = NLA_U32 },
	[NL80211_ATTR_IE_PROBE_RESP] = { .type = NLA_BINARY,
					 .maxlen = IEEE80211_MAX_DATA_LEN },
	[NL80211_ATTR_IE_ASSOC_RESP] = { .type = NLA_BINARY,
					 .maxlen = IEEE80211_MAX_DATA_LEN },
	[NL80211_ATTR_ROAM_SUPPORT] = { .type = NLA_FLAG },
	[NL80211_ATTR_SCHED_SCAN_MATCH] = { .type = NLA_NESTED },
	[NL80211_ATTR_TX_NO_CCK_RATE] = { .type = NLA_FLAG },
	[NL80211_ATTR_TDLS_ACTION] = { .type = NLA_U8 },
	[NL80211_ATTR_TDLS_DIALOG_TOKEN] = { .type = NLA_U8 },
	[NL80211_ATTR_TDLS_OPERATION] = { .type = NLA_U8 },
	[NL80211_ATTR_TDLS_SUPPORT] = { .type = NLA_FLAG },
	[NL80211_ATTR_TDLS_EXTERNAL_SETUP] = { .type = NLA_FLAG },
	[NL80211_ATTR_DONT_WAIT_FOR_ACK] = { .type = NLA_FLAG },
	[NL80211_ATTR_PROBE_RESP] = { .type = NLA_BINARY,
				      .maxlen = IEEE80211_MAX_DATA_LEN },
	[NL80211_ATTR_DFS_REGION] = { .type = NLA_U8 },
	[NL80211_ATTR_DISABLE_HT] = { .type = NLA_FLAG },
	[NL80211_ATTR_HT_CAPABILITY_MASK] = {
		.maxlen = NL80211_HT_CAPABILITY_LEN
	},
	[NL80211_ATTR_NOACK_MAP] = { .type = NLA_U16 },
	[NL80211_ATTR_INACTIVITY_TIMEOUT] = { .type = NLA_U16 },
	[NL80211_ATTR_BG_SCAN_PERIOD] = { .type = NLA_U16 },
	[NL80211_ATTR_WDEV] = { .type = NLA_U64 },
	[NL80211_ATTR_USER_REG_HINT_TYPE] = { .type = NLA_U32 },
	[NL80211_ATTR_SAE_DATA] = { .type = NLA_BINARY, },
	[NL80211_ATTR_VHT_CAPABILITY] = { .maxlen = NL80211_VHT_CAPABILITY_LEN },
	[NL80211_ATTR_SCAN_FLAGS] = { .type = NLA_U32 },
	[NL80211_ATTR_P2P_CTWINDOW] = { .type = NLA_U8 },
	[NL80211_ATTR_P2P_OPPPS] = { .type = NLA_U8 },
	[NL80211_ATTR_ACL_POLICY] = {. type = NLA_U32 },
	[NL80211_ATTR_MAC_ADDRS] = { .type = NLA_NESTED },
	[NL80211_ATTR_STA_CAPABILITY] = { .type = NLA_U16 },
	[NL80211_ATTR_STA_EXT_CAPABILITY] = { .type = NLA_BINARY, },
	[NL80211_ATTR_SPLIT_WIPHY_DUMP] = { .type = NLA_FLAG, },
	[NL80211_ATTR_DISABLE_VHT] = { .type = NLA_FLAG },
	[NL80211_ATTR_VHT_CAPABILITY_MASK] = {
		.maxlen = NL80211_VHT_CAPABILITY_LEN,
	},
	[NL80211_ATTR_MDID] = { .type = NLA_U16 },
	[NL80211_ATTR_IE_RIC] = { .type = NLA_BINARY,
				  .maxlen = IEEE80211_MAX_DATA_LEN },
	[NL80211_ATTR_PEER_AID] = { .type = NLA_U16 },
};

/* policy for the key attributes */
const struct nla_policy nl80211_key_policy[NL80211_KEY_MAX + 1] = {
	[NL80211_KEY_DATA] = { .type = NLA_BINARY, .maxlen = WLAN_MAX_KEY_LEN },
	[NL80211_KEY_IDX] = { .type = NLA_U8 },
	[NL80211_KEY_CIPHER] = { .type = NLA_U32 },
	[NL80211_KEY_SEQ] = { .type = NLA_BINARY, .maxlen = 16 },
	[NL80211_KEY_DEFAULT] = { .type = NLA_FLAG },
	[NL80211_KEY_DEFAULT_MGMT] = { .type = NLA_FLAG },
	[NL80211_KEY_TYPE] = { .type = NLA_U32 },
	[NL80211_KEY_DEFAULT_TYPES] = { .type = NLA_NESTED },
};

/* policy for the key default flags */
const struct nla_policy
nl80211_key_default_policy[NUM_NL80211_KEY_DEFAULT_TYPES] = {
	[NL80211_KEY_DEFAULT_TYPE_UNICAST] = { .type = NLA_FLAG },
	[NL80211_KEY_DEFAULT_TYPE_MULTICAST] = { .type = NLA_FLAG },
};

/* policy for WoWLAN attributes */
const struct nla_policy
nl80211_wowlan_policy[NUM_NL80211_WOWLAN_TRIG] = {
	[NL80211_WOWLAN_TRIG_ANY] = { .type = NLA_FLAG },
	[NL80211_WOWLAN_TRIG_DISCONNECT] = { .type = NLA_FLAG },
	[NL80211_WOWLAN_TRIG_MAGIC_PKT] = { .type = NLA_FLAG },
	[NL80211_WOWLAN_TRIG_PKT_PATTERN] = { .type = NLA_NESTED },
	[NL80211_WOWLAN_TRIG_GTK_REKEY_FAILURE] = { .type = NLA_FLAG },
	[NL80211_WOWLAN_TRIG_EAP_IDENT_REQUEST] = { .type = NLA_FLAG },
	[NL80211_WOWLAN_TRIG_4WAY_HANDSHAKE] = { .type = NLA_FLAG },
	[NL80211_WOWLAN_TRIG_RFKILL_RELEASE] = { .type = NLA_FLAG },
	[NL80211_WOWLAN_TRIG_TCP_CONNECTION] = { .type = NLA_NESTED },
};

const struct nla_policy
nl80211_wowlan_tcp_policy[NUM_NL80211_WOWLAN_TCP] = {
	[NL80211_WOWLAN_TCP_SRC_IPV4] = { .type = NLA_U32 },
	[NL80211_WOWLAN_TCP_DST_IPV4] = { .type = NLA_U32 },
	[NL80211_WOWLAN_TCP_DST_MAC] = { .maxlen = ETH_ALEN },
	[NL80211_WOWLAN_TCP_SRC_PORT] = { .type = NLA_U16 },
	[NL80211_WOWLAN_TCP_DST_PORT] = { .type = NLA_U16 },
	[NL80211_WOWLAN_TCP_DATA_PAYLOAD] = { .maxlen = 1 },
	[NL80211_WOWLAN_TCP_DATA_PAYLOAD_SEQ] = {
		.maxlen = sizeof(struct nl80211_wowlan_tcp_data_seq)
	},
	[NL80211_WOWLAN_TCP_DATA_PAYLOAD_TOKEN] = {
		.maxlen = sizeof(struct nl80211_wowlan_tcp_data_token)
	},
	[NL80211_WOWLAN_TCP_DATA_INTERVAL] = { .type = NLA_U32 },
	[NL80211_WOWLAN_TCP_WAKE_PAYLOAD] = { .maxlen = 1 },
	[NL80211_WOWLAN_TCP_WAKE_MASK] = { .maxlen = 1 },
};

/* policy for GTK rekey offload attributes */
const struct nla_policy
nl80211_rekey_policy[NUM_NL80211_REKEY_DATA] = {
	[NL80211_REKEY_DATA_KEK] = { .maxlen = NL80211_KEK_LEN },
	[NL80211_REKEY_DATA_KCK] = { .maxlen = NL80211_KCK_LEN },
	[NL80211_REKEY_DATA_REPLAY_CTR] = { .maxlen = NL80211_REPLAY_CTR_LEN },
};

const struct nla_policy
nl80211_match_policy[NL80211_SCHED_SCAN_MATCH_ATTR_MAX + 1] = {
	[NL80211_SCHED_SCAN_MATCH_ATTR_SSID] = { .type = NLA_BINARY,
						 .maxlen = IEEE80211_MAX_SSID_LEN },
	[NL80211_SCHED_SCAN_MATCH_ATTR_RSSI] = { .type = NLA_U32 },
};
