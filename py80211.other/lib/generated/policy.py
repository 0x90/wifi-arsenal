###########################################################
# This file is generated using extract.py using pycparser
###########################################################
# revision:
#	d0266db Linux 3.12.6
###########################################################
from netlink.capi import *
from defs import *

# defines used in nl80211.c
ETH_ALEN = 6
WLAN_MAX_KEY_LEN = 32
WLAN_PMKID_LEN = 16
IEEE80211_MAX_DATA_LEN = 2304
IEEE80211_MAX_MESH_ID_LEN = 32
IEEE80211_MAX_SSID_LEN = 32
NLA_NUL_STRING = NLA_NESTED + 2
NLA_BINARY = NLA_NESTED + 3

#
# policy: nl80211_policy
#
nl80211_policy = nla_policy_array(ATTR_MAX + 1)
nl80211_policy[ATTR_WIPHY].type = NLA_U32
nl80211_policy[ATTR_WIPHY_NAME].type = NLA_NUL_STRING
nl80211_policy[ATTR_WIPHY_NAME].len = None
nl80211_policy[ATTR_WIPHY_BANDS].type = NLA_NESTED
nl80211_policy[ATTR_WIPHY_TXQ_PARAMS].type = NLA_NESTED
nl80211_policy[ATTR_WIPHY_FREQ].type = NLA_U32
nl80211_policy[ATTR_WIPHY_CHANNEL_TYPE].type = NLA_U32
nl80211_policy[ATTR_CHANNEL_WIDTH].type = NLA_U32
nl80211_policy[ATTR_CENTER_FREQ1].type = NLA_U32
nl80211_policy[ATTR_CENTER_FREQ2].type = NLA_U32
nl80211_policy[ATTR_WIPHY_RETRY_SHORT].type = NLA_U8
nl80211_policy[ATTR_WIPHY_RETRY_LONG].type = NLA_U8
nl80211_policy[ATTR_WIPHY_FRAG_THRESHOLD].type = NLA_U32
nl80211_policy[ATTR_WIPHY_RTS_THRESHOLD].type = NLA_U32
nl80211_policy[ATTR_WIPHY_COVERAGE_CLASS].type = NLA_U8
nl80211_policy[ATTR_SUPPORTED_IFTYPES].type = NLA_NESTED
nl80211_policy[ATTR_IFTYPE].type = NLA_U32
nl80211_policy[ATTR_IFINDEX].type = NLA_U32
nl80211_policy[ATTR_IFNAME].type = NLA_NUL_STRING
nl80211_policy[ATTR_IFNAME].len = None
nl80211_policy[ATTR_MAC].len = ETH_ALEN
nl80211_policy[ATTR_PREV_BSSID].len = ETH_ALEN
nl80211_policy[ATTR_KEY].type = NLA_NESTED
nl80211_policy[ATTR_KEY_DATA].type = NLA_BINARY
nl80211_policy[ATTR_KEY_DATA].len = WLAN_MAX_KEY_LEN
nl80211_policy[ATTR_KEY_IDX].type = NLA_U8
nl80211_policy[ATTR_KEY_CIPHER].type = NLA_U32
nl80211_policy[ATTR_KEY_DEFAULT].type = NLA_FLAG
nl80211_policy[ATTR_KEY_SEQ].type = NLA_BINARY
nl80211_policy[ATTR_KEY_SEQ].len = 16
nl80211_policy[ATTR_KEY_TYPE].type = NLA_U32
nl80211_policy[ATTR_BEACON_INTERVAL].type = NLA_U32
nl80211_policy[ATTR_DTIM_PERIOD].type = NLA_U32
nl80211_policy[ATTR_BEACON_HEAD].type = NLA_BINARY
nl80211_policy[ATTR_BEACON_HEAD].len = IEEE80211_MAX_DATA_LEN
nl80211_policy[ATTR_BEACON_TAIL].type = NLA_BINARY
nl80211_policy[ATTR_BEACON_TAIL].len = IEEE80211_MAX_DATA_LEN
nl80211_policy[ATTR_STA_AID].type = NLA_U16
nl80211_policy[ATTR_STA_FLAGS].type = NLA_NESTED
nl80211_policy[ATTR_STA_LISTEN_INTERVAL].type = NLA_U16
nl80211_policy[ATTR_STA_SUPPORTED_RATES].type = NLA_BINARY
nl80211_policy[ATTR_STA_SUPPORTED_RATES].len = 32
nl80211_policy[ATTR_STA_PLINK_ACTION].type = NLA_U8
nl80211_policy[ATTR_STA_VLAN].type = NLA_U32
nl80211_policy[ATTR_MNTR_FLAGS].type = NLA_UNSPEC
nl80211_policy[ATTR_MESH_ID].type = NLA_BINARY
nl80211_policy[ATTR_MESH_ID].len = IEEE80211_MAX_MESH_ID_LEN
nl80211_policy[ATTR_MPATH_NEXT_HOP].type = NLA_U32
nl80211_policy[ATTR_REG_ALPHA2].type = NLA_STRING
nl80211_policy[ATTR_REG_ALPHA2].len = 2
nl80211_policy[ATTR_REG_RULES].type = NLA_NESTED
nl80211_policy[ATTR_BSS_CTS_PROT].type = NLA_U8
nl80211_policy[ATTR_BSS_SHORT_PREAMBLE].type = NLA_U8
nl80211_policy[ATTR_BSS_SHORT_SLOT_TIME].type = NLA_U8
nl80211_policy[ATTR_BSS_BASIC_RATES].type = NLA_BINARY
nl80211_policy[ATTR_BSS_BASIC_RATES].len = 32
nl80211_policy[ATTR_BSS_HT_OPMODE].type = NLA_U16
nl80211_policy[ATTR_MESH_CONFIG].type = NLA_NESTED
nl80211_policy[ATTR_SUPPORT_MESH_AUTH].type = NLA_FLAG
nl80211_policy[ATTR_HT_CAPABILITY].len = 26
nl80211_policy[ATTR_MGMT_SUBTYPE].type = NLA_U8
nl80211_policy[ATTR_IE].type = NLA_BINARY
nl80211_policy[ATTR_IE].len = IEEE80211_MAX_DATA_LEN
nl80211_policy[ATTR_SCAN_FREQUENCIES].type = NLA_NESTED
nl80211_policy[ATTR_SCAN_SSIDS].type = NLA_NESTED
nl80211_policy[ATTR_SSID].type = NLA_BINARY
nl80211_policy[ATTR_SSID].len = IEEE80211_MAX_SSID_LEN
nl80211_policy[ATTR_AUTH_TYPE].type = NLA_U32
nl80211_policy[ATTR_REASON_CODE].type = NLA_U16
nl80211_policy[ATTR_FREQ_FIXED].type = NLA_FLAG
nl80211_policy[ATTR_TIMED_OUT].type = NLA_FLAG
nl80211_policy[ATTR_USE_MFP].type = NLA_U32
nl80211_policy[ATTR_STA_FLAGS2].len = None
nl80211_policy[ATTR_CONTROL_PORT].type = NLA_FLAG
nl80211_policy[ATTR_CONTROL_PORT_ETHERTYPE].type = NLA_U16
nl80211_policy[ATTR_CONTROL_PORT_NO_ENCRYPT].type = NLA_FLAG
nl80211_policy[ATTR_PRIVACY].type = NLA_FLAG
nl80211_policy[ATTR_CIPHER_SUITE_GROUP].type = NLA_U32
nl80211_policy[ATTR_WPA_VERSIONS].type = NLA_U32
nl80211_policy[ATTR_PID].type = NLA_U32
nl80211_policy[ATTR_4ADDR].type = NLA_U8
nl80211_policy[ATTR_PMKID].type = NLA_BINARY
nl80211_policy[ATTR_PMKID].len = WLAN_PMKID_LEN
nl80211_policy[ATTR_DURATION].type = NLA_U32
nl80211_policy[ATTR_COOKIE].type = NLA_U64
nl80211_policy[ATTR_TX_RATES].type = NLA_NESTED
nl80211_policy[ATTR_FRAME].type = NLA_BINARY
nl80211_policy[ATTR_FRAME].len = IEEE80211_MAX_DATA_LEN
nl80211_policy[ATTR_FRAME_MATCH].type = NLA_BINARY
nl80211_policy[ATTR_PS_STATE].type = NLA_U32
nl80211_policy[ATTR_CQM].type = NLA_NESTED
nl80211_policy[ATTR_LOCAL_STATE_CHANGE].type = NLA_FLAG
nl80211_policy[ATTR_AP_ISOLATE].type = NLA_U8
nl80211_policy[ATTR_WIPHY_TX_POWER_SETTING].type = NLA_U32
nl80211_policy[ATTR_WIPHY_TX_POWER_LEVEL].type = NLA_U32
nl80211_policy[ATTR_FRAME_TYPE].type = NLA_U16
nl80211_policy[ATTR_WIPHY_ANTENNA_TX].type = NLA_U32
nl80211_policy[ATTR_WIPHY_ANTENNA_RX].type = NLA_U32
nl80211_policy[ATTR_MCAST_RATE].type = NLA_U32
nl80211_policy[ATTR_OFFCHANNEL_TX_OK].type = NLA_FLAG
nl80211_policy[ATTR_KEY_DEFAULT_TYPES].type = NLA_NESTED
nl80211_policy[ATTR_WOWLAN_TRIGGERS].type = NLA_NESTED
nl80211_policy[ATTR_STA_PLINK_STATE].type = NLA_U8
nl80211_policy[ATTR_SCHED_SCAN_INTERVAL].type = NLA_U32
nl80211_policy[ATTR_REKEY_DATA].type = NLA_NESTED
nl80211_policy[ATTR_SCAN_SUPP_RATES].type = NLA_NESTED
nl80211_policy[ATTR_HIDDEN_SSID].type = NLA_U32
nl80211_policy[ATTR_IE_PROBE_RESP].type = NLA_BINARY
nl80211_policy[ATTR_IE_PROBE_RESP].len = IEEE80211_MAX_DATA_LEN
nl80211_policy[ATTR_IE_ASSOC_RESP].type = NLA_BINARY
nl80211_policy[ATTR_IE_ASSOC_RESP].len = IEEE80211_MAX_DATA_LEN
nl80211_policy[ATTR_ROAM_SUPPORT].type = NLA_FLAG
nl80211_policy[ATTR_SCHED_SCAN_MATCH].type = NLA_NESTED
nl80211_policy[ATTR_TX_NO_CCK_RATE].type = NLA_FLAG
nl80211_policy[ATTR_TDLS_ACTION].type = NLA_U8
nl80211_policy[ATTR_TDLS_DIALOG_TOKEN].type = NLA_U8
nl80211_policy[ATTR_TDLS_OPERATION].type = NLA_U8
nl80211_policy[ATTR_TDLS_SUPPORT].type = NLA_FLAG
nl80211_policy[ATTR_TDLS_EXTERNAL_SETUP].type = NLA_FLAG
nl80211_policy[ATTR_DONT_WAIT_FOR_ACK].type = NLA_FLAG
nl80211_policy[ATTR_PROBE_RESP].type = NLA_BINARY
nl80211_policy[ATTR_PROBE_RESP].len = IEEE80211_MAX_DATA_LEN
nl80211_policy[ATTR_DFS_REGION].type = NLA_U8
nl80211_policy[ATTR_DISABLE_HT].type = NLA_FLAG
nl80211_policy[ATTR_HT_CAPABILITY_MASK].len = 26
nl80211_policy[ATTR_NOACK_MAP].type = NLA_U16
nl80211_policy[ATTR_INACTIVITY_TIMEOUT].type = NLA_U16
nl80211_policy[ATTR_BG_SCAN_PERIOD].type = NLA_U16
nl80211_policy[ATTR_WDEV].type = NLA_U64
nl80211_policy[ATTR_USER_REG_HINT_TYPE].type = NLA_U32
nl80211_policy[ATTR_SAE_DATA].type = NLA_BINARY
nl80211_policy[ATTR_VHT_CAPABILITY].len = 12
nl80211_policy[ATTR_SCAN_FLAGS].type = NLA_U32
nl80211_policy[ATTR_P2P_CTWINDOW].type = NLA_U8
nl80211_policy[ATTR_P2P_OPPPS].type = NLA_U8
nl80211_policy[ATTR_ACL_POLICY].type = NLA_U32
nl80211_policy[ATTR_MAC_ADDRS].type = NLA_NESTED
nl80211_policy[ATTR_STA_CAPABILITY].type = NLA_U16
nl80211_policy[ATTR_STA_EXT_CAPABILITY].type = NLA_BINARY
nl80211_policy[ATTR_SPLIT_WIPHY_DUMP].type = NLA_FLAG
nl80211_policy[ATTR_DISABLE_VHT].type = NLA_FLAG
nl80211_policy[ATTR_VHT_CAPABILITY_MASK].len = 12
nl80211_policy[ATTR_MDID].type = NLA_U16
nl80211_policy[ATTR_IE_RIC].type = NLA_BINARY
nl80211_policy[ATTR_IE_RIC].len = IEEE80211_MAX_DATA_LEN
nl80211_policy[ATTR_PEER_AID].type = NLA_U16
nl80211_policy[ATTR_CH_SWITCH_COUNT].type = NLA_U32
nl80211_policy[ATTR_CH_SWITCH_BLOCK_TX].type = NLA_FLAG
nl80211_policy[ATTR_CSA_IES].type = NLA_NESTED
nl80211_policy[ATTR_CSA_C_OFF_BEACON].type = NLA_U16
nl80211_policy[ATTR_CSA_C_OFF_PRESP].type = NLA_U16
#
# policy: nl80211_key_policy
#
nl80211_key_policy = nla_policy_array(KEY_MAX + 1)
nl80211_key_policy[KEY_DATA].type = NLA_BINARY
nl80211_key_policy[KEY_DATA].len = WLAN_MAX_KEY_LEN
nl80211_key_policy[KEY_IDX].type = NLA_U8
nl80211_key_policy[KEY_CIPHER].type = NLA_U32
nl80211_key_policy[KEY_SEQ].type = NLA_BINARY
nl80211_key_policy[KEY_SEQ].len = 16
nl80211_key_policy[KEY_DEFAULT].type = NLA_FLAG
nl80211_key_policy[KEY_DEFAULT_MGMT].type = NLA_FLAG
nl80211_key_policy[KEY_TYPE].type = NLA_U32
nl80211_key_policy[KEY_DEFAULT_TYPES].type = NLA_NESTED
#
# policy: nl80211_key_default_policy
#
nl80211_key_default_policy = nla_policy_array(NUM_NL80211_KEY_DEFAULT_TYPES)
nl80211_key_default_policy[KEY_DEFAULT_TYPE_UNICAST].type = NLA_FLAG
nl80211_key_default_policy[KEY_DEFAULT_TYPE_MULTICAST].type = NLA_FLAG
#
# policy: nl80211_wowlan_policy
#
nl80211_wowlan_policy = nla_policy_array(NUM_NL80211_WOWLAN_TRIG)
nl80211_wowlan_policy[WOWLAN_TRIG_ANY].type = NLA_FLAG
nl80211_wowlan_policy[WOWLAN_TRIG_DISCONNECT].type = NLA_FLAG
nl80211_wowlan_policy[WOWLAN_TRIG_MAGIC_PKT].type = NLA_FLAG
nl80211_wowlan_policy[WOWLAN_TRIG_PKT_PATTERN].type = NLA_NESTED
nl80211_wowlan_policy[WOWLAN_TRIG_GTK_REKEY_FAILURE].type = NLA_FLAG
nl80211_wowlan_policy[WOWLAN_TRIG_EAP_IDENT_REQUEST].type = NLA_FLAG
nl80211_wowlan_policy[WOWLAN_TRIG_4WAY_HANDSHAKE].type = NLA_FLAG
nl80211_wowlan_policy[WOWLAN_TRIG_RFKILL_RELEASE].type = NLA_FLAG
nl80211_wowlan_policy[WOWLAN_TRIG_TCP_CONNECTION].type = NLA_NESTED
#
# policy: nl80211_wowlan_tcp_policy
#
nl80211_wowlan_tcp_policy = nla_policy_array(NUM_NL80211_WOWLAN_TCP)
nl80211_wowlan_tcp_policy[WOWLAN_TCP_SRC_IPV4].type = NLA_U32
nl80211_wowlan_tcp_policy[WOWLAN_TCP_DST_IPV4].type = NLA_U32
nl80211_wowlan_tcp_policy[WOWLAN_TCP_DST_MAC].len = ETH_ALEN
nl80211_wowlan_tcp_policy[WOWLAN_TCP_SRC_PORT].type = NLA_U16
nl80211_wowlan_tcp_policy[WOWLAN_TCP_DST_PORT].type = NLA_U16
nl80211_wowlan_tcp_policy[WOWLAN_TCP_DATA_PAYLOAD].len = 1
nl80211_wowlan_tcp_policy[WOWLAN_TCP_DATA_PAYLOAD_SEQ].len = None
nl80211_wowlan_tcp_policy[WOWLAN_TCP_DATA_PAYLOAD_TOKEN].len = None
nl80211_wowlan_tcp_policy[WOWLAN_TCP_DATA_INTERVAL].type = NLA_U32
nl80211_wowlan_tcp_policy[WOWLAN_TCP_WAKE_PAYLOAD].len = 1
nl80211_wowlan_tcp_policy[WOWLAN_TCP_WAKE_MASK].len = 1
#
# policy: nl80211_coalesce_policy
#
nl80211_coalesce_policy = nla_policy_array(NUM_NL80211_ATTR_COALESCE_RULE)
nl80211_coalesce_policy[ATTR_COALESCE_RULE_DELAY].type = NLA_U32
nl80211_coalesce_policy[ATTR_COALESCE_RULE_CONDITION].type = NLA_U32
nl80211_coalesce_policy[ATTR_COALESCE_RULE_PKT_PATTERN].type = NLA_NESTED
#
# policy: nl80211_rekey_policy
#
nl80211_rekey_policy = nla_policy_array(NUM_NL80211_REKEY_DATA)
nl80211_rekey_policy[REKEY_DATA_KEK].len = 16
nl80211_rekey_policy[REKEY_DATA_KCK].len = 16
nl80211_rekey_policy[REKEY_DATA_REPLAY_CTR].len = 8
#
# policy: nl80211_match_policy
#
nl80211_match_policy = nla_policy_array(SCHED_SCAN_MATCH_ATTR_MAX + 1)
nl80211_match_policy[SCHED_SCAN_MATCH_ATTR_SSID].type = NLA_BINARY
nl80211_match_policy[SCHED_SCAN_MATCH_ATTR_SSID].len = IEEE80211_MAX_SSID_LEN
nl80211_match_policy[SCHED_SCAN_MATCH_ATTR_RSSI].type = NLA_U32
#
# policy: txq_params_policy
#
txq_params_policy = nla_policy_array(TXQ_ATTR_MAX + 1)
txq_params_policy[TXQ_ATTR_AC].type = NLA_U8
txq_params_policy[TXQ_ATTR_TXOP].type = NLA_U16
txq_params_policy[TXQ_ATTR_CWMIN].type = NLA_U16
txq_params_policy[TXQ_ATTR_CWMAX].type = NLA_U16
txq_params_policy[TXQ_ATTR_AIFS].type = NLA_U8
#
# policy: mntr_flags_policy
#
mntr_flags_policy = nla_policy_array(MNTR_FLAG_MAX + 1)
mntr_flags_policy[MNTR_FLAG_FCSFAIL].type = NLA_FLAG
mntr_flags_policy[MNTR_FLAG_PLCPFAIL].type = NLA_FLAG
mntr_flags_policy[MNTR_FLAG_CONTROL].type = NLA_FLAG
mntr_flags_policy[MNTR_FLAG_OTHER_BSS].type = NLA_FLAG
mntr_flags_policy[MNTR_FLAG_COOK_FRAMES].type = NLA_FLAG
mntr_flags_policy[MNTR_FLAG_ACTIVE].type = NLA_FLAG
#
# policy: sta_flags_policy
#
sta_flags_policy = nla_policy_array(STA_FLAG_MAX + 1)
sta_flags_policy[STA_FLAG_AUTHORIZED].type = NLA_FLAG
sta_flags_policy[STA_FLAG_SHORT_PREAMBLE].type = NLA_FLAG
sta_flags_policy[STA_FLAG_WME].type = NLA_FLAG
sta_flags_policy[STA_FLAG_MFP].type = NLA_FLAG
sta_flags_policy[STA_FLAG_AUTHENTICATED].type = NLA_FLAG
sta_flags_policy[STA_FLAG_TDLS_PEER].type = NLA_FLAG
#
# policy: nl80211_sta_wme_policy
#
nl80211_sta_wme_policy = nla_policy_array(STA_WME_MAX + 1)
nl80211_sta_wme_policy[STA_WME_UAPSD_QUEUES].type = NLA_U8
nl80211_sta_wme_policy[STA_WME_MAX_SP].type = NLA_U8
#
# policy: reg_rule_policy
#
reg_rule_policy = nla_policy_array(REG_RULE_ATTR_MAX + 1)
reg_rule_policy[ATTR_REG_RULE_FLAGS].type = NLA_U32
reg_rule_policy[ATTR_FREQ_RANGE_START].type = NLA_U32
reg_rule_policy[ATTR_FREQ_RANGE_END].type = NLA_U32
reg_rule_policy[ATTR_FREQ_RANGE_MAX_BW].type = NLA_U32
reg_rule_policy[ATTR_POWER_RULE_MAX_ANT_GAIN].type = NLA_U32
reg_rule_policy[ATTR_POWER_RULE_MAX_EIRP].type = NLA_U32
#
# policy: nl80211_meshconf_params_policy
#
nl80211_meshconf_params_policy = nla_policy_array(MESHCONF_ATTR_MAX + 1)
nl80211_meshconf_params_policy[MESHCONF_RETRY_TIMEOUT].type = NLA_U16
nl80211_meshconf_params_policy[MESHCONF_CONFIRM_TIMEOUT].type = NLA_U16
nl80211_meshconf_params_policy[MESHCONF_HOLDING_TIMEOUT].type = NLA_U16
nl80211_meshconf_params_policy[MESHCONF_MAX_PEER_LINKS].type = NLA_U16
nl80211_meshconf_params_policy[MESHCONF_MAX_RETRIES].type = NLA_U8
nl80211_meshconf_params_policy[MESHCONF_TTL].type = NLA_U8
nl80211_meshconf_params_policy[MESHCONF_ELEMENT_TTL].type = NLA_U8
nl80211_meshconf_params_policy[MESHCONF_AUTO_OPEN_PLINKS].type = NLA_U8
nl80211_meshconf_params_policy[MESHCONF_SYNC_OFFSET_MAX_NEIGHBOR].type = NLA_U32
nl80211_meshconf_params_policy[MESHCONF_HWMP_MAX_PREQ_RETRIES].type = NLA_U8
nl80211_meshconf_params_policy[MESHCONF_PATH_REFRESH_TIME].type = NLA_U32
nl80211_meshconf_params_policy[MESHCONF_MIN_DISCOVERY_TIMEOUT].type = NLA_U16
nl80211_meshconf_params_policy[MESHCONF_HWMP_ACTIVE_PATH_TIMEOUT].type = NLA_U32
nl80211_meshconf_params_policy[MESHCONF_HWMP_PREQ_MIN_INTERVAL].type = NLA_U16
nl80211_meshconf_params_policy[MESHCONF_HWMP_PERR_MIN_INTERVAL].type = NLA_U16
nl80211_meshconf_params_policy[MESHCONF_HWMP_NET_DIAM_TRVS_TIME].type = NLA_U16
nl80211_meshconf_params_policy[MESHCONF_HWMP_ROOTMODE].type = NLA_U8
nl80211_meshconf_params_policy[MESHCONF_HWMP_RANN_INTERVAL].type = NLA_U16
nl80211_meshconf_params_policy[MESHCONF_GATE_ANNOUNCEMENTS].type = NLA_U8
nl80211_meshconf_params_policy[MESHCONF_FORWARDING].type = NLA_U8
nl80211_meshconf_params_policy[MESHCONF_RSSI_THRESHOLD].type = NLA_U32
nl80211_meshconf_params_policy[MESHCONF_HT_OPMODE].type = NLA_U16
nl80211_meshconf_params_policy[MESHCONF_HWMP_PATH_TO_ROOT_TIMEOUT].type = NLA_U32
nl80211_meshconf_params_policy[MESHCONF_HWMP_ROOT_INTERVAL].type = NLA_U16
nl80211_meshconf_params_policy[MESHCONF_HWMP_CONFIRMATION_INTERVAL].type = NLA_U16
nl80211_meshconf_params_policy[MESHCONF_POWER_MODE].type = NLA_U32
nl80211_meshconf_params_policy[MESHCONF_AWAKE_WINDOW].type = NLA_U16
nl80211_meshconf_params_policy[MESHCONF_PLINK_TIMEOUT].type = NLA_U32
#
# policy: nl80211_mesh_setup_params_policy
#
nl80211_mesh_setup_params_policy = nla_policy_array(MESH_SETUP_ATTR_MAX + 1)
nl80211_mesh_setup_params_policy[MESH_SETUP_ENABLE_VENDOR_SYNC].type = NLA_U8
nl80211_mesh_setup_params_policy[MESH_SETUP_ENABLE_VENDOR_PATH_SEL].type = NLA_U8
nl80211_mesh_setup_params_policy[MESH_SETUP_ENABLE_VENDOR_METRIC].type = NLA_U8
nl80211_mesh_setup_params_policy[MESH_SETUP_USERSPACE_AUTH].type = NLA_FLAG
nl80211_mesh_setup_params_policy[MESH_SETUP_AUTH_PROTOCOL].type = NLA_U8
nl80211_mesh_setup_params_policy[MESH_SETUP_USERSPACE_MPM].type = NLA_FLAG
nl80211_mesh_setup_params_policy[MESH_SETUP_IE].type = NLA_BINARY
nl80211_mesh_setup_params_policy[MESH_SETUP_IE].len = IEEE80211_MAX_DATA_LEN
nl80211_mesh_setup_params_policy[MESH_SETUP_USERSPACE_AMPE].type = NLA_FLAG
#
# policy: nl80211_txattr_policy
#
nl80211_txattr_policy = nla_policy_array(TXRATE_MAX + 1)
nl80211_txattr_policy[TXRATE_LEGACY].type = NLA_BINARY
nl80211_txattr_policy[TXRATE_LEGACY].len = 32
nl80211_txattr_policy[TXRATE_MCS].type = NLA_BINARY
nl80211_txattr_policy[TXRATE_MCS].len = 77
#
# policy: nl80211_attr_cqm_policy
#
nl80211_attr_cqm_policy = nla_policy_array(ATTR_CQM_MAX + 1)
nl80211_attr_cqm_policy[ATTR_CQM_RSSI_THOLD].type = NLA_U32
nl80211_attr_cqm_policy[ATTR_CQM_RSSI_HYST].type = NLA_U32
nl80211_attr_cqm_policy[ATTR_CQM_RSSI_THRESHOLD_EVENT].type = NLA_U32
nl80211_attr_cqm_policy[ATTR_CQM_TXE_RATE].type = NLA_U32
nl80211_attr_cqm_policy[ATTR_CQM_TXE_PKTS].type = NLA_U32
nl80211_attr_cqm_policy[ATTR_CQM_TXE_INTVL].type = NLA_U32
