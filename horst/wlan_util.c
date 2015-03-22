#include "main.h"
#include "util.h"
#include "wlan80211.h"
#include "wlan_util.h"

/* lists of packet names */

static struct pkt_name mgmt_names[] = {
	{ 'a', "ASOCRQ", WLAN_FRAME_ASSOC_REQ, "Association request" },
	{ 'A', "ASOCRP", WLAN_FRAME_ASSOC_RESP, "Association response" },
	{ 'a', "REASRQ", WLAN_FRAME_REASSOC_REQ, "Reassociation request" },
	{ 'A', "REASRP", WLAN_FRAME_REASSOC_RESP, "Reassociation response" },
	{ 'p', "PROBRQ", WLAN_FRAME_PROBE_REQ, "Probe request" },
	{ 'P', "PROBRP", WLAN_FRAME_PROBE_RESP, "Probe response" },
	{ 'T', "TIMING", WLAN_FRAME_TIMING, "Timing Advertisement" },
	{ '-', "-RESV-", 0x0070, "RESERVED" },
	{ 'B', "BEACON", WLAN_FRAME_BEACON, "Beacon" },
	{ 't', "ATIM",   WLAN_FRAME_ATIM, "ATIM" },
	{ 'D', "DISASC", WLAN_FRAME_DISASSOC, "Disassociation" },
	{ 'u', "AUTH",   WLAN_FRAME_AUTH, "Authentication" },
	{ 'U', "DEAUTH", WLAN_FRAME_DEAUTH, "Deauthentication" },
	{ 'C', "ACTION", WLAN_FRAME_ACTION, "Action" },
	{ 'c', "ACTNOA", WLAN_FRAME_ACTION_NOACK, "Action No Ack" },
};

static struct pkt_name ctrl_names[] = {
	{ 'w', "CTWRAP", WLAN_FRAME_CTRL_WRAP, "Control Wrapper" },
	{ 'b', "BACKRQ", WLAN_FRAME_BLKACK_REQ, "Block Ack Request" },
	{ 'B', "BACK",   WLAN_FRAME_BLKACK, "Block Ack" },
	{ 's', "PSPOLL", WLAN_FRAME_PSPOLL, "PS-Poll" },
	{ 'R', "RTS",    WLAN_FRAME_RTS, "RTS" },
	{ 'C', "CTS",    WLAN_FRAME_CTS, "CTS" },
	{ 'K', "ACK",    WLAN_FRAME_ACK, "ACK" },
	{ 'f', "CFEND",  WLAN_FRAME_CF_END, "CF-End" },
	{ 'f', "CFENDK", WLAN_FRAME_CF_END_ACK, "CF-End + CF-Ack" },
};

static struct pkt_name data_names[] = {
	{ 'D', "DATA",   WLAN_FRAME_DATA, "Data" },
	{ 'F', "DCFACK", WLAN_FRAME_DATA_CF_ACK, "Data + CF-Ack" },
	{ 'F', "DCFPLL", WLAN_FRAME_DATA_CF_POLL, "Data + CF-Poll" },
	{ 'F', "DCFKPL", WLAN_FRAME_DATA_CF_ACKPOLL, "Data + CF-Ack + CF-Poll" },
	{ 'n', "NULL",   WLAN_FRAME_NULL, "Null (no data)" },
	{ 'f', "CFACK",  WLAN_FRAME_CF_ACK, "CF-Ack (no data)" },
	{ 'f', "CFPOLL",  WLAN_FRAME_CF_POLL, "CF-Poll (no data)" },
	{ 'f', "CFCKPL", WLAN_FRAME_CF_ACKPOLL, "CF-Ack + CF-Poll (no data)" },
	{ 'Q', "QDATA",  WLAN_FRAME_QDATA, "QoS Data" },
	{ 'F', "QDCFCK", WLAN_FRAME_QDATA_CF_ACK, "QoS Data + CF-Ack" },
	{ 'F', "QDCFPL", WLAN_FRAME_QDATA_CF_POLL, "QoS Data + CF-Poll" },
	{ 'F', "QDCFKP", WLAN_FRAME_QDATA_CF_ACKPOLL, "QoS Data + CF-Ack + CF-Poll" },
	{ 'N', "QDNULL", WLAN_FRAME_QOS_NULL, "QoS Null (no data)" },
	{ '-', "-RESV-", 0x00D0, "RESERVED" },
	{ 'f', "QCFPLL", WLAN_FRAME_QOS_CF_POLL, "QoS CF-Poll (no data)" },
	{ 'f', "QCFKPL", WLAN_FRAME_QOS_CF_ACKPOLL, "QoS CF-Ack + CF-Poll (no data)" },
};

static struct pkt_name unknow = { '?', "UNKNOW", 0 , "Unknown" };
static struct pkt_name badfcs = { '*', "BADFCS", 0 , "Bad FCS" };

#define DATA_NAME_INDEX(_i) (((_i) & WLAN_FRAME_FC_STYPE_MASK)>>4)
#define MGMT_NAME_INDEX(_i) (((_i) & WLAN_FRAME_FC_STYPE_MASK)>>4)
#define CTRL_NAME_INDEX(_i) ((((_i) & WLAN_FRAME_FC_STYPE_MASK)>>4)-7)


struct pkt_name
get_packet_struct(u_int16_t type) {
	u_int16_t index;

	if (type == 1) /* special case for bad FCS */
		return badfcs;

	if (WLAN_FRAME_IS_MGMT(type)) {
		index = MGMT_NAME_INDEX(type);
		if (index < sizeof(mgmt_names)/sizeof(struct pkt_name)) {
			if (mgmt_names[index].c)
				return mgmt_names[index];
		}
	} else if (WLAN_FRAME_IS_CTRL(type)) {
		index = CTRL_NAME_INDEX(type);
		if (index < sizeof(ctrl_names)/sizeof(struct pkt_name)) {
			if (ctrl_names[index].c)
				return ctrl_names[index];
		}
	} else if (WLAN_FRAME_IS_DATA(type)) {
		index = DATA_NAME_INDEX(type);
		if (index < sizeof(data_names)/sizeof(struct pkt_name)) {
			if (data_names[index].c)
				return data_names[index];
		}
	}
	return unknow;
}


char
get_packet_type_char(u_int16_t type)
{
	return get_packet_struct(type).c;
}


const char*
get_packet_type_name(u_int16_t type)
{
	return get_packet_struct(type).name;
}


/* rate in 100kbps */
int
rate_to_index(int rate)
{
	switch (rate) {
		case 540: return 12;
		case 480: return 11;
		case 360: return 10;
		case 240: return 9;
		case 180: return 8;
		case 120: return 7;
		case 110: return 6;
		case 90: return 5;
		case 60: return 4;
		case 55: return 3;
		case 20: return 2;
		case 10: return 1;
		default: return 0;
	}
}


/* return rate in 100kbps */
int
rate_index_to_rate(int idx)
{
	switch (idx) {
		case 12: return 540;
		case 11: return 480;
		case 10: return 360;
		case 9: return 240;
		case 8: return 180;
		case 7: return 120;
		case 6: return 110;
		case 5: return 90;
		case 4: return 60;
		case 3: return 55;
		case 2: return 20;
		case 1: return 10;
		default: return 0;
	}
}


/* return rate in 100kbps */
int
mcs_index_to_rate(int mcs, int ht20, int lgi)
{
	/* MCS Index, http://en.wikipedia.org/wiki/IEEE_802.11n-2009#Data_rates */
	switch (mcs) {
		case 0:  return ht20 ? (lgi ? 65 : 72) : (lgi ? 135 : 150);
		case 1:  return ht20 ? (lgi ? 130 : 144) : (lgi ? 270 : 300);
		case 2:  return ht20 ? (lgi ? 195 : 217) : (lgi ? 405 : 450);
		case 3:  return ht20 ? (lgi ? 260 : 289) : (lgi ? 540 : 600);
		case 4:  return ht20 ? (lgi ? 390 : 433) : (lgi ? 810 : 900);
		case 5:  return ht20 ? (lgi ? 520 : 578) : (lgi ? 1080 : 1200);
		case 6:  return ht20 ? (lgi ? 585 : 650) : (lgi ? 1215 : 1350);
		case 7:  return ht20 ? (lgi ? 650 : 722) : (lgi ? 1350 : 1500);
		case 8:  return ht20 ? (lgi ? 130 : 144) : (lgi ? 270 : 300);
		case 9:  return ht20 ? (lgi ? 260 : 289) : (lgi ? 540 : 600);
		case 10: return ht20 ? (lgi ? 390 : 433) : (lgi ? 810 : 900);
		case 11: return ht20 ? (lgi ? 520 : 578) : (lgi ? 1080 : 1200);
		case 12: return ht20 ? (lgi ? 780 : 867) : (lgi ? 1620 : 1800);
		case 13: return ht20 ? (lgi ? 1040 : 1156) : (lgi ? 2160 : 2400);
		case 14: return ht20 ? (lgi ? 1170 : 1300) : (lgi ? 2430 : 2700);
		case 15: return ht20 ? (lgi ? 1300 : 1444) : (lgi ? 2700 : 3000);
		case 16: return ht20 ? (lgi ? 195 : 217) : (lgi ? 405 : 450);
		case 17: return ht20 ? (lgi ? 39 : 433) : (lgi ? 810 : 900);
		case 18: return ht20 ? (lgi ? 585 : 650) : (lgi ? 1215 : 1350);
		case 19: return ht20 ? (lgi ? 78 : 867) : (lgi ? 1620 : 1800);
		case 20: return ht20 ? (lgi ? 1170 : 1300) : (lgi ? 2430 : 2700);
		case 21: return ht20 ? (lgi ? 1560 : 1733) : (lgi ? 3240 : 3600);
		case 22: return ht20 ? (lgi ? 1755 : 1950) : (lgi ? 3645 : 4050);
		case 23: return ht20 ? (lgi ? 1950 : 2167) : (lgi ? 4050 : 4500);
		case 24: return ht20 ? (lgi ? 260 : 288) : (lgi ? 540 : 600);
		case 25: return ht20 ? (lgi ? 520 : 576) : (lgi ? 1080 : 1200);
		case 26: return ht20 ? (lgi ? 780 : 868) : (lgi ? 1620 : 1800);
		case 27: return ht20 ? (lgi ? 1040 : 1156) : (lgi ? 2160 : 2400);
		case 28: return ht20 ? (lgi ? 1560 : 1732) : (lgi ? 3240 : 3600);
		case 29: return ht20 ? (lgi ? 2080 : 2312) : (lgi ? 4320 : 4800);
		case 30: return ht20 ? (lgi ? 2340 : 2600) : (lgi ? 4860 : 5400);
		case 31: return ht20 ? (lgi ? 2600 : 2888) : (lgi ? 5400 : 6000);
	}
	return 0;
}

void
wlan_parse_information_elements(unsigned char *buf, int len, struct packet_info *p) {

	while (len > 2) {
		struct information_element* ie = (struct information_element*)buf;
		//DEBUG("------ IE %d len %d t len %d\n", ie->id, ie->len, len);

		switch (ie->id) {
		case WLAN_IE_ID_SSID:
			if (ie->len < WLAN_MAX_SSID_LEN-1) {
				memcpy(p->wlan_essid, ie->var, ie->len);
				p->wlan_essid[ie->len] = '\0';
			} else {
				memcpy(p->wlan_essid, ie->var, WLAN_MAX_SSID_LEN-1);
				p->wlan_essid[WLAN_MAX_SSID_LEN-1] = '\0';
			}
			break;

		case WLAN_IE_ID_DSSS_PARAM:
			p->wlan_channel = *ie->var;
			break;

		case WLAN_IE_ID_RSN:
			p->wlan_rsn = 1;
			break;

		case WLAN_IE_ID_VENDOR:
			if (ie->len >= 4 &&
			    ie->var[0] == 0x00 && ie->var[1] == 0x50 && ie->var[2] == 0xf2 && /* Microsoft OUI (00:50:F2) */
			    ie->var[3] == 1) {	/* OUI Type 1 - WPA IE */
				p->wlan_wpa=1;
			}

			break;
		}

		buf += (ie->len + 2);
		len -= (ie->len + 2);
	}
}
