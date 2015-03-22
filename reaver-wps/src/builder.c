/*
 * Reaver - Packet building functions
 * Copyright (c) 2011, Tactical Network Solutions, Craig Heffner <cheffner@tacnetsol.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL. *  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so. *  If you
 *  do not wish to do so, delete this exception statement from your
 *  version. *  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#include "builder.h"

const void *build_radio_tap_header(size_t *len)
{
	struct radio_tap_header *rt_header = NULL;
	const void *buf = NULL;

	buf = malloc(sizeof(struct radio_tap_header));
	if(buf)
	{
		memset((void *) buf, 0, sizeof(struct radio_tap_header));
		rt_header = (struct radio_tap_header *) buf;

		rt_header->len = sizeof(struct radio_tap_header);
	
		*len = rt_header->len;
	}
	
	return buf;
}

const void *build_dot11_frame_header(uint16_t fc, size_t *len)
{
	struct dot11_frame_header *header = NULL;
	const void *buf = NULL;
	static uint16_t frag_seq;

	buf = malloc(sizeof(struct dot11_frame_header));
	if(buf)
	{
		*len = sizeof(struct dot11_frame_header);
		memset((void *) buf, 0, sizeof(struct dot11_frame_header));
		header = (struct dot11_frame_header *) buf;
	
		frag_seq += SEQ_MASK;

		header->duration = DEFAULT_DURATION;
		memcpy((void *) &header->fc, (void *) &fc, sizeof(struct frame_control));
		header->frag_seq = frag_seq;

		memcpy((void *) header->addr1, get_bssid(), MAC_ADDR_LEN);
		memcpy((void *) header->addr2, get_mac(), MAC_ADDR_LEN);
		memcpy((void *) header->addr3, get_bssid(), MAC_ADDR_LEN);
	}

	return buf;
}

const void *build_authentication_management_frame(size_t *len)
{
	struct authentication_management_frame *frame = NULL;
	const void *buf = NULL;

	buf = malloc(sizeof(struct authentication_management_frame));
	if(buf)
	{
		*len = sizeof(struct authentication_management_frame);
		memset((void *) buf, 0, *len);
		frame = (struct authentication_management_frame *) buf;

		frame->algorithm = OPEN_SYSTEM;
		frame->sequence = 1;
		frame->status = 0;
	}
	
	return buf;
}

const void *build_association_management_frame(size_t *len)
{
	struct association_request_management_frame *frame = NULL;
	const void *buf = NULL;

	buf = malloc(sizeof(struct association_request_management_frame));
	if(buf)
	{
		*len = sizeof(struct association_request_management_frame);
		memset((void *) buf, 0, *len);
		frame = (struct association_request_management_frame *) buf;

		frame->capability = get_ap_capability();
		frame->listen_interval = LISTEN_INTERVAL;
	}

	return buf;
}

const void *build_llc_header(size_t *len)
{
	struct llc_header *header = NULL;
	const void *buf = NULL;
	
	buf = malloc(sizeof(struct llc_header));
	if(buf)
	{
		*len = sizeof(struct llc_header);
		memset((void *) buf, 0, sizeof(struct llc_header));
		header = (struct llc_header *) buf;

		header->dsap = LLC_SNAP;
		header->ssap = LLC_SNAP;
		header->control_field = UNNUMBERED_FRAME;
		header->type = DOT1X_AUTHENTICATION;

	}

	return buf;
}

const void *build_wps_probe_request(unsigned char *bssid, char *essid, size_t *len)
{
	struct tagged_parameter ssid_tag = { 0 };
	const void *rt_header = NULL, *dot11_header = NULL, *packet = NULL;
	size_t offset = 0, rt_len = 0, dot11_len = 0, ssid_tag_len = 0, packet_len = 0;

	if(essid != NULL)
	{
		ssid_tag.len = (uint8_t) strlen(essid);
	}
	else
	{
		ssid_tag.len = 0;
	}

	ssid_tag.number = SSID_TAG_NUMBER;
	ssid_tag_len = ssid_tag.len + sizeof(struct tagged_parameter);

	rt_header = build_radio_tap_header(&rt_len);
	dot11_header = build_dot11_frame_header(FC_PROBE_REQUEST, &dot11_len);
	
	if(rt_header && dot11_header)
	{
		packet_len = rt_len + dot11_len + ssid_tag_len + WPS_PROBE_IE_SIZE;
		packet = malloc(packet_len);

		if(packet)
		{
			memset((void *) packet, 0, packet_len);
			memcpy((void *) packet, rt_header, rt_len);
			offset += rt_len;
			memcpy((void *) ((char *) packet+offset), dot11_header, dot11_len);
			offset += dot11_len;
			memcpy((void *) ((char *) packet+offset), (void *) &ssid_tag, sizeof(ssid_tag));
			offset += sizeof(ssid_tag);
			memcpy((void *) ((char *) packet+offset), essid, ssid_tag.len);
			offset += ssid_tag.len;
			memcpy((void *) ((char *) packet+offset), WPS_PROBE_IE, WPS_PROBE_IE_SIZE);
			offset += WPS_PROBE_IE_SIZE;

			*len = packet_len;
		}
	}
	
	if(rt_header) free((void *) rt_header);
	if(dot11_header) free((void *) dot11_header);

	return packet;
}

/* Wrapper function for Radio Tap / Dot11 / LLC */
const void *build_snap_packet(size_t *len)
{
	const void *rt_header = NULL, *dot11_header = NULL, *llc_header = NULL, *packet = NULL;
	size_t rt_len = 0, dot11_len = 0, llc_len = 0, packet_len = 0;

	rt_header = build_radio_tap_header(&rt_len);
        dot11_header = build_dot11_frame_header(FC_STANDARD, &dot11_len);
        llc_header = build_llc_header(&llc_len);

	if(rt_header && dot11_header && llc_header)
	{
		packet_len = rt_len + dot11_len + llc_len;
		packet = malloc(packet_len);

		if(packet)
		{
			memset((void *) packet, 0, packet_len);
			memcpy((void *) packet, rt_header, rt_len);
			memcpy((void *) ((char *) packet+rt_len), dot11_header, dot11_len);
			memcpy((void *) ((char *) packet+rt_len+dot11_len), llc_header, llc_len);

			*len = packet_len;
		}
	
		free((void *) rt_header);
		free((void *) dot11_header);
		free((void *) llc_header);
	}

	return packet;
}

const void *build_dot1X_header(uint8_t type, uint16_t payload_len, size_t *len)
{
	struct dot1X_header *header = NULL;
	const void *buf = NULL;

	buf = malloc(sizeof(struct dot1X_header));
	if(buf)
	{
		*len = sizeof(struct dot1X_header);
		memset((void *) buf, 0, sizeof(struct dot1X_header));
		header = (struct dot1X_header *) buf;

		header->version = DOT1X_VERSION;
		header->type = type;
		header->len = htons(payload_len);
	}

	return buf;
}

const void *build_eap_header(uint8_t id, uint8_t code, uint8_t type, uint16_t payload_len, size_t *len)
{
	struct eap_header *header = NULL;
	const void *buf = NULL;

	buf = malloc(sizeof(struct eap_header));
	if(buf)
	{
		*len = sizeof(struct eap_header);
		memset((void *) buf, 0, sizeof(struct eap_header));
		header = (struct eap_header *) buf;
		
		header->code = code;
		header->id = id;
		header->len = htons((payload_len + *len));
		header->type = type;

		id++;
	}

	return buf;
}

const void *build_wfa_header(uint8_t op_code, size_t *len)
{
	const void *buf = NULL;
	struct wfa_expanded_header *header = NULL;

	buf = malloc(sizeof(struct wfa_expanded_header));
	if(buf)
	{
		*len = sizeof(struct wfa_expanded_header);
		memset((void *) buf, 0, *len);
		header = (struct wfa_expanded_header *) buf;
	
		memcpy(header->id, WFA_VENDOR_ID, sizeof(header->id));
		header->type = SIMPLE_CONFIG;
		header->opcode = op_code;
	}
	
	return buf;
}

/* Wrapper for SNAP / Dot1X Start */
const void *build_eapol_start_packet(size_t *len)
{
	const void *snap_packet = NULL, *dot1x_header = NULL, *packet = NULL;
        size_t snap_len = 0, dot1x_len = 0, packet_len = 0;

        /* Build a SNAP packet and a 802.1X START header */
        snap_packet = build_snap_packet(&snap_len);
        dot1x_header = build_dot1X_header(DOT1X_START, 0, &dot1x_len);

	if(snap_packet && dot1x_header)
	{
        	packet_len = snap_len + dot1x_len;
        	packet = malloc(packet_len);

        	if(packet)
        	{
        	        /* Build packet */
        	        memset((void *) packet, 0, packet_len);
        	        memcpy((void *) packet, snap_packet, snap_len);
        	        memcpy((void *) ((char *) packet+snap_len), dot1x_header, dot1x_len);

			*len = packet_len;
		}

		free((void *) snap_packet);
		free((void *) dot1x_header);
	}

	return packet;
}

/* Wrapper for SNAP / Dot1X / EAP / WFA / Payload */
const void *build_eap_packet(const void *payload, uint16_t payload_len, size_t *len)
{
	const void *buf = NULL, *snap_packet = NULL, *eap_header = NULL, *dot1x_header = NULL, *wfa_header = NULL;
	size_t buf_len = 0, snap_len = 0, eap_len = 0, dot1x_len = 0, wfa_len = 0, offset = 0, total_payload_len = 0;
	uint8_t eap_type = 0, eap_code = 0;
	struct wps_data *wps = get_wps();

	/* Decide what type of EAP packet to build based on the current WPS state */
	switch(wps->state)
	{
		case RECV_M1:
			eap_code = EAP_RESPONSE;
			eap_type = EAP_IDENTITY;
			break;
		default:
			eap_code = EAP_RESPONSE;
			eap_type = EAP_EXPANDED;
	}

	/* Total payload size may or may not be equal to payload_len depending on if we
	 * need to build and add a WFA header to the packet payload.
	 */
	total_payload_len = payload_len;

	/* If eap_type is Expanded, then we need to add a WFA header */
	if(eap_type == EAP_EXPANDED)
	{
		wfa_header = build_wfa_header(get_opcode(), &wfa_len);
		total_payload_len += wfa_len;
	}

	/* Build SNAP, EAP and 802.1x headers */
	snap_packet = build_snap_packet(&snap_len);
	eap_header = build_eap_header(get_eap_id(), eap_code, eap_type, total_payload_len, &eap_len);
	dot1x_header = build_dot1X_header(DOT1X_EAP_PACKET, (total_payload_len+eap_len), &dot1x_len);

	if(snap_packet && eap_header && dot1x_header)
	{
		buf_len = snap_len + dot1x_len + eap_len + total_payload_len;
		buf = malloc(buf_len);
		if(buf)
		{
			memset((void *) buf, 0, buf_len);

			/* Build the packet */
			memcpy((void *) buf, snap_packet, snap_len);
			offset += snap_len;
			memcpy((void *) ((char *) buf+offset), dot1x_header, dot1x_len);
			offset += dot1x_len;
			memcpy((void *) ((char *) buf+offset), eap_header, eap_len);
			offset += eap_len;
	
			if(eap_type == EAP_EXPANDED)
			{
				memcpy((void *) ((char *) buf+offset), wfa_header, wfa_len);
				offset += wfa_len;
			}

			if(payload && payload_len)
			{
				memcpy((void *) ((char *) buf+offset), payload, payload_len);
			}

			*len = (offset + payload_len);
		}

		free((void *) snap_packet);
		free((void *) eap_header);
		free((void *) dot1x_header);
		if(wfa_header) free((void *) wfa_header);
	}

	return buf;
}

const void *build_eap_failure_packet(size_t *len)
{
	const void *buf = NULL, *snap_packet = NULL, *eap_header = NULL, *dot1x_header = NULL;
	size_t buf_len = 0, snap_len = 0, eap_len = 0, dot1x_len = 0, offset = 0;

	/* Build SNAP, EAP and 802.1x headers */
        snap_packet = build_snap_packet(&snap_len);
        eap_header = build_eap_header(get_eap_id(), EAP_FAILURE, EAP_FAILURE, 0, &eap_len);
        dot1x_header = build_dot1X_header(DOT1X_EAP_PACKET, eap_len, &dot1x_len);

	buf_len = snap_len + eap_len + dot1x_len;

	if(snap_packet && eap_header && dot1x_header)
	{
		buf = malloc(buf_len);
		if(buf)
		{
			memset((void *) buf, 0, buf_len);
			
			memcpy((void *) buf, snap_packet, snap_len);
			offset += snap_len;
			memcpy((void *) ((char *) buf+offset), dot1x_header, dot1x_len);
			offset += dot1x_len;
			memcpy((void *) ((char *) buf+offset), eap_header, eap_len);

			*len = buf_len;
		}
	}

	if(snap_packet) free((void *) snap_packet);
	if(eap_header) free((void *) eap_header);
	if(dot1x_header) free((void *) dot1x_header);

	return buf;
}

const void *build_tagged_parameter(uint8_t number, uint8_t size, size_t *len)
{
	struct tagged_parameter *param = NULL;
        const void *buf = NULL;
	size_t buf_len = 0;

	buf_len = sizeof(struct tagged_parameter);
	buf = malloc(buf_len);
        if(buf)
        {
                *len = buf_len;
                memset((void *) buf, 0, buf_len);
                param = (struct tagged_parameter *) buf;

                param->number = number;
                param->len = size;
	}

	return buf;
}

const void *build_ssid_tagged_parameter(size_t *len)
{
	const void *buf = NULL, *ssid_param = NULL;
	size_t ssid_len = 0, ssid_param_len = 0, buf_len = 0;

	if(get_ssid())
	{
		ssid_len = strlen(get_ssid());
	}

	ssid_param = build_tagged_parameter(SSID_TAG_NUMBER, ssid_len, &ssid_param_len);

	if(ssid_param)
	{
		buf_len = ssid_param_len + ssid_len;
		buf = malloc(buf_len);
		if(buf)
		{
			*len = buf_len;
			memset((void *) buf, 0, buf_len);
	
			memcpy((void *) buf, ssid_param, ssid_param_len);
			memcpy((void *) ((char *) buf+ssid_param_len), get_ssid(), ssid_len);
		}

		free((void *) ssid_param);
	}

	return buf;
}

const void *build_wps_tagged_parameter(size_t *len)
{
	const void *buf = NULL, *wps_param = NULL;
	size_t buf_len = 0, wps_param_len = 0;

	wps_param = build_tagged_parameter(WPS_TAG_NUMBER, WPS_TAG_SIZE, &wps_param_len);

	if(wps_param)
	{
		buf_len = wps_param_len + WPS_TAG_SIZE;
		buf = malloc(buf_len);
		if(buf)
		{
			*len = buf_len;
			memset((void *) buf, 0, buf_len);

			memcpy((void *) buf, wps_param, wps_param_len);
			memcpy((void *) ((char *) buf+wps_param_len), WPS_REGISTRAR_TAG, WPS_TAG_SIZE);
		}
		
		free((void *) wps_param);
	}

	return buf;
}

const void *build_supported_rates_tagged_parameter(size_t *len)
{
	const void *buf = NULL, *supported_rates = NULL, *extended_rates = NULL;
	unsigned char *srates = NULL;
	int srates_tag_size = 0;
        size_t buf_len = 0, srates_len = 0, erates_len = 0, offset = 0;

	srates = get_ap_rates(&srates_tag_size);
        supported_rates = build_tagged_parameter(SRATES_TAG_NUMBER, srates_tag_size, &srates_len);
	extended_rates = build_tagged_parameter(ERATES_TAG_NUMBER, ERATES_TAG_SIZE, &erates_len);

        if(supported_rates && extended_rates)
        {
                buf_len = srates_len + erates_len + srates_tag_size + ERATES_TAG_SIZE;
                buf = malloc(buf_len);
                if(buf)
                {
                        *len = buf_len;
                        memset((void *) buf, 0, buf_len);

                        memcpy((void *) buf, supported_rates, srates_len);
			offset += srates_len;
			memcpy((void *) ((char *) buf+offset), srates, srates_tag_size);
			offset += srates_tag_size;
			memcpy((void *) ((char *) buf+offset), extended_rates, erates_len);
			offset += erates_len;
                        memcpy((void *) ((char *) buf+offset), EXTENDED_RATES_TAG, ERATES_TAG_SIZE);
                }
        }

	if(supported_rates) free((void *) supported_rates);
	if(extended_rates) free((void *) extended_rates);
	return buf;
}
