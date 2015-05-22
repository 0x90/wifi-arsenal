/*
 * Reaver - 802.11 functions
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

#include "80211.h"

/*Reads the next packet from pcap_next() and validates the FCS. */
const u_char *next_packet(struct pcap_pkthdr *header)
{
	const u_char *packet = NULL;

	/* Loop until we get a valid packet, or until we run out of packets */
	while((packet = pcap_next(get_handle(), header)) != NULL)
	{
		if(get_validate_fcs())
		{
			if(check_fcs(packet, header->len))
			{
				break;
			}
			else
			{
				cprintf(INFO, "[!] Found packet with bad FCS, skipping...\n");
			}
		}
		else
		{
			break;
		}
	}

	return packet;
}

/* 
 * Waits for a beacon packet from the target AP and populates the globule->ap_capabilities field.
 * This is used for obtaining the capabilities field and AP SSID.
 */
void read_ap_beacon()
{
        struct pcap_pkthdr header;
        const u_char *packet = NULL;
        struct radio_tap_header *rt_header = NULL;
        struct dot11_frame_header *frame_header = NULL;
        struct beacon_management_frame *beacon = NULL;
	int channel = 0;
	size_t tag_offset = 0;
	time_t start_time = 0;

	set_ap_capability(0);
	start_time = time(NULL);
	
        while(get_ap_capability() == 0)
        {
                packet = next_packet(&header);
                if(packet == NULL)
                {
                        break;
                }

                if(header.len >= MIN_BEACON_SIZE)
                {
                        rt_header = (struct radio_tap_header *) radio_header(packet, header.len);
                        frame_header = (struct dot11_frame_header *) (packet + rt_header->len);

			if(is_target(frame_header))
			{
                                if(frame_header->fc.type == MANAGEMENT_FRAME && frame_header->fc.sub_type == SUBTYPE_BEACON)
                                {
                                       	beacon = (struct beacon_management_frame *) (packet + rt_header->len + sizeof(struct dot11_frame_header));
                                       	set_ap_capability(beacon->capability);

					/* Obtain the SSID and channel number from the beacon packet */
					tag_offset = rt_header->len + sizeof(struct dot11_frame_header) + sizeof(struct beacon_management_frame);
					channel = parse_beacon_tags(packet, header.len);
					
					/* If no channel was manually specified, switch to the AP's current channel */
					if(!get_fixed_channel() && get_auto_channel_select() && channel > 0 && channel != get_channel())
					{
						change_channel(channel);
						set_channel(channel);
					}

                                       	break;
				}
			}
                }

		/* If we haven't seen any beacon packets from the target within BEACON_WAIT_TIME seconds, try another channel */
		if((time(NULL) - start_time) >= BEACON_WAIT_TIME)
		{
			next_channel();
			start_time = time(NULL);
		}
        }
}

/* Extracts the signal strength field (if any) from the packet's radio tap header */
int8_t signal_strength(const u_char *packet, size_t len)
{
	int8_t ssi = 0;
	int offset = sizeof(struct radio_tap_header);
	struct radio_tap_header *header = NULL;

	if(has_rt_header() && (len > (sizeof(struct radio_tap_header) + TSFT_SIZE + FLAGS_SIZE + RATE_SIZE + CHANNEL_SIZE + FHSS_FLAG)))
	{
		header = (struct radio_tap_header *) packet;

		if((header->flags & SSI_FLAG) == SSI_FLAG)
		{
			if((header->flags & TSFT_FLAG) == TSFT_FLAG)
			{
				offset += TSFT_SIZE;
			}

			if((header->flags & FLAGS_FLAG) == FLAGS_FLAG)
			{
				offset += FLAGS_SIZE;
			}
	
			if((header->flags & RATE_FLAG) == RATE_FLAG)
			{
				offset += RATE_SIZE;
			}

			if((header->flags & CHANNEL_FLAG) == CHANNEL_FLAG)
			{
				offset += CHANNEL_SIZE;
			}

			if((header->flags & FHSS_FLAG) == FHSS_FLAG)
			{
				offset += FHSS_FLAG;
			}

			if(offset < len)
			{
				ssi = (int8_t) packet[offset];
			}
		}
	}

	return ssi;
}

/* 
 * Determines if the target AP has locked its WPS state or not.
 * Returns 0 if not locked, 1 if locked.
 */
int is_wps_locked()
{
	int locked = 0;
	struct libwps_data wps = { 0 };
	struct pcap_pkthdr header;
        const u_char *packet = NULL;
        struct radio_tap_header *rt_header = NULL;
        struct dot11_frame_header *frame_header = NULL;

	while(1)
	{
		packet = next_packet(&header);
        	if(packet == NULL)
		{
			break;
		}

		if(header.len >= MIN_BEACON_SIZE)
		{
			rt_header = (struct radio_tap_header *) radio_header(packet, header.len);
			frame_header = (struct dot11_frame_header *) (packet + rt_header->len);

			if(memcmp(frame_header->addr3, get_bssid(), MAC_ADDR_LEN) == 0)
			{
				if(frame_header->fc.type == MANAGEMENT_FRAME && frame_header->fc.sub_type == SUBTYPE_BEACON)
				{
					if(parse_wps_parameters(packet, header.len, &wps))
					{
						if(wps.locked == WPSLOCKED)
						{
							locked = 1;
						}
						break;
					}
				}

                        }
		}
	}

	return locked;
}

/* Deauths and re-associates a MAC address with the AP. Returns 0 on failure, 1 for success. */
int reassociate()
{
	int tries = 0, retval = 0;

	/* Make sure we can still see beacons (also, read_ap_beaon will ensure we're on the right channel) */
	read_ap_beacon();

	if(!get_external_association())
	{
		/* Deauth to void any previous association with the AP */
		deauthenticate();

		/* Try MAX_AUTH_TRIES times to authenticate to the AP */
		do
		{
			authenticate();
			tries++;
		}
		while((associate_recv_loop() != AUTH_OK) && (tries < MAX_AUTH_TRIES));

		/* If authentication was successful, try MAX_AUTH_TRIES to associate with the AP */
		if(tries < MAX_AUTH_TRIES)
		{
			tries = 0;

			do
			{
				associate();
				tries++;
			}
			while((associate_recv_loop() != ASSOCIATE_OK) && (tries < MAX_AUTH_TRIES));
		}

		if(tries < MAX_AUTH_TRIES)
		{
			retval = 1;
		}
		else
		{
			retval = 0;
		}
	}
	else
	{
		retval = 1;
	}

	return retval;
}

/* Deauthenticate ourselves from the AP */
void deauthenticate()
{
	const void *radio_tap = NULL, *dot11_frame = NULL, *packet = NULL;
	size_t radio_tap_len = 0, dot11_frame_len = 0, packet_len = 0;
	
	radio_tap = build_radio_tap_header(&radio_tap_len);
        dot11_frame = build_dot11_frame_header(FC_DEAUTHENTICATE, &dot11_frame_len);
	packet_len = radio_tap_len + dot11_frame_len + DEAUTH_REASON_CODE_SIZE;

	if(radio_tap && dot11_frame)
	{
		packet = malloc(packet_len);
		if(packet)
		{
			memset((void *) packet, 0, packet_len);

			memcpy((void *) packet, radio_tap, radio_tap_len);
			memcpy((void *) ((char *) packet+radio_tap_len), dot11_frame, dot11_frame_len);
			memcpy((void *) ((char *) packet+radio_tap_len+dot11_frame_len), DEAUTH_REASON_CODE, DEAUTH_REASON_CODE_SIZE);

			pcap_inject(get_handle(), packet, packet_len);

			free((void *) packet);
		}
	}

	if(radio_tap) free((void *) radio_tap);
	if(dot11_frame) free((void *) dot11_frame);

	return;
}

/* Authenticate ourselves with the AP */
void authenticate()
{
	const void *radio_tap = NULL, *dot11_frame = NULL, *management_frame = NULL, *packet = NULL;
	size_t radio_tap_len = 0, dot11_frame_len = 0, management_frame_len = 0, packet_len = 0;

	radio_tap = build_radio_tap_header(&radio_tap_len);
	dot11_frame = build_dot11_frame_header(FC_AUTHENTICATE, &dot11_frame_len);
	management_frame = build_authentication_management_frame(&management_frame_len);
	packet_len = radio_tap_len + dot11_frame_len + management_frame_len;

	if(radio_tap && dot11_frame && management_frame)
	{
		packet = malloc(packet_len);
		if(packet)
		{
			memset((void *) packet, 0, packet_len);

			memcpy((void *) packet, radio_tap, radio_tap_len);
			memcpy((void *) ((char *) packet+radio_tap_len), dot11_frame, dot11_frame_len);
			memcpy((void *) ((char *) packet+radio_tap_len+dot11_frame_len), management_frame, management_frame_len);

			pcap_inject(get_handle(), packet, packet_len);

			free((void *) packet);
		}
	}

	if(radio_tap) free((void *) radio_tap);
	if(dot11_frame) free((void *) dot11_frame);
	if(management_frame) free((void *) management_frame);

	return;
}

/* Associate with the AP */
void associate()
{
	const void *radio_tap = NULL, *dot11_frame = NULL, *management_frame = NULL, *ssid_tag = NULL, *wps_tag = NULL, *rates_tag = NULL, *packet = NULL;
        size_t radio_tap_len = 0, dot11_frame_len = 0, management_frame_len = 0, ssid_tag_len = 0, wps_tag_len = 0, rates_tag_len = 0, packet_len = 0, offset = 0;

        radio_tap = build_radio_tap_header(&radio_tap_len);
        dot11_frame = build_dot11_frame_header(FC_ASSOCIATE, &dot11_frame_len);
        management_frame = build_association_management_frame(&management_frame_len);
	ssid_tag = build_ssid_tagged_parameter(&ssid_tag_len);
	rates_tag = build_supported_rates_tagged_parameter(&rates_tag_len);
	wps_tag = build_wps_tagged_parameter(&wps_tag_len);
        packet_len = radio_tap_len + dot11_frame_len + management_frame_len + ssid_tag_len + wps_tag_len + rates_tag_len;
	
	if(radio_tap && dot11_frame && management_frame && ssid_tag && wps_tag && rates_tag)
        {
                packet = malloc(packet_len);
                if(packet)
                {
                        memset((void *) packet, 0, packet_len);

                        memcpy((void *) packet, radio_tap, radio_tap_len);
			offset += radio_tap_len;
                        memcpy((void *) ((char *) packet+offset), dot11_frame, dot11_frame_len);
			offset += dot11_frame_len;
                        memcpy((void *) ((char *) packet+offset), management_frame, management_frame_len);
			offset += management_frame_len;
			memcpy((void *) ((char *) packet+offset), ssid_tag, ssid_tag_len);
			offset += ssid_tag_len;
			memcpy((void *) ((char *) packet+offset), rates_tag, rates_tag_len);
			offset += rates_tag_len;
			memcpy((void *) ((char *) packet+offset), wps_tag, wps_tag_len);

                        pcap_inject(get_handle(), packet, packet_len);

                        free((void *) packet);
                }
        }

        if(radio_tap) free((void *) radio_tap);
        if(dot11_frame) free((void *) dot11_frame);
        if(management_frame) free((void *) management_frame);
	if(ssid_tag) free((void *) ssid_tag);
	if(wps_tag) free((void *) wps_tag);
	if(rates_tag) free((void *) rates_tag);

	return;
}

/* Waits for authentication and association responses from the target AP */
int associate_recv_loop()
{
	struct pcap_pkthdr header;
        const u_char *packet = NULL;
	struct radio_tap_header *rt_header = NULL;
        struct dot11_frame_header *dot11_frame = NULL;
        struct authentication_management_frame *auth_frame = NULL;
        struct association_response_management_frame *assoc_frame = NULL;
        int ret_val = 0, start_time = 0;

        start_time = time(NULL);

        while((time(NULL) - start_time) < ASSOCIATE_WAIT_TIME)
        {
                packet = next_packet(&header);
                if(packet == NULL)
                {
                        break;
                }

                if(header.len >= MIN_AUTH_SIZE)
                {
			rt_header = (struct radio_tap_header *) radio_header(packet, header.len);
                        dot11_frame = (struct dot11_frame_header *) (packet + rt_header->len);

                        if((memcmp(dot11_frame->addr3, get_bssid(), MAC_ADDR_LEN) == 0) &&
                           (memcmp(dot11_frame->addr1, get_mac(), MAC_ADDR_LEN) == 0))
                        {
				if(dot11_frame->fc.type == MANAGEMENT_FRAME)
				{
                                	auth_frame = (struct authentication_management_frame *) (packet + sizeof(struct dot11_frame_header) + rt_header->len);
                                	assoc_frame = (struct association_response_management_frame *) (packet + sizeof(struct dot11_frame_header) + rt_header->len);

					/* Did we get an authentication packet with a successful status? */
					if((dot11_frame->fc.sub_type == SUBTYPE_AUTHENTICATION) && (auth_frame->status == AUTHENTICATION_SUCCESS))
                               		{
                               	        	ret_val = AUTH_OK;
                               	        	break;
                               		}
					/* Did we get an association packet with a successful status? */
                               		else if((dot11_frame->fc.sub_type == SUBTYPE_ASSOCIATION) && (assoc_frame->status == ASSOCIATION_SUCCESS))
					{
						ret_val = ASSOCIATE_OK;
						break;
                               		}
				}
                        }
                }
        }

        return ret_val;
}

/* Given a beacon / probe response packet, returns the reported encryption type (WPA, WEP, NONE)
   THIS IS BROKE!!! DO NOT USE!!!
*/
enum encryption_type supported_encryption(const u_char *packet, size_t len)
{
	enum encryption_type enc = NONE;
	const u_char *tag_data = NULL;
	struct radio_tap_header *rt_header = NULL;
	size_t vlen = 0, voff = 0, tag_offset = 0, tag_len = 0, offset = 0;
	struct beacon_management_frame *beacon = NULL;

	if(len > MIN_BEACON_SIZE)
	{
		rt_header = (struct radio_tap_header *) radio_header(packet, len);
		beacon = (struct beacon_management_frame *) (packet + rt_header->len + sizeof(struct dot11_frame_header));
		offset = tag_offset = rt_header->len + sizeof(struct dot11_frame_header) + sizeof(struct beacon_management_frame);
		
		tag_len = len - tag_offset;
		tag_data = (const u_char *) (packet + tag_offset);

		if((beacon->capability & CAPABILITY_WEP) == CAPABILITY_WEP)
		{
			enc = WEP;

			tag_data = parse_ie_data(tag_data, tag_len, (uint8_t) RSN_TAG_NUMBER, &vlen, &voff);
			if(tag_data && vlen > 0)
			{
				enc = WPA;
				free((void *) tag_data);
			}
			else
			{
				while(offset < len)
				{
					tag_len = len - offset;
					tag_data = (const u_char *) (packet + offset);

					tag_data = parse_ie_data(tag_data, tag_len, (uint8_t) VENDOR_SPECIFIC_TAG, &vlen, &voff);
					if(vlen > WPA_IE_ID_LEN)
					{
						if(memcmp(tag_data, WPA_IE_ID, WPA_IE_ID_LEN) == 0)
						{
							enc = WPA;
							break;
						}
						free((void *) tag_data);
					}

					offset = tag_offset + voff + vlen;
				}
			}
		}
	}

	return enc;
}

/* Given the tagged parameter sets from a beacon packet, locate the AP's SSID and return its current channel number */
int parse_beacon_tags(const u_char *packet, size_t len)
{
	char *ssid = NULL;
	const u_char *tag_data = NULL;
	unsigned char *ie = NULL, *channel_data = NULL;
	size_t ie_len = 0, ie_offset = 0, tag_len = 0, tag_offset = 0;
	int channel = 0;
	struct radio_tap_header *rt_header = NULL;

	rt_header = (struct radio_tap_header *) radio_header(packet, len);
	tag_offset = rt_header->len + sizeof(struct dot11_frame_header) + sizeof(struct beacon_management_frame);

	if(tag_offset < len)
	{
		tag_len = (len - tag_offset);
		tag_data = (const u_char *) (packet + tag_offset);

		/* If no SSID was manually specified, parse and save the AP SSID */
		if(get_ssid() == NULL)
		{
			ie = parse_ie_data(tag_data, tag_len, (uint8_t) SSID_TAG_NUMBER, &ie_len, &ie_offset);
			if(ie)
			{
				/* Return data is not null terminated; allocate ie_len+1 and memcpy string */
				ssid = malloc(ie_len+1);
				if(ssid)
				{
					memset(ssid, 0, (ie_len+1));
					memcpy(ssid, ie, ie_len);
					set_ssid(ssid);
					free(ssid);
				}

				free(ie);
			}
		}

		ie = parse_ie_data(tag_data, tag_len, (uint8_t) RATES_TAG_NUMBER, &ie_len, &ie_offset);
		if(ie)
		{
			set_ap_rates(ie, ie_len);
			free(ie);
		}

		channel_data = parse_ie_data(tag_data, tag_len, (uint8_t) CHANNEL_TAG_NUMBER, &ie_len, &ie_offset);
		if(channel_data)
		{
			if(ie_len  == 1)
			{
				memcpy((int *) &channel, channel_data, ie_len);
			}
			free(channel_data);
		}
	}

	return channel;
}

/* Gets the data for a given IE inside a tagged parameter list */
unsigned char *parse_ie_data(const u_char *data, size_t len, uint8_t tag_number, size_t *ie_len, size_t *ie_offset)
{
	unsigned char *tag_data = NULL;
        int offset = 0, tag_size = 0;
        struct tagged_parameter *tag = NULL;

        tag_size = sizeof(struct tagged_parameter);
	*ie_len = 0;
	*ie_offset = 0;

        while((offset + tag_size) < len)
        {
                tag = (struct tagged_parameter *) (data + offset);
                /* Check for the tag number and a sane tag length value */
                if((tag->number == tag_number) &&
                   (tag->len <= (len - offset - tag_size))
                )
                {
                        tag_data = malloc(tag->len);
                        if(tag_data)
                        {
                                memset(tag_data, 0, (tag->len));
                                memcpy(tag_data, (data + offset + tag_size), tag->len);
				*ie_len = tag->len;
				*ie_offset = offset;
                        }
                        break;
                }

                offset += (tag_size + tag->len);
        }

        return tag_data;
}

/* Validates a packet's reported FCS value */
int check_fcs(const u_char *packet, size_t len)
{
	int offset = 0, match = 0;
	uint32_t fcs = 0, fcs_calc = 0;
	struct radio_tap_header *rt_header = NULL;
	
	if(len > 4)
	{
		/* Get the packet's reported FCS (last 4 bytes of the packet) */
		memcpy((uint32_t *) &fcs, (packet + (len-4)), 4);

		/* FCS is not calculated over the radio tap header */
		if(has_rt_header())
		{
			rt_header = (struct radio_tap_header *) packet;
			offset += rt_header->len;
		}

		if(len > offset)
		{
			/* FCS is the inverse of the CRC32 checksum of the data packet minus the frame's FCS and radio tap header (if any) */
			fcs_calc = ~crc32((char *) packet+offset, (len-offset-4));

			if(fcs_calc == fcs)
			{
				match = 1;
			}
		}
	}

	return match;
	
}

/* Checks a given BSSID to see if it's on our target list */
int is_target(struct dot11_frame_header *frame_header)
{
        int yn = 1;

        if(memcmp(get_bssid(), NULL_MAC, MAC_ADDR_LEN) != 0)
        {
                if(memcmp(frame_header->addr3, get_bssid(), MAC_ADDR_LEN) != 0)
                {
                        yn = 0;
                }
        }

        return yn;
}

/* Make best guess to determine if a radio tap header is present */
int has_rt_header(void)
{
        int yn = 0;

	if(pcap_datalink(get_handle()) == DLT_IEEE802_11_RADIO)
	{
		yn = 1;
	}

        return yn;
}

/* 
 * Returns a pointer to the radio tap header. If there is no radio tap header,
 * it returns a pointer to a dummy radio tap header.
 */
const u_char *radio_header(const u_char *packet, size_t len)
{
        if(has_rt_header())
        {
                return packet;
        }
        else
        {
                return (u_char *) FAKE_RADIO_TAP_HEADER;
        }

}
