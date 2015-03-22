/*
 * Reaver - Transmit functions
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

#include "send.h"

/* Initiate the WPS session with an EAPOL START packet */
int send_eapol_start()
{
	const void *packet = NULL;
	size_t packet_len = 0;
	int ret_val = 0;

	packet = build_eapol_start_packet(&packet_len);

	if(packet)
	{
		cprintf(VERBOSE, "[+] Sending EAPOL START request\n");
		ret_val = send_packet(packet, packet_len);
		free((void *) packet);
	}

	/* 
	 * This is used to track how many times an EAPOL START request is sent
	 * in a row.
	 *  
	 * It is cleared by the process_packets() function when an EAP identity
	 * resquest is received.
	 * 
	 * If it reaches EAPOL_START_MAX_TRIES, do_wps_exchange() will notify
	 * the user.
	 */
	set_eapol_start_count(get_eapol_start_count() + 1);

	return ret_val;
}

/* Send an identity response packet */
int send_identity_response()
{
	const void *packet = NULL, *identity = NULL;
	size_t packet_len = 0;
	int ret_val = 0;

	identity = WFA_REGISTRAR;

	packet = build_eap_packet(identity, strlen(identity), &packet_len);

	if(packet)
	{
		cprintf(VERBOSE, "[+] Sending identity response\n");
		ret_val = send_packet(packet, packet_len);
		free((void *) packet);
	}

	return ret_val;
}

/* Send the appropriate WPS message based on the current WPS state (globule->wps->state) */
int send_msg(int type)
{
	int ret_val = 0;
	const struct wpabuf *msg = NULL;
	unsigned char *payload = NULL;
        const void *packet = NULL;
        size_t packet_len = 0;
        uint16_t payload_len = 0;
	enum wsc_op_code opcode = 0;
	struct wps_data *wps = get_wps();

	/* 
	 * Get the next message we need to send based on the data retrieved 
	 * from wps_registrar_process_msg (see exchange.c).
	 */
        msg = wps_registrar_get_msg(wps, &opcode, type);
	set_opcode(opcode);
        if(msg)
        {
		/* Get a pointer to the actual data inside of the wpabuf */
                payload = (unsigned char *) wpabuf_head(msg);
                payload_len = (uint16_t) msg->used;

		/* Build and send an EAP packet with the message payload */
                packet = build_eap_packet(payload, payload_len, &packet_len);
		if(packet)
		{
			if(send_packet(packet, packet_len))
			{
				ret_val = 1;
			} else {
				free((void *) packet);
			}
		}

		wpabuf_free((struct wpabuf *) msg);
        }

	return ret_val;
}

/* 
 * Send a WSC_NACK message followed by an EAP failure packet.
 * This is only called when completely terminating a cracking session.
 */
void send_termination()
{
	const void *data = NULL;
	size_t data_size = 0;

	data = build_eap_failure_packet(&data_size);
	if(data)
	{
		send_packet(data, data_size);
		free((void*) data);
	}
}

/* Send a WSC_NACK message */
void send_wsc_nack()
{
	struct wps_data *wps = get_wps();

	wps->state = SEND_WSC_NACK;
	send_msg(SEND_WSC_NACK);
}

/* 
 * All transmissions are handled here to ensure that the receive timer 
 * is always started immediately after a packet is transmitted.
 */
int send_packet(const void *packet, size_t len)
{
	int ret_val = 0;

	if(pcap_inject(get_handle(), packet, len) == len)
	{
		ret_val = 1;
	}
		
	start_timer();

	return ret_val;
}
