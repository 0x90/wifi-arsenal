/*
 * Reaver - WPS exchange functions
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

#include "exchange.h"

/* Main loop to listen for packets on a wireless card in monitor mode. */
enum wps_result do_wps_exchange()
{
	struct pcap_pkthdr header;
	const u_char *packet = NULL;
	enum wps_type packet_type = UNKNOWN, last_msg = UNKNOWN;
	enum wps_result ret_val = KEY_ACCEPTED;
	int premature_timeout = 0, terminated = 0, got_nack = 0;
	int id_response_sent = 0, tx_type = 0;
	int m2_sent = 0, m4_sent = 0, m6_sent = 0;

	/* Initialize settings for this WPS exchange */
	set_last_wps_state(0);
	set_eap_id(0);

	/* Initiate an EAP session */
	send_eapol_start();

	/* 
	 * Loop until:
	 *
	 * 	o The pin has been cracked
	 * 	o An EAP_FAIL packet is received
	 * 	o We receive a NACK message
	 *	o We hit an unrecoverable receive timeout
	 */
	while((get_key_status() != KEY_DONE) && 
	      !terminated &&
	      !got_nack && 
              !premature_timeout)
	{
		tx_type = 0;

		if(packet_type > last_msg)
		{
			last_msg = packet_type;
		}

		packet = next_packet(&header);
		if(packet == NULL)
		{	
			break;
		}

		packet_type = process_packet(packet, &header);
		memset((void *) packet, 0, header.len);
	
		switch(packet_type)
		{
			case IDENTITY_REQUEST:
				cprintf(VERBOSE, "[+] Received identity request\n");
				tx_type = IDENTITY_RESPONSE;
				id_response_sent = 1;
				break;
			case M1:
				cprintf(VERBOSE, "[+] Received M1 message\n");
				if(id_response_sent && !m2_sent)
				{
					tx_type = SEND_M2;
					m2_sent = 1;
				}
				else if(get_oo_send_nack())
				{
					tx_type = SEND_WSC_NACK;
					terminated = 1;
				}
				break;
			case M3:
				cprintf(VERBOSE, "[+] Received M3 message\n");
				if(m2_sent && !m4_sent)
				{
					tx_type = SEND_M4;
					m4_sent = 1;
				}
				else if(get_oo_send_nack())
				{
					tx_type = SEND_WSC_NACK;
					terminated = 1;
				}
				break;
                        case M5:
				cprintf(VERBOSE, "[+] Received M5 message\n");
                                if(get_key_status() == KEY1_WIP)
				{
					set_key_status(KEY2_WIP);
				}
				if(m4_sent && !m6_sent)
				{
                                	tx_type = SEND_M6;
					m6_sent = 1;
				}
				else if(get_oo_send_nack())
				{
					tx_type = SEND_WSC_NACK;
					terminated = 1;
				}
                                break;
			case M7:
				cprintf(VERBOSE, "[+] Received M7 message\n");
				/* Fall through */
			case DONE:
				if(get_key_status() == KEY2_WIP) 
				{
					set_key_status(KEY_DONE);
				}
				tx_type = SEND_WSC_NACK;
				break;
			case NACK:
				cprintf(VERBOSE, "[+] Received WSC NACK\n");
				got_nack = 1;
				break;
			case TERMINATE:
				terminated = 1;
				break;
			default:
				if(packet_type != 0)
				{
					cprintf(VERBOSE, "[!] WARNING: Unexpected packet received (0x%.02X), terminating transaction\n", packet_type);
					terminated = 1;
				}
				break;
		}

		if(tx_type == IDENTITY_RESPONSE)
		{
			send_identity_response();
		}
		else if(tx_type)
		{
			send_msg(tx_type);
		}
		/* 
		 * If get_oo_send_nack is 0, then when out of order packets come, we don't
		 * NACK them. However, this also means that we wait infinitely for the expected
		 * packet, since the timer is started by send_msg. Manually start the timer to
		 * prevent infinite loops.
		 */
		else if(packet_type != 0)
		{
			start_timer();
		}

		/* Check to see if our receive timeout has expired */
		if(get_out_of_time())
		{
			/* If we have not sent an identity response, try to initiate an EAP session again */
			if(!id_response_sent)
			{
				/* Notify the user after EAPOL_START_MAX_TRIES eap start failures */
				if(get_eapol_start_count() == EAPOL_START_MAX_TRIES)
				{
					cprintf(WARNING, "[!] WARNING: %d successive start failures\n", EAPOL_START_MAX_TRIES);
					set_eapol_start_count(0);
					premature_timeout = 1;
				}

				send_eapol_start();
			}
			else
			{
				/* Treat all other time outs as unexpected errors */
				premature_timeout = 1;
			}
		}
	} 

	/*
	 * There are four states that can signify a pin failure:
	 *
	 * 	o Got NACK instead of an M5 message			(first half of pin wrong)
	 * 	o Got NACK instead of an M7 message			(second half of pin wrong)
	 * 	o Got receive timeout while waiting for an M5 message	(first half of pin wrong)
	 * 	o Got receive timeout while waiting for an M7 message	(second half of pin wrong)
	 */
	if(got_nack)
	{
		/*
		 * If a NACK message was received, then the current wps->state value will be
		 * SEND_WSC_NACK, indicating that we need to reply with a NACK. So check the
		 * previous state to see what state we were in when the NACK was received.
		 */
		if(last_msg == M3 || last_msg == M5)
		{
			/* The AP is properly sending WSC_NACKs, so don't treat future timeouts as pin failures. */
			set_timeout_is_nack(0);
			
			ret_val = KEY_REJECTED;
		}
		else
		{
			ret_val = UNKNOWN_ERROR;
		}
	}
	else if(premature_timeout)
	{
		/* 
		 * Some WPS implementations simply drop the connection on the floor instead of sending a NACK.
		 * We need to be able to handle this, but at the same time using a timeout on the M5/M7 messages
		 * can result in false negatives. Thus, treating M5/M7 receive timeouts as NACKs can be disabled.
		 * Only treat the timeout as a NACK if this feature is enabled.
		 */
		if(get_timeout_is_nack() &&
		  (last_msg == M3 || last_msg == M5))
		{
			ret_val = KEY_REJECTED;
		}
		else
		{
			/* If we timed out at any other point in the session, then we need to try the pin again */
			ret_val = RX_TIMEOUT;
		}
	}
	/*
	 * If we got an EAP FAIL message without a preceeding NACK, then something went wrong. 
	 * This should be treated the same as a RX_TIMEOUT by the caller: try the pin again.
	 */
	else if(terminated)
	{
		ret_val = EAP_FAIL;
	}
	else if(get_key_status() != KEY_DONE)
	{
		ret_val = UNKNOWN_ERROR;
	}

	/* 
	 * Always completely terminate the WPS session, else some WPS state machines may
	 * get stuck in their current state and won't accept new WPS registrar requests
	 * until rebooted.
 	 *
	 * Stop the receive timer that is started by the termination transmission.
	 */
	send_wsc_nack();
	stop_timer();
	
	if(get_eap_terminate() || ret_val == EAP_FAIL)
	{
		send_termination();
		stop_timer();
	}
	
	return ret_val;
}

/* 
 * Processes incoming packets looking for EAP and WPS messages.
 * Responsible for stopping the timer when a valid EAP packet is received.
 * Returns the type of WPS message received, if any.
 */
enum wps_type process_packet(const u_char *packet, struct pcap_pkthdr *header)
{
	struct radio_tap_header *rt_header = NULL;
	struct dot11_frame_header *frame_header = NULL;
	struct llc_header *llc = NULL;
	struct dot1X_header *dot1x = NULL;
	struct eap_header *eap = NULL;
	struct wfa_expanded_header *wfa = NULL;
	const void *wps_msg = NULL;
	size_t wps_msg_len = 0;
	enum wps_type type = UNKNOWN;
	struct wps_data *wps = NULL;

	if(packet == NULL || header == NULL)
	{
		return UNKNOWN;
	}
	else if(header->len < MIN_PACKET_SIZE)
	{
		return UNKNOWN;
	}

	/* Cast the radio tap and 802.11 frame headers and parse out the Frame Control field */
	rt_header = (struct radio_tap_header *) packet;
	frame_header = (struct dot11_frame_header *) (packet+rt_header->len);

	/* Does the BSSID/source address match our target BSSID? */
	if(memcmp(frame_header->addr3, get_bssid(), MAC_ADDR_LEN) == 0)
	{
		/* Is this a data packet sent to our MAC address? */
		if(frame_header->fc.type == DATA_FRAME && 
			frame_header->fc.sub_type == SUBTYPE_DATA && 
			(memcmp(frame_header->addr1, get_mac(), MAC_ADDR_LEN) == 0)) 
		{
			llc = (struct llc_header *) (packet +
							rt_header->len +
							sizeof(struct dot11_frame_header)
			);

			/* All packets in our exchanges will be 802.1x */
			if(llc->type == DOT1X_AUTHENTICATION)
			{
				dot1x = (struct dot1X_header *) (packet +
								rt_header->len +
								sizeof(struct dot11_frame_header) +
								sizeof(struct llc_header)
				);

				/* All packets in our exchanges will be EAP packets */
				if(dot1x->type == DOT1X_EAP_PACKET && (header->len >= EAP_PACKET_SIZE))
				{
					eap = (struct eap_header *) (packet +
									rt_header->len +
									sizeof(struct dot11_frame_header) +
									sizeof(struct llc_header) +
									sizeof(struct dot1X_header)
					);

					/* EAP session termination. Break and move on. */
					if(eap->code == EAP_FAILURE)
					{
						type = TERMINATE;
					} 
					/* If we've received an EAP request and then this should be a WPS message */
					else if(eap->code == EAP_REQUEST)
					{
						/* The EAP header builder needs this ID value */
						set_eap_id(eap->id);

						/* Stop the receive timer that was started by the last send_packet() */
						stop_timer();

						/* Check to see if we received an EAP identity request */
						if(eap->type == EAP_IDENTITY)
						{
							/* We've initiated an EAP session, so reset the counter */
							set_eapol_start_count(0);

							type = IDENTITY_REQUEST;
						} 
						/* An expanded EAP type indicates a probable WPS message */
						else if((eap->type == EAP_EXPANDED) && (header->len > WFA_PACKET_SIZE))
						{
							wfa = (struct wfa_expanded_header *) (packet +
											rt_header->len +
											sizeof(struct dot11_frame_header) +
											sizeof(struct llc_header) +
											sizeof(struct dot1X_header) +
											sizeof(struct eap_header)
							);
						
							/* Verify that this is a WPS message */
							if(wfa->type == SIMPLE_CONFIG)
							{
								wps_msg_len = 	(size_t) ntohs(eap->len) - 
										sizeof(struct eap_header) - 
										sizeof(struct wfa_expanded_header);

								wps_msg = (const void *) (packet +
											rt_header->len +
                                                                       	                sizeof(struct dot11_frame_header) +
                                                                               	        sizeof(struct llc_header) +
                                                                                       	sizeof(struct dot1X_header) +
                                                       	             	                sizeof(struct eap_header) +
											sizeof(struct wfa_expanded_header)
								);

								/* Save the current WPS state. This way if we get a NACK message, we can 
								 * determine what state we were in when the NACK arrived.
								 */
								wps = get_wps();
								set_last_wps_state(wps->state);
								set_opcode(wfa->opcode);

								/* Process the WPS message and send a response */
								type = process_wps_message(wps_msg, wps_msg_len);
							}
						}
					}
				}
			}	
		}
	}

	return type;
}

/* Processes a received WPS message and returns the message type */
enum wps_type process_wps_message(const void *data, size_t data_size)
{
	const struct wpabuf *msg = NULL;
	enum wps_type type = UNKNOWN;
	struct wps_data *wps = get_wps();
	unsigned char *element_data = NULL;
        struct wfa_element_header element = { 0 };
        int i = 0, header_size = sizeof(struct wfa_element_header);

	/* Shove data into a wpabuf structure for processing */
	msg = wpabuf_alloc_copy(data, data_size);
	if(msg)
	{
		/* Process the incoming message */
		wps_registrar_process_msg(wps, get_opcode(), msg);
		wpabuf_free((struct wpabuf *) msg);
	
		/* Loop through until we hit the end of the data buffer */
                for(i=0; i<data_size; i+=header_size)
                {
                        element_data = NULL;
                        memset((void *) &element, 0, header_size);

                        /* Get the element header data */
                        memcpy((void *) &element, (data + i), header_size);
                        element.type = htons(element.type);
                        element.length = htons(element.length);

                        /* Make sure the element length does not exceed the remaining buffer size */
                        if(element.length <= (data_size - i - header_size))
                        {
                                element_data = (unsigned char *) (data + i + header_size);

                                switch(element.type)
                                {
                                        case MESSAGE_TYPE:
                                                type = (uint8_t) element_data[0];
                                                break;
                                        default:
                                                break;
                                }
                        }

                        /* Offset must include element length(s) */
                        i += element.length;
                }
	
	}

	return type;
}

/* 
 * Get the reason code for a WSC NACK message. Not really useful because in practice the NACK
 * reason code could be anything (even a non-existent code!), but keep it around just in case... 
 */
int parse_nack(const void *data, size_t data_size)
{
	struct wps_parse_attr attr = { 0 };
	const struct wpabuf *msg = NULL;
	int ret_val = 0;

	/* Shove data into a wpabuf structure for processing */
        msg = wpabuf_alloc_copy(data, data_size);
	if(msg)
	{
		if(wps_parse_msg(msg, &attr) >= 0)
		{
			if(attr.config_error)
			{
				ret_val = WPA_GET_BE16(attr.config_error);
			}
		}
		
		wpabuf_free((struct wpabuf *) msg);
	}

	return ret_val;
}
