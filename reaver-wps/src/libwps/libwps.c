/*
 * LibWPS
 * Copyright (c) 2011, Tactical Network Solutions, Craig Heffner <cheffner@tacnetsol.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * See README and LICENSE for more details.
 */

#define LIBWPS_C

#include "libwps.h"

/*
 * This is the only function that external code should call. 
 *
 * const u_char *packet		Pointer to a beacon or probe response packet
 * size_t len			Size of the packet
 * struct libwps_data *wps	Pointer to an allocated libwps_data structure
 *
 * Returns 1 if WPS data was found and the libwps_data structure has been populated.
 * Returns 0 if no WPS data was found.
 */
int parse_wps_parameters(const u_char *packet, size_t len, struct libwps_data *wps)
{
	const u_char *data = NULL;
	size_t data_len = 0, offset = 0;
	struct radio_tap_header *rt_header = NULL;
	int ret_val = 0;

	if(wps)
	{
		memset(wps, 0, sizeof(struct libwps_data));
	
		if(len > (sizeof(struct radio_tap_header) + 
			  sizeof(struct dot11_frame_header) + 
		 	  sizeof(struct management_frame)))
		{
			rt_header = (struct radio_tap_header *) libwps_radio_header(packet, len);

			offset = rt_header->len + sizeof(struct dot11_frame_header) + sizeof(struct management_frame);
			data = (packet + offset);
			data_len = (len - offset);

			ret_val = parse_wps_tag(data, len, wps);
		}
	}

	return ret_val;
}

/* Parse and print WPS data in beacon packets and probe responses */
int parse_wps_tag(const u_char *tags, size_t len, struct libwps_data *wps)
{
	unsigned char *wps_ie_data = NULL, *el = NULL;
	char *ptr = NULL, *src = NULL;
	int i = 0, ret_val = 0;
	size_t wps_data_len = 0, el_len = 0;
	enum wps_el_number elements[] = {
			VERSION,
			STATE,
			LOCKED,
			MANUFACTURER,
			MODEL_NAME,
			MODEL_NUMBER,
			DEVICE_NAME,
			SSID,
			UUID,
			SERIAL,
			SELECTED_REGISTRAR,
			RESPONSE_TYPE,
			PRIMARY_DEVICE_TYPE,
			CONFIG_METHODS,
			RF_BANDS,
			OS_VERSION
	};

	/* Get the WPS IE data blob */
	wps_ie_data = get_wps_data(tags, len, &wps_data_len);
	wps->locked = UNSPECIFIED;

	if(wps_ie_data)
	{
		for(i=0; i<sizeof(elements); i++)
		{
			/* Search for each WPS element inside the WPS IE data blob */
			el = get_wps_data_element(wps_ie_data, wps_data_len, elements[i], &el_len);
			if(el)
			{
				if(el_len > LIBWPS_MAX_STR_LEN)
				{
					el_len = LIBWPS_MAX_STR_LEN;
				}

				switch(elements[i])
				{
					case VERSION:
						wps->version = (uint8_t) el[0];
						break;
					case STATE:
						wps->state = (uint8_t) el[0];
						break;
					case LOCKED:
						wps->locked = (uint8_t) el[0];
						break;
					case MANUFACTURER:
						ptr = wps->manufacturer;
						break;
					case MODEL_NAME:
						ptr = wps->model_name;
						break;
					case MODEL_NUMBER:
						ptr = wps->model_number;
						break;
					case DEVICE_NAME:
						ptr = wps->device_name;
						break;
					case SSID:
						ptr = wps->ssid;
						break;
					case UUID:
						src = hex2str(el, el_len);
						ptr = wps->uuid;
						break;
					case SERIAL:
						src = hex2str(el, el_len);
						ptr = wps->serial;
						break;
					case SELECTED_REGISTRAR:
						src = hex2str(el, el_len);
						ptr = wps->selected_registrar;
						break;
					case RESPONSE_TYPE:
						src = hex2str(el, el_len);
						ptr = wps->response_type;
						break;
					case PRIMARY_DEVICE_TYPE:
						src = hex2str(el, el_len);
						ptr = wps->primary_device_type;
						break;
					case CONFIG_METHODS:
						src = hex2str(el, el_len);
						ptr = wps->config_methods;
						break;
					case RF_BANDS:
						src = hex2str(el, el_len);
						ptr = wps->rf_bands;
						break;
					case OS_VERSION:
						src = hex2str(el, el_len);
						ptr = wps->os_version;
						break;
					default:
						src = NULL;
						ptr = NULL; 
				}

				if(!ptr)
				{
					continue;
				}

				memset(ptr, 0, LIBWPS_MAX_STR_LEN);
				if(!src)
				{
					memcpy(ptr, el, el_len);
				}
				else
				{
					strncpy(ptr, src, LIBWPS_MAX_STR_LEN);
					free(src);
				}

				src = NULL;
				ptr = NULL;
				free(el);
			}
		}

		ret_val = 1;
		free(wps_ie_data);
	} 

	return ret_val;
}

/* Extracts and returns the WPS IE from a beacon/probe response packet */
unsigned char *get_wps_data(const u_char *data, size_t len, size_t *tag_len)
{
	unsigned char *tag_data = NULL;
	struct tagged_parameter *tag_params = NULL;
	size_t tag_data_len = 0;
	int i = 0;

	for(i=0; i<len; i++)
	{
		/* Look for the WPS IE tag number */
		if(data[i] != WPS_TAG_NUMBER)
		{
			continue;
		}

		/* Double check remaining size in data buffer */
		if((len - i) > (WPS_VENDOR_ID_SIZE + VENDOR_ID_OFFSET))
		{
			/* 
			 * The WPS IE tag number is 'Vendor Specific' and has various other uses. 
			 * Verify that this is actually a WPS IE.
			 */
			if(memcmp((data+i+VENDOR_ID_OFFSET), WPS_VENDOR_ID, WPS_VENDOR_ID_SIZE) == 0)
			{
				tag_params = (struct tagged_parameter *) (data+i);
				tag_data_len = tag_params->len - WPS_VENDOR_ID_SIZE;

				tag_data = malloc(tag_data_len);
				if(tag_data)
				{
					memset(tag_data, 0, tag_data_len);
					memcpy(tag_data, (data+i+VENDOR_ID_OFFSET+WPS_VENDOR_ID_SIZE), tag_data_len);
					*tag_len = tag_data_len;
				}
	
				break;
			}
		}
	}

        return tag_data;
}

/* Gets the data for a given IE inside a tagged parameter list */
unsigned char *get_wps_data_element(const u_char *data, size_t len, uint16_t type, size_t *el_len)
{
        unsigned char *el_data = NULL;
        int offset = 0, tag_size = 0, el_data_size = 0;
        struct data_element *el = NULL;

        tag_size = sizeof(struct data_element);

        while((offset + tag_size) < len)
        {
                el = (struct data_element *) (data + offset);

                /* Check for the tag number and a sane tag length value */
                if((ntohs(el->type) == type) &&
                   (ntohs(el->len) <= (len - offset - tag_size))
                )
                {
			el_data_size = ntohs(el->len);
                        el_data = malloc(el_data_size);
                        if(el_data)
                        {
                                memset(el_data, 0, el_data_size);
                                memcpy(el_data, (data + offset + tag_size), el_data_size);
                                *el_len = el_data_size;
                        }
                        break;
		}

                offset += (tag_size + ntohs(el->len));
        }

        return el_data;
}

/* Make best guess to determine if a radio tap header is present */
int libwps_has_rt_header(const u_char *packet, size_t len)
{
        struct radio_tap_header *rt_header = 0;
        int yn = 1;

        rt_header = (struct radio_tap_header *) packet;

        if((rt_header->revision != RADIO_TAP_VERSION) ||
           ((int) rt_header->len <= 0) ||
           (rt_header->len >= len)
          )
        {
                yn = 0;
        }

        return yn;
}

/* 
 * Returns a pointer to the radio tap header. If there is no radio tap header,
 * it returns a pointer to a dummy radio tap header.
 */
const u_char *libwps_radio_header(const u_char *packet, size_t len)
{
        if(libwps_has_rt_header(packet, len))
        {
                return packet;
        }
        else
        {
                return (u_char *) FAKE_RADIO_TAP_HEADER;
        }

}

/* Convert raw data to a hex string */
char *hex2str(unsigned char *hex, int len)
{
	char *str = NULL;
	int str_len = 0, i = 0;
	char tmp_str[3] = { 0 };

	str_len = (len * 2);
	
	str = malloc(str_len+1);
	if(str)
	{
		memset(str, 0, (str_len+1));

		for(i=0; i<len; i++)
		{
			memset((char *) &tmp_str, 0, sizeof(tmp_str));
			snprintf((char *) &tmp_str, sizeof(tmp_str), "%.2X", hex[i]);
			strncat(str, (char *) &tmp_str, 2);
		}
	}

	return str;
}
