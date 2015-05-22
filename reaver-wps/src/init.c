/*
 * Reaver - Initialization functions
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

#include "init.h"

/* 
 * Generates a wps_config structure which is passed to wps_init() to create
 * an initial wps_data structure.
 */
struct wps_data *initialize_wps_data()
{
	struct wps_config *wpsconf = NULL;
	struct wps_data *wps = NULL;
	struct wps_registrar_config *reg_conf = NULL;
	
	wpsconf = malloc(sizeof(struct wps_config));
	if(!wpsconf)
	{
		perror("malloc");
		goto end;
	}
	memset(wpsconf, 0, sizeof(struct wps_config));

	reg_conf = malloc(sizeof(struct wps_registrar_config));
	if(!reg_conf)
	{
		perror("malloc");
		goto end;
	}
	memset(reg_conf, 0, sizeof(struct wps_registrar_config));

	/* Configure ourselves as a registrar */
        wpsconf->registrar = 1;

	/* Tell the AP to not generate a random PSK */
	reg_conf->disable_auto_conf = 1;

	/* Allocate space for the wps_context structure member */
	wpsconf->wps = malloc(sizeof(struct wps_context));
	if(!wpsconf->wps)
	{
		perror("malloc");
		goto end;
	}
	memset(wpsconf->wps, 0, sizeof(struct wps_context));

	/* 
	 * Initialize the registrar sub-structure. This is necessary when calling
	 * wpa_supplicant functions to build registrar response payloads.
	 */
	wpsconf->wps->registrar = wps_registrar_init(wpsconf->wps, (const struct wps_registrar_config *) reg_conf);
	if(wpsconf->wps->registrar == NULL)
	{
		cprintf(CRITICAL, "[X] ERROR: Failed to initialize registrar structure!\n");
	}

	/* 
	 * In registrar mode, only the uuid wps_context member needs to be 
	 * populated in order to call wps_init(). If acting as an enrollee,
	 * the wps_device_data sub-structure must also be populated.
	 */
	if(os_get_random(wpsconf->wps->uuid, UUID_LEN) == -1)
	{
		memcpy(wpsconf->wps->uuid, DEFAULT_UUID, UUID_LEN);
	}

	wps = wps_init(wpsconf);
	if(wps)
	{
		/* Report that we are a Windows 7 registrar, if --win7 was specified on the command line */
		if(wps->wps && get_win7_compat())
		{
			wps->wps->dev.device_name = WPS_DEVICE_NAME;
			wps->wps->dev.manufacturer = WPS_MANUFACTURER;
			wps->wps->dev.model_name = WPS_MODEL_NAME;
			wps->wps->dev.model_number = WPS_MODEL_NUMBER;
			memcpy(wps->wps->dev.pri_dev_type, WPS_DEVICE_TYPE, WPS_DEV_TYPE_LEN);
			memcpy((void *) &wps->wps->dev.os_version, WPS_OS_VERSION, 4);
			wps->wps->dev.rf_bands = WPS_RF_BANDS;
		}
	}
end:
	if(wpsconf) free(wpsconf);
	if(reg_conf) free(reg_conf);
	return wps;
}

/* Initializes pcap capture settings and returns a pcap handle on success, NULL on error */
pcap_t *capture_init(char *capture_source)
{
	pcap_t *handle = NULL;
	char errbuf[PCAP_ERRBUF_SIZE] = { 0 };
	
	handle = pcap_open_live(capture_source, BUFSIZ, 1, 0, errbuf);
	if(!handle)
	{
		handle = pcap_open_offline(capture_source, errbuf);
	}

	return handle;
}

