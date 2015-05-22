/*
 * Reaver - WPS PIN functions
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

#include "pins.h"

/* Builds a WPS PIN from the key tables */
char *build_wps_pin()
{
        char *key = NULL, *pin = NULL;
        int pin_len = PIN_SIZE + 1;

        pin = malloc(pin_len);
        key = malloc(pin_len);
        if(pin && key)
        {
                memset(key, 0, pin_len);
                memset(pin, 0, pin_len);

                /* Generate a 7-digit pin from the given key index values */
                snprintf(key, pin_len, "%s%s", get_p1(get_p1_index()), get_p2(get_p2_index()));

                /* Generate and append the pin checksum digit */
                snprintf(pin, pin_len, "%s%d", key, wps_pin_checksum(atoi(key)));

                free(key);
        }

        return pin;
}

/* 
 * Remove the last WPS pin (if any), build the next WPS pin in the p1 and p2 arrays, 
 * and populate the wps structure with the new pin.
 */
char *build_next_pin()
{
        char *pin = NULL;
        struct wps_data *wps = get_wps();

        /* Remove previous pin */
        wps_registrar_invalidate_pin(wps->wps->registrar, wps->uuid_e);

        /* Build a new pin */
        pin = build_wps_pin();
        if(pin)
        {
                /* Add the new pin */
                if(wps_registrar_add_pin(wps->wps->registrar, NULL, (const u8 *) pin, PIN_SIZE, 0) != 0)
                {
                        free(pin);
                        pin = NULL;
                }
        }

        return pin;
}

/* Generate the p1 and p2 pin arrays */
void generate_pins()
{
        int i = 0, index = 0;

	/* If the first half of the pin was not specified, generate a list of possible pins */
	if(!get_static_p1())
	{
		/* 
		 * Look for P1 keys marked as priority. These are pins that have been 
		 * reported to be commonly used on some APs and should be tried first. 
		 */
		for(index=0, i=0; i<P1_SIZE; i++)
		{
			if(k1[i].priority == 1)
			{
				set_p1(index, k1[i].key);
				index++;
			}
		}
        
		/* Randomize the rest of the P1 keys */
		for(i=0; index < P1_SIZE; i++)
        	{
	                if(!k1[i].priority)
	                {
	                        set_p1(index, k1[i].key);
	                        index++;
			}
		}
        }
	else
	{
		/* If the first half of the pin was specified by the user, only use that */
		for(index=0; index<P1_SIZE; index++)
		{
			set_p1(index, get_static_p1());
		}
	}

	/* If the second half of the pin was not specified, generate a list of possible pins */
	if(!get_static_p2())
	{
		/* 
		 * Look for P2 keys statically marked as priority. These are pins that have been 
		 * reported to be commonly used on some APs and should be tried first. 
		 */
		for(index=0, i=0; i<P2_SIZE; i++)
		{
			if(k2[i].priority == 1)
			{
				set_p2(index, k2[i].key);
				index++;
			}
		}

		/* Randomize the rest of the P2 keys */
        	for(i=0; index < P2_SIZE; i++)
        	{
                	if(!k2[i].priority)
                	{
                	        set_p2(index, k2[i].key);
                	        index++;
			}
                }
        }
	else
	{
		/* If the second half of the pin was specified by the user, only use that */
		for(index=0; index<P2_SIZE; index++)
		{
			set_p2(index, get_static_p2());
		}
	}

        return;
}

