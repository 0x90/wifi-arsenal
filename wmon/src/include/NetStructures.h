/*
 *  Wireless Network Monitor
 *
 *  Copyright 2011 David Garcia Villalba, Daniel López Rovira, Marc Portoles Comeras and Albert Cabellos Aparicio
 *
 *  This file is part of wmon.
 *
 *  wmon is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  wmon is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with wmon.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef NET_STRUTS_H
#define NET_STRUTS_H

#include <stdint.h>

/**
 * IEEE 802.11 Mac header structure.
 *
 * @author David Garcia Villalba    <dagavi@gmail.com>
 * @author Daniel López Rovira      <daniellopezrovira@gmail.com>
 * @author Marc Portoles Comeras    <mportoles@cttc.cat>
 * @author Albert Cabellos Aparicio <acabello@ac.upc.edu>
 */
struct ieee80211_mac_header {
    union {
        struct {
            unsigned short int version : 2;
            unsigned short int type : 2;
            unsigned short int subtype : 4;
            bool toDS : 1;
            bool fromDS : 1;
            bool moreFrag : 1;
            bool retry : 1;
            bool pwrMgt : 1;
            bool moreData : 1;
            bool WEP : 1;
            bool order : 1;
        } fields;
        
        uint16_t value;
    } frameControl;
    
    uint16_t duration;
    uint8_t da[6];         ///< Destination Address
    uint8_t sa[6];         ///< Source Address
    uint8_t bssid[6];      ///< BSS ID
    uint16_t seq;          ///< Sequence Control
}__attribute__ ((packed)) ;

/**
 * Structure of the tagged parameters included on the IEEE 802.11 management frames.
 *
 * @author David Garcia Villalba    <dagavi@gmail.com>
 * @author Daniel López Rovira      <daniellopezrovira@gmail.com>
 * @author Marc Portoles Comeras    <mportoles@cttc.cat>
 * @author Albert Cabellos Aparicio <acabello@ac.upc.edu>
 */
struct tag_param {
	uint8_t	element_id; ///< Element identifier
	uint8_t	length;     ///< Lenght of the tagged parameter (excluding the 16 bytes of this structure)
};

/**
 * SSID tag parameter structure.
 *
 * @author David Garcia Villalba    <dagavi@gmail.com>
 * @author Daniel López Rovira      <daniellopezrovira@gmail.com>
 * @author Marc Portoles Comeras    <mportoles@cttc.cat>
 * @author Albert Cabellos Aparicio <acabello@ac.upc.edu>
 */
struct ssid_t : public tag_param {
	unsigned char ssid[33];	/* 32 + 1 for null */
};

/**
 * DS tag parameter structure.
 *
 * @author David Garcia Villalba    <dagavi@gmail.com>
 * @author Daniel López Rovira      <daniellopezrovira@gmail.com>
 * @author Marc Portoles Comeras    <mportoles@cttc.cat>
 * @author Albert Cabellos Aparicio <acabello@ac.upc.edu>
 */
struct ds_t : public tag_param {
    uint8_t channel;
};

/**
 * Vendor specific tag parameter structure.
 *
 * @author David Garcia Villalba    <dagavi@gmail.com>
 * @author Daniel López Rovira      <daniellopezrovira@gmail.com>
 * @author Marc Portoles Comeras    <mportoles@cttc.cat>
 * @author Albert Cabellos Aparicio <acabello@ac.upc.edu>
 */
struct vendorspecific_t : public tag_param {
    uint8_t data[];
};

/**
 * IEEE 802.11 management frame header structure.
 *
 * @author David Garcia Villalba    <dagavi@gmail.com>
 * @author Daniel López Rovira      <daniellopezrovira@gmail.com>
 * @author Marc Portoles Comeras    <mportoles@cttc.cat>
 * @author Albert Cabellos Aparicio <acabello@ac.upc.edu>
 */
struct ieee80211_management_frame {
	long long timestamp;
	uint16_t interval;
	union {
	    struct {
	        bool ess : 1;   ///< Transmitter is an AP
	        bool ibss : 1;  ///< Transmitter belongs to a BSS
	        bool cfp0 : 1;
	        bool cpf1 : 1;
	        
	        bool privacy : 1; ///< AP/STA can support WEP
	        bool shortPreamble : 1;
	        bool pbcc : 1;
	        bool channelAgility : 1;
	        
	        bool spectrumManagement : 1;
	        bool cpf2 : 1;
	        bool shortSlotTime : 1;
	        bool apsd : 1;  ///< Automatic Power Save Delivery
	        
	        bool notUsed : 1;
	        bool dsssOfdm : 1;
	        bool delayedAck : 1;
	        bool immediateAck : 1;
	    } fields;
	    uint16_t value;
	} info;
} __attribute__ ((packed));

/**
 * IEEE 802.11 Radiotap header structure.
 *
 * @author David Garcia Villalba    <dagavi@gmail.com>
 * @author Daniel López Rovira      <daniellopezrovira@gmail.com>
 * @author Marc Portoles Comeras    <mportoles@cttc.cat>
 * @author Albert Cabellos Aparicio <acabello@ac.upc.edu>
 */
struct ieee80211_radiotap_header {
    uint8_t    it_version;
    uint8_t    it_pad;
    uint16_t   it_len;  ///< Radiotap header lenght
    uint32_t   it_present;
} __attribute__((__packed__));

#endif
