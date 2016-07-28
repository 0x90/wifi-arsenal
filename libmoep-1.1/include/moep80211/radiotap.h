/*
 * Copyright 2013, 2014		Maurice Leclaire <leclaire@in.tum.de>
 * 				Stephan M. Guenther <moepi@moepi.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * See COPYING for more details.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __MOEP80211_RADIOTAP_H
#define __MOEP80211_RADIOTAP_H


#include <moep80211/ieee80211_radiotap.h>


struct moep80211_radiotap {
	struct ieee80211_radiotap_header hdr;
	u64 mactime;			/* Value in microseconds of the MAC's
					 * 64-bit 802.11 Time Synchronization
					 * Function timer when the first bit of
					 * the MPDU arrived at the MAC. For
					 * received frames only.              */
	u8 flags;			/* Properties of transmitted and
					 * received frames.                   */
	u8 rate;			/* TX/RX data rate in 500 Kbps        */
	struct {
		u16 frequency;		/* Tx/Rx frequency in MHz             */
		u16 flags;
	} channel;
	struct {
		u8 hop_set;
		u8 hop_pattern;
	} fhss;				/* The hop set and pattern for
					 * frequency-hopping radios.          */
	s8 signal;			/* RF signal power at the antenna. This
					 * field contains a single signed 8-bit
					 * value, which indicates the RF signal
					 * power at the antenna, in decibels
					 * difference from 1mW.               */
	s8 noise;			/* RF noise power at the antenna. This
					 * field contains a single signed 8-bit
					 * value, which indicates the RF signal
					 * power at the antenna, in decibels
					 * difference from 1mW.               */
	u16 lock_quality;		/* Quality of Barker code lock. Unitless.
					 * Monotonically nondecreasing with
					 * "better" lock strength. Called
					 * "Signal Quality" in datasheets.    */
	u16 tx_attenuation;		/* Transmit power expressed as unitless
					 * distance from max power set at
					 * factory calibration. 0 is max power.
					 * Monotonically nondecreasing with
					 * lower power levels.                */
	u16 tx_attenuation_dB;		/* Transmit power expressed as decibel
					 * distance from max power set at
					 * factory calibration. 0 is max power.
					 * Monotonically nondecreasing with
					 * lower power levels.                */
	s8 tx_power;			/* Transmit power expressed as dBm
					 * (decibels from a 1 milliwatt
					 * reference). This is the absolute
					 * power level measured at the antenna
					 * port.                              */
	u8 antenna;			/* Unitless indication of the Rx/Tx
					 * antenna for this packet. The first
					 * antenna is antenna 0.              */
	u8 signal_dB;			/* RF signal power at the antenna,
					 * decibel difference from an arbitrary,
					 * fixed reference. This field contains
					 * a single unsigned 8-bit value.     */
	u8 noise_dB;			/* RF noise power at the antenna,
					 * decibel difference from an arbitrary,
					 * fixed reference. This field contains
					 * a single unsigned 8-bit value.     */
	u16 rx_flags;			/* Properties of received frames.     */
	u16 tx_flags;			/* Properties of transmitted frames.  */
	u8 rts_retries;			/* Number of RTS retries a transmitted
					 * frame used.                        */
	u8 data_retries;		/* Number of data retries a transmitted
					 * frame used.                        */
	struct {
		u8 known;		/* The known field indicates which
					 * information is known               */
		u8 flags;
		u8 mcs;			/* The mcs field indicates the MCS rate
					 * index as in IEEE_802.11n-2009      */
	} mcs;
	struct {
		u32 reference;
		u16 flags;
		u8 crc;
		u8 reserved;
	} ampdu;			/* The presence of this field indicates
					 * that the frame was received as part
					 * of an a-MPDU.                      */
	struct {
		u16 known;
		u8 flags;
		u8 bandwidth;
		u8 mcs_nss[4];
		u8 coding;
		u8 group_id;
		u16 partial_aid;
	} vht;
};

#endif /* __MOEP80211_RADIOTAP_H */
