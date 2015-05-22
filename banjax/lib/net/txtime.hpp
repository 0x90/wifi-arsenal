/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2011 Steve Glass
 * 
 * This file is part of banjax.
 * 
 * Banjax is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 * 
 * Banjax is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 */

#ifndef NET_TXTIME_HPP
#define NET_TXTIME_HPP

#include <stdint.h>

namespace net {

	/**
    * Return the airtime (in microseconds) that it will take to
    * transmit at the given rate and frame size using the FHSS PHY.
    *
    * \param rate_Kbps The data rate in units of 1Kb/s.
    * \param frame_sz The size of the frame (including the FCS) in octets.
    * \param short_preamble True if short preambles are in use; otherwise false.
    * \return The airtime in microseconds.
    */
   uint32_t
   txtime_fhss(uint32_t rate_Kbs, uint16_t frame_sz, bool short_preamble);

	/**
    * Return the airtime (in microseconds) that it will take to
    * transmit at the given rate and frame size using the DSSS
    * PHY. This function is defined by the HR TXTIME calculation (IEEE
    * 802.11-2007 18.3.4). Note the size must include the FCS (which
    * is normally removed by banjax).
    *
    * \param rate_Kbps The data rate in units of 1Kb/s.
    * \param frame_sz The size of the frame (including the FCS) in octets.
    * \param short_preamble True if short preambles are in use; otherwise false.
    * \return The airtime in microseconds.
    */
   uint32_t
   txtime_dsss(uint32_t rate_Kbs, uint16_t frame_sz, bool short_preamble);

	/**
    * Return the airtime (in microseconds) that it will take to
    * transmit at the given rate and frame size using the OFDM
    * PHY. This function is defined by the OFDM TXTIME calculation
    * (IEEE 802.11-2007 17.4.3). Note the size must include the FCS
    * (which is normally removed by banjax).
    *
    * \param rate_Kbps The data rate in units of 1Kb/s.
    * \param frame_sz The size of the frame (including the FCS) in octets.
    * \return The airtime in microseconds.
    */
   uint32_t
   txtime_ofdm(uint32_t rate_Kbs, uint16_t frame_sz);

	/**
    * Return the airtime (in microseconds) that it will take to
    * transmit at the given rate and frame size using the DSSS/OFDM
    * PHY. This function is defined by the DSSS/OFDM TXTIME
    * calculation (IEEE 802.11-2007 19.8.3.3). Note the size must
    * include the FCS (which is normally removed by banjax).
    *
    * \param rate_Kbps The data rate in units of 1Kb/s.
    * \param frame_sz The size of the frame (including the FCS) in octets.
    * \param short_preamble True if short preambles are in use; otherwise false.
    * \return The airtime in microseconds.
    */
   uint32_t
   txtime_dsss_ofdm(uint32_t rate_Kbs, uint16_t frame_sz, bool short_preamble);

}

#endif // NET_TXTIME_HPP
