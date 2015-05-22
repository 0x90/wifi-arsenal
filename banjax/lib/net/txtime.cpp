/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2009-2011 Steve Glass
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

#include <net/txtime.hpp>
#include <util/exceptions.hpp>

#include <cmath>
#include <sstream>

using namespace net;
using namespace std;
using util::raise;

uint32_t
net::txtime_fhss(uint32_t rate_Kbs, uint16_t frame_sz, bool short_preamble)
{
   float RATE_Mbs = rate_Kbs / 1000;
   const uint16_t PREAMBLE = 32 + 96;
   return PREAMBLE + ceill((frame_sz * 8) / RATE_Mbs);
}

uint32_t
net::txtime_dsss(uint32_t rate_Kbs, uint16_t frame_sz, bool short_preamble)
{
   float RATE_Mbs = rate_Kbs / 1000;
   const uint16_t PREAMBLE = (short_preamble ? 72 + 24 : 144 + 48);
   return PREAMBLE + ceill((frame_sz * 8) / RATE_Mbs);
}

/**
 * Number of data bits per symbol (NDBPS) lookup. This is defined by
 * IEEE 802.11-2007 table 17.3.
 *
 * \param rate_Kbs The data rate of the frame in units of 1Kb/s.
 * \return The number of data bits per symbol.
 * \throws invalid_argument When rate_Kbs is not a known data rate.
 */
static uint16_t
ndbps(uint32_t rate_Kbs)
{
   const uint32_t RATE_Mbs = rate_Kbs / 1000;
   static const uint8_t RATE_NSYMS[][2] = {
      {  6,  24 },
      {  9,  36 },
      { 12,  48 },
      { 18,  72 },
      { 24,  96 },
      { 36, 144 },
      { 48, 192 },
      { 54, 216 }
   };
   static const size_t NOF_RATE_NSYMS = sizeof(RATE_NSYMS) / sizeof(RATE_NSYMS[0]);
   for(size_t i = 0; i < NOF_RATE_NSYMS; ++i) {
      if(RATE_Mbs == RATE_NSYMS[i][0]) {
         return RATE_NSYMS[i][1];
      }
   }
   ostringstream msg;
   msg << "invalid data rate (rate = " << rate_Kbs << ")" << endl;
   raise<invalid_argument>(__PRETTY_FUNCTION__, __FILE__, __LINE__, msg.str());
}

uint32_t
net::txtime_ofdm(uint32_t rate_Kbs, uint16_t frame_sz)
{
   const float NDBPS = ndbps(rate_Kbs);
   const uint16_t PREAMBLE = 16;
   const uint16_t SIGNAL = 4;
   const uint16_t SYM = 4;
   return PREAMBLE + SIGNAL + SYM * ceill((16 + (8 * frame_sz) + 6) / NDBPS);
}

uint32_t
net::txtime_dsss_ofdm(uint32_t rate_Kbs, uint16_t frame_sz, bool short_preamble)
{
   const float NDBPS = ndbps(rate_Kbs);
   const uint16_t DSSS_PREAMBLE = (short_preamble ? 72 + 24 : 144 + 48);
   const uint16_t OFDM_PREAMBLE = 8 + 4;
   const uint16_t NSYMS = ceill((16 + 8 * frame_sz + 6) / NDBPS);
   return DSSS_PREAMBLE + OFDM_PREAMBLE + 4 * NSYMS + 6;
}
