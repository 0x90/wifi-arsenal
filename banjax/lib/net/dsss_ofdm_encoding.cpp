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

#include <net/dsss_ofdm_encoding.hpp>
#include <util/exceptions.hpp>

#include <iostream>
#include <math.h>
#include <sstream>

using namespace net;
using namespace std;
using util::raise;

encoding_sptr
dsss_ofdm_encoding::get()
{
   static encoding_sptr enc(new dsss_ofdm_encoding);
   return enc;
}

dsss_ofdm_encoding::~dsss_ofdm_encoding()
{
}

uint16_t
dsss_ofdm_encoding::ACKTimeout() const
{
   const uint16_t DSSS_OFDM_PHY_RXSTART_DELAY = 192; // NB: 96us is possible when short_preambles are in use!
   return SIFS() + slot_time() + DSSS_OFDM_PHY_RXSTART_DELAY;
}

rateset
dsss_ofdm_encoding::basic_rates() const
{
   static const uint32_t RATES[] = {
      1000, 2000, 5500, 11000
   };
   static const size_t RATES_SZ = sizeof(RATES) / sizeof(RATES[0]);
   return rateset(&RATES[0], &RATES[RATES_SZ]);
}

uint16_t
dsss_ofdm_encoding::CWMIN() const
{
   return 31;
}

string
dsss_ofdm_encoding::name() const
{
   return "DSSS/OFDM";
}

uint16_t
dsss_ofdm_encoding::SIFS() const
{
   return 10;
}

uint16_t
dsss_ofdm_encoding::slot_time() const
{
   return 9;
}

rateset
dsss_ofdm_encoding::supported_rates() const
{
   static const uint32_t RATES[] = {
      1000, 2000, 5500, 11000, 6000, 9000, 12000, 18000, 24000, 36000, 48000, 54000
   };
   static const size_t RATES_SZ = sizeof(RATES) / sizeof(RATES[0]);
   return rateset(&RATES[0], &RATES[RATES_SZ]);
}

uint16_t
dsss_ofdm_encoding::txtime(uint16_t frame_sz, uint32_t rate_Kbs, bool has_short_preamble) const
{
   CHECK(is_legal_rate(rate_Kbs));

   uint32_t usecs = 0;
   rateset dsss_rates(basic_rates());
   const uint16_t PREAMBLE_DSSS = has_short_preamble ? 72 : 144;
   const uint16_t PLCP_DSSS = has_short_preamble ? 24 : 48;
   if(dsss_rates.find(rate_Kbs) != dsss_rates.end()) {
      // IEEE 802.11-2007 section 18.3.4 TXTIME calculation
      float RATE_Mbs = rate_Kbs / 1000;
      usecs = PREAMBLE_DSSS + PLCP_DSSS + ceill((frame_sz * 8) / RATE_Mbs);
   } else {
      // IEEE 802.11-2007 section 19.8.3 TXTIME calculation 
      const float NDBPS = (rate_Kbs * 4) / 1000; // cf IEEE 802.11-2007 table 17.3
      const uint16_t PREAMBLE_OFDM = 8;
      const uint16_t PLCP_OFDM = 4;
      const uint8_t PLCP_SVC_BITS = 16;
      const uint8_t PAD_BITS = 6;
      const uint16_t SIGNAL_EXT = 6;
      usecs = PREAMBLE_DSSS + PLCP_DSSS + PREAMBLE_OFDM + PLCP_OFDM + 4 * ceill((PLCP_SVC_BITS + (8 * frame_sz) + PAD_BITS) / NDBPS) + SIGNAL_EXT;
   }
   return usecs;
}

dsss_ofdm_encoding::dsss_ofdm_encoding()
{
}
