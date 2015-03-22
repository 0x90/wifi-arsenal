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

#include <net/ofdm_encoding.hpp>
#include <util/exceptions.hpp>

#include <iostream>
#include <math.h>
#include <sstream>

using namespace net;
using namespace std;
using util::raise;

encoding_sptr
ofdm_encoding::get()
{
   static encoding_sptr enc(new ofdm_encoding);
   return enc;
}

ofdm_encoding::~ofdm_encoding()
{
}

uint16_t
ofdm_encoding::ACKTimeout() const
{
   const uint16_t OFDM_PHY_RX_START_DELAY = 25;
   return SIFS() + slot_time() + OFDM_PHY_RX_START_DELAY;
}

rateset
ofdm_encoding::basic_rates() const
{
   static const uint32_t RATES[] = {
      6000, 12000, 24000
   };
   static const size_t RATES_SZ = sizeof(RATES) / sizeof(RATES[0]);
   return rateset(&RATES[0], &RATES[RATES_SZ]);
}

uint16_t
ofdm_encoding::CWMIN() const
{
   return 15;
}

string
ofdm_encoding::name() const
{
   return "OFDM";
}

uint16_t
ofdm_encoding::SIFS() const
{
   return 16;
}

uint16_t
ofdm_encoding::slot_time() const
{
   return 9;
}

rateset
ofdm_encoding::supported_rates() const
{
   static const uint32_t RATES[] = {
      6000, 9000, 12000, 18000, 24000, 36000, 48000, 54000
   };
   static const size_t RATES_SZ = sizeof(RATES) / sizeof(RATES[0]);
   return rateset(&RATES[0], &RATES[RATES_SZ]);
}

uint16_t
ofdm_encoding::txtime(uint16_t frame_sz, uint32_t rate_Kbs, bool ignored) const
{
   CHECK(is_legal_rate(rate_Kbs));

   const float NDBPS = (rate_Kbs * 4) / 1000; // cf IEEE 802.11-2007 table 17.3
   const uint16_t PREAMBLE = 16;
   const uint16_t SIGNAL = 4;
   const uint16_t SYM = 4;
   return PREAMBLE + SIGNAL + SYM * ceill((16 + (8 * frame_sz) + 6) / NDBPS);
}

ofdm_encoding::ofdm_encoding()
{
}
