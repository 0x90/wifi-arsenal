/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2010-2011 Steve Glass
 * 
 * This file is part of banjax.
 * 
 * Banjax is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 * 
 * Banjax is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 */

#include <net/buffer_info.hpp>
#include <net/encoding.hpp>
#include <net/dsss_encoding.hpp>
#include <net/dsss_ofdm_encoding.hpp>
#include <net/fhss_encoding.hpp>
#include <net/ofdm_encoding.hpp>
#include <util/exceptions.hpp>

#include <iostream>
#include <iomanip>
#include <sstream>
#include <string.h>

using namespace net;
using namespace std;
using util::raise;

buffer_info::buffer_info() :
   present_(0)
{
}

buffer_info::~buffer_info()
{
}

void
buffer_info::clear(property_t props)
{
   present_ &= ~props;
}

bool
buffer_info::has(property_t props) const
{
   return((present_ & props) == props);
}

encoding_sptr
buffer_info::channel_encoding() const
{
   encoding_sptr enc;
   flags_t flags = channel_flags();
   if(flags & CHANNEL_CODING_DSSS) {
      enc = dsss_encoding::get();
   } else if(flags & CHANNEL_CODING_DYNAMIC) {
      enc = dsss_ofdm_encoding::get();
   } else if(flags & CHANNEL_CODING_FHSS) {
      enc = fhss_encoding::get();
   } else if(flags & CHANNEL_CODING_OFDM) {
      enc = ofdm_encoding::get();
   } else {
      ostringstream msg;
      msg << "unrecognized channel encoding (rxflags=" << hex << showbase << flags << ")";
      raise<logic_error>(__PRETTY_FUNCTION__, __FILE__, __LINE__, msg.str());
   }
   return enc;
}

flags_t
buffer_info::channel_flags() const
{
   PRECONDITION(has(CHANNEL_FLAGS));
   return channel_flags_;
}

void
buffer_info::channel_flags(flags_t f)
{
   channel_flags_ = f;
   present_ |= CHANNEL_FLAGS;
}

uint8_t
buffer_info::data_retries() const
{
   PRECONDITION(has(DATA_RETRIES));
   return data_retries_;
}

void
buffer_info::data_retries(uint8_t r)
{
   data_retries_ = r;
   present_ |= DATA_RETRIES;
}

uint32_t
buffer_info::freq_MHz() const
{
   PRECONDITION(has(FREQ_MHz));
   return freq_MHz_;
}

void
buffer_info::freq_MHz(uint32_t f)
{
   freq_MHz_ = f;
   present_ |= FREQ_MHz;
}

uint32_t
buffer_info::rate_Kbs() const
{
   PRECONDITION(has(RATE_Kbs));
   return rate_Kbs_;
}

void
buffer_info::rate_Kbs(uint32_t r)
{
   rate_Kbs_ = r;
   present_ |= RATE_Kbs;
}

uint8_t
buffer_info::rts_retries() const
{
   PRECONDITION(has(RTS_RETRIES));
   return rts_retries_;
}

void
buffer_info::rts_retries(uint8_t r)
{
   rts_retries_ = r;
   present_ |= RTS_RETRIES;
}

uint32_t
buffer_info::rx_flags() const
{
   PRECONDITION(has(RX_FLAGS));
   return rx_flags_;
}

void
buffer_info::rx_flags(uint32_t f)
{
   rx_flags_ = f;
   present_ |= RX_FLAGS;
}

int8_t
buffer_info::signal_dBm() const
{
   PRECONDITION(has(SIGNAL_dBm));
   return signal_dBm_;
}

void
buffer_info::signal_dBm(int8_t s)
{
   signal_dBm_ = s;
   present_ |= SIGNAL_dBm;
}

uint64_t
buffer_info::timestamp1() const
{
   PRECONDITION(has(TIMESTAMP1));
   return timestamp1_;
}

void
buffer_info::timestamp1(uint64_t t)
{
   timestamp1_ = t;
   present_ |= TIMESTAMP1;
}

uint64_t
buffer_info::timestamp2() const
{
   PRECONDITION(has(TIMESTAMP2));
   return timestamp2_;
}

void
buffer_info::timestamp2(uint64_t t)
{
   timestamp2_ = t;
   present_ |= TIMESTAMP2;
}

uint64_t
buffer_info::timestamp_wallclock() const
{
   PRECONDITION(has(TIMESTAMP_WALLCLOCK));
   return timestamp_wallclock_;
}

void
buffer_info::timestamp_wallclock(uint64_t t)
{
   timestamp_wallclock_ = t;
   present_ |= TIMESTAMP_WALLCLOCK;
}

uint32_t
buffer_info::tx_flags() const
{
   PRECONDITION(has(TX_FLAGS));
   return tx_flags_;
}

void
buffer_info::tx_flags(uint32_t f)
{
   tx_flags_ = f;
   present_ |= TX_FLAGS;
}

void
buffer_info::write(ostream& os) const
{
   if(has(TIMESTAMP1) && has(TIMESTAMP2))
      os << "PACKET-TIME: " << packet_time() << ", ";
   if(has(TIMESTAMP1))
      os << "TIMESTAMP1: " << timestamp1() << ", ";
   if(has(TIMESTAMP2))
      os << "TIMESTAMP2: " << timestamp2() << ", ";

   if(has(CHANNEL_FLAGS)) {
      os << "CHANNEL FLAGS:";
      uint32_t flags = channel_flags();
      char sep = ' ';
      if(flags & CHANNEL_PREAMBLE_LONG) {
         os << sep << "CHANNEL_PREAMBLE_LONG";
         sep = '|';
      }
      if(flags & CHANNEL_PREAMBLE_SHORT) {
         os << sep << "CHANNEL_PREAMBLE_SHORT";
         sep = '|';
      }
      if(flags & CHANNEL_CODING_DSSS) {
         os << sep << "CHANNEL_CODING_DSSS";
         sep = '|';
      }
      if(flags & CHANNEL_CODING_OFDM) {
         os << sep << "CHANNEL_CODING_OFDM";
         sep = '|';
      }
      if(flags & CHANNEL_CODING_FHSS) {
         os << sep << "CHANNEL_CODING_FHSS";
         sep = '|';
      }
      if(flags & CHANNEL_CODING_DYNAMIC) {
         os << sep << "CHANNEL_CODING_DYNAMIC";
         sep = '|';
      }
      if(flags & CHANNEL_RATE_FULL) {
         os << sep << "CHANNEL_RATE_FULL";
         sep = '|';
      }
      if(flags & CHANNEL_RATE_HALF) {
         os << sep << "CHANNEL_RATE_HALF";
         sep = '|';
      }
      if(flags & CHANNEL_RATE_QUARTER) {
         os << sep << "CHANNEL_RATE_QUARTER";
         sep = '|';
      }
      os << ", ";
   }

   if(has(RATE_Kbs))
      os << "RATE_Kbs: " << rate_Kbs() << ", ";
   if(has(FREQ_MHz))
      os << "FREQ_MHz: " << freq_MHz() << ", ";
   if(has(SIGNAL_dBm))
      os << "SIGNAL_dBm: " << static_cast<int16_t>(signal_dBm()) << ", ";
   if(has(DATA_RETRIES))
      os << "DATA RETRIES: " << static_cast<uint16_t>(data_retries()) << ", ";
   if(has(RTS_RETRIES))
      os << "RTS RETRIES: " <<  static_cast<uint16_t>(rts_retries()) << ", ";

   if(has(RX_FLAGS)) {
      os << "RX FLAGS:";
      uint32_t flags = rx_flags();
      char sep = ' ';
      if(flags & RX_FLAGS_BAD_FCS) {
         os << sep << "RX_FLAGS_BAD_FCS";
         sep = '|';
      }
      os << ", ";
   }

   if(has(TX_FLAGS)) {
      os << "TX FLAGS:";
      flags_t flags = tx_flags();
      char sep = ' ';
      if(flags & TX_FLAGS_FAIL) {
         os << sep << "TX_FLAGS_FAIL";
         sep = '|';
      }
      os << ", ";
   }

   if(has(RATES_Kbs)) {
      os << "RATES:";
      char sep = ' ';
      for(size_t i = 0; i < rates_.size(); ++i) {
         os << sep << rates_[i];
         sep='|';
      }
      os << ", ";
   }

   if(has(METRIC))
      os << "Metric: " << metric_ << ", ";

}

vector<uint32_t>
buffer_info::rates() const
{
   PRECONDITION(has(RATES_Kbs));
   return rates_;
}

void
buffer_info::rates(const vector<uint32_t>& rates)
{
   rates_ = rates;
   present_ |= RATES_Kbs;
}

uint32_t
buffer_info::packet_time() const
{
   return timestamp2() - timestamp1();
}

uint32_t
buffer_info::metric() const
{
   PRECONDITION(has(METRIC));
   return metric_;
}

void
buffer_info::metric(uint32_t m)
{
   metric_ = m;
   present_ |= METRIC;
}

ostream&
net::operator<<(ostream& os, const buffer_info& info)
{
   info.write(os);
   return os;
}
