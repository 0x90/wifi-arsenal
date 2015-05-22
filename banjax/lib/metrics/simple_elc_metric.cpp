/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2011 NICTA
 * 
 */

#define __STDC_CONSTANT_MACROS
#include <metrics/simple_elc_metric.hpp>
#include <dot11/frame.hpp>
#include <dot11/data_frame.hpp>

#include <iostream>
#include <iomanip>
#include <math.h>

using namespace dot11;
using namespace net;
using namespace std;
using metrics::simple_elc_metric;

simple_elc_metric::simple_elc_metric() :
   abstract_metric(),
   t_pkt_(0.0),
   packet_octets_(0),
   elc_(0)
{
}

simple_elc_metric::simple_elc_metric(const simple_elc_metric& other) :
   abstract_metric(other),
   t_pkt_(other.t_pkt_),
   packet_octets_(other.packet_octets_),
   elc_(other.elc_)
{
}

simple_elc_metric&
simple_elc_metric::operator=(const simple_elc_metric& other)
{
   if(&other != this) {
      abstract_metric::operator=(other);
      t_pkt_ = other.t_pkt_;
      packet_octets_ = other.packet_octets_;
      elc_ = other.elc_;
   }
   return *this;
}

simple_elc_metric::~simple_elc_metric()
{
}

void
simple_elc_metric::add(buffer_sptr b)
{
   frame f(b);
   buffer_info_sptr info(b->info());
   data_frame_sptr df(f.as_data_frame());
   if(info->has(TX_FLAGS) && info->has(PACKET_TIME) && df && info->packet_time() != 0) {
      uint32_t tx_flags = info->tx_flags();
      if(!(tx_flags & TX_FLAGS_FAIL)) {
         const uint16_t CRC_SZ = 4;
         packet_octets_ += b->data_size() + CRC_SZ;
      }
      t_pkt_ += info->packet_time();
   }
}

simple_elc_metric*
simple_elc_metric::clone() const
{
   return new simple_elc_metric(*this);
}

double
simple_elc_metric::compute(uint32_t delta_us)
{
   elc_ = packet_octets_ / t_pkt_;
   return elc_;
}

void
simple_elc_metric::reset()
{
   t_pkt_ = 0.0;
   packet_octets_ = 0;
}

void
simple_elc_metric::write(ostream& os) const
{
   os << "ELC-Measured: " << elc_;
}
