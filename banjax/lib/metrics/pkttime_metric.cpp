/* -*- mode C++; tab-width: 3; -*- */

/*
 * Copyright 2011 NICTA
 * 
 */

#define __STDC_CONSTANT_MACROS
#define __STDC_LIMIT_MACROS
#include <metrics/pkttime_metric.hpp>

#include <dot11/frame.hpp>
#include <dot11/data_frame.hpp>
#include <dot11/ip_hdr.hpp>
#include <dot11/llc_hdr.hpp>
#include <dot11/udp_hdr.hpp>

#include <iostream>
#include <iomanip>
#include <math.h>
#include <stdlib.h>

using namespace dot11;
using namespace net;
using namespace std;
using metrics::pkttime_metric;

pkttime_metric::pkttime_metric() :
   abstract_metric(),
   packets_(0),
   octets_(0),
   pkttime_(0),
   valid_(false)
{
}

pkttime_metric::pkttime_metric(const pkttime_metric& other) :
   abstract_metric(other),
   packets_(other.packets_),
   octets_(other.octets_),
   pkttime_(other.pkttime_),
   valid_(other.valid_)
{
}

pkttime_metric&
pkttime_metric::operator=(const pkttime_metric& other)
{
   if(this != &other) {
      abstract_metric::operator=(other);
      packets_ = other.packets_;
      octets_ = other.octets_;
      pkttime_ = other.pkttime_;
      valid_ = other.valid_;
   }
   return *this;
}

pkttime_metric::~pkttime_metric()
{
}

void
pkttime_metric::add(buffer_sptr b)
{
   frame f(b);
   buffer_info_sptr info(b->info());
   if(info->has(TX_FLAGS)) {
      bool tx_success = (0 == (info->tx_flags() & TX_FLAGS_FAIL));
      if(tx_success) {
         ++packets_;
         const uint32_t CRC_SZ = 4;
         octets_ += b->data_size() + CRC_SZ;
      }
   }
}

pkttime_metric*
pkttime_metric::clone() const
{
   return new pkttime_metric(*this);
}

double
pkttime_metric::compute(uint32_t elapsed)
{
   valid_ = (packets_ > 0);
   if(valid_) {
      pkttime_ = (static_cast<double>(elapsed) / packets_);
   } else {
      pkttime_ = 0.0;
   }
   return pkttime_;
}

void
pkttime_metric::reset()
{
   packets_ = 0;
   octets_ = 0;
}

void
pkttime_metric::write(ostream& os) const
{
   if(valid_)
      os << "PKTTIME: " << pkttime_;
   else
      os << "PKTTIME: - ";
}
