/* -*- mode C++; tab-width: 3; -*- */

/*
 * Copyright 2011 NICTA
 * 
 */

#define __STDC_CONSTANT_MACROS
#define __STDC_LIMIT_MACROS
#include <metrics/pktsz_metric.hpp>

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
using metrics::pktsz_metric;

pktsz_metric::pktsz_metric() :
   packets_(0),
   octets_(0),
   pktsz_(0.0)
{
}

pktsz_metric::pktsz_metric(const pktsz_metric& other) :
   abstract_metric(other),
   packets_(other.packets_),
   octets_(other.octets_),
   pktsz_(other.pktsz_)
{
}

pktsz_metric&
pktsz_metric::operator=(const pktsz_metric& other)
{
   if(this != &other) {
      abstract_metric::operator=(other);
      packets_ = other.packets_;
      octets_ = other.octets_;
      pktsz_ = other.pktsz_;
   }
   return *this;
}

pktsz_metric::~pktsz_metric()
{
}

void
pktsz_metric::add(buffer_sptr b)
{
   frame f(b);
   buffer_info_sptr info(b->info());
   data_frame_sptr df(f.as_data_frame());
   if(info->has(TX_FLAGS) && df) {
      // ignore non-iperf traffic
      llc_hdr_sptr llc(df->get_llc_hdr());
      if(!llc)
         return;
      ip_hdr_sptr ip(llc->get_ip_hdr());
      if(!ip)
         return;
      udp_hdr_sptr udp(ip->get_udp_hdr());
      if(!udp)
         return;
      if(udp->dst_port() != 5001)
         return;

      bool tx_success = (0 == (info->tx_flags() & TX_FLAGS_FAIL));
      if(tx_success) {
         const uint32_t CRC_SZ = 4;
         octets_ += b->data_size() + CRC_SZ;
         ++packets_;
      }
   }
}

pktsz_metric*
pktsz_metric::clone() const
{
   return new pktsz_metric(*this);
}

double
pktsz_metric::compute(uint32_t junk)
{
   pktsz_ = octets_ / static_cast<double>(packets_);
   return pktsz_;
}

void
pktsz_metric::reset()
{
   packets_ = 0;
   octets_ = 0;
}

void
pktsz_metric::write(ostream& os) const
{
   os << "PKTSZ: " << pktsz_;
}
