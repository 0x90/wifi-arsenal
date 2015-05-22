/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2011 NICTA
 * 
 */

#define __STDC_CONSTANT_MACROS

#include <metrics/goodput_metric.hpp>
#include <dot11/data_frame.hpp>

#include <iostream>
#include <iomanip>
#include <math.h>
#include <sstream>

using namespace dot11;
using namespace net;
using namespace std;
using metrics::goodput_metric;

goodput_metric::goodput_metric() :
   abstract_metric(),
   frame_octets_(0),
   packet_octets_(0),
   packets_(0),
   debug_(),
   mac_goodput_(0.0),
   transport_goodput_(0)
{
}

goodput_metric::goodput_metric(const goodput_metric& other) :
   abstract_metric(other),
   frame_octets_(other.frame_octets_),
   packet_octets_(other.packet_octets_),
   packets_(other.packets_),
   debug_(other.debug_),
   mac_goodput_(other.mac_goodput_),
   transport_goodput_(other.transport_goodput_)
{
}

goodput_metric&
goodput_metric::operator=(const goodput_metric& other)
{
   if(this != &other) {
      abstract_metric::operator=(other);
      frame_octets_ = other.frame_octets_;
      packet_octets_ = other.packet_octets_;
      packets_ = other.packets_;
      debug_ = other.debug_;
      mac_goodput_ = other.mac_goodput_;
      transport_goodput_ = other.transport_goodput_;
   }
   return *this;
}

goodput_metric::~goodput_metric()
{
}

void
goodput_metric::add(buffer_sptr b)
{
   frame f(b);
   buffer_info_sptr info(b->info());
   if(info->has(TX_FLAGS)) {
      bool failed = (info->tx_flags() & TX_FLAGS_FAIL);
      if(!failed) {
         const uint32_t IEEE80211_HDR_SZ = 24;
         const uint32_t LLC_HDR_SZ = 8;
         const uint32_t IP_HDR_SZ = 20;
         const uint32_t UDP_HDR_SZ = 8;
         const uint32_t CRC_SZ = 4;
         const uint16_t HDR_SZ = IEEE80211_HDR_SZ + LLC_HDR_SZ + IP_HDR_SZ + UDP_HDR_SZ + CRC_SZ;
         const uint16_t FRAME_SZ = b->data_size() + CRC_SZ;
         frame_octets_ += FRAME_SZ;
         packet_octets_ += FRAME_SZ - HDR_SZ;
         packets_++;
      }
   }
}

goodput_metric*
goodput_metric::clone() const
{
   return new goodput_metric(*this);
}

double
goodput_metric::compute(uint32_t delta_us)
{
   double delta = delta_us;
#ifndef NDEBUG
   ostringstream os;
   // os << ", goodput-packet-count: " << packets_;
   // os << ", goodput-packet-octets: " << packet_octets_;
   // os << ", good-putframe-octets: " << frame_octets_;
   os << ", pktsz-goodput: " << frame_octets_ / static_cast<double>(packets_);
   os << ", pkttime-goodput: " << delta / packets_;
   debug_ = os.str();
#endif
   transport_goodput_ = packet_octets_ / delta;
   mac_goodput_ = frame_octets_ / delta;
   return mac_goodput_;
}

void
goodput_metric::reset()
{
   frame_octets_ = 0;
   packet_octets_ = 0;
   packets_ = 0;
}

void
goodput_metric::write(ostream& os) const
{
   os << "goodput-transport: " << transport_goodput_ << ", ";
   os << "goodput-mac: " << mac_goodput_;
   os << debug_;
}
