/* -*- mode C++; tab-width: 3; -*- */

/*
 * Copyright 2011 NICTA
 * 
 */

#define __STDC_CONSTANT_MACROS
#define __STDC_LIMIT_MACROS
#include <metrics/iperf_metric.hpp>

#include <dot11/data_frame.hpp>
#include <dot11/ip_hdr.hpp>
#include <dot11/llc_hdr.hpp>
#include <dot11/udp_hdr.hpp>
#include <util/exceptions.hpp>
#include <sstream>

using namespace dot11;
using namespace net;
using namespace std;
using metrics::iperf_metric;

iperf_metric::iperf_metric(const char *name, bool cw) :
   metric(),
   name_(name),
   cw_(cw),
   first_(true),
   last_seq_no_(0),
   packet_time_(0),
   packets_attempted_(0),
   packets_delivered_(0),
   packets_dropped_(0),
   metric_(0.0),
   valid_(0.0),
   debug_()
{
}

iperf_metric::iperf_metric(const iperf_metric& other) :
   metric(other),
   name_(other.name_),
   cw_(other.cw_),
   first_(other.first_),
   last_seq_no_(other.last_seq_no_),
   packet_time_(other.packet_time_),
   packets_attempted_(other.packets_attempted_),
   packets_delivered_(other.packets_delivered_),
   packets_dropped_(other.packets_dropped_),
   metric_(other.metric_),
   valid_(other.valid_),
   debug_(other.debug_)
{
}

iperf_metric&
iperf_metric::operator=(const iperf_metric& other)
{
   if(this != &other) {
      metric::operator=(other);
      name_ = other.name_;
      cw_ = other.cw_;
      first_ = other.first_;
      last_seq_no_ = other.last_seq_no_;
      packet_time_ = other.packet_time_;
      packets_attempted_ = other.packets_attempted_;
      packets_delivered_ = other.packets_delivered_;
      packets_dropped_ = other.packets_dropped_;
      metric_ = other.metric_;
      valid_ = other.valid_;
      debug_ = other.debug_;
   }
   return *this;
}

iperf_metric::~iperf_metric()
{
}

void
iperf_metric::add(buffer_sptr b)
{
   frame f(b);
   buffer_info_sptr info(b->info());
   encoding_sptr enc(info->channel_encoding());

   // is it an iperf packet?
   data_frame_sptr df(f.as_data_frame());
   if(!df)
      return;

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

   // compute packet overhead
   uint16_t IFS = 0;
   if(cw_) {
      switch(f.fc().type()) {
      case CTRL_FRAME:
         IFS = enc->SIFS();
         break;
      case MGMT_FRAME:
      case DATA_FRAME:
         IFS = enc->DIFS() + enc->slot_time(); // AIFS
         IFS += static_cast<uint16_t>((enc->CWMIN() / 2.0) * enc->slot_time());
         break;
      }
   }

   // update stats
   packets_attempted_++;
   packets_delivered_ += info->has(TX_FLAGS) ? ((info->tx_flags() & TX_FLAGS_FAIL) ? 0 : 1) : 0;
   packet_time_ += info->packet_time() + IFS;

   buffer_sptr udp_payload(udp->get_payload());
   uint32_t seq_no = udp_payload->read_u32(0);
   packets_dropped_ += first_ ? 0 : seq_no - last_seq_no_ + 1;
   last_seq_no_ = seq_no;
   first_ = false;

   // ToDo: use packet time to compute: jitter/avg packet time/actual offered load?
}

iperf_metric*
iperf_metric::clone() const
{
   return new iperf_metric(*this);
}

double
iperf_metric::compute(uint64_t mactime, uint32_t delta_us)
{
#ifndef NDEBUG
   ostringstream os;
   os << ", " << name_ << "-time: " << packet_time_;
   os << ", " << name_ << "-seq-no: " << last_seq_no_;
   os << ", " << name_ << "-delivered: " << packets_delivered_;
   os << ", " << name_ << "-dropped: " << packets_dropped_;
   debug_ = os.str();
#endif
   if(valid_ = (packets_delivered_ > 0))
   return metric_;
}

void
iperf_metric::reset()
{
   packet_time_ = 0;
   packets_attempted_ = 0;
   packets_delivered_ = 0;
   packets_dropped_ = 0;
}

void
iperf_metric::write(ostream& os) const
{
   if(valid_)
      os << name_ << ": " << metric_;
   else 
      os << " -";
   os << debug_;
}
