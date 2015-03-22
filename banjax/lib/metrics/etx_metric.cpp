/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2011 NICTA
 * 
 */

#include <metrics/etx_metric.hpp>
#include <dot11/data_frame.hpp>
#include <dot11/frame.hpp>
#include <dot11/ip_hdr.hpp>
#include <dot11/llc_hdr.hpp>
#include <dot11/udp_hdr.hpp>

#include <iostream>
#include <iomanip>


using namespace dot11;
using namespace net;
using namespace std;
using metrics::etx_metric;

etx_metric::etx_metric(uint16_t probe_port, uint16_t window_sz) :
   probe_port_(probe_port),
   window_sz_(window_sz * 1000000),
   rx_probes_(),
   seq_no_(0)
{
}

etx_metric::etx_metric(const etx_metric& other) :
   probe_port_(other.probe_port_),
   window_sz_(other.window_sz_),
   rx_probes_(other.rx_probes_),
   seq_no_(other.seq_no_)
{
}

etx_metric&
etx_metric::operator=(const etx_metric& other)
{
   if(&other != this) {
      probe_port_ = other.probe_port_;
      rx_probes_ = other.rx_probes_;
      seq_no_ = other.seq_no_;
   }
   return *this;
}

etx_metric::~etx_metric()
{
}

void
etx_metric::add(buffer_sptr b)
{
   frame f(b);
   data_frame_sptr df(f.as_data_frame());
   if(df) {

      // ignore non-probe traffic
      llc_hdr_sptr llc(df->get_llc_hdr());
      if(!llc)
         return;
      ip_hdr_sptr ip(llc->get_ip_hdr());
      if(!ip)
         return;
      udp_hdr_sptr udp(ip->get_udp_hdr());
      if(!udp)
         return;

      // ToDo: find my forward ratio from this packet's content!
      buffer_sptr udp_packet(udp->get_payload());

      // add UDP probe to queue
      buffer_info_sptr info(b->info());
      if(udp->src_port() == probe_port_&& !info->has(TX_FLAGS)) {
         if(!rx_probes_.empty()) {
            buffer_sptr p(rx_probes_.back());
            data_frame prev(p);
         }
         rx_probes_.push_back(b);
      }
   }
}

etx_metric*
etx_metric::clone() const
{
   return new etx_metric(*this);
}

double
etx_metric::compute(uint64_t mactime, uint32_t delta_us)
{
   double d_f = 1.0;

   // drop all probes that arrived before start of current probe window
   while(!rx_probes_.empty()) {
      buffer_sptr b(rx_probes_.front());
      buffer_info_sptr info(b->info());
      if(window_sz_ <= (mactime - info->timestamp_wallclock())) {
         rx_probes_.pop_front();
      } else {
         break;
      }
   }

   double d_r = rx_probes_.size();
   etx_ = 1.0 / d_f * d_r;
   return etx_;
}

void
etx_metric::reset()
{
}

void
etx_metric::write(ostream& os) const
{
   os << "ETX: " << etx_;
}
