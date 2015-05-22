/* -*- mode C++; tab-width: 3; -*- */

/*
 * Copyright 2011 NICTA
 * 
 */

#define __STDC_CONSTANT_MACROS
#define __STDC_LIMIT_MACROS
#include <metrics/iperf_metric_wrapper.hpp>

#include <dot11/data_frame.hpp>
#include <dot11/ip_hdr.hpp>
#include <dot11/llc_hdr.hpp>
#include <dot11/udp_hdr.hpp>
#include <util/exceptions.hpp>
#include <sstream>

using namespace dot11;
using namespace net;
using namespace std;
using metrics::iperf_metric_wrapper;

iperf_metric_wrapper::iperf_metric_wrapper(metric_sptr wrapped_metric) :
   metric(),
   wrapped_metric_(wrapped_metric),
   all_frames_(0),
   iperf_frames_(0),
   debug_()
{
   CHECK_NOT_NULL(wrapped_metric);
}

iperf_metric_wrapper::iperf_metric_wrapper(const iperf_metric_wrapper& other) :
   metric(other),
   wrapped_metric_(other.wrapped_metric_->clone()),
   all_frames_(other.all_frames_),
   iperf_frames_(other.iperf_frames_),
   debug_(other.debug_)
{
}

iperf_metric_wrapper&
iperf_metric_wrapper::operator=(const iperf_metric_wrapper& other)
{
   if(this != &other) {
      metric::operator=(other);
      wrapped_metric_ = metric_sptr(other.wrapped_metric_->clone());
      all_frames_ = other.all_frames_;
      iperf_frames_ = other.iperf_frames_;
      debug_ = other.debug_;
   }
   return *this;
}

iperf_metric_wrapper::~iperf_metric_wrapper()
{
}

void
iperf_metric_wrapper::add(buffer_sptr b)
{
   frame f(b);
   all_frames_++;

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

   wrapped_metric_->add(b);
   iperf_frames_++;
}

iperf_metric_wrapper*
iperf_metric_wrapper::clone() const
{
   return new iperf_metric_wrapper(*this);
}

double
iperf_metric_wrapper::compute(uint64_t mactime, uint32_t delta_us)
{
#ifndef NDEBUG
   ostringstream os;
   os << ", all-frames: " << all_frames_;
   os << ", iperf-frames: " << iperf_frames_;
   debug_ = os.str();
#endif
   return wrapped_metric_->compute(mactime, delta_us);
}

void
iperf_metric_wrapper::reset()
{
   all_frames_ = 0;
   iperf_frames_ = 0;
   wrapped_metric_->reset();
}

void
iperf_metric_wrapper::write(ostream& os) const
{
   wrapped_metric_->write(os);
#ifndef NDEBUG
   os << debug_;
#endif
}
