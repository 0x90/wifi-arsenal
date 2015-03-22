/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2011-2012 NICTA
 * 
 */

#define __STDC_LIMIT_MACROS
#include <metrics/elc_metric.hpp>
#include <dot11/frame.hpp>
#include <dot11/data_frame.hpp>

#include <iostream>
#include <iomanip>
#include <math.h>
#include <sstream>

using namespace dot11;
using namespace net;
using namespace std;
using metrics::elc_metric;

elc_metric::elc_metric(const string& name, uint16_t rts_cts_threshold, uint16_t cw_time_us, uint32_t dead_time, uint16_t acktimeout) :
   abstract_metric(),
   name_(name),
   rts_cts_threshold_(rts_cts_threshold),
   cw_time_us_(cw_time_us),
   t_dead_(dead_time),
   acktimeout_(acktimeout),
   n_pkt_succ_(0),
   t_pkt_succ_(0.0),
   t_pkt_fail_(0.0),
   packet_octets_(0),
   elc_(0),
   debug_()
{
}

elc_metric::elc_metric(const elc_metric& other) :
   abstract_metric(other),
   name_(other.name_),
   rts_cts_threshold_(other.rts_cts_threshold_),
   cw_time_us_(other.cw_time_us_),
   t_dead_(other.t_dead_),
   acktimeout_(other.acktimeout_),
   n_pkt_succ_(other.n_pkt_succ_),
   t_pkt_succ_(other.t_pkt_succ_),
   t_pkt_fail_(other.t_pkt_fail_),
   packet_octets_(other.packet_octets_),
   elc_(other.elc_),
   debug_(other.debug_)
{
}

elc_metric&
elc_metric::operator=(const elc_metric& other)
{
   if(&other != this) {
      abstract_metric::operator=(other);
      name_ = other.name_;
      rts_cts_threshold_ = other.rts_cts_threshold_;
      cw_time_us_ = other.cw_time_us_;
      t_dead_ = other.t_dead_;
      acktimeout_ = other.acktimeout_;
      n_pkt_succ_ = other.n_pkt_succ_;
      t_pkt_succ_ = other.t_pkt_succ_;
      t_pkt_fail_ = other.t_pkt_fail_;
      packet_octets_ = other.packet_octets_;
      elc_ = other.elc_;
      debug_ = other.debug_;
   }
   return *this;
}

elc_metric::~elc_metric()
{
}

void
elc_metric::add(buffer_sptr b)
{
   frame f(b);
   buffer_info_sptr info(b->info());
   data_frame_sptr df(f.as_data_frame());
   if(info->has(TX_FLAGS) && df) {
      uint32_t tx_flags = info->tx_flags();
      if(tx_flags & TX_FLAGS_FAIL) {
         t_pkt_fail_ += packet_fail_time(b);
      } else {
         ++n_pkt_succ_;
         t_pkt_succ_ += packet_succ_time(b);
         const uint32_t CRC_SZ = 4;
         packet_octets_ += b->data_size() + CRC_SZ;
      }
   }
}

elc_metric*
elc_metric::clone() const
{
   return new elc_metric(*this);
}

double
elc_metric::compute(uint32_t delta_us)
{
   elc_ = packet_octets_ / (t_pkt_succ_ + t_pkt_fail_ + t_dead_);
#ifndef NDEBUG
   ostringstream os;
   streamsize p = os.precision();
   os << setprecision(0);
   os << ", n-pkts: " << n_pkt_succ_;
   os << ", t-pkt-succ: " << fixed << t_pkt_succ_;
   os << ", t-pkts-fail: " << fixed << t_pkt_fail_;
   os << ", t-dead: " << t_dead_ << ", ";  
   debug_ = os.str();
#endif
   return elc_;
}

void
elc_metric::reset()
{
   n_pkt_succ_ = 0;
   t_pkt_succ_ = 0;
   t_pkt_fail_ = 0;
   packet_octets_ = 0;
}

void
elc_metric::write(ostream& os) const
{
   os << name_ << ": " << elc_;
}

double
elc_metric::packet_succ_time(buffer_sptr b) const
{
   double usecs = 0.0;
   buffer_info_sptr info(b->info());
   encoding_sptr enc(info->channel_encoding());
   uint8_t retries = info->data_retries();
   for(uint8_t i = 0; i < retries; ++i) {
      usecs += (UINT16_MAX == cw_time_us_ ? avg_contention_time(enc, i) : cw_time_us_) + frame_fail_time(b);
   }
   return usecs + (UINT16_MAX == cw_time_us_ ? avg_contention_time(enc, retries) : cw_time_us_) + frame_succ_time(b);
}

double
elc_metric::packet_fail_time(buffer_sptr b) const
{
   double usecs = 0.0;
   buffer_info_sptr info(b->info());
   encoding_sptr enc(info->channel_encoding());
   uint8_t retries = info->data_retries();
   for(uint8_t i = 0; i < retries + 1; ++i) {
      usecs += (UINT16_MAX == cw_time_us_ ? avg_contention_time(enc, i) : cw_time_us_) + frame_fail_time(b);
  }
   return usecs;
}

double 
elc_metric::frame_succ_time(buffer_sptr b) const
{
   buffer_info_sptr info(b->info());
   encoding_sptr enc(info->channel_encoding());

   const uint32_t CRC_SZ = 4;
   const uint32_t FRAME_SZ = b->data_size() + CRC_SZ;
   const bool PREAMBLE =  info->has(CHANNEL_FLAGS) && (info->channel_flags() & CHANNEL_PREAMBLE_SHORT);
   const uint32_t T_RTS_CTS = (rts_cts_threshold_ <= FRAME_SZ) ? rts_cts_time(enc, FRAME_SZ, PREAMBLE) : 0;
   const uint32_t DATA_RATE = info->rate_Kbs();
   const uint32_t T_DATA = enc->txtime(FRAME_SZ, DATA_RATE, PREAMBLE);
   const uint32_t ACK_SZ = 14;
   const uint32_t ACK_RATE = enc->response_rate(DATA_RATE);
   const uint32_t T_ACK = enc->txtime(ACK_SZ, ACK_RATE, PREAMBLE);

   /* TODO: use enc->AIFS() not DIFS + slot-time */
   return /**/ enc->DIFS() + enc->slot_time() /**/ + T_RTS_CTS + T_DATA + enc->SIFS() + T_ACK;
}

double
elc_metric::frame_fail_time(buffer_sptr b) const
{
   buffer_info_sptr info(b->info());
   encoding_sptr enc(info->channel_encoding());

   const uint32_t CRC_SZ = 4;
   const uint32_t FRAME_SZ = b->data_size() + CRC_SZ;
   const bool PREAMBLE =  info->has(CHANNEL_FLAGS) && (info->channel_flags() & CHANNEL_PREAMBLE_SHORT);
   const uint32_t T_RTS_CTS = (rts_cts_threshold_ <= FRAME_SZ) ? rts_cts_time(enc, FRAME_SZ, PREAMBLE) : 0;
   const uint32_t DATA_RATE = info->rate_Kbs();
   const uint32_t T_DATA = enc->txtime(FRAME_SZ, DATA_RATE, PREAMBLE);
   const uint16_t T_ACKTIMEOUT = (UINT16_MAX == acktimeout_) ? enc->ACKTimeout() : acktimeout_;

   /* TODO: use AIFS not DIFS + slot-time */
   return /**/ enc->DIFS() + enc->slot_time() /**/ + T_RTS_CTS + T_DATA + T_ACKTIMEOUT;
}
