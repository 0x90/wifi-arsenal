/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2012 NICTA
 * 
 */

#define __STDC_CONSTANT_MACROS
#define __STDC_LIMIT_MACROS
#include <metrics/tmt_metric.hpp>

#include <dot11/frame.hpp>

#include <iostream>
#include <iomanip>
#include <math.h>
#include <sstream>
#include <stdlib.h>

using namespace dot11;
using namespace net;
using namespace std;
using metrics::tmt_metric;


tmt_metric::tmt_metric(encoding_sptr enc, uint32_t rate_kbs, uint16_t mpdu_sz, uint16_t rts_cts_threshold) :
   abstract_metric(),
   tmt_(0.0),
   debug_()
{
   const double TXTIME = successful_tx_time(enc, rate_kbs, mpdu_sz, rts_cts_threshold);
   tmt_ = mpdu_sz / TXTIME;

#ifndef NDEBUG
   ostringstream os;
   os << ", min-pkt-time: " << TXTIME;
#endif
}

tmt_metric::tmt_metric(const tmt_metric& other) :
   abstract_metric(other),
   tmt_(other.tmt_),
   debug_(other.debug_)
{
}

tmt_metric&
tmt_metric::operator=(const tmt_metric& other)
{
   if(this != &other) {
      abstract_metric::operator=(other);
      tmt_ = other.tmt_;
      debug_ = other.debug_;
   }
   return *this;
}

tmt_metric::~tmt_metric()
{
}

void
tmt_metric::add(buffer_sptr b)
{
}

tmt_metric*
tmt_metric::clone() const
{
   return new tmt_metric(*this);
}

double
tmt_metric::compute(uint32_t ignored_delta_us)
{
   return tmt_;
}

void
tmt_metric::reset()
{
}

void
tmt_metric::write(ostream& os) const
{
   os << "TMT: " << tmt_;
   os << debug_;
}

uint32_t 
tmt_metric::successful_tx_time(encoding_sptr enc, uint32_t rate_kbs, uint16_t frame_sz, uint16_t rts_cts_threshold) const
{
   const bool PREAMBLE = false; // ToDo: recover preamble from encoding

   const uint32_t T_CW = avg_contention_time(enc, 0); // NB we assume frame always succeeds
   const uint32_t T_RTS_CTS = (rts_cts_threshold <= frame_sz) ? rts_cts_time(enc, frame_sz, PREAMBLE) : 0;
   const uint32_t T_DATA = enc->txtime(frame_sz, rate_kbs, PREAMBLE);
   const uint32_t ACK_SZ = 14;
   const uint32_t T_ACK = enc->txtime(ACK_SZ, enc->response_rate(rate_kbs), PREAMBLE);

   /* TODO: make QoS aware!
    */
   return /* AIFS[BE] */ 9 + enc->DIFS() /* AIFS[BE] */ + T_CW + T_RTS_CTS + T_DATA + enc->SIFS() + T_ACK;
}
