/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2011 NICTA
 * 
 */

#define __STDC_CONSTANT_MACROS
#define __STDC_LIMIT_MACROS
#include <metrics/abstract_metric.hpp>
#include <dot11/frame.hpp>
#include <util/exceptions.hpp>

#include <algorithm>
#include <math.h>
#include <stdexcept>

using namespace dot11;
using namespace net;
using namespace std;
using metrics::abstract_metric;
using util::raise;

abstract_metric::~abstract_metric()
{
}

double
abstract_metric::compute(uint64_t, uint32_t delta_us)
{
   return compute(delta_us);
}

double
abstract_metric::compute(uint32_t delta_us)
{
   raise<logic_error>(__PRETTY_FUNCTION__, __FILE__, __LINE__, "not implemented!");
}

abstract_metric::abstract_metric() :
   metric()
{
}

abstract_metric::abstract_metric(const abstract_metric& other) :
   metric(other)
{
}

abstract_metric&
abstract_metric::operator=(const abstract_metric& other)
{
   if(this != &other) {
      metric::operator=(other);
   }
   return *this;
}

double
abstract_metric::avg_contention_time(encoding_sptr enc, uint8_t txc) const
{
   CHECK_NOT_NULL(enc.get());

   double n_slots_avg = (max_contention_slots(enc, txc) - 1) / 2.0;
   double t_contention = (n_slots_avg * enc->slot_time());
   return t_contention;
}

uint16_t
abstract_metric::max_contention_slots(net::encoding_sptr enc, uint8_t txc) const
{
   CHECK_NOT_NULL(enc.get());
   
   const uint32_t CWMIN = enc->CWMIN();
   const uint32_t CWMAX = enc->CWMAX();
   const uint32_t CW = ((CWMIN + 1) << txc) - 1;

   return min(max(CW, CWMIN), CWMAX) + 1;
}

double
abstract_metric::max_contention_time(encoding_sptr enc, uint8_t txc) const
{
   return max_contention_slots(enc, txc) * enc->slot_time();
}

double
abstract_metric::rts_cts_time(encoding_sptr enc, uint32_t frame_sz, bool short_preamble) const
{
   CHECK_NOT_NULL(enc.get());
   CHECK_NOT_EQUAL(frame_sz, 0);

   const uint32_t RTS_SZ = 20;
   const uint32_t CTS_SZ = 14;
   const uint32_t T_SIFS = enc->SIFS();
   const uint32_t RATE = enc->default_rate();
   return enc->txtime(RTS_SZ, RATE, short_preamble) + T_SIFS + enc->txtime(CTS_SZ, RATE, short_preamble) + T_SIFS;
}

uint32_t
abstract_metric::closest_rate(encoding_sptr enc, uint32_t r) const
{
   uint32_t rate = 0;
   uint32_t d = UINT32_MAX;
   rateset rates(enc->supported_rates());
   for(rateset::const_iterator i(rates.begin()); i != rates.end(); ++i) {
      uint32_t t = llabs(static_cast<int64_t>(*i) - static_cast<int64_t>(r));
      if(t < d) {
         d = t;
         rate = *i;
      }      
   }
   return rate;
}
