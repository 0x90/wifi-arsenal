/* -*- mode C++; tab-width: 3; -*- */

/*
 * Copyright 2011 NICTA
 * 
 */

#define __STDC_CONSTANT_MACROS
#define __STDC_LIMIT_MACROS
#include <metrics/pdr_metric.hpp>

#include <dot11/frame.hpp>
#include <dot11/data_frame.hpp>

#include <iostream>
#include <iomanip>
#include <math.h>
#include <stdlib.h>

using namespace dot11;
using namespace net;
using namespace std;
using metrics::pdr_metric;

pdr_metric::pdr_metric() :
   attempts_(0),
   good_(0),
   pdr_(0.0)
{
}

pdr_metric::pdr_metric(const pdr_metric& other) :
   abstract_metric(other),
   attempts_(other.attempts_),
   good_(other.good_),
   pdr_(other.pdr_)
{
}

pdr_metric&
pdr_metric::operator=(const pdr_metric& other)
{
   if(this != &other) {
      abstract_metric::operator=(other);
      attempts_ = other.attempts_;
      good_ = other.good_;
      pdr_ = other.pdr_;
   }
   return *this;
}

pdr_metric::~pdr_metric()
{
}

void
pdr_metric::add(buffer_sptr b)
{
   frame f(b);
   buffer_info_sptr info(b->info());
   data_frame_sptr df(f.as_data_frame());
   if(info->has(TX_FLAGS) && df) {
      bool tx_success = (0 == (info->tx_flags() & TX_FLAGS_FAIL));
      if(tx_success) {
         ++good_;
      }
      attempts_ += info->has(DATA_RETRIES) ? 1 + info->data_retries() : 1;
   }
}

pdr_metric*
pdr_metric::clone() const
{
   return new pdr_metric(*this);
}

double
pdr_metric::compute(uint32_t delta_us)
{
   const double ATTEMPTS = attempts_;
   const double GOOD = good_;
   pdr_ = GOOD / ATTEMPTS;
   return pdr_;
}

void
pdr_metric::reset()
{
   attempts_ = 0;
   good_ = 0;
}

void
pdr_metric::write(ostream& os) const
{
   os << "PDR: " << pdr_;
}
