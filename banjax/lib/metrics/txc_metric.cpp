/* -*- mode C++; tab-width: 3; -*- */

/*
 * Copyright 2011 NICTA
 * 
 */

#define __STDC_CONSTANT_MACROS
#define __STDC_LIMIT_MACROS
#include <metrics/txc_metric.hpp>

#include <dot11/frame.hpp>

#include <iostream>
#include <iomanip>
#include <math.h>
#include <sstream>
#include <stdlib.h>

using namespace dot11;
using namespace net;
using namespace std;
using metrics::txc_metric;

txc_metric::txc_metric(string name) :
   abstract_metric(),
   name_(name),
   txc_(0.0),
   frames_delivered_(0),
   frame_transmissions_(0),
   max_txc_(0),
   debug_()
{
}

txc_metric::txc_metric(const txc_metric& other) :
   abstract_metric(other),
   name_(other.name_),
   txc_(other.txc_),
   frames_delivered_(other.frames_delivered_),
   frame_transmissions_(other.frame_transmissions_),
   max_txc_(other.max_txc_),
   debug_(other.debug_)
{
}

txc_metric&
txc_metric::operator=(const txc_metric& other)
{
   if(this != &other) {
      abstract_metric::operator=(other);
      name_ = other.name_;
      txc_ = other.txc_;
      frames_delivered_ = other.frames_delivered_;
      frame_transmissions_ = other.frame_transmissions_;
      max_txc_ = other.max_txc_;
      debug_ = other.debug_;
   }
   return *this;
}

txc_metric::~txc_metric()
{
}

void
txc_metric::add(buffer_sptr b)
{
   frame f(b);
   buffer_info_sptr info(b->info());
   if(info->has(TX_FLAGS)) {
      uint8_t txc = info->has(DATA_RETRIES) ? 1 + info->data_retries() : 1;
      frame_transmissions_ += txc;
      max_txc_ = max(max_txc_, txc);
      bool tx_success = !(info->tx_flags() & TX_FLAGS_FAIL);
      if(tx_success) {
         ++frames_delivered_;
      }
   }
}

txc_metric*
txc_metric::clone() const
{
   return new txc_metric(*this);
}

double
txc_metric::compute(uint32_t junk)
{
   txc_ = frame_transmissions_ / static_cast<double>(frames_delivered_);
#ifndef NDEBUG
   ostringstream os;
   os << ", " << name_ << "-max: " << static_cast<uint16_t>(max_txc_);
   os << ", " << name_ << "-transmissions: " << frame_transmissions_;
   os << ", " << name_ << "-delivered: " << frames_delivered_;
   debug_ = os.str();
#endif
   return txc_;
}

void
txc_metric::reset()
{
   frames_delivered_ = 0;
   frame_transmissions_ = 0;
   max_txc_ = 0;
}

void
txc_metric::write(ostream& os) const
{
   os << name_ << ": " << txc_;
   os << debug_;
}
