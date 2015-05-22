/* -*- mode C++; tab-width: 3; -*- */

/*
 * Copyright 2011-2012 NICTA
 * 
 */

#define __STDC_CONSTANT_MACROS
#define __STDC_LIMIT_MACROS

#include <metrics/airtime_metric_kernel.hpp>

#include <dot11/frame.hpp>
#include <util/exceptions.hpp>

#include <iostream>
#include <iomanip>
#include <math.h>
#include <stdlib.h>
#include <sstream>

using namespace dot11;
using namespace net;
using namespace std;
using metrics::airtime_metric_kernel;

airtime_metric_kernel::airtime_metric_kernel() :
   abstract_metric(),
   info_(),
   last_info_()
{
}

airtime_metric_kernel::airtime_metric_kernel(const airtime_metric_kernel& other) :
   abstract_metric(other),
   info_(other.info_),
   last_info_(other.last_info_)
{
}

airtime_metric_kernel&
airtime_metric_kernel::operator=(const airtime_metric_kernel& other)
{
   if(this != &other) {
      abstract_metric::operator=(other);
      info_ = other.info_;
      last_info_ = other.last_info_;
   }
   return *this;
}

airtime_metric_kernel::~airtime_metric_kernel()
{
}

void
airtime_metric_kernel::add(buffer_sptr b)
{
   frame f(b);
   buffer_info_sptr info(b->info());
   if(info->has(TX_FLAGS)) {
      bool tx_success = (0 == (info->tx_flags() & TX_FLAGS_FAIL));
      info_ = info;
   }
}

airtime_metric_kernel*
airtime_metric_kernel::clone() const
{
   return new airtime_metric_kernel(*this);
}

double
airtime_metric_kernel::compute(uint32_t ignored_delta_us)
{
   last_info_ = info_;
   return last_info_ ? last_info_->metric() : 0.0;
}

void
airtime_metric_kernel::reset()
{
   info_.reset();
}

void
airtime_metric_kernel::write(ostream& os) const
{
   os << "Airtime-Kernel: ";
   if(last_info_)
      os << last_info_->metric();
   else
      os << "- ";
}
