/* -*- mode C++; tab-width: 3; -*- */

/*
 * Copyright 2013 NICTA
 * 
 */

#define __STDC_CONSTANT_MACROS
#define __STDC_LIMIT_MACROS
#include <metrics/saturation_metric.hpp>

#include <dot11/frame.hpp>
#include <util/exceptions.hpp>

#include <iostream>
#include <iomanip>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <sstream>

using namespace dot11;
using namespace net;
using namespace std;
using metrics::saturation_metric;

saturation_metric::saturation_metric(const string& name) :
   metric(),
   name_(name),
   time_(0),
   saturation_(0.0),
   debug_()
{
}

saturation_metric::saturation_metric(const saturation_metric& other) :
   metric(other),
   name_(other.name_),
   time_(other.time_),
   saturation_(other.saturation_),
   debug_(other.debug_)
{
}

saturation_metric&
saturation_metric::operator=(const saturation_metric& other)
{
   if(this != &other) {
      metric::operator=(other);
      name_ = other.name_;
      time_ = other.time_;
      saturation_ = other.saturation_;
      debug_ = other.debug_;
   }
   return *this;
}

saturation_metric::~saturation_metric()
{
}

void
saturation_metric::add(buffer_sptr b)
{
   buffer_info_sptr info(b->info());
   time_ += info->packet_time();
}

saturation_metric*
saturation_metric::clone() const
{
   return new saturation_metric(*this);
}

double
saturation_metric::compute(uint64_t time, uint32_t delta_us)
{
   saturation_ = (static_cast<double>(time_) / delta_us) * 100.0;
#ifndef NDEBUG
   ostringstream os;
   os << ", " << name_ << "-time: " << time_;
   debug_ = os.str();
#endif
   return saturation_;
}

void
saturation_metric::reset()
{
   time_ = 0;
   saturation_ = 0;
}

void
saturation_metric::write(ostream& os) const
{
   os << name_ << ": " << saturation_;
   os << debug_;
}
