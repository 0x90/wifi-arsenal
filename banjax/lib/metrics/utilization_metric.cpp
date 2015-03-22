/* -*- mode C++; tab-width: 3; -*- */

/*
 * Copyright 2013 NICTA
 * 
 */

#define __STDC_CONSTANT_MACROS
#define __STDC_LIMIT_MACROS
#include <metrics/utilization_metric.hpp>

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
using metrics::utilization_metric;

utilization_metric::utilization_metric(const string& name) :
   metric(),
   name_(name),
   time_(0),
   utilization_(0.0),
   debug_()
{
}

utilization_metric::utilization_metric(const utilization_metric& other) :
   metric(other),
   name_(other.name_),
   time_(other.time_),
   utilization_(other.utilization_),
   debug_(other.debug_)
{
}

utilization_metric&
utilization_metric::operator=(const utilization_metric& other)
{
   if(this != &other) {
      metric::operator=(other);
      name_ = other.name_;
      time_ = other.time_;
      utilization_ = other.utilization_;
      debug_ = other.debug_;
   }
   return *this;
}

utilization_metric::~utilization_metric()
{
}

void
utilization_metric::add(buffer_sptr b)
{
   const uint16_t AIFS = 43;
   const uint16_t CW = 67;
   const uint16_t SIFS = 16;

   frame f(b);
   buffer_info_sptr info(b->info());
   switch(f.fc().type()) {
   case CTRL_FRAME:
      time_ += SIFS + b->info()->packet_time();
      break;
   case MGMT_FRAME:
      time_ += AIFS + CW + b->info()->packet_time();
      break;
   case DATA_FRAME:
      time_ += AIFS + CW + b->info()->packet_time();
      break;
   }


}

utilization_metric*
utilization_metric::clone() const
{
   return new utilization_metric(*this);
}

double
utilization_metric::compute(uint64_t time, uint32_t delta_us)
{
   utilization_ = (static_cast<double>(time_) / delta_us) * 100.0;
#ifndef NDEBUG
   ostringstream os;
   os << ", " << name_ << "-time: " << time_;
   debug_ = os.str();
#endif
   return utilization_;
}

void
utilization_metric::reset()
{
   time_ = 0;
   utilization_ = 0;
}

void
utilization_metric::write(ostream& os) const
{
   os << name_ << ": " << utilization_;
   os << debug_;
}
