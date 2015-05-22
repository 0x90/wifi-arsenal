/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2012 NICTA
 * 
 */

#include <metrics/metric_damper.hpp>
#include <util/exceptions.hpp>

#include <iostream>
#include <iomanip>

using namespace std;
using metrics::metric_damper;
using net::buffer_sptr;

metric_damper::metric_damper(std::string name, metric_sptr metric, uint16_t queue_sz) :
   name_(name),
   metric_(metric),
   queue_sz_(queue_sz),
   queue_(),
   value_(0.0)
{
}

metric_damper::metric_damper(const metric_damper& other) :
   metric(other),
   name_(other.name_),
   metric_(other.metric_->clone()),
   queue_sz_(other.queue_sz_),
   queue_(other.queue_),
   value_(other.value_)
{
}

metric_damper&
metric_damper::operator=(const metric_damper& other)
{
   if(&other != this) {
      metric::operator=(other);
      name_ = other.name_;
      metric_ = metric_sptr(other.metric_->clone());
      queue_sz_ = other.queue_sz_;
      queue_ = other.queue_;
      value_ = other.value_;
   }
   return *this;
}

metric_damper::~metric_damper()
{
}

metric_damper*
metric_damper::clone() const
{
   return new metric_damper(*this);
}

void
metric_damper::add(buffer_sptr b)
{
   metric_->add(b);
}

double
metric_damper::compute(uint64_t mactime, uint32_t delta_us)
{
   double m = metric_->compute(mactime, delta_us);
   queue_.push_back(m);
   while(queue_sz_ < queue_.size()) {
      queue_.pop_front();
   }
   double x = 0.0;
   for(deque<double>::iterator i(queue_.begin()); i != queue_.end(); ++i) {
      x += *i;
   }
   value_ = x / queue_.size();
   return value_;
}

void
metric_damper::reset()
{
   metric_->reset();
}

void
metric_damper::write(ostream& os) const
{
   os << name_ << ": " << value_;
}
