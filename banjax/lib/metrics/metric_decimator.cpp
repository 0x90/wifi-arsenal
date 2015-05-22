/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2012 NICTA
 * 
 */

#include <metrics/metric_decimator.hpp>
#include <util/exceptions.hpp>

#include <iostream>
#include <iomanip>

using namespace std;
using metrics::metric_decimator;
using net::buffer_sptr;

metric_decimator::metric_decimator(std::string name, metric_sptr metric, uint16_t n) :
   name_(name),
   metric_(metric),
   n_(n),
   i_(0),
   value_(0.0)
{
}

metric_decimator::metric_decimator(const metric_decimator& other) :
   metric(other),
   name_(other.name_),
   metric_(other.metric_->clone()),
   n_(other.n_),
   i_(other.i_),
   value_(other.value_)
{
}

metric_decimator&
metric_decimator::operator=(const metric_decimator& other)
{
   if(&other != this) {
      metric::operator=(other);
      name_ = other.name_;
      metric_ = metric_sptr(other.metric_->clone());
      n_ = other.n_;
      i_ = other.i_;
      value_ = other.value_;
   }
   return *this;
}

metric_decimator::~metric_decimator()
{
}

metric_decimator*
metric_decimator::clone() const
{
   return new metric_decimator(*this);
}

void
metric_decimator::add(buffer_sptr b)
{
   if((++i_ % n_) == 0) {
      metric_->add(b);
   }
}

double
metric_decimator::compute(uint64_t mactime, uint32_t delta_us)
{
   value_ = metric_->compute(mactime, delta_us);
   return value_;
}

void
metric_decimator::reset()
{
   metric_->reset();
}

void
metric_decimator::write(ostream& os) const
{
   os << name_ << ": " << value_;
}
