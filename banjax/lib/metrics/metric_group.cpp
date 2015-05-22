/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2011 NICTA
 * 
 */

#include <metrics/metric_group.hpp>
#include <util/exceptions.hpp>

#include <iostream>
#include <iomanip>

using namespace std;
using metrics::metric_group;
using net::buffer_sptr;

metric_group::metric_group() :
   metric(),
   metrics_()
{
}

metric_group::metric_group(const metric_group& other) :
   metric(other),
   metrics_()
{
   for(metric_list::const_iterator i(other.metrics_.begin()); i != other.metrics_.end(); ++i)
      metrics_.push_back(metric_sptr((*i)->clone()));
}

metric_group&
metric_group::operator=(const metric_group& other)
{
   if(&other != this) {
      metric::operator=(other);
      metrics_.clear();
      for(metric_list::const_iterator i(other.metrics_.begin()); i != other.metrics_.end(); ++i)
         metrics_.push_back(metric_sptr((*i)->clone()));
   }
   return *this;
}

metric_group::~metric_group()
{
}

void
metric_group::push_back(metric_sptr m)
{
   metrics_.push_back(m);
}

void
metric_group::add(buffer_sptr b)
{
   for(metric_list::iterator i(metrics_.begin()); i != metrics_.end(); ++i) {
      (*i)->add(b);
   }
}

metric_group*
metric_group::clone() const
{
   return new metric_group(*this);
}

double
metric_group::compute(uint64_t mactime, uint32_t delta_us)
{
   double sum = 0.0;
   for(metric_list::iterator i(metrics_.begin()); i != metrics_.end(); ++i) {
      sum += (*i)->compute(mactime, delta_us);
   }
   return sum / metrics_.size();
}

void
metric_group::reset()
{
   for(metric_list::iterator i(metrics_.begin()); i != metrics_.end(); ++i) {
      (*i)->reset();
   }
}

void
metric_group::write(ostream& os) const
{
   metric_list::const_iterator i(metrics_.begin());
   if(i != metrics_.end()) {
      os << **i;
      while(++i != metrics_.end()) {
         os << ", " << **i;
      }
   }
}
