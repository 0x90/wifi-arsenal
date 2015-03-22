/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2011 NICTA
 * 
 */

#define __STDC_CONSTANT_MACROS
#include <metrics/metric.hpp>

#include <iostream>

using namespace std;
using metrics::metric;
using net::buffer_sptr;

metric::~metric()
{
}

void
metric::add(buffer_sptr)
{
}

void
metric::write(ostream&) const
{
}

metric::metric()
{
}

metric::metric(const metric& other)
{
}

metric&
metric::operator=(const metric& other)
{
   return *this;
}
